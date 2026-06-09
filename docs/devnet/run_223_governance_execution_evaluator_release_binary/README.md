# Run 223 — Release-binary governance-execution evaluator-interface evidence

## Scope

Run 223 is the release-binary evidence run for the Run 222 source/test
production governance execution **evaluator interface** boundary in
`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`:

* the typed `ProductionGovernanceExecutionEvaluator` trait
  (`evaluate_governance_decision_source` /
  `verify_governance_evaluator_response`);
* the `EvaluatorSourceKind` and `EvaluatorPolicy` selectors;
* the `DecisionSourceIdentity`, `EvaluatorRequest`, and `EvaluatorResponse`
  typed records;
* the deterministic, domain-separated digest helpers
  (`source_identity_digest`, `request_digest`, `response_digest`,
  `evaluator_transcript_digest`);
* the fixture / emergency-council fixture evaluator implementations
  (`FixtureGovernanceExecutionEvaluatorInterface`,
  `EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface`);
* the production / on-chain / MainNet evaluator implementations
  (`ProductionDecisionSourceEvaluatorInterface`,
  `OnChainDecisionSourceEvaluatorInterface`,
  `MainnetDecisionSourceEvaluatorInterface`), callable but fail-closed as
  unavailable;
* the typed `EvaluatorOutcome` and `EvaluatorComposedOutcome`;
* `evaluate_governance_evaluator_with_peer_driven_guard`.

Where Run 222 proved the evaluator interface at the source/test level, Run
223 proves on real `target/release/qbind-node` plus a release-built helper
using the production library symbols that the release-built code exposes and
exercises the interface:

* the deterministic source / request / response / transcript digests are
  stable and field-binding in release mode;
* the fixture evaluator accepts only DevNet/TestNet decision sources under
  the explicit `FixtureDecisionSourceAllowed` policy;
* the emergency-council fixture evaluator accepts only an explicit emergency
  decision under the explicit `EmergencyCouncilFixtureSourceAllowed` policy;
* an evaluator response authorizes a lifecycle action only when the
  authorized action, candidate digest, and sequence all match;
* the production / on-chain / MainNet evaluator boundaries are callable and
  return the typed unavailable / fail-closed outcome;
* the Run 220 runtime-consumption behaviour remains compatible when the
  evaluator policy is `Disabled` (inert);
* `evaluate_governance_evaluator_with_peer_driven_guard` preserves the
  MainNet peer-driven apply refusal even when a fixture evaluator would
  otherwise approve.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
exit_codes/
helper_evidence/run_223/
reachability/source_reachability.txt
reachability/module_registration.txt
reachability/run_220_consumption_reachability.txt
grep_summaries/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
test_results/
```

## Reproduce

```bash
bash scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 222 evaluator interface is typed and release-evidenced through
  library symbols. It has **no** runtime CLI/env selector and **no**
  production call-site wiring: it composes with the Run 220 runtime
  consumption as a *future* production evaluator target, and the `Disabled`
  evaluator policy is inert, so the Run 221 runtime-consumption behaviour is
  unchanged. Full positive evaluator acceptance with a real proposal binding
  is exercised through the release-built helper, which uses the same library
  symbols a future production call site would.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet evaluators are callable but always return the typed unavailable /
  fail-closed outcome, regardless of the resolved policy.
* No real on-chain governance proof verifier is implemented.
* The fixture evaluator remains DevNet/TestNet evidence-only and is refused
  on a MainNet trust domain.
* The emergency-council fixture evaluator is explicit and non-production.
* The evaluator module is pure: every public function and trait method
  performs no network or file I/O, writes no marker, writes no sequence,
  mutates no live trust, evicts no sessions, and never invokes Run 070 apply.
  Validation-only and mutating rejection paths therefore perform no mutation.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  with a fixture evaluator approval.
* Full C4 remains open. C5 remains open.
