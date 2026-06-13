# Run 237 — Release-binary governance evaluator replay consume runtime integration evidence

## Scope

Run 237 is the release-binary evidence run for the Run 236 source/test
governance evaluator **replay consume runtime integration** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`:

* the typed input binding `ReplayConsumeRuntimeIntegrationInput` (which carries
  the Run 232 replay/freshness runtime-integration context plus the Run 234
  post-mutation consume input / expectations / policy) and its projections
  (`mutation_surface`, `mutation_completion_status`, `validation_surface`,
  `environment`, `chain_id`, `genesis_hash`);
* the typed outcome `ReplayConsumeRuntimeOutcome` (`ProceedLegacyBypassNoConsume`,
  `ProceedDeferredNoConsume`, `ProceedValidationOnlyNoConsume`,
  `ProceedFreshMutationAuthorized`, `ConsumeFixtureAfterMutationSuccess`,
  `DoNotConsumeBeforeApply`, `DoNotConsumeApplyFailed`, `DoNotConsumeRolledBack`,
  `DoNotConsumeUnsupportedSurface`, `DoNotConsumeMainNetRefused`,
  `ReplayRuntimeFailClosed`, `ConsumeFailClosed`, `ProductionConsumeUnavailable`,
  `MainNetConsumeUnavailable`, `MainNetPeerDrivenApplyRefused`) and its
  predicates (`authorizes_consume`, `no_consume`, `is_proceed`,
  `is_fail_closed`, `is_mainnet_peer_driven_apply_refused`, `tag`);
* the entry point `integrate_replay_consume_runtime`, which runs the real Run 232
  replay/freshness runtime integration **first** and only reaches the real
  Run 234 post-mutation consume boundary on a `ProceedFresh`, over the Run 230
  reader/writer traits;
* the wiring helper `wire_replay_consume_runtime_callsite` and its
  `ReplayConsumeRuntimeCallsiteFailClosed` guard;
* the invariant / fail-closed guard functions
  `consume_integrated_as_after_success_only_post_mutation_step`,
  `fresh_required_before_mutation_authorization_under_consume_runtime`,
  `deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime`,
  `mainnet_peer_driven_apply_remains_refused_under_consume_runtime`,
  `production_mainnet_consume_remains_unavailable_under_consume_runtime`,
  `validator_set_rotation_remains_unsupported_under_consume_runtime`, and
  `policy_change_action_remains_unsupported_under_consume_runtime`.

Where Run 236 proved the replay consume runtime integration at the source/test
level, Run 237 proves on real `target/release/qbind-node` plus a release-built
helper
(`crates/qbind-node/examples/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper.rs`,
driven by
`scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the integration:

* the Run 232 replay/freshness runtime integration runs **before** consume; any
  non-`ProceedFresh` replay/freshness outcome maps to a non-consuming outcome
  without ever calling the writer;
* fresh is required before mutation authorization;
* consume is **after-success-only**: only `ConsumeFixtureAfterMutationSuccess`
  (after a modeled `AppliedSuccessfully` on a wired DevNet/TestNet fixture
  policy) authorizes a fixture consume;
* legacy-bypass, deferred (fresh-but-not-yet-effective), validation-only,
  before-apply, failed-apply, rolled-back, unsupported-surface, and
  MainNet-refused outcomes never consume;
* the DevNet/TestNet `FixtureReplayStateStore` writer records consumed only on
  an explicit after-success path with a prior observation, and a re-validation
  then classifies the decision already-consumed / fail-closed through the
  Run 230 state;
* the production / MainNet consume writers remain callable but always fail
  closed unavailable;
* **MainNet peer-driven apply remains refused** and never consumes even when
  the replay state would otherwise be fresh;
* the consume authorization is overridden with the exact Run 232 freshness
  result;
* existing Run 235, Run 233, Run 231, Run 229, and Run 227 release behaviour
  remains compatible.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 236 replay consume runtime integration is a local/source-test-only
  pure composition. Run 237 exercises it through release-built library symbols
  (the same symbols a future production call site would use), but the
  integration itself performs no I/O and authorizes no mutation directly.
* The integration runs the real Run 232 replay/freshness runtime integration
  first and the real Run 234 post-mutation consume boundary only on a
  `ProceedFresh`, over the Run 230 reader/writer traits.
* Fresh is required before mutation authorization; consume is after-success-only
  — only `ConsumeFixtureAfterMutationSuccess` (after `AppliedSuccessfully`)
  authorizes a fixture consume; deferred, validation-only, before-apply,
  failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes
  never consume.
* The `FixtureReplayStateStore` backing the DevNet/TestNet policy is an
  in-process map only. It is DevNet/TestNet evidence-only, reads as
  `Unavailable` for a MainNet environment, and introduces **no** RocksDB schema,
  file format, or database migration.
* Production / MainNet consume is callable but always returns the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine, mutation engine, or on-chain governance
  proof verifier is implemented. No real KMS / HSM / RemoteSigner backend.
* The integration is pure: it performs no network or file I/O, writes no marker,
  writes no sequence, mutates no live trust, and never invokes Run 070 apply.
  The writer is never called on a non-consume path.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) and never
  consumes even when the replay/freshness state would otherwise be fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The integration changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage format
  change or database migration.
* Full C4 remains open. C5 remains open.
