# Run 235 — Release-binary governance evaluator post-mutation replay consume boundary evidence

## Scope

Run 235 is the release-binary evidence run for the Run 234 source/test
governance evaluator **post-mutation replay consume boundary** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`:

* the typed phase projections `MutationAuthorizationOutcome` (`LegacyBypass` /
  `Deferred` / `AuthorizedFresh` / `FreshnessFailClosed` / `ValidationOnly` /
  `MainNetRefused`, with `from_replay_runtime_outcome` projecting a Run 232
  `GovernanceEvaluatorReplayRuntimeOutcome`) and `MutationCompletionStatus`
  (`NotAttempted` / `AuthorizedButNotApplied` / `AppliedSuccessfully` /
  `ApplyFailed` / `RolledBack` / `ValidationOnly` / `UnsupportedSurface` /
  `MainNetRefused`);
* the consume binding `PostMutationConsumeInput` /
  `PostMutationConsumeExpectations`, both derivable from a Run 230
  `EvaluatorReplayFreshnessInput` via `from_freshness_input`;
* the typed outcome `ConsumeBoundaryOutcome` (`DoNotConsumeLegacyBypass`,
  `DoNotConsumeDeferred`, `DoNotConsumeValidationOnly`,
  `DoNotConsumeBeforeApply`, `DoNotConsumeApplyFailed`,
  `DoNotConsumeRolledBack`, `DoNotConsumeUnsupportedSurface`,
  `DoNotConsumeMainNetRefused`, `ConsumeFixtureAfterSuccess`,
  `FailClosedConsumeUnavailable`, `FailClosedProductionConsumeUnavailable`,
  `FailClosedMainNetConsumeUnavailable`, `FailClosedWrongBinding`) and its
  predicates (`authorizes_consume`, `no_consume`, `is_fail_closed`, `tag`);
* the pure entry point `evaluate_post_mutation_consume` and the explicit-consume
  entry point `perform_post_mutation_consume` that calls the Run 230
  `GovernanceEvaluatorReplayStateWriter::mark_consumed` **only** on the
  after-success consume path;
* the deterministic digest helpers `consume_authorization_digest`,
  `consume_transcript_digest`, and `post_mutation_consume_record_digest`;
* the invariant / fail-closed guard functions
  `mainnet_peer_driven_apply_remains_refused_under_consume_boundary`,
  `consume_only_after_successful_mutation`, `deferred_is_never_consumed`,
  `validation_only_is_never_consumed`,
  `production_mainnet_consume_remains_unavailable`,
  `local_operator_cannot_satisfy_consume_policy`,
  `peer_majority_cannot_satisfy_consume_policy`,
  `validator_set_rotation_remains_unsupported_under_consume_boundary`, and
  `policy_change_action_remains_unsupported_under_consume_boundary`.

Where Run 234 proved the consume boundary at the source/test level, Run 235
proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_235_governance_evaluator_replay_consume_boundary_release_binary_helper.rs`,
driven by
`scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh`)
that the release-built code exposes and exercises the consume boundary:

* consume is **after-success-only**: only `ConsumeFixtureAfterSuccess` (after
  `MutationCompletionStatus::AppliedSuccessfully` on a wired DevNet/TestNet
  fixture policy) authorizes a fixture consume;
* legacy-bypass, deferred (fresh-but-not-yet-effective), validation-only,
  authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface,
  and MainNet-refused outcomes never consume;
* the DevNet/TestNet `FixtureReplayStateStore` writer records consumed only on
  an explicit after-success `perform_post_mutation_consume` call (with a prior
  observation), and a re-validation then classifies the decision
  already-consumed through the Run 230 state;
* the production / MainNet consume writers remain callable but always fail
  closed unavailable;
* **MainNet peer-driven apply remains refused** and never consumes even when
  the replay state would otherwise be fresh;
* the consume authorization / transcript / record digests are deterministic in
  release mode and bind the full A15 field set;
* the Run 232/233 runtime integration remains compatible when the consume
  boundary is not wired; the Run 231 standalone and Run 229 peer-context
  release behaviour remains compatible.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/run_235/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 234 post-mutation consume boundary is a local/source-test-only pure
  function. Run 235 exercises it through release-built library symbols (the same
  symbols a future production call site would use), but the boundary itself
  performs no I/O and authorizes no mutation directly.
* The boundary composes with the Run 230 reader/writer traits and projects the
  Run 232 runtime-integration outcome into its `MutationAuthorizationOutcome`
  view.
* The `FixtureReplayStateStore` backing the DevNet/TestNet policy is an
  in-process map only. It is not a persistent store, reads as `Unavailable` for
  a MainNet environment, and introduces **no** RocksDB schema, file format, or
  database migration.
* Consume is after-success-only — only `ConsumeFixtureAfterSuccess` (after
  `AppliedSuccessfully`) authorizes a fixture consume; deferred,
  validation-only, authorized-but-not-applied, failed-apply, rolled-back,
  unsupported-surface, and MainNet-refused outcomes never consume.
* Production / MainNet consume is callable but always returns the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine is implemented. No real on-chain
  governance proof verifier is implemented.
* The boundary is pure: it performs no network or file I/O, writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, and never
  invokes Run 070 apply. The writer is never called on a non-consume path.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) and never
  consumes even when the replay/freshness state would otherwise be fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage format
  change or database migration.
* Existing Run 233, Run 231, Run 229, Run 227, and Run 225 release behaviour
  remains compatible.
* Full C4 remains open. C5 remains open.