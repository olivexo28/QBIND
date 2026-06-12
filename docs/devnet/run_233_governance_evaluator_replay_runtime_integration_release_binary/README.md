# Run 233 — Release-binary governance evaluator replay/freshness runtime integration evidence

## Scope

Run 233 is the release-binary evidence run for the Run 232 source/test
governance evaluator **replay/freshness runtime integration** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`:

* the integration context
  `GovernanceEvaluatorReplayRuntimeIntegrationContext` which composes the Run
  224 / Run 226 evaluator-runtime integration context (selector resolution ->
  sidecar/load-status -> runtime consumption -> evaluator request -> evaluator
  evaluation -> governance execution decision validation), the active Run 230
  `ReplayStatePolicy`, and the Run 230 `EvaluatorReplayFreshnessInput` /
  `EvaluatorReplayFreshnessExpectations` bound to the same evaluator material;
* the typed outcome `GovernanceEvaluatorReplayRuntimeOutcome`
  (`ProceedLegacyBypass`, `ProceedDeferred`, `ProceedFresh { .. }`,
  `ReplayFreshnessFailClosed(..)`, `RuntimeIntegrationFailClosed(..)`,
  `MainNetPeerDrivenApplyRefused`) and its predicates (`is_proceed`,
  `is_mutate_authorized`, `is_legacy_bypass`, `is_deferred`, `is_fail_closed`,
  `is_mainnet_peer_driven_apply_refused`, `tag`);
* the pure entry point `integrate_governance_evaluator_replay_runtime` that
  runs the composed stages in order, failing closed at the first stage that
  cannot proceed and authorizing a mutation only via the terminal
  `ProceedFresh` outcome after the replay/freshness state classified the
  decision fresh;
* the call-site / peer-context wiring entry points
  `wire_governance_evaluator_replay_runtime_callsite` and
  `wire_governance_evaluator_replay_runtime_peer_context`, plus the
  `GovernanceEvaluatorReplayRuntimeCallsiteFailClosed` carrier;
* the invariant guard functions
  `mainnet_peer_driven_apply_remains_refused_under_replay_runtime`,
  `fresh_replay_state_required_before_mutation`,
  `deferred_is_never_mutation_approval`,
  `production_mainnet_replay_state_remains_unavailable`,
  `validator_set_rotation_remains_unsupported_under_replay_runtime`, and
  `policy_change_action_remains_unsupported_under_replay_runtime`.

Where Run 232 proved the runtime integration at the source/test level, Run 233
proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper.rs`,
driven by
`scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the composed runtime
integration:

* the composition distinguishes legacy-bypass, deferred (fresh-but-not-yet
  effective), fully-authorized fresh mutate, replay/freshness fail-closed,
  runtime-integration fail-closed, and MainNet-peer-driven-apply-refused
  outcomes;
* the replay/freshness validation runs **after** the Run 224 layer authorizes
  a mutate and **before** any mutation is authorized, so a fresh replay state
  is required before mutation;
* only `ProceedFresh` authorizes a mutation; `ProceedDeferred` is **not** an
  approval, and every fail-closed outcome is pure and non-mutating;
* the production / MainNet replay readers remain callable but unavailable /
  fail-closed regardless of the resolved policy;
* **MainNet peer-driven apply remains refused** even when the replay/freshness
  state would otherwise be fresh;
* validator-set rotation and policy-change actions remain unsupported under the
  replay runtime;
* the composed Run 224 integration, Run 226 call-site wiring, Run 228 peer
  context, and Run 230 replay/freshness state boundary remain compatible.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/run_233/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 232 replay/freshness runtime integration is a local/source-test-only
  pure composition layer. Run 233 exercises it through release-built library
  symbols (the same symbols a future production call site would use), but the
  composition itself performs no I/O and authorizes no mutation directly.
* The composition layers the Run 224 evaluator runtime integration, the Run 226
  call-site wiring, the Run 228 peer evaluator context, and the Run 230
  replay/freshness state boundary as a mandatory pre-mutation gate.
* The `FixtureReplayStateStore` backing the DevNet/TestNet policy is an
  in-process map only. It is not a persistent store, reads as `Unavailable` for
  a MainNet environment, and introduces **no** RocksDB schema, file format, or
  database migration.
* Production / MainNet replay state is callable but always returns the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine is implemented. No real on-chain
  governance proof verifier is implemented.
* Read-only validation never marks consumed; explicit consume marks consumed
  only in the fixture evidence after a successful `ProceedFresh` authorization.
* The composition is pure: it performs no network or file I/O, writes no
  marker, writes no sequence, mutates no live trust, evicts no sessions, and
  never invokes Run 070 apply. The only mutation-authorizing outcome is
  `ProceedFresh`; `ProceedDeferred` is explicitly **not** an approval.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  when the replay/freshness state would otherwise be fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The composition changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage
  format change or database migration.
* Existing Run 231, Run 229, Run 227, Run 225, and Run 223 release behaviour
  remains compatible.
* Full C4 remains open. C5 remains open.