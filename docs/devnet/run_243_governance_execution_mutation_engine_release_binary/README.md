# Run 243 — Release-binary governance execution mutation-engine boundary evidence

## Scope

Run 243 is the release-binary evidence run for the Run 242 source/test
governance execution **mutation-engine boundary** in
`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`:

* the typed bindings `GovernanceMutationEngineInput`,
  `GovernanceMutationEngineExpectations`, `GovernanceMutationCandidate`,
  `GovernanceMutationSurface`, `GovernanceMutationPolicy`,
  `GovernanceMutationEnvironmentBinding`, and
  `GovernanceMutationRuntimeBinding`;
* the engine kind / outcome taxonomy `GovernanceMutationEngineKind`
  (`Disabled` / `FixtureDevNet` / `FixtureTestNet` / `ProductionUnavailable` /
  `MainNetUnavailable`) and `GovernanceMutationOutcome`
  (`ProceedLegacyBypassNoMutation`, `MutationAuthorized`,
  `MutationAppliedSuccessfully`, `MutationRejectedBeforeApply`,
  `MutationApplyFailed`, `MutationRolledBack`, `MutationAmbiguousFailClosed`,
  `ProductionMutationUnavailable`, `MainNetMutationUnavailable`,
  `MainNetPeerDrivenApplyRefused`, `ValidatorSetRotationUnsupported`,
  `PolicyChangeUnsupported`) and their predicates / `tag()` strings;
* the pure/mockable executor trait `GovernanceMutationExecutor` with the
  `FixtureMutationExecutor` (DevNet/TestNet, programmed result + invocation
  counter), `ProductionMutationExecutor`, and `MainNetMutationExecutor`
  (always unavailable / fail-closed) implementations;
* the entry point `evaluate_governance_mutation_engine`, which refuses MainNet
  peer-driven apply first, honours the legacy bypass, validates the binding
  before any apply, gates read-only / unsupported-action surfaces, routes
  production / MainNet engine kinds to unavailable, and hands a validated
  request to the executor only for a DevNet/TestNet fixture kind;
* the crash-window recovery helper `recover_governance_mutation_window`, which
  types every window and fails closed on every after-authorization / in-flight /
  unknown window;
* the call-site wiring helper `wire_governance_mutation_engine_callsite`
  (`Ok` only on a proceed outcome, `Err` on every fail-closed outcome);
* the durable composition helper
  `project_mutation_outcome_to_durable_completion`, which maps mutation-engine
  outcomes into the Run 240 durable runtime's `DurableMutationCompletion`
  semantics (only `MutationAppliedSuccessfully` projects to a consume-eligible
  `AppliedSuccessfully`);
* the grep-verifiable invariant / fail-closed guard functions
  (`mutation_engine_rejection_is_non_mutating`,
  `mutation_success_is_required_before_durable_consume`,
  `mutation_failure_never_consumes_durable_replay_state`,
  `mutation_rollback_never_consumes_durable_replay_state`,
  `production_mainnet_mutation_engine_unavailable`,
  `mainnet_peer_driven_apply_refused_by_mutation_engine`,
  `no_rocksdb_file_schema_migration_change_under_mutation_engine`,
  `validator_set_rotation_unsupported_by_mutation_engine`,
  `policy_change_unsupported_by_mutation_engine`,
  `local_operator_cannot_satisfy_mutation_engine_authority`,
  `peer_majority_cannot_satisfy_mutation_engine_authority`).

Where Run 242 proved the mutation-engine boundary at the source/test level, Run
243 proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs`,
driven by
`scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a `Disabled` policy and a `Disabled` engine kind are a legacy bypass that
  performs no mutation and never invokes the executor;
* a DevNet/TestNet fixture mutation success returns
  `MutationAppliedSuccessfully` and projects to the only consume-eligible
  `DurableMutationCompletion::AppliedSuccessfully`;
* authorized-not-applied, read-only validation, failed apply, rollback, and
  ambiguous after-authorization windows never consume;
* binding validation happens **before** any apply — a wrong environment / chain
  / genesis / governance surface / mutation surface / candidate digest /
  decision digest / proposal id / decision id / authority-domain sequence /
  lifecycle action, or a malformed candidate, is rejected before the executor
  (the helper proves the fixture executor invocation counter stays at zero);
* the crash-window recovery helper types every window and fails closed on an
  ambiguous / unknown window;
* production / MainNet engine kinds are reachable but always fail closed
  unavailable;
* **MainNet peer-driven apply remains refused** — before binding validation and
  before executor invocation, even when the binding is otherwise broken;
* validator-set rotation and policy-change actions remain unsupported;
* existing Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231 release
  behaviour remains compatible.

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
fixtures/
tables/
scenarios/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 242 mutation-engine boundary is a pure, typed function over its inputs
  plus a mockable executor. Run 243 exercises it through release-built library
  symbols (the same symbols a future production call site would use), but the
  boundary itself performs no I/O and applies no real mutation.
* The boundary specifies the MainNet-refusal-first, legacy-bypass,
  binding-validation, read-only-gating, unsupported-action-gating,
  engine-kind-routing, executor-hand-off, and durable-projection ordering a real
  mutation engine would have to honour, but implements **none** of that
  mutation: there is no real production mutation engine, no real governance
  execution engine, no real on-chain governance proof verifier, no real
  persistent replay backend, no RocksDB backend, no file format, no schema, no
  database migration, and no storage-format change.
* The `FixtureMutationExecutor` models success / authorized / failure / rollback
  / ambiguous outcomes and performs no real trust mutation; the
  `ProductionMutationExecutor` and `MainNetMutationExecutor` always return the
  typed unavailable / fail-closed result.
* `MutationAppliedSuccessfully` is the only outcome that projects to the
  consume-eligible `DurableMutationCompletion::AppliedSuccessfully`;
  authorized-not-applied, failed apply, rollback, and ambiguous after-
  authorization windows never consume.
* The boundary is non-mutating on every rejection path: it writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, performs no
  durable consume of its own, and never invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) before any
  mutation attempt, before binding validation, and before executor invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No real KMS / HSM / RemoteSigner backend. The boundary changes **no** network
  wire schema, trust-bundle schema, authority-marker schema, or sequence schema.
* Full C4 remains open. C5 remains open.
