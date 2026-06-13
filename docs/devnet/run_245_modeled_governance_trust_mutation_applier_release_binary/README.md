# Run 245 — Release-binary modeled governance trust-state mutation applier evidence

## Scope

Run 245 is the release-binary evidence run for the Run 244 source/test
governance **modeled trust-state mutation applier boundary** in
`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`:

* the modeled in-memory state `ModeledGovernanceTrustState`,
  `ModeledGovernanceTrustSnapshot`, `ModeledGovernanceTrustRoot`, and the
  `ModeledTrustRootStatus` (`active` / `retired` / `revoked` /
  `emergency-revoked`) lifecycle;
* the typed bindings `ModeledGovernanceTrustMutation`,
  `ModeledGovernanceTrustMutationInput`,
  `ModeledGovernanceTrustMutationExpectations`,
  `ModeledGovernanceTrustMutationPolicy`,
  `ModeledGovernanceTrustMutationSurface`,
  `ModeledGovernanceTrustMutationEnvironmentBinding`, and
  `ModeledGovernanceTrustMutationRuntimeBinding`;
* the action / outcome taxonomy `ModeledTrustMutationAction`
  (`AddTrustRoot` / `RetireTrustRoot` / `RevokeTrustRoot` /
  `EmergencyRevokeTrustRoot` / `Noop` and the unsupported
  `ValidatorSetRotationUnsupported` / `PolicyChangeUnsupported`) and
  `ModeledTrustMutationOutcome` (`ModeledMutationNotAttempted`,
  `ModeledMutationApplied`, `ModeledMutationRejectedBeforeSnapshot`,
  `ModeledMutationRejectedBeforeApply`, `ModeledMutationApplyFailed`,
  `ModeledMutationRolledBack`, `ModeledMutationRollbackFailedFatal`,
  `ModeledMutationAmbiguousFailClosed`, `ProductionModeledMutationUnavailable`,
  `MainNetModeledMutationUnavailable`, `MainNetPeerDrivenApplyRefused`,
  `ValidatorSetRotationUnsupported`, `PolicyChangeUnsupported`) and their
  predicates / `tag()` strings;
* the pure/mockable applier trait `ModeledGovernanceTrustMutationApplier` with
  the `FixtureModeledTrustMutationApplier` (DevNet/TestNet, invocation-counted,
  mutates only the modeled in-memory state), `ProductionModeledTrustMutationApplier`,
  and `MainNetModeledTrustMutationApplier` (always unavailable / fail-closed)
  implementations;
* the entry point `evaluate_modeled_trust_mutation`, which refuses MainNet
  peer-driven apply first, honours the legacy bypass, validates the binding
  before any snapshot, gates read-only / unsupported-action surfaces, routes
  production / MainNet applier kinds to unavailable, and hands a validated
  request to the applier only for a DevNet/TestNet fixture kind;
* the crash-window recovery helper `recover_modeled_trust_mutation`, which types
  every window and fails closed on every after-apply / in-flight / unknown
  window;
* the composition helpers `map_modeled_outcome_to_mutation_engine_outcome` (into
  the Run 242 `GovernanceMutationOutcome`),
  `project_modeled_outcome_to_durable_completion`, and
  `modeled_outcome_authorizes_durable_consume`, which project a modeled outcome
  through the Run 242 mutation outcome into the Run 240 durable runtime's
  `DurableMutationCompletion` semantics (only `ModeledMutationApplied` projects
  to a consume-eligible `AppliedSuccessfully`);
* the grep-verifiable invariant / fail-closed guard functions
  (`modeled_trust_applier_rejection_is_non_mutating`,
  `modeled_trust_applier_never_calls_run_070`,
  `modeled_trust_applier_never_mutates_live_pqc_trust_state`,
  `modeled_trust_applier_success_required_before_durable_consume`,
  `modeled_trust_applier_failure_never_consumes`,
  `modeled_trust_applier_rollback_never_consumes`,
  `modeled_trust_applier_ambiguous_window_fails_closed`,
  `production_mainnet_modeled_trust_applier_unavailable`,
  `mainnet_peer_driven_apply_refused_by_modeled_trust_applier`,
  `validator_set_rotation_unsupported_by_modeled_trust_applier`,
  `policy_change_unsupported_by_modeled_trust_applier`,
  `modeled_trust_applier_no_rocksdb_file_schema_migration_change`,
  `local_operator_cannot_satisfy_modeled_trust_applier_authority`,
  `peer_majority_cannot_satisfy_modeled_trust_applier_authority`).

Where Run 244 proved the modeled-applier boundary at the source/test level, Run
245 proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs`,
driven by
`scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a `Disabled` policy and a `Disabled` applier kind are a legacy bypass that
  performs no modeled mutation and never invokes the applier;
* a DevNet/TestNet fixture modeled add / retire / revoke / emergency-revoke /
  noop succeeds and mutates **only** the in-memory
  `ModeledGovernanceTrustState`;
* a modeled apply success maps to `MutationAppliedSuccessfully` and projects to
  the only consume-eligible `DurableMutationCompletion::AppliedSuccessfully`;
* binding validation happens **before** any snapshot — a wrong environment /
  chain / genesis / governance surface / mutation surface / candidate digest /
  decision digest / proposal id / decision id / authority-domain sequence /
  lifecycle action, or a malformed modeled mutation, is rejected before snapshot
  (the helper proves the fixture applier invocation counter stays at zero and
  the modeled state is unchanged);
* a read-only validation surface never mutates, and retiring / revoking a missing
  root snapshots then rejects-before-apply with the modeled state unchanged;
* the crash-window recovery helper types every window and fails closed on an
  after-apply / ambiguous / unknown window;
* production / MainNet applier kinds are reachable but always fail closed
  unavailable;
* **MainNet peer-driven apply remains refused** — before any snapshot and before
  applier invocation, even when the binding is otherwise broken;
* validator-set rotation and policy-change actions remain unsupported;
* existing Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231
  release behaviour remains compatible.

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
bash scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 244 modeled-applier boundary is a pure, typed function over its inputs
  plus a mockable applier that mutates only the in-memory
  `ModeledGovernanceTrustState`. Run 245 exercises it through release-built
  library symbols (the same symbols a future production call site would use), but
  the boundary itself performs no I/O and applies no real (live) mutation.
* The boundary specifies the MainNet-refusal-first, legacy-bypass,
  binding-validation, read-only-gating, unsupported-action-gating,
  applier-kind-routing, applier-hand-off, modeled-apply/rollback/report, and
  durable-projection ordering a real mutation applier would have to honour, but
  implements **none** of that production mutation: there is no real production
  mutation engine, no real governance execution engine, no real on-chain
  governance proof verifier, no real persistent replay backend, no RocksDB
  backend, no file format, no schema, no database migration, and no
  storage-format change.
* The `FixtureModeledTrustMutationApplier` mutates only the modeled in-memory
  `ModeledGovernanceTrustState` and performs no real trust mutation; the
  `ProductionModeledTrustMutationApplier` and `MainNetModeledTrustMutationApplier`
  always return the typed unavailable / fail-closed result.
* `ModeledMutationApplied` is the only outcome that maps to
  `MutationAppliedSuccessfully` and projects to the consume-eligible
  `DurableMutationCompletion::AppliedSuccessfully`; rejected, failed apply,
  rollback, rollback-failed, ambiguous, unavailable, and unsupported outcomes
  never consume.
* The boundary is non-mutating on every rejection path: it does not mutate
  `LivePqcTrustState`, writes no marker, writes no sequence, performs no live
  trust swap, evicts no sessions, performs no durable consume of its own, and
  never invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) before any
  snapshot, before binding validation, and before applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No real KMS / HSM / RemoteSigner backend. The boundary changes **no** network
  wire schema, trust-bundle schema, authority-marker schema, or sequence schema.
* Full C4 remains open. C5 remains open.