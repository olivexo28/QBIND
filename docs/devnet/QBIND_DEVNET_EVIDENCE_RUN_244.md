# QBIND DevNet evidence — Run 244

**Title.** Source/test governance modeled trust-state mutation applier boundary.

**Status.** PASS (source/test only). Run 244 adds the smallest in-memory model of
what a future governance mutation applier would do **after** every Run 242
mutation-engine gate has already passed: it snapshots a modeled trust state,
applies a modeled trust-state update, reports success / failure / rollback /
rollback-failed / ambiguous windows, and projects the result back through the Run
242 mutation outcome into the Run 240 durable completion semantics. Run 242 made
the hand-off of an already-authorized governance evaluator decision to a future
mutation executor explicit and typed, and Run 243 release-evidenced that
boundary, but the Run 242/243 fixture executor only *modeled outcomes* — it did
not model even an in-memory state transition shape. Run 244 closes that gap at the
source/test level.

Run 244 introduces a modeled in-memory trust-state mutation applier **boundary**,
**not** a real production mutation engine. It enables **no** production mutating
behavior. Any production-source module remains pure / source-test bounded and
fail-closed. It implements **no** real governance execution engine, **no** real
production mutation engine, **no** real on-chain governance proof verifier, **no**
real persistent replay backend, **no** RocksDB backend, **no** file format,
**no** schema, **no** database migration, **no** storage-format change, **no**
KMS/HSM backend, **no** RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format.

## Strict scope

* Source/test evidence only. No release-binary harness.
* The modeled applier mutates **only** the in-memory `ModeledGovernanceTrustState`
  in DevNet/TestNet fixture tests.
* It does **not** mutate `LivePqcTrustState`.
* It does **not** call Run 070.
* It does **not** perform a real trust swap.
* It does **not** evict sessions.
* It does **not** write sequence files.
* It does **not** write authority markers.
* It does **not** perform a durable consume by itself.
* Production/MainNet modeled appliers remain reachable but
  unavailable/fail-closed.
* No real governance execution engine; no real production mutation engine; no
  real on-chain governance proof verifier; no real persistent replay backend.
* No RocksDB/file/schema/migration/storage-format change.
* No KMS/HSM backend; no RemoteSigner backend.
* No MainNet governance enablement; no MainNet peer-driven apply enablement; no
  validator-set rotation; no policy-change action.
* Rejected modeled-applier paths are non-mutating; a rejection that happens before
  apply never invokes the fixture applier.
* Modeled apply success is required before a durable consume; failed apply,
  rollback, rollback failure, and ambiguous windows never consume.
* Run 244 does not weaken any prior run (Runs 070, 130–243) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`

Run 244 adds a new source module (registered in `lib.rs`) that defines:

* **Modeled in-memory trust-state types** — `ModeledGovernanceTrustState`,
  `ModeledGovernanceTrustSnapshot`, `ModeledGovernanceTrustRoot`
  (`ModeledTrustRootStatus`: `Active` / `Retired` / `Revoked` /
  `EmergencyRevoked`), `ModeledGovernanceTrustMutation`,
  `ModeledGovernanceTrustMutationInput`,
  `ModeledGovernanceTrustMutationExpectations`,
  `ModeledGovernanceTrustMutationPolicy`,
  `ModeledGovernanceTrustMutationSurface`,
  `ModeledGovernanceTrustMutationEnvironmentBinding`, and
  `ModeledGovernanceTrustMutationRuntimeBinding`. The modeled mutation references
  Run 222 evaluator / Run 242 mutation-engine material — never a copy of any wire
  payload.
* **Modeled mutation actions** — `ModeledTrustMutationAction`: `AddTrustRoot`,
  `RetireTrustRoot`, `RevokeTrustRoot`, `EmergencyRevokeTrustRoot`, `Noop`,
  `ValidatorSetRotationUnsupported`, `PolicyChangeUnsupported`.
* **Modeled applier outcomes** — `ModeledTrustMutationOutcome`:
  `ModeledMutationNotAttempted`, `ModeledMutationApplied`,
  `ModeledMutationRejectedBeforeSnapshot`, `ModeledMutationRejectedBeforeApply`,
  `ModeledMutationApplyFailed`, `ModeledMutationRolledBack`,
  `ModeledMutationRollbackFailedFatal`, `ModeledMutationAmbiguousFailClosed`,
  `ProductionModeledMutationUnavailable`, `MainNetModeledMutationUnavailable`,
  `MainNetPeerDrivenApplyRefused`, `ValidatorSetRotationUnsupported`, and
  `PolicyChangeUnsupported`, plus predicates (`is_applied`, `is_not_attempted`,
  `no_consume`, `applier_must_not_run`, `is_mainnet_peer_driven_apply_refused`)
  and a stable `tag`.
* **A pure/mockable trait boundary** — `ModeledGovernanceTrustMutationApplier`
  with `apply_modeled_mutation(...)` and `recover_modeled_mutation_window(...)`,
  taking a validated `ModeledTrustMutationRequest` (only constructed **after**
  every gate has passed, so an applier never sees a rejected-before-snapshot
  decision).
* **Source/test-only fixture appliers** — `FixtureModeledTrustMutationApplier`
  (DevNet/TestNet; mutates **only** the in-memory `ModeledGovernanceTrustState`,
  supports a programmed `ModeledApplierFault` to exercise apply-failed /
  rolled-back / rollback-failed / ambiguous paths, and counts invocations so
  tests can prove a rejected-before-snapshot path never reaches the applier),
  `ProductionModeledTrustMutationApplier`, and
  `MainNetModeledTrustMutationApplier` (always unavailable / fail-closed).
* **Composition helper #1** — `map_modeled_outcome_to_mutation_engine_outcome`
  maps modeled applier outcomes into the Run 242
  `GovernanceMutationOutcome`: modeled apply success →
  `MutationAppliedSuccessfully`; not-attempted →
  `ProceedLegacyBypassNoMutation`; rejected before snapshot/apply →
  `MutationRejectedBeforeApply`; apply failure → `MutationApplyFailed`; rollback
  success → `MutationRolledBack`; rollback failure / ambiguous →
  `MutationAmbiguousFailClosed`; production unavailable →
  `ProductionMutationUnavailable`; MainNet unavailable →
  `MainNetMutationUnavailable`; MainNet peer-driven refused →
  `MainNetPeerDrivenApplyRefused`; validator-set rotation unsupported →
  `ValidatorSetRotationUnsupported`; policy-change unsupported →
  `PolicyChangeUnsupported`.
* **Composition helper #2** — `project_modeled_outcome_to_durable_completion`
  (and `modeled_outcome_authorizes_durable_consume`) projects modeled applier
  outcomes through Run 242 into the Run 240 durable runtime's
  `DurableMutationCompletion` semantics via `MutationEngineDurableProjection`:
  only `ModeledMutationApplied` becomes consume-eligible; rejected / failed /
  rollback / rollback-failed / ambiguous / unavailable / unsupported outcomes
  never consume.
* **`evaluate_modeled_trust_mutation`** — the entry point enforcing the ordering:
  MainNet peer-driven refusal → legacy bypass → binding validation (reject before
  snapshot) → read-only validation gating → unsupported-action gating →
  applier-kind routing → applier hand-off.
* **`recover_modeled_trust_mutation`** — typed modeled mutation-window recovery
  that refuses MainNet peer-driven apply first, treats production/MainNet
  classification as unavailable, recovers a before-snapshot window as
  not-attempted, rolls back an after-snapshot-before-apply window, recovers only
  an explicit after-report success as applied, and fails closed on every
  after-apply-before-report / after-report-ambiguous / rollback-failed / unknown
  window.
* **Grep-verifiable invariant helpers** —
  `modeled_trust_applier_rejection_is_non_mutating`,
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
  `local_operator_cannot_satisfy_modeled_trust_applier_authority`, and
  `peer_majority_cannot_satisfy_modeled_trust_applier_authority`.

## Composition / ordering contract

The engine is pure aside from the fixture applier's modeled in-memory effect: the
engine itself performs no I/O, mutates no `LivePqcTrustState`, writes no marker,
writes no sequence, swaps no live trust, evicts no sessions, performs no durable
consume, and never invokes Run 070.

* **MainNet peer-driven apply refused first.** The refusal is guarded before any
  modeled snapshot, before binding validation, and before the applier is reached.
* **Legacy bypass performs no modeled mutation.** An unwired
  `ModeledGovernanceTrustMutationPolicy::Disabled` or a
  `ModeledGovernanceTrustMutationApplierKind::Disabled` returns
  `ModeledMutationNotAttempted` and never invokes the applier.
* **Binding validation before snapshot.** A wrong environment / chain / genesis /
  governance surface / mutation surface / candidate digest / decision digest /
  proposal id / decision id / authority-domain sequence / lifecycle action, or a
  malformed modeled mutation, is a typed, non-mutating
  `ModeledMutationRejectedBeforeSnapshot`; the applier is never invoked.
* **Read-only validation never mutates.** A validation-only surface is rejected
  before snapshot.
* **Unsupported actions.** Validator-set rotation and policy-change actions are
  typed unsupported and never reach the applier.
* **Applier-kind routing.** Production / MainNet appliers are reachable but
  unavailable; only DevNet/TestNet fixture kinds reach the applier.
* **Reject-before-apply inside the applier.** Retiring / revoking a missing or
  inactive modeled root snapshots first then rejects before apply; the modeled
  state is left unchanged.
* **Consume only after success.** Only `ModeledMutationApplied` projects through
  `MutationAppliedSuccessfully` to the consume-eligible
  `DurableMutationCompletion::AppliedSuccessfully`; failed apply, rollback,
  rollback-failed, and ambiguous windows never consume.

## Tests

`crates/qbind-node/tests/run_244_modeled_governance_trust_mutation_applier_tests.rs`
(45 tests, PASS).

* **Accepted / compatible** — disabled policy preserves the legacy bypass and
  performs no modeled mutation; DevNet and TestNet fixture modeled add-root
  succeed and change only modeled in-memory state; modeled retire / revoke /
  emergency-revoke succeed in fixture state only; modeled noop succeeds without
  state drift; modeled apply success maps to `MutationAppliedSuccessfully` and
  projects to a consume-eligible durable completion; duplicate root is handled
  idempotently under an explicit typed applied outcome; production and MainNet
  modeled applier paths are reachable but unavailable/fail-closed; MainNet
  peer-driven apply is refused before snapshot and before applier invocation;
  validator-set rotation and policy-change are unsupported.
* **Rejected before snapshot** — wrong environment / chain / genesis / governance
  surface / mutation surface / candidate digest / decision digest / proposal id /
  decision id / authority-domain sequence, a malformed modeled mutation, and a
  read-only validation surface are all rejected before snapshot and never invoke
  the applier (invocation counter remains 0; modeled state unchanged).
* **Rejected before apply** — retiring / revoking a missing root snapshots then
  rejects before apply, leaving modeled state unchanged.
* **Apply failure / rollback / fatal / ambiguous** — apply-failed-before-mutation
  leaves modeled state unchanged and never consumes; apply failure rolls back the
  modeled state and never consumes; rollback failure is fatal/fail-closed and
  never consumes; an ambiguous window fails closed and never consumes.
* **Durable projection** — every non-success outcome never authorizes a durable
  consume; only the applied success does.
* **Recovery** — before-snapshot recovers as not-attempted; after-snapshot-before-
  apply rolls back; after-apply-before-report fails closed; an explicit
  after-report success recovers as applied; after-report-ambiguous fails closed;
  rollback-failed is fatal; production/MainNet classification is unavailable;
  MainNet peer-driven refusal precedes classification.
* **Invariant helpers** — all grep-verifiable invariant helpers assert
  fail-closed; local operator and peer majority cannot satisfy MainNet authority.

### Compatibility (no regression)

The Run 224 / 226 / 228 / 230 / 232 / 234 / 236 / 238 / 240 / 242 test suites and
the full `qbind-node` library test suite (`cargo test -p qbind-node --lib`,
`cargo test -p qbind-node --lib pqc_authority`) all pass unchanged. Run 244 adds a
new source module and a new test file and does not modify any prior run's
behavior.

## Validation commands

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests
cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests
cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests
cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests
cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests
cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests
cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests
cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests
cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests
cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests
cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

All commands pass.

## Security invariants preserved

* Rejected modeled-applier paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
  sequence write, no marker write, no durable consume — and a rejection that
  happens before apply never invokes the fixture applier.
* The modeled applier mutates only the in-memory `ModeledGovernanceTrustState`.
* Modeled apply success is required before a durable consume.
* Failed apply, rollback, rollback failure, and ambiguous windows never consume.
* Production / MainNet modeled appliers remain unavailable / fail-closed.
* MainNet peer-driven apply is refused before any snapshot or applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No RocksDB / file / schema / migration / storage-format change; no wire /
  marker / sequence / trust-bundle change.

## Honest limitations

* Run 244 is source/test only and introduces a modeled in-memory trust-state
  mutation applier **boundary**, not a real production mutation engine. No
  production mutating behavior is enabled.
* The fixture applier mutates only modeled in-memory state; it performs no real
  trust mutation.
* No real governance execution engine, on-chain governance proof verifier,
  persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 244 advances the modeled
in-memory mutation-applier boundary at the source/test level but does **not**
claim full C4 or C5 closure.

## Suggested Run 245 next step

Release-binary evidence for the Run 244 modeled trust-state mutation applier
boundary (mirroring the Run 239 / 241 / 243 pattern): build the release binary,
exercise the modeled-applier-composed durable runtime path through the
source/test fixture applier, and capture grep-verifiable evidence that the modeled
applier mutates only the in-memory modeled state, that rejected paths remain
non-mutating, and that production/MainNet modeled appliers remain
unavailable/fail-closed in a release binary.
