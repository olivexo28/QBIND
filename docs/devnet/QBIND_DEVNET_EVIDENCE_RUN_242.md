# QBIND DevNet evidence — Run 242

**Title.** Source/test governance execution mutation-engine boundary.

**Status.** PASS (source/test only). Run 242 makes the hand-off of an
already-authorized governance evaluator decision to a future mutation executor
**explicit and typed**, instead of leaving Run 240/241 to rely only on a modeled
mutation-completion enum. Run 238 defined the typed durable replay-state backend
contract, Run 240 wired that durable backend into the Run 236 / 232 / 230
replay/freshness + after-success-only consume runtime path, and Run 241
release-evidenced the Run 240 durable runtime integration. What was still
implicit is **how** an authorized evaluator decision would be handed to a
mutation executor and **how** mutation success/failure/rollback is reported back
to the durable replay runtime. Run 242 closes that gap at the source/test level
with a typed mutation-engine boundary, a pure/mockable executor trait,
source/test-only fixture executors, and a composition helper that projects
mutation-engine outcomes into the Run 240 durable runtime's mutation-completion
semantics.

Run 242 introduces a typed mutation-engine **boundary**, **not** a real
production mutation engine. It enables **no** production mutating behavior. Any
new production-source module remains pure / source-test bounded and fail-closed.
It implements **no** real governance execution engine, **no** real mutation
engine, **no** real on-chain governance proof verifier, **no** real persistent
replay backend, **no** RocksDB backend, **no** file format, **no** schema, **no**
database migration, **no** storage-format change, **no** KMS/HSM backend, **no**
RemoteSigner backend, **no** MainNet governance enablement, **no** MainNet
peer-driven apply enablement, and **no** validator-set rotation. It changes
**no** wire, schema, marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness.
* The mutation engine is a typed boundary only; it is a pure function over its
  typed inputs plus a mockable executor, fail-closed by default.
* Fixture mutation executors remain DevNet/TestNet source-test only.
* Production/MainNet mutation engines remain reachable but unavailable/fail-closed.
* No real governance execution engine; no real mutation engine; no real on-chain
  governance proof verifier; no real persistent replay backend.
* No RocksDB/file/schema/migration/storage-format change.
* No KMS/HSM backend; no RemoteSigner backend.
* No MainNet governance enablement; no MainNet peer-driven apply enablement; no
  validator-set rotation; no policy-change action.
* Rejected mutation-engine paths are non-mutating and never invoke Run 070.
* Mutation success is required before a durable consume; failed apply, rollback,
  and ambiguous after-authorization windows never consume.
* Run 242 does not weaken any prior run (Runs 070, 130–241) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`

Run 242 adds a new source module (registered in `lib.rs`) that defines:

* **Typed input/context structures** — `GovernanceMutationEngineInput`,
  `GovernanceMutationEngineExpectations`, `GovernanceMutationCandidate`,
  `GovernanceMutationSurface`, `GovernanceMutationPolicy`,
  `GovernanceMutationEnvironmentBinding`, and `GovernanceMutationRuntimeBinding`.
  The candidate references Run 222 evaluator / Run 230 replay material — never a
  copy of any wire payload.
* **Mutation-engine kinds** — `GovernanceMutationEngineKind`: `Disabled`,
  `FixtureDevNet`, `FixtureTestNet`, `ProductionUnavailable`, `MainNetUnavailable`.
* **Mutation outcomes** — `GovernanceMutationOutcome`:
  `ProceedLegacyBypassNoMutation`, `MutationAuthorized`,
  `MutationAppliedSuccessfully`, `MutationRejectedBeforeApply`,
  `MutationApplyFailed`, `MutationRolledBack`, `MutationAmbiguousFailClosed`,
  `ProductionMutationUnavailable`, `MainNetMutationUnavailable`,
  `MainNetPeerDrivenApplyRefused`, `ValidatorSetRotationUnsupported`, and
  `PolicyChangeUnsupported`, plus predicates (`is_applied_successfully`,
  `is_fail_closed`, `no_consume`, `executor_must_not_run`,
  `is_mainnet_peer_driven_apply_refused`) and a stable `tag`.
* **A pure/mockable trait boundary** — `GovernanceMutationExecutor` with
  `execute_authorized_mutation(...)` and `recover_mutation_window(...)`, taking a
  validated `AuthorizedMutationRequest` (only constructed **after** every gate
  has passed, so an executor never sees a rejected decision).
* **Source/test-only fixture executors** — `FixtureMutationExecutor`
  (DevNet/TestNet, returns a programmed typed
  success/failure/rollback/ambiguous result and counts invocations so tests can
  prove a rejected path never reaches the executor), `ProductionMutationExecutor`
  and `MainNetMutationExecutor` (always `Unavailable` / fail-closed).
* **A composition helper** — `project_mutation_outcome_to_durable_completion`
  maps mutation-engine outcomes into the Run 240 durable runtime's
  `DurableMutationCompletion` semantics via `MutationEngineDurableProjection`:
  successful fixture mutation → `AppliedSuccessfully` (after-success-only consume
  path); authorized-not-applied → `AuthorizedButNotApplied` (no consume); failed
  apply → `ApplyFailed` (no consume); rollback → `RolledBack` (no consume); legacy
  bypass → `NotAttempted`; ambiguous / refusal / unavailable / unsupported /
  rejected → `FailClosedBeforeDurable` (no durable observe/consume reached).
* **`evaluate_governance_mutation_engine`** — the entry point enforcing the
  ordering: MainNet peer-driven refusal → legacy bypass → binding validation →
  read-only validation gating → unsupported-action gating → engine-kind routing →
  executor hand-off.
* **`recover_governance_mutation_window`** — typed mutation-window recovery that
  refuses MainNet peer-driven apply first, treats production/MainNet
  classification as unavailable, and fails closed on every determinable
  after-authorization / in-flight / after-report / unknown window.
* **`wire_governance_mutation_engine_callsite`** — runtime call-site wiring that
  maps the outcome into a `Result`, returning a
  `MutationEngineCallsiteFailClosed` on any fail-closed outcome.
* **Grep-verifiable invariant helpers** —
  `mutation_engine_rejection_is_non_mutating`,
  `mutation_success_is_required_before_durable_consume`,
  `mutation_failure_never_consumes_durable_replay_state`,
  `mutation_rollback_never_consumes_durable_replay_state`,
  `production_mainnet_mutation_engine_unavailable`,
  `mainnet_peer_driven_apply_refused_by_mutation_engine`,
  `no_rocksdb_file_schema_migration_change_under_mutation_engine`,
  `validator_set_rotation_unsupported_by_mutation_engine`,
  `policy_change_unsupported_by_mutation_engine`,
  `local_operator_cannot_satisfy_mutation_engine_authority`, and
  `peer_majority_cannot_satisfy_mutation_engine_authority`.

## Composition / ordering contract

The engine is pure aside from the executor's own (fixture-modeled) effect: the
engine itself performs no I/O, writes no marker, writes no sequence, swaps no
live trust, evicts no sessions, and never invokes Run 070.

* **MainNet peer-driven apply refused first.** The refusal is guarded before any
  mutation attempt, before binding validation, and before the executor is
  reached, so nothing can bypass it.
* **Legacy bypass performs no mutation.** An unwired `GovernanceMutationPolicy::Disabled`
  or a `GovernanceMutationEngineKind::Disabled` returns
  `ProceedLegacyBypassNoMutation` and never invokes the executor.
* **Binding validation before apply.** A wrong environment / chain / genesis /
  governance surface / mutation surface / candidate digest / decision digest /
  proposal id / decision id / authority-domain sequence / lifecycle action, or a
  malformed candidate, is a typed, non-mutating `MutationRejectedBeforeApply`; the
  executor is never invoked.
* **Read-only validation never mutates.** A validation-only surface never reaches
  the executor.
* **Unsupported actions.** Validator-set rotation and policy-change actions are
  typed unsupported and never reach the executor.
* **Engine-kind routing.** Production / MainNet engine kinds are reachable but
  unavailable; only DevNet/TestNet fixture kinds reach the executor.
* **Consume only after success.** Only `MutationAppliedSuccessfully` projects to
  the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`; failed
  apply, rollback, and ambiguous windows never consume.

## Tests

`crates/qbind-node/tests/run_242_governance_execution_mutation_engine_tests.rs`
(38 tests, PASS).

* **A1–A15 (accepted/compatible)** — disabled policy / disabled engine kind
  preserve the legacy no-mutation bypass; DevNet and TestNet fixture mutation
  success returns `MutationAppliedSuccessfully`; mutation success composes into
  the durable consume-after-success projection; read-only validation never
  mutates; failed apply, rollback, and authorized-not-applied never consume;
  ambiguous after-authorization window fails closed; production and MainNet
  mutation paths are reachable but unavailable; MainNet peer-driven apply is
  refused before mutation; validator-set rotation and policy-change actions are
  unsupported; the call-site wiring returns `Ok` on success and `Err` on a
  fail-closed outcome.
* **R1–R15 (rejected)** — wrong environment / chain / genesis / governance
  surface / mutation surface / candidate digest / decision digest / proposal id /
  decision id / authority-domain sequence / lifecycle action, and a malformed
  candidate, are all rejected before apply and never reach the executor; consume
  after failed apply / after rollback is never authorized; local operator and
  peer majority cannot satisfy authority.
* **Recovery** — ambiguous after-apply-before-report fails closed;
  before-authorization recovers as rejected-before-apply; MainNet peer-driven is
  refused before classification; production classification is unavailable.
* **Executor trait** — fixture window classification; production / MainNet
  executors always report `Unavailable`.
* **Invariant helpers** — all grep-verifiable invariant helpers assert
  fail-closed.

### Compatibility (no regression)

The Run 224 / 226 / 228 / 230 / 232 / 234 / 236 / 238 / 240 test suites and the
full `qbind-node` library test suite (`cargo test -p qbind-node --lib`,
`cargo test -p qbind-node --lib pqc_authority`) all pass unchanged. Run 242 adds
a new source module and a new test file and does not modify any prior run's
behavior.

## Validation commands

```
cargo build -p qbind-node --lib
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

* Rejected mutation-engine paths are non-mutating: no Run 070 call, no live trust
  swap, no session eviction, no sequence write, no marker write, no durable
  consume — and the executor is never invoked.
* Mutation success is required before a durable consume.
* Failed apply, rollback, and ambiguous after-authorization windows never
  consume.
* Production / MainNet mutation engines remain unavailable / fail-closed.
* MainNet peer-driven apply is refused before any mutation attempt.
* Validator-set rotation and policy-change actions remain unsupported.
* No RocksDB / file / schema / migration / storage-format change; no wire /
  marker / sequence / trust-bundle change.

## Honest limitations

* Run 242 is source/test only and introduces a typed mutation-engine **boundary**,
  not a real production mutation engine. No production mutating behavior is
  enabled.
* The fixture executors model mutation outcomes; they perform no real trust
  mutation.
* No real governance execution engine, on-chain governance proof verifier,
  persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 242 advances the
mutation-engine boundary at the source/test level but does **not** claim full C4
or C5 closure.

## Suggested Run 243 next step

Release-binary evidence for the Run 242 mutation-engine boundary (mirroring the
Run 239/241 pattern): build the release binary, exercise the
mutation-engine-composed durable runtime path through the source/test fixture
executors, and capture grep-verifiable evidence that the typed mutation-engine
boundary remains fail-closed in a release binary, while production/MainNet
mutation and MainNet peer-driven apply remain refused.