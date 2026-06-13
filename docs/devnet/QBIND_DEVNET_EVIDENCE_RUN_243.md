# QBIND DevNet evidence — Run 243

**Title.** Release-binary governance execution mutation-engine boundary evidence.

**Status.** PASS (release-binary evidence). Run 243 is the release-binary
evidence run for the Run 242 source/test governance execution **mutation-engine
boundary** in
`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`. Run 242
landed the typed mutation-engine boundary that makes the hand-off of an
already-authorized governance evaluator decision to a future mutation executor
explicit and typed, and projects mutation-engine outcomes into the Run 240
durable runtime's mutation-completion semantics, but captured **no**
release-binary evidence (deferred to Run 243). Run 243 proves on real
`target/release/qbind-node` plus a release-built helper that the release-built
code exposes and exercises that boundary.

Run 243 is **release-binary evidence only**. It implements **no** real production
mutation engine, **no** real governance execution engine, **no** real on-chain
governance proof verifier, **no** real persistent replay backend, **no** RocksDB
backend, **no** file format, **no** schema, **no** database migration, **no**
storage-format change, **no** real KMS/HSM backend, **no** real RemoteSigner
backend, **no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. Any production-source module remains
pure / source-test bounded and fail-closed; the mutation-engine boundary is
release-evidenced, not production-enabled.

## What Run 243 states

* Run 243 is release-binary evidence for Run 242.
* No production mutating behaviour is enabled.
* Any production-source module remains pure / source-test bounded and
  fail-closed.
* The mutation-engine boundary is release-evidenced, not production-enabled.
* No real production mutation engine is implemented.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No real persistent replay backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No KMS/HSM/RemoteSigner backend is implemented.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* Rejected mutation-engine paths are non-mutating.
* Mutation success is required before durable consume.
* Failed apply, rollback, and ambiguous windows never consume.
* MainNet peer-driven apply remains refused before any mutation attempt.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Strict scope

* Release-binary evidence only.
* Uses the release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behaviour change (the run adds only an example helper, a
  harness script, evidence, and narrow doc updates, plus a docs-only typo fix).
* No real production mutation engine; no real governance execution engine; no
  real on-chain governance proof verifier; no real persistent replay backend; no
  RocksDB schema; no file format; no database migration; no storage-format
  change; no MainNet governance enablement; no MainNet peer-driven apply
  enablement; no validator-set rotation; no KMS/HSM backend; no RemoteSigner
  backend.
* Rejected mutation-engine paths are non-mutating and never invoke Run 070.
* Mutation success is required before a durable consume; failed apply, rollback,
  and ambiguous after-authorization windows never consume.
* Run 243 does not weaken any prior run (Runs 070, 130–242) and does not claim
  full C4 or C5 closure.

## Preflight docs hygiene

Run 243 narrowly fixed a Run 242 docs typo where the mutation-outcome list
rendered the `ProductionMutationUnavailable` variant as the split token
`` `Production`/`MainNetMutationUnavailable` ``. It now reads
`` `ProductionMutationUnavailable` / `MainNetMutationUnavailable` `` in
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`,
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, and
`docs/whitepaper/contradiction.md`. This is docs-only hygiene and is not a
behaviour change.

## Deliverables

* **Release helper** —
  `crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs`.
  Links against the release-built production library symbols and exercises
  `pqc_governance_execution_mutation_engine`, `GovernanceMutationEngineInput`,
  `GovernanceMutationEngineExpectations`, `GovernanceMutationCandidate`,
  `GovernanceMutationSurface`, `GovernanceMutationPolicy`,
  `GovernanceMutationEnvironmentBinding`, `GovernanceMutationRuntimeBinding`,
  `GovernanceMutationEngineKind`, `GovernanceMutationOutcome`,
  `GovernanceMutationExecutor`, `FixtureMutationExecutor`,
  `ProductionMutationExecutor`, `MainNetMutationExecutor`,
  `evaluate_governance_mutation_engine`, `recover_governance_mutation_window`,
  `wire_governance_mutation_engine_callsite`,
  `project_mutation_outcome_to_durable_completion`, and all grep-verifiable
  invariant helpers from Run 242.
* **Release harness** —
  `scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh`.
  Builds `target/release/qbind-node` and the Run 243 helper; captures git
  commit, rustc/cargo versions, SHA-256 + ELF Build ID for both binaries; runs
  real-binary surface scenarios; runs the helper corpus in release mode; runs
  source- and helper-reachability greps for the Run 242 symbols; runs a denylist
  proving no active production/MainNet enablement claims; runs the regression
  test corpus; and writes generated evidence into the ignored evidence
  directory.
* **Evidence archive** —
  `docs/devnet/run_243_governance_execution_mutation_engine_release_binary/`
  (tracks only `README.md`, `summary.txt`, `.gitignore`; generated artifacts are
  ignored, following the Run 241 convention).
* **Canonical report** — this file.

## Release-helper corpus

`crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs`
drives five tables through the release-built Run 242 symbols
(206 checks total, all PASS):

* **accepted (50)** — disabled policy / disabled engine kind preserve the legacy
  no-mutation bypass with a zero executor-invocation count; DevNet and TestNet
  fixture mutation success returns `MutationAppliedSuccessfully`; mutation
  success projects to `DurableMutationCompletion::AppliedSuccessfully`;
  authorized-not-applied, read-only validation, failed apply, and rollback never
  consume; the ambiguous after-authorization window fails closed; production and
  MainNet engine kinds are reachable but unavailable; MainNet peer-driven apply
  is refused before binding validation and before executor invocation;
  validator-set rotation and policy-change actions are unsupported; the existing
  Run 240 durable projection remains compatible; the call-site wiring returns
  `Ok` only on a proceed outcome and `Err` on a fail-closed outcome.
* **rejection (79)** — wrong environment / chain / genesis / governance surface /
  mutation surface / candidate digest / decision digest / proposal id / decision
  id / authority-domain sequence / lifecycle action, and a malformed candidate,
  are all rejected before apply and never reach the executor (zero invocation
  count); production / MainNet engine kinds remain unavailable; validator-set
  rotation and policy-change attempts are unsupported; consume before success,
  after failed apply, and after rollback are never authorized; local operator
  and peer majority cannot satisfy authority; every rejected path is
  non-mutating.
* **recovery (12)** — before-authorization recovers as rejected-before-apply / no
  consume; after-authorization-before-executor, after-apply-before-report,
  after-report, and unknown windows fail closed; production / MainNet recovery
  classification is unavailable; MainNet peer-driven apply refusal precedes
  recovery classification.
* **projection (24)** — only `MutationAppliedSuccessfully` projects to a
  consume-eligible durable completion; `MutationAuthorized`, `MutationApplyFailed`,
  `MutationRolledBack`, `MutationAmbiguousFailClosed`,
  `ProductionMutationUnavailable`, `MainNetMutationUnavailable`,
  `MainNetPeerDrivenApplyRefused`, `ValidatorSetRotationUnsupported`,
  `PolicyChangeUnsupported`, `MutationRejectedBeforeApply`, and the legacy bypass
  all do not consume.
* **reachability (41)** — every outcome / engine-kind `tag()` is stable; the
  outcome / kind / policy predicates partition correctly; and all eleven
  grep-verifiable invariant / fail-closed helpers hold in release mode.

## Real release-binary surface scenarios

The harness runs the real `target/release/qbind-node`:

* **S1** — `--help` exposes no mutation-engine enablement banner or visible
  public flag drift (rc=0).
* **S2 / S3 / S4** — default DevNet / TestNet / MainNet startup parse/smoke
  surfaces emit no mutation-engine enablement claim (rc=0).
* **S5** — the hidden governance-execution selector still parses and remains
  silent on any mutation-engine enablement (rc=1, parse-only smoke without a
  network).
* **S6** — an invalid governance-execution selector fails closed before mutation
  (rc≠0) and prints the fail-closed banner (`no marker write; no sequence write;
  no live trust swap; no session eviction; no Run 070 call`).

No Run 242/243 hidden selector or helper-only path appears as a public
production enablement surface.

## Denylist

The harness proves the captured real-binary and helper logs contain no
active/enabled claims for: real production mutation engine, MainNet mutation
engine, MainNet governance, MainNet peer-driven apply, real governance execution
engine, real on-chain governance proof verifier, real persistent replay backend,
RocksDB/file replay backend, schema/storage-format migration, KMS/HSM/
RemoteSigner backend, validator-set rotation, policy-change action, autonomous
apply / apply-on-receipt, peer-majority authority, Run 070 apply / live trust
swap / session eviction / marker write / sequence write from the mutation-engine
boundary, and active DummySig/DummyKem/DummyAead. All 32 forbidden patterns are
proven empty.

## Tests

All regression targets PASS (rc=0):

```
cargo build -p qbind-node --release --bin qbind-node
cargo build -p qbind-node --release --example run_243_governance_execution_mutation_engine_release_binary_helper
bash scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh
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

## Security invariants preserved

* Rejected mutation-engine paths are non-mutating: no Run 070 call, no live trust
  swap, no session eviction, no sequence write, no marker write, no durable
  consume, and no executor invocation.
* Mutation success is required before a durable consume; only
  `MutationAppliedSuccessfully` projects to the consume-eligible
  `DurableMutationCompletion::AppliedSuccessfully`.
* Failed apply, rollback, and ambiguous after-authorization windows never
  consume.
* Production / MainNet engine kinds are reachable but always unavailable /
  fail-closed.
* MainNet peer-driven apply remains refused before any mutation attempt, before
  binding validation, and before executor invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes no wire / marker / sequence / trust-bundle / storage
  format and introduces no RocksDB schema, file format, or database migration.

## Honest limitations

* The Run 242 mutation-engine boundary is a pure, typed function over its inputs
  plus a mockable executor, exercised here through release-built library symbols
  (the same symbols a future production call site would use); it applies no real
  mutation.
* The boundary specifies the ordering a real mutation engine would have to
  honour but implements none of that mutation: no real production mutation
  engine, no real governance execution engine, no real on-chain governance proof
  verifier, no real persistent replay backend, no RocksDB backend, no file
  format, no schema, no database migration, and no storage-format change.
* The `FixtureMutationExecutor` models success / authorized / failure / rollback
  / ambiguous outcomes and performs no real trust mutation; the
  `ProductionMutationExecutor` and `MainNetMutationExecutor` are always
  unavailable / fail-closed.
* No real KMS / HSM / RemoteSigner backend. No MainNet governance enablement, no
  MainNet peer-driven apply enablement, no validator-set rotation.
* Existing Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231 release
  behaviour remains compatible.

## C4 / C5 status

Run 243 closes the Run 242 release-binary evidence gap only. **Full C4 remains
OPEN; C5 remains OPEN.** Run 243 makes no production mutating enablement claim.

## Suggested Run 244 next step

A source/test step that makes the **runtime call-site composition** of the Run
242 mutation-engine boundary with the Run 240 durable runtime explicit and typed
— i.e. a single typed pipeline that threads
`evaluate_governance_mutation_engine` →
`project_mutation_outcome_to_durable_completion` →
`integrate_durable_replay_runtime` so the after-success-only durable consume is
gated by a modeled successful mutation outcome end to end — still source/test
only, still fail-closed, with no production mutating enablement, followed by a
Run 245 release-binary evidence run mirroring this pattern.