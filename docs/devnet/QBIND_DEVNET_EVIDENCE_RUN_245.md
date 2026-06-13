# QBIND DevNet evidence — Run 245

**Title.** Release-binary modeled governance trust-state mutation applier
evidence.

**Status.** PASS (release-binary evidence). Run 245 is the release-binary
evidence run for the Run 244 source/test governance **modeled trust-state
mutation applier boundary** in
`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`. Run 244
landed the typed modeled-applier boundary that adds the smallest in-memory model
of what a future governance mutation applier would do after every Run 242
mutation-engine gate has already passed — snapshot a modeled trust state, apply a
modeled trust-state update, report success / failure / rollback / rollback-failed
/ ambiguous windows, and project the result back through the Run 242 mutation
outcome into the Run 240 durable completion semantics — but captured **no**
release-binary evidence (deferred to Run 245). Run 245 proves on real
`target/release/qbind-node` plus a release-built helper that the release-built
code exposes and exercises that boundary.

Run 245 is **release-binary evidence only**. It implements **no** real production
mutation engine, **no** real governance execution engine, **no** real on-chain
governance proof verifier, **no** real persistent replay backend, **no** RocksDB
backend, **no** file format, **no** schema, **no** database migration, **no**
storage-format change, **no** real KMS/HSM backend, **no** real RemoteSigner
backend, **no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. Any production-source module remains
pure / source-test bounded and fail-closed; the modeled-applier boundary is
release-evidenced, not production-enabled.

## What Run 245 states

* Run 245 is release-binary evidence for Run 244.
* No production mutating behaviour is enabled.
* Any production-source module remains pure / source-test bounded and
  fail-closed.
* The modeled-applier boundary is release-evidenced, not production-enabled.
* The modeled applier mutates only modeled in-memory state in DevNet/TestNet
  fixture helper cases.
* The modeled applier does not mutate `LivePqcTrustState`.
* The modeled applier does not call Run 070.
* The modeled applier does not perform a real trust swap.
* The modeled applier does not evict sessions.
* The modeled applier does not write sequence files.
* The modeled applier does not write authority markers.
* The modeled applier does not perform a durable consume by itself.
* No real production mutation engine is implemented.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No real persistent replay backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No KMS/HSM/RemoteSigner backend is implemented.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* Rejected modeled-applier paths are non-mutating.
* Modeled apply success is required before durable consume.
* Failed apply, rollback, rollback failure, and ambiguous windows never consume.
* MainNet peer-driven apply remains refused before any snapshot or applier
  invocation.
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
* Rejected modeled-applier paths are non-mutating and never invoke Run 070.
* Modeled apply success is required before a durable consume; failed apply,
  rollback, rollback failure, and ambiguous windows never consume.
* Run 245 does not weaken any prior run (Runs 070, 130–244) and does not claim
  full C4 or C5 closure.

## Preflight docs hygiene

Run 245 narrowly fixed a Run 244 docs typo where the modeled-outcome list
rendered the `ProductionModeledMutationUnavailable` variant as the split token
`` `Production`/`MainNetModeledMutationUnavailable` ``. It now reads
`` `ProductionModeledMutationUnavailable` / `MainNetModeledMutationUnavailable` ``
in `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and
`docs/whitepaper/contradiction.md`. This is docs-only hygiene and is not a
behaviour change.

## Deliverables

* **Release helper** —
  `crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs`.
  Links against the release-built production library symbols and exercises
  `pqc_governance_modeled_trust_mutation_applier`, `ModeledGovernanceTrustState`,
  `ModeledGovernanceTrustSnapshot`, `ModeledGovernanceTrustRoot`,
  `ModeledTrustRootStatus`, `ModeledGovernanceTrustMutation`,
  `ModeledGovernanceTrustMutationInput`,
  `ModeledGovernanceTrustMutationExpectations`,
  `ModeledGovernanceTrustMutationPolicy`,
  `ModeledGovernanceTrustMutationSurface`,
  `ModeledGovernanceTrustMutationEnvironmentBinding`,
  `ModeledGovernanceTrustMutationRuntimeBinding`, `ModeledTrustMutationAction`,
  `ModeledTrustMutationOutcome`, `ModeledGovernanceTrustMutationApplier`,
  `FixtureModeledTrustMutationApplier`, `ProductionModeledTrustMutationApplier`,
  `MainNetModeledTrustMutationApplier`, `evaluate_modeled_trust_mutation`,
  `recover_modeled_trust_mutation`,
  `map_modeled_outcome_to_mutation_engine_outcome`,
  `project_modeled_outcome_to_durable_completion`,
  `modeled_outcome_authorizes_durable_consume`, and all grep-verifiable invariant
  helpers from Run 244.
* **Release harness** —
  `scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh`.
  Builds `target/release/qbind-node` and the Run 245 helper; captures git
  commit, rustc/cargo versions, SHA-256 + ELF Build ID for both binaries; runs
  real-binary surface scenarios; runs the helper corpus in release mode; runs
  source- and helper-reachability greps for the Run 244 symbols; runs a denylist
  proving no active production/MainNet enablement claims; runs the regression
  test corpus; and writes generated evidence into the ignored evidence
  directory.
* **Evidence archive** —
  `docs/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary/`
  (tracks only `README.md`, `summary.txt`, `.gitignore`; generated artifacts are
  ignored, following the Run 241 / Run 243 convention).
* **Canonical report** — this file.

## Release-helper corpus

`crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs`
drives six tables through the release-built Run 244 symbols
(221 checks total, all PASS):

* **accepted (42)** — disabled policy / disabled applier kind preserve the legacy
  no-mutation bypass with a zero applier-invocation count and an empty modeled
  state; DevNet and TestNet fixture modeled add-root succeed and mutate only the
  modeled state; modeled retire / revoke / emergency-revoke succeed in fixture
  state only; noop succeeds with no modeled state drift; a duplicate root is
  handled idempotently under an explicit applied outcome; modeled apply success
  maps to `MutationAppliedSuccessfully` and projects to a consume-eligible
  `DurableMutationCompletion::AppliedSuccessfully`; production and MainNet applier
  kinds are reachable but unavailable; MainNet peer-driven apply is refused
  before snapshot and before applier invocation; validator-set rotation and
  policy-change actions are unsupported.
* **rejection (92)** — wrong environment / chain / genesis / governance surface /
  mutation surface / candidate digest / decision digest / proposal id / decision
  id / authority-domain sequence / lifecycle action, and a malformed modeled
  mutation, are all rejected before snapshot and never reach the applier (zero
  invocation count, modeled state unchanged); a read-only validation surface is
  rejected before snapshot; retiring / revoking a missing root snapshots then
  rejects-before-apply with modeled state unchanged; apply failure, rollback,
  rollback failure, and the ambiguous window never consume; production / MainNet
  applier kinds remain unavailable; validator-set rotation and policy-change
  attempts are unsupported; local operator and peer majority cannot satisfy
  authority; every rejected path is non-mutating.
* **recovery (18)** — before-snapshot recovers as not-attempted / no consume;
  after-snapshot-before-apply rolls back / no consume; after-apply-before-report
  fails closed unless an explicit success report exists; after-report-success
  recovers as modeled applied; after-report-ambiguous and unknown windows fail
  closed; rollback-failed is fatal / fail-closed; production / MainNet recovery
  classification is unavailable; MainNet peer-driven apply refusal precedes
  recovery classification.
* **projection (26)** — only `ModeledMutationApplied` maps to
  `MutationAppliedSuccessfully` and projects to a consume-eligible durable
  completion; `ModeledMutationNotAttempted`, `ModeledMutationRejectedBeforeSnapshot`,
  `ModeledMutationRejectedBeforeApply`, `ModeledMutationApplyFailed`,
  `ModeledMutationRolledBack`, `ModeledMutationRollbackFailedFatal`,
  `ModeledMutationAmbiguousFailClosed`, `ProductionModeledMutationUnavailable`,
  `MainNetModeledMutationUnavailable`, `MainNetPeerDrivenApplyRefused`,
  `ValidatorSetRotationUnsupported`, and `PolicyChangeUnsupported` all do not
  consume.
* **modeled-state (23)** — add / retire / revoke / emergency-revoke change only
  the modeled in-memory state; noop produces no drift; rejected-before-snapshot
  leaves modeled state unchanged with a zero invocation count;
  rejected-before-apply leaves modeled state unchanged after snapshot; apply
  failure rolls back modeled state; rollback failure does not claim success and
  never consumes; no fixture case mutates `LivePqcTrustState` or writes
  sequence/marker/durable state.
* **reachability (20)** — every modeled-outcome / root-status `tag()` is stable;
  the `ModeledGovernanceTrustMutationApplier` trait method classifies a window in
  release mode; and all fifteen grep-verifiable invariant / fail-closed helpers
  hold in release mode.

## Real release-binary surface scenarios

The harness runs the real `target/release/qbind-node`:

* **S1** — `--help` exposes no modeled-applier enablement banner or visible
  public flag drift (rc=0).
* **S2 / S3 / S4** — default DevNet / TestNet / MainNet startup parse/smoke
  surfaces emit no modeled-applier enablement claim (rc=0).
* **S5** — the hidden governance-execution selector still parses and remains
  silent on any modeled-applier enablement (rc=1, parse-only smoke without a
  network).
* **S6** — an invalid governance-execution selector fails closed before mutation
  (rc≠0) and prints the fail-closed banner (`no marker write; no sequence write;
  no live trust swap; no session eviction; no Run 070 call`).

No Run 244/245 hidden selector or helper-only path appears as a public
production enablement surface.

## Denylist

The harness proves the captured real-binary and helper logs contain no
active/enabled claims for: real production mutation engine, modeled applier
production enabled, MainNet modeled applier, MainNet mutation engine, MainNet
governance, MainNet peer-driven apply, real governance execution engine, real
on-chain governance proof verifier, real persistent replay backend, RocksDB/file
replay backend, schema/storage-format migration, KMS/HSM/RemoteSigner backend,
validator-set rotation, policy-change action, autonomous apply / apply-on-receipt,
peer-majority authority, Run 070 apply / `LivePqcTrustState` mutation / real trust
swap / session eviction / marker write / sequence write / durable consume from
the modeled-applier boundary, and active DummySig/DummyKem/DummyAead. All 36
forbidden patterns are proven empty.

## Tests

All regression targets PASS (rc=0):

```
cargo build -p qbind-node --release --bin qbind-node
cargo build -p qbind-node --release --example run_245_modeled_governance_trust_mutation_applier_release_binary_helper
bash scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh
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

## Security invariants preserved

* Rejected modeled-applier paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and (for a
  rejection-before-apply) no applier invocation.
* Modeled apply success is required before a durable consume; only
  `ModeledMutationApplied` projects through `MutationAppliedSuccessfully` to the
  consume-eligible `DurableMutationCompletion::AppliedSuccessfully`.
* Failed apply, rollback, rollback failure, and ambiguous windows never consume.
* Production / MainNet applier kinds are reachable but always unavailable /
  fail-closed.
* MainNet peer-driven apply remains refused before any snapshot, before binding
  validation, and before applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes no wire / marker / sequence / trust-bundle / storage
  format and introduces no RocksDB schema, file format, or database migration.

## Honest limitations

* The Run 244 modeled-applier boundary is a pure, typed function over its inputs
  plus a mockable applier that mutates only the in-memory
  `ModeledGovernanceTrustState`, exercised here through release-built library
  symbols (the same symbols a future production call site would use); it applies
  no real (live) mutation.
* The boundary specifies the ordering a real mutation applier would have to
  honour but implements none of that production mutation: no real production
  mutation engine, no real governance execution engine, no real on-chain
  governance proof verifier, no real persistent replay backend, no RocksDB
  backend, no file format, no schema, no database migration, and no
  storage-format change.
* The `FixtureModeledTrustMutationApplier` mutates only the modeled in-memory
  state and performs no real trust mutation; the
  `ProductionModeledTrustMutationApplier` and `MainNetModeledTrustMutationApplier`
  are always unavailable / fail-closed.
* No real KMS / HSM / RemoteSigner backend. No MainNet governance enablement, no
  MainNet peer-driven apply enablement, no validator-set rotation.
* Existing Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231
  release behaviour remains compatible.

## C4 / C5 status

Run 245 closes the Run 244 release-binary evidence gap only. **Full C4 remains
OPEN; C5 remains OPEN.** Run 245 makes no production mutating enablement claim.

## Suggested Run 246 next step

A source/test step that composes the Run 244 modeled trust-state applier with the
Run 226 governance evaluator runtime call-site into a single typed end-to-end
pipeline — threading `evaluate_modeled_trust_mutation` →
`project_modeled_outcome_to_durable_completion` →
`integrate_durable_replay_runtime` so the after-success-only durable consume is
gated by a modeled successful applier outcome end to end — still source/test
only, still fail-closed, with no production mutating enablement, followed by a
Run 247 release-binary evidence run mirroring this pattern.