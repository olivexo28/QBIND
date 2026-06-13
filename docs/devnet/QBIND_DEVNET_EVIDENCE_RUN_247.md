# QBIND DevNet evidence — Run 247

**Title.** Release-binary governance modeled end-to-end pipeline evidence.

**Status.** PASS (release-binary evidence). Run 247 is the release-binary
evidence run for the Run 246 source/test governance **modeled end-to-end
pipeline boundary** in
`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`. Run 246
landed the typed end-to-end pipeline boundary that composes the Run 226
governance evaluator runtime call-site, the Run 240 durable replay observation,
the Run 242 mutation-engine, and the Run 244 modeled trust-state applier into a
single ordered pipeline — refuse MainNet peer-driven apply first, honour the
legacy disabled-policy bypass, require evaluator/call-site authorization, then
durable replay freshness, then mutation-engine authorization, then a modeled
applier success, before authorizing a durable consume — but captured **no**
release-binary evidence (deferred to Run 247). Run 247 proves on real
`target/release/qbind-node` plus a release-built helper that the release-built
code exposes and exercises that boundary.

Run 247 is **release-binary evidence only**. It implements **no** real production
mutation engine, **no** real governance execution engine, **no** real on-chain
governance proof verifier, **no** real persistent replay backend, **no** RocksDB
backend, **no** file format, **no** schema, **no** database migration, **no**
storage-format change, **no** real KMS/HSM backend, **no** real RemoteSigner
backend, **no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. Any production-source module remains
pure / source-test bounded and fail-closed; the modeled end-to-end pipeline
boundary is release-evidenced, not production-enabled.

## What Run 247 states

* Run 247 is release-binary evidence for Run 246.
* No production mutating behaviour is enabled.
* The modeled end-to-end pipeline boundary is release-evidenced, not
  production-enabled.
* The release helper exercises the Run 246 production library symbols in release
  mode.
* The release helper remains dead code from the production runtime.
* No real production mutation engine is implemented.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No real persistent replay backend is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No KMS/HSM/RemoteSigner backend is implemented.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* The pipeline does not call Run 070.
* The pipeline does not mutate `LivePqcTrustState`.
* The pipeline does not perform a real trust swap.
* The pipeline does not evict sessions.
* The pipeline does not write sequence files.
* The pipeline does not write authority markers.
* The pipeline does not perform durable consume by itself beyond existing
  fixture/test projection semantics.
* Durable consume is authorized only after evaluator/call-site authorization,
  durable replay freshness, mutation-engine authorization, and modeled applier
  success all agree.
* Evaluator success alone is insufficient for consume.
* Durable replay freshness alone is insufficient for consume.
* Mutation-engine authorization alone is insufficient for consume.
* Modeled applier success is required before durable consume.
* Failed apply, rollback, rollback-failed, ambiguous windows, unavailable
  production/MainNet paths, rejected replay states, and unsupported actions never
  consume.
* MainNet peer-driven apply remains refused before replay consume, modeled
  snapshot, or applier invocation.
* Rejected end-to-end pipeline paths are non-mutating.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Strict scope

* Release-binary evidence only.
* Uses the release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behaviour change (the run adds only an example helper, a
  harness script, evidence, and narrow doc updates).
* No real production mutation engine; no real governance execution engine; no
  real on-chain governance proof verifier; no real persistent replay backend; no
  RocksDB schema; no file format; no database migration; no storage-format
  change; no MainNet governance enablement; no MainNet peer-driven apply
  enablement; no validator-set rotation; no KMS/HSM backend; no RemoteSigner
  backend.
* Rejected end-to-end pipeline paths are non-mutating and never invoke Run 070.
* Durable consume is authorized only after evaluator/call-site authorization,
  durable replay freshness, mutation-engine authorization, and modeled applier
  success all agree; failed apply, rollback, rollback failure, ambiguous windows,
  unavailable production/MainNet paths, rejected replay states, and unsupported
  actions never consume.
* Run 247 does not weaken any prior run (Runs 070, 130–246) and does not claim
  full C4 or C5 closure.

## Deliverables

* **Release helper** —
  `crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs`.
  Links against the release-built production library symbols and exercises
  `pqc_governance_modeled_end_to_end_pipeline`,
  `run_modeled_end_to_end_pipeline`,
  `GovernanceModeledEndToEndPipelineExecutor`,
  `DefaultGovernanceModeledEndToEndPipelineExecutor`,
  `recover_modeled_end_to_end_pipeline_window`,
  `GovernanceModeledEndToEndPipelineInput`,
  `GovernanceModeledEndToEndPipelineExpectations`,
  `GovernanceModeledEndToEndPipelinePolicy`,
  `GovernanceModeledEndToEndPipelineSurface`,
  `GovernanceModeledEndToEndPipelineEnvironmentBinding`,
  `GovernanceModeledEndToEndPipelineRuntimeBinding`,
  `GovernanceModeledEndToEndPipelineCandidate`,
  `GovernanceModeledEndToEndPipelineReplayBinding`,
  `GovernanceModeledEndToEndPipelineMutationBinding`, the stage records
  `EvaluatorCallsiteStage`, `DurableReplayObserveStage`, `MutationEngineStage`,
  `ModeledApplierStage`, `DurableProjectionStage`, `DurableConsumeDecisionStage`,
  the classifications `EvaluatorCallsiteAuthorization` and
  `DurableReplayObservation`, the `GovernanceModeledEndToEndPipelineOutcome`
  taxonomy, the `GovernanceModeledEndToEndPipelineDecision` result with its
  `tag()` / predicate surface, and all grep-verifiable invariant / fail-closed
  helpers from Run 246.
* **Release harness** —
  `scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh`.
  Builds `target/release/qbind-node` and the Run 247 helper; captures git
  commit, rustc/cargo versions, SHA-256 + ELF Build ID for both binaries; runs
  real-binary surface scenarios; runs the helper corpus in release mode; runs
  source- and helper-reachability greps for the Run 246 symbols; runs a denylist
  proving no active production/MainNet enablement claims; runs the regression
  test corpus; and writes generated evidence into the ignored evidence
  directory.
* **Evidence archive** —
  `docs/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary/`
  (tracks only `README.md`, `summary.txt`, `.gitignore`; generated artifacts are
  ignored, following the Run 243 / Run 245 convention).
* **Canonical report** — this file.

## Release-helper corpus

`crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs`
drives seven tables through the release-built Run 246 symbols
(262 checks total, all PASS):

* **accepted (47)** — a disabled pipeline policy and a disabled evaluator/
  call-site policy preserve the legacy no-mutation, no-consume bypass with a zero
  applier-invocation count and an unchanged modeled state; DevNet and TestNet
  fixture evaluator + durable replay fresh + mutation-engine authorized + modeled
  add / retire / revoke / emergency-revoke / noop success authorize a durable
  consume only after the modeled applier success, mutating only the modeled
  state; the only consume-authorizing outcome is
  `ModeledApplierAppliedAndDurableConsumeAuthorized`; production and MainNet
  applier kinds are reachable but unavailable; MainNet peer-driven apply is
  refused before replay consume, modeled snapshot, and applier invocation;
  validator-set rotation and policy-change actions are unsupported.
* **rejection (130)** — wrong environment / chain / genesis / governance surface /
  candidate digest / decision digest / proposal id / decision id / authority
  sequence / lifecycle action, a malformed modeled mutation, every rejected
  durable replay state (stale / expired / consumed / superseded /
  backend-unavailable / deferred), a read-only validation surface, and a missing
  root before apply are each rejected without consume and (when the rejection is
  before the applier stage) never reach the applier — zero invocation count,
  modeled state unchanged; apply failure, rollback, rollback failure, and the
  ambiguous window never consume; production / MainNet applier kinds remain
  unavailable; validator-set rotation and policy-change attempts are unsupported;
  local operator and peer majority cannot satisfy MainNet authority; every
  rejected path is non-mutating.
* **recovery (15)** — before-apply recovers as rolled-back / no consume;
  after-apply-before-report fails closed unless an explicit success report
  exists; after-report-success recovers as modeled applied; after-report-ambiguous,
  rollback-failed, and unknown windows fail closed; production / MainNet recovery
  classification is unavailable; MainNet peer-driven apply refusal precedes
  recovery classification.
* **projection (12)** — only
  `ModeledApplierAppliedAndDurableConsumeAuthorized` authorizes a durable
  consume; every other outcome (evaluator-rejected, replay-rejected,
  mutation-engine-rejected, applier-failed, rolled-back, rollback-failed,
  ambiguous, production/MainNet-unavailable, MainNet-peer-driven-refused,
  legacy-bypass, validator-set-rotation-unsupported, policy-change-unsupported)
  does not consume.
* **stage_ordering (22)** — MainNet peer-driven apply refusal precedes everything;
  the legacy disabled-policy bypass precedes evaluator authorization; evaluator/
  call-site authorization precedes durable replay observation; durable replay
  freshness precedes mutation-engine authorization; mutation-engine authorization
  precedes modeled applier invocation; modeled applier success precedes durable
  consume authorization; evaluator success alone, durable replay freshness alone,
  and mutation-engine authorization alone are each individually insufficient for
  consume.
* **non_mutation (16)** — every rejected path leaves the modeled state unchanged,
  performs no live trust swap, writes no marker, writes no sequence, evicts no
  session, performs no durable consume, and calls no Run 070; a rejection before
  the applier stage leaves the applier invocation count at zero; no fixture case
  mutates `LivePqcTrustState`.
* **reachability (20)** — every outcome / root-status `tag()` is stable; the
  executor trait classifies a pipeline in release mode; and all grep-verifiable
  invariant / fail-closed helpers from Run 246 hold in release mode.

## Real release-binary surface scenarios

The harness runs the real `target/release/qbind-node`:

* **S1** — `--help` exposes no end-to-end-pipeline enablement banner or visible
  public flag drift (rc=0).
* **S2 / S3 / S4** — default DevNet / TestNet / MainNet startup parse/smoke
  surfaces emit no end-to-end-pipeline enablement claim (rc=0).
* **S5** — the hidden governance-execution selector still parses and remains
  silent on any end-to-end-pipeline enablement (rc=1, parse-only smoke without a
  network).
* **S6** — an invalid governance-execution selector fails closed before mutation
  (rc≠0) and prints the fail-closed banner (`no marker write; no sequence write;
  no live trust swap; no session eviction; no Run 070 call`).

No Run 246/247 hidden selector or helper-only path appears as a public
production enablement surface.

## Denylist

The harness proves the captured real-binary and helper logs contain no
active/enabled claims for: real production mutation engine, modeled end-to-end
pipeline production enabled, MainNet modeled pipeline, MainNet mutation engine,
MainNet governance, MainNet peer-driven apply, real governance execution engine,
real on-chain governance proof verifier, real persistent replay backend,
RocksDB/file replay backend, schema/storage-format migration, KMS/HSM/RemoteSigner
backend, validator-set rotation, policy-change action, autonomous apply /
apply-on-receipt, peer-majority authority, Run 070 apply / `LivePqcTrustState`
mutation / real trust swap / session eviction / marker write / sequence write /
durable consume from the end-to-end pipeline boundary, and active
DummySig/DummyKem/DummyAead. All 36 forbidden patterns are proven empty.

## Tests

All regression targets PASS (rc=0):

```
cargo build -p qbind-node --release --bin qbind-node
cargo build -p qbind-node --release --example run_247_governance_modeled_end_to_end_pipeline_release_binary_helper
bash scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh
cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests
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

* Rejected end-to-end pipeline paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no real trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and (for a
  rejection-before-apply) no applier invocation.
* Durable consume is authorized only after evaluator/call-site authorization,
  durable replay freshness, mutation-engine authorization, and modeled applier
  success all agree; only
  `ModeledApplierAppliedAndDurableConsumeAuthorized` consumes.
* Evaluator success alone, durable replay freshness alone, and mutation-engine
  authorization alone are each individually insufficient for consume.
* Failed apply, rollback, rollback failure, ambiguous windows, unavailable
  production/MainNet paths, rejected replay states, and unsupported actions never
  consume.
* Production / MainNet applier kinds are reachable but always unavailable /
  fail-closed.
* MainNet peer-driven apply remains refused before any replay consume, modeled
  snapshot, or applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes no wire / marker / sequence / trust-bundle / storage
  format and introduces no RocksDB schema, file format, or database migration.

## Honest limitations

* The Run 246 end-to-end pipeline boundary is a pure, typed ordering/composition
  over the already-landed Run 226 evaluator call-site, Run 240 durable replay
  observation, Run 242 mutation-engine, and Run 244 modeled trust-state applier
  boundaries plus a mockable applier that mutates only the in-memory
  `ModeledGovernanceTrustState`, exercised here through release-built library
  symbols (the same symbols a future production call site would use); it applies
  no real (live) mutation and performs no I/O.
* The boundary specifies the ordering a real end-to-end governance pipeline would
  have to honour but implements none of that production mutation: no real
  production mutation engine, no real governance execution engine, no real
  on-chain governance proof verifier, no real persistent replay backend, no
  RocksDB backend, no file format, no schema, no database migration, and no
  storage-format change.
* The `FixtureModeledTrustMutationApplier` mutates only the modeled in-memory
  state and performs no real trust mutation; the
  `ProductionModeledTrustMutationApplier` and `MainNetModeledTrustMutationApplier`
  are always unavailable / fail-closed.
* No real KMS / HSM / RemoteSigner backend. No MainNet governance enablement, no
  MainNet peer-driven apply enablement, no validator-set rotation.
* Existing Run 245, Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and
  Run 231 release behaviour remains compatible.

## C4 / C5 status

Run 247 closes the Run 246 release-binary evidence gap only. **Full C4 remains
OPEN; C5 remains OPEN.** Run 247 makes no production mutating enablement claim.

## Suggested Run 248 next step

A source/test step that extends the Run 246 modeled end-to-end pipeline with a
typed, mockable durable-consume *projection sink* — modelling how a future
production call site would record the after-success-only consume receipt through
the Run 240 durable completion semantics without enabling any real persistent
backend — still source/test only, still fail-closed, with no production mutating
enablement, followed by a Run 249 release-binary evidence run mirroring this one.

## Contradiction crosscheck

Run 247 was crosschecked against Runs 050–246. No contradiction was found: Run
247 adds only a release-built example helper, a harness script, an evidence
archive, this canonical report, and narrow doc updates; it changes no production
source behaviour, enables no production mutation, and preserves every prior
fail-closed invariant (MainNet peer-driven apply refusal, evaluator/replay/
mutation-engine/applier ordering, after-success-only durable consume, and the
non-mutating rejection guarantees). A “no Run 247 contradiction” entry is
recorded in `docs/whitepaper/contradiction.md`.
