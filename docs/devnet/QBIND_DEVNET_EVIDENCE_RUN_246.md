# QBIND DevNet evidence — Run 246

**Title.** Source/test governance modeled end-to-end pipeline boundary.

**Status.** PASS (source/test only). Run 246 composes the already-landed typed
boundaries into **one** typed source/test end-to-end modeled governance pipeline.
Run 224/226 wired the governance evaluator runtime call sites, Run 240 added the
durable replay-state runtime integration, Run 242 added the mutation-engine
boundary, and Run 244 added the modeled trust-state mutation applier. Each piece
was separately evidenced, but there was not yet one typed source/test end-to-end
pipeline that composes evaluator/call-site authorization, durable replay/freshness
observation, mutation-engine authorization, modeled trust-state applier
success/failure, and durable consume-after-success projection. Run 246 closes that
source/test composition gap only.

Run 246 introduces an **ordering/composition layer**, **not** a replacement for
any existing module. It reuses the Run 244 modeled applier entry point (which
itself already composes the Run 242 mutation-engine outcome and the Run 240
durable completion projection) and consumes the typed Run 226 evaluator and Run
240 durable replay outcomes as stage classifications. It implements **no** real
production mutation engine, **no** real governance execution engine, **no** real
on-chain governance proof verifier, **no** real persistent replay backend, **no**
RocksDB backend, **no** file format, **no** schema, **no** database migration,
**no** storage-format change, **no** KMS/HSM backend, **no** RemoteSigner
backend, **no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 246 composes existing typed boundaries into one source/test end-to-end
  modeled governance pipeline.
* It does **not** implement a real production mutation engine.
* It does **not** implement a real governance execution engine.
* It does **not** implement a real on-chain governance proof verifier.
* It does **not** implement a real persistent replay backend.
* It does **not** add RocksDB / file / schema / migration / storage-format
  changes.
* It does **not** add KMS/HSM/RemoteSigner backend.
* It does **not** enable MainNet governance.
* It does **not** enable MainNet peer-driven apply.
* It does **not** implement validator-set rotation.
* It does **not** call Run 070.
* It does **not** mutate `LivePqcTrustState`.
* It does **not** perform a real trust swap.
* It does **not** evict sessions.
* It does **not** write sequence files.
* It does **not** write authority markers.
* It does **not** perform a durable consume by itself beyond the existing
  fixture/test projection semantics.
* Rejected end-to-end pipeline paths are non-mutating.
* Run 246 does not weaken any prior run (Runs 070, 130–245) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`

Run 246 adds a new source module (registered in `lib.rs`) that defines:

* typed pipeline input / policy / stage-classification types
  (`GovernanceModeledEndToEndPipelineInput`,
  `GovernanceModeledEndToEndPipelinePolicy`, `EvaluatorCallsiteAuthorization`,
  `DurableReplayObservation`) plus type aliases over the Run 244 bindings
  (`GovernanceModeledEndToEndPipelineSurface`,
  `…EnvironmentBinding`, `…RuntimeBinding`, `…Candidate`, `…Expectations`,
  `…MutationBinding`, `…ReplayBinding`);
* explicit stage records (`EvaluatorCallsiteStage`, `DurableReplayObserveStage`,
  `MutationEngineStage`, `ModeledApplierStage`, `DurableProjectionStage`,
  `DurableConsumeDecisionStage`) and the full
  `GovernanceModeledEndToEndPipelineDecision`;
* a typed pipeline outcome enum
  (`GovernanceModeledEndToEndPipelineOutcome`) whose only consume-authorizing
  variant is `ModeledApplierAppliedAndDurableConsumeAuthorized`;
* a pure/mockable executor trait
  (`GovernanceModeledEndToEndPipelineExecutor`) with a default executor, plus the
  free functions `run_modeled_end_to_end_pipeline` and
  `recover_modeled_end_to_end_pipeline_window`;
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** any replay consume,
   modeled snapshot, or applier invocation.
2. Evaluator / call-site authorization completes **before** durable replay
   consume is considered.
3. Durable replay / freshness observation completes **before** mutation-engine
   authorization (only a fresh `MutationAuthorized` observation proceeds).
4. Mutation-engine authorization completes **before** modeled applier invocation
   (via the Run 244 `evaluate_modeled_trust_mutation` composition).
5. Modeled applier success completes **before** durable consume is authorized.
6. Durable consume is represented only as a typed projection / decision; the
   pipeline performs no persistent durable consume beyond existing fixture/test
   behavior.

### Grep-verifiable invariant helpers

* `modeled_end_to_end_pipeline_rejection_is_non_mutating`
* `modeled_end_to_end_pipeline_never_calls_run_070`
* `modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state`
* `modeled_end_to_end_pipeline_success_required_before_durable_consume`
* `modeled_end_to_end_pipeline_applier_success_required_before_consume`
* `modeled_end_to_end_pipeline_failed_apply_never_consumes`
* `modeled_end_to_end_pipeline_rollback_never_consumes`
* `modeled_end_to_end_pipeline_ambiguous_window_fails_closed`
* `modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first`
* `modeled_end_to_end_pipeline_production_mainnet_unavailable`
* `modeled_end_to_end_pipeline_validator_set_rotation_unsupported`
* `modeled_end_to_end_pipeline_policy_change_unsupported`
* `modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change`
* `modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority`
* `modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_246_governance_modeled_end_to_end_pipeline_tests.rs`
— 47 tests, all passing. The matrix covers:

* **Accepted / compatible:** disabled pipeline policy and disabled
  evaluator/call-site policy both preserve the legacy no-mutation, no-consume
  bypass; DevNet and TestNet fixture add-root success authorize durable consume;
  modeled retire / revoke / emergency-revoke / noop success authorize consume only
  after a modeled success and with no state drift; production and MainNet paths are
  reachable but unavailable / fail-closed; MainNet peer-driven apply is refused
  before replay consume, before modeled snapshot, and before applier invocation;
  validator-set rotation and policy-change are unsupported.
* **Rejected / fail-closed:** evaluator rejection before replay; every binding
  mismatch (environment, chain, genesis, governance/mutation surface, candidate /
  decision digest, proposal / decision id, authority-domain sequence, lifecycle
  action, malformed mutation) rejected before modeled snapshot; read-only
  validation surface rejected before snapshot; stale / expired / consumed /
  superseded durable replay states and backend-unavailable cannot reach mutation
  or consume; consume before modeled applier success, after apply failure, after
  rollback, after rollback-failed, and after an ambiguous window are all rejected;
  retiring / revoking a missing root rejects before apply.
* **Recovery / crash-window:** after-report success authorizes consume;
  after-snapshot-before-apply rolls back; ambiguous and rollback-failed windows
  fail closed; MainNet peer-driven refusal precedes recovery classification.
* **Projection:** only a modeled applier applied success reaches
  `ModeledApplierAppliedAndDurableConsumeAuthorized`; evaluator success alone,
  durable replay freshness alone, and mutation-engine authorization alone are each
  insufficient to consume.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_246_governance_modeled_end_to_end_pipeline_tests`
  — `47 passed; 0 failed`.
* `cargo test -p qbind-node --test run_244_modeled_governance_trust_mutation_applier_tests`
  — `45 passed; 0 failed`.
* `cargo test -p qbind-node --test run_242_governance_execution_mutation_engine_tests`
  — `38 passed; 0 failed`.
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests`
  — `63 passed; 0 failed`.
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests`
  — `68 passed; 0 failed`.
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
  — `56 passed; 0 failed`.
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
  — `58 passed; 0 failed`.
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
  — `47 passed; 0 failed`.
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
  — `52 passed; 0 failed`.
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
  — `48 passed; 0 failed`.
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
  — `59 passed; 0 failed`.
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
  — `48 passed; 0 failed`.
* `cargo test -p qbind-node --lib pqc_authority` — `164 passed; 0 failed`.
* `cargo test -p qbind-node --lib` — `1365 passed; 0 failed`.

## Security invariants preserved

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
* Rejected end-to-end pipeline paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and no applier invocation
  where the rejection happens before the applier stage.
* MainNet peer-driven apply is refused before any replay consume, modeled
  snapshot, or applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No RocksDB / file / schema / migration / storage-format change; no wire /
  marker / sequence / trust-bundle change.

## Honest limitations

* Run 246 is source/test only and introduces an ordering/composition layer over
  modeled in-memory boundaries, not a real production governance pipeline. No
  production mutating behavior is enabled.
* The composed fixture applier mutates only modeled in-memory state; it performs
  no real trust mutation, and the durable consume is only a typed projection /
  decision in this boundary.
* No real governance execution engine, production mutation engine, on-chain
  governance proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner
  backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 246 closes the source/test
end-to-end composition gap only and does **not** claim full C4 or C5 closure.

## Suggested Run 247 next step

Release-binary evidence for the Run 246 modeled end-to-end governance pipeline
(mirroring the Run 241 / 243 / 245 pattern): build the release binary, exercise
the composed evaluator → durable replay → mutation-engine → modeled applier →
durable consume pipeline through the source/test fixture applier, and capture
grep-verifiable evidence that durable consume remains gated end-to-end on a
modeled successful applier outcome, that rejected paths remain non-mutating, and
that production/MainNet and MainNet peer-driven paths remain
unavailable/refused in a release binary.