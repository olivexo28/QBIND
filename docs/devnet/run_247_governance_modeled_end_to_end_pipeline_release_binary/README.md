# Run 247 — Release-binary modeled governance end-to-end pipeline evidence

## Scope

Run 247 is the release-binary evidence run for the Run 246 source/test
governance **modeled end-to-end pipeline boundary** in
`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`:

* the typed pipeline entry point `run_modeled_end_to_end_pipeline` and the
  pure/mockable executor trait `GovernanceModeledEndToEndPipelineExecutor` with
  `DefaultGovernanceModeledEndToEndPipelineExecutor`;
* the crash-window recovery helper `recover_modeled_end_to_end_pipeline_window`;
* the typed bindings `GovernanceModeledEndToEndPipelineInput`,
  `GovernanceModeledEndToEndPipelineExpectations`,
  `GovernanceModeledEndToEndPipelinePolicy`,
  `GovernanceModeledEndToEndPipelineSurface`,
  `GovernanceModeledEndToEndPipelineEnvironmentBinding`,
  `GovernanceModeledEndToEndPipelineRuntimeBinding`,
  `GovernanceModeledEndToEndPipelineCandidate`,
  `GovernanceModeledEndToEndPipelineReplayBinding`, and
  `GovernanceModeledEndToEndPipelineMutationBinding`;
* the stage records `EvaluatorCallsiteStage`, `DurableReplayObserveStage`,
  `MutationEngineStage`, `ModeledApplierStage`, `DurableProjectionStage`, and
  `DurableConsumeDecisionStage`;
* the stage classifications `EvaluatorCallsiteAuthorization` and
  `DurableReplayObservation`;
* the `GovernanceModeledEndToEndPipelineOutcome` taxonomy (the only
  consume-authorizing variant is
  `ModeledApplierAppliedAndDurableConsumeAuthorized`) and the full
  `GovernanceModeledEndToEndPipelineDecision` result with its `tag()` /
  predicate surface;
* the grep-verifiable invariant / fail-closed guard functions
  (`modeled_end_to_end_pipeline_rejection_is_non_mutating`,
  `modeled_end_to_end_pipeline_never_calls_run_070`,
  `modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state`,
  `modeled_end_to_end_pipeline_success_required_before_durable_consume`,
  `modeled_end_to_end_pipeline_applier_success_required_before_consume`,
  `modeled_end_to_end_pipeline_failed_apply_never_consumes`,
  `modeled_end_to_end_pipeline_rollback_never_consumes`,
  `modeled_end_to_end_pipeline_ambiguous_window_fails_closed`,
  `modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first`,
  `modeled_end_to_end_pipeline_production_mainnet_unavailable`,
  `modeled_end_to_end_pipeline_validator_set_rotation_unsupported`,
  `modeled_end_to_end_pipeline_policy_change_unsupported`,
  `modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change`,
  `modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority`,
  `modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority`).

Where Run 246 proved the end-to-end pipeline boundary at the source/test level,
Run 247 proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs`,
driven by
`scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh`)
that the release-built code exposes and exercises the boundary:

* a disabled pipeline policy and a disabled evaluator/call-site policy preserve
  the legacy no-mutation, no-consume bypass and never invoke the applier;
* a DevNet/TestNet fixture evaluator + durable replay fresh + mutation-engine
  authorized + modeled add / retire / revoke / emergency-revoke / noop success
  authorizes a durable consume **only after** the modeled applier success, and
  mutates **only** the in-memory `ModeledGovernanceTrustState`;
* the only consume-authorizing outcome is
  `ModeledApplierAppliedAndDurableConsumeAuthorized`; evaluator success alone,
  durable replay freshness alone, and mutation-engine authorization alone are
  each individually insufficient;
* every evaluator/call-site rejection, replay rejection
  (stale/expired/consumed/superseded/backend-unavailable/deferred), binding
  mismatch, read-only surface, missing-root before-apply rejection, apply
  failure, rollback, rollback-failed, ambiguous window, unavailable
  production/MainNet path, validator-set rotation, and policy-change attempt is
  non-mutating and non-consuming, and a rejection before the applier stage
  leaves the applier invocation counter at zero with the modeled state
  unchanged;
* **MainNet peer-driven apply remains refused** — before any replay consume,
  modeled snapshot, or applier invocation;
* the crash-window recovery helper reuses the Run 244 modeled outcome semantics
  and fails closed on every after-apply / ambiguous / rollback-failed / unknown
  window;
* existing Run 245, Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and
  Run 231 release behaviour remains compatible.

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
bash scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 246 end-to-end pipeline boundary is a pure, typed ordering/composition
  over the already-landed Run 226 evaluator call-site, Run 240 durable replay
  observation, Run 242 mutation-engine, and Run 244 modeled trust-state applier
  boundaries plus a mockable applier that mutates only the in-memory
  `ModeledGovernanceTrustState`. Run 247 exercises it through release-built
  library symbols (the same symbols a future production call site would use), but
  the boundary itself performs no I/O and applies no real (live) mutation.
* The boundary specifies the MainNet-refusal-first, legacy-bypass,
  evaluator/call-site, durable-replay, mutation-engine, modeled-applier, and
  durable-consume ordering a real end-to-end governance pipeline would have to
  honour, but implements **none** of that production mutation: there is no real
  production mutation engine, no real governance execution engine, no real
  on-chain governance proof verifier, no real persistent replay backend, no
  RocksDB backend, no file format, no schema, no database migration, and no
  storage-format change.
* The `FixtureModeledTrustMutationApplier` mutates only the modeled in-memory
  state and performs no real trust mutation; the
  `ProductionModeledTrustMutationApplier` and `MainNetModeledTrustMutationApplier`
  always return the typed unavailable / fail-closed result.
* `ModeledApplierAppliedAndDurableConsumeAuthorized` is the only outcome that
  authorizes a durable consume, and only after evaluator/call-site authorization,
  durable replay freshness, mutation-engine authorization, and modeled applier
  success all agree; rejected, failed apply, rollback, rollback-failed, ambiguous,
  unavailable, and unsupported outcomes never consume.
* The boundary is non-mutating on every rejection path: it does not mutate
  `LivePqcTrustState`, writes no marker, writes no sequence, performs no live
  trust swap, evicts no sessions, performs no durable consume of its own, and
  never invokes Run 070 apply.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) before any
  replay consume, modeled snapshot, or applier invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* No real KMS / HSM / RemoteSigner backend. The boundary changes **no** network
  wire schema, trust-bundle schema, authority-marker schema, or sequence schema.
* Full C4 remains open. C5 remains open.
