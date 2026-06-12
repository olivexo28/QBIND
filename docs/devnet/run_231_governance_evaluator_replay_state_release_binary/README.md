# Run 231 — Release-binary governance evaluator replay/freshness state evidence

## Scope

Run 231 is the release-binary evidence run for the Run 230 source/test
governance evaluator **replay and freshness state boundary** in
`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`:

* the typed inputs / expectations `EvaluatorReplayFreshnessInput` /
  `EvaluatorReplayFreshnessExpectations` (binding environment, chain id,
  genesis hash, evaluator source identity / request / response / transcript
  digests, governance execution decision digest, proposal id, decision id,
  lifecycle action, candidate digest, authority-domain sequence, effective /
  expiry epoch, replay nonce, validation surface, current canonical epoch, and
  the previously-seen decision state);
* the state classification `ReplayFreshnessState` (`Fresh`,
  `FreshButNotYetEffective`, `Expired`, `Stale`, `ReplayDetected`,
  `AlreadyConsumed`, `Superseded`, `WrongEpoch`, `WrongEnvironment`,
  `WrongChain`, `WrongGenesis`, `WrongSurface`, `MalformedState`,
  `StateUnavailable`, `ProductionStateUnavailable`, `MainNetStateUnavailable`);
* the typed outcome `EvaluatorReplayFreshnessOutcome` (`ProceedFresh`,
  `ProceedDeferred`, `FailClosedExpired`, `FailClosedReplay`,
  `FailClosedAlreadyConsumed`, `FailClosedSuperseded`, `FailClosedWrongBinding`,
  `FailClosedStateUnavailable`, `FailClosedProductionUnavailable`,
  `FailClosedMainNetUnavailable`) and its predicates (`authorizes_mutation`,
  `is_deferred`, `is_fail_closed`, `no_mutation`);
* the pure entry points `classify_evaluator_replay_freshness`,
  `evaluate_evaluator_replay_freshness`, and `gate_evaluator_replay_freshness`;
* the deterministic digest helpers `replay_state_key_digest`,
  `replay_observation_digest`, `consumed_decision_digest`, and
  `freshness_transcript_digest`;
* the `GovernanceEvaluatorReplayStateReader` /
  `GovernanceEvaluatorReplayStateWriter` boundary traits, the DevNet/TestNet
  `FixtureReplayStateStore`, and the callable-but-unavailable
  `ProductionReplayStateReader` / `MainnetReplayStateReader`.

Where Run 230 proved the boundary at the source/test level, Run 231 proves on
real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_231_governance_evaluator_replay_state_release_binary_helper.rs`,
driven by
`scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`)
that the release-built code exposes and exercises the replay/freshness
boundary:

* the boundary distinguishes fresh, deferred (not-yet-effective), expired,
  stale, replayed, already-consumed, superseded, wrong-binding, unavailable,
  production-unavailable, and MainNet-unavailable outcomes;
* the deterministic digests (replay state key / observation / consumed
  decision / freshness transcript) are stable and field-sensitive in release
  mode;
* read-only validation (`read_for` / `read_previous_state`) never marks a
  decision consumed;
* explicit fixture consume (`consume_for` / `mark_consumed`) marks consumed
  only in the DevNet/TestNet fixture store;
* the production / MainNet readers are callable and return the typed
  unavailable / fail-closed state;
* **MainNet peer-driven apply remains refused** even when the state is fresh;
* every rejection is pure and non-mutating — only `ProceedFresh` authorizes a
  mutation, and `ProceedDeferred` is **not** an approval;
* the Run 224 integration and Run 228 peer context remain compatible when the
  replay-state policy is `Disabled` / not wired.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/run_231/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The Run 230 replay/freshness state boundary is a local/source-test-only
  pure classification layer. Run 231 exercises it through release-built
  library symbols (the same symbols a future production call site would use),
  but the boundary itself performs no I/O and authorizes no mutation directly.
* The `FixtureReplayStateStore` is a DevNet/TestNet in-process map only. It is
  not a persistent store, reads as `Unavailable` for a MainNet environment,
  and introduces **no** RocksDB schema, file format, or database migration.
* Production / MainNet replay state is callable but always returns the typed
  unavailable / fail-closed result, regardless of the resolved policy.
* No real governance execution engine is implemented. No real on-chain
  governance proof verifier is implemented.
* Read-only validation never marks consumed; explicit consume marks consumed
  only in the fixture evidence.
* The boundary is pure: it performs no network or file I/O, writes no marker,
  writes no sequence, mutates no live trust, evicts no sessions, and never
  invokes Run 070 apply. The only mutation-authorizing outcome is
  `ProceedFresh`; `ProceedDeferred` is explicitly **not** an approval.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  when the replay/freshness state would otherwise be fresh.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes **no** network wire schema, trust-bundle schema,
  authority-marker schema, or sequence schema, and implements no storage
  format change or database migration.
* Existing Run 229, Run 227, Run 225, and Run 223 release behaviour remains
  compatible.
* Full C4 remains open. C5 remains open.