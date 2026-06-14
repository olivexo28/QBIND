# QBIND DevNet evidence — Run 249

**Title.** Release-binary governance modeled durable-consume projection sink
evidence.

**Status.** PASS (release-binary evidence). Run 249 is the release-binary
evidence run for the Run 248 source/test governance **modeled durable-consume
projection sink boundary** in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`.
Run 248 landed the typed durable-consume projection sink boundary that projects
a Run 246 modeled end-to-end pipeline outcome into a typed consume-sink intent
and records, through a pure/mockable sink, only the in-memory
`ModeledDurableConsumeReceiptLedger` — refuse MainNet peer-driven apply first,
honour the legacy disabled-policy bypass, require a
`ModeledApplierAppliedAndDurableConsumeAuthorized` pipeline outcome, validate the
pre-sink bindings, then record a receipt under receipt-identity, idempotency, and
equivocation gates — but captured **no** release-binary evidence (deferred to
Run 249). Run 249 proves on real `target/release/qbind-node` plus a release-built
helper that the release-built code exposes and exercises that boundary.

Run 249 is **release-binary evidence only**. It implements **no** real durable
consume backend, **no** real persistent replay backend, **no** real production
mutation engine, **no** real governance execution engine, **no** real on-chain
governance proof verifier, **no** RocksDB backend, **no** file format, **no**
schema, **no** database migration, **no** storage-format change, **no** real
KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format. Any production-source module remains pure / source-test bounded and
fail-closed; the modeled durable-consume projection sink boundary is
release-evidenced, not production-enabled.

## What Run 249 states

* Run 249 is release-binary evidence for Run 248.
* No production mutating behaviour is enabled.
* The modeled durable-consume projection sink boundary is release-evidenced, not
  production-enabled.
* The release helper exercises the Run 248 production library symbols in release
  mode.
* The release helper remains dead code from the production runtime.
* The fixture sink mutates only modeled in-memory
  `ModeledDurableConsumeReceiptLedger` state.
* Only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome can
  create a sink intent.
* Only `ConsumeReceiptRecorded` authorizes a new modeled receipt-recorded state.
* A duplicate identical receipt is idempotent and creates no second receipt.
* A same receipt id with a different digest fails closed as equivocation.
* Every non-success pipeline outcome produces no sink invocation and no receipt.
* Failed record, rollback, rollback-failed, ambiguous windows, unavailable
  production/MainNet sink paths, rejected replay states, and unsupported actions
  never consume.
* MainNet peer-driven apply remains refused before pipeline projection and before
  sink invocation.
* Rejected sink paths are non-mutating.
* No real durable consume backend is implemented.
* No real persistent replay backend is implemented.
* No real production mutation engine is implemented.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* No wire/schema/marker/sequence/trust-bundle change is implemented.
* No KMS/HSM/RemoteSigner backend is implemented.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* The sink does not call Run 070.
* The sink does not mutate `LivePqcTrustState`.
* The sink does not perform a real trust swap.
* The sink does not evict sessions.
* The sink does not write sequence files.
* The sink does not write authority markers.
* Full C4 remains **OPEN**.
* C5 remains **OPEN**.

## Symbol substitutions

None. Every Run 248 symbol named in the task exists in
`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`
with the exact name used by the helper, harness, and this report. No
compatibility shim was required.

## Strict scope

* Release-binary evidence only.
* Uses the release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behaviour change (the run adds only an example helper, a
  harness script, evidence, and narrow doc updates).
* No real durable consume backend; no real persistent replay backend; no real
  production mutation engine; no real governance execution engine; no real
  on-chain governance proof verifier; no RocksDB schema; no file format; no
  database migration; no storage-format change; no MainNet governance
  enablement; no MainNet peer-driven apply enablement; no validator-set rotation;
  no KMS/HSM backend; no RemoteSigner backend.
* Rejected sink paths are non-mutating and never invoke Run 070.
* A receipt is recorded only after a
  `ModeledApplierAppliedAndDurableConsumeAuthorized` pipeline outcome and a clean
  pre-sink binding validation; failed record, rollback, rollback failure,
  ambiguous windows, unavailable production/MainNet paths, rejected replay
  states, and unsupported actions never consume.
* Run 249 does not weaken any prior run (Runs 070, 130–248) and does not claim
  full C4 or C5 closure.

## Deliverables

* **Release helper** —
  `crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs`.
  Links against the release-built production library symbols and exercises
  `pqc_governance_modeled_durable_consume_projection_sink`,
  `evaluate_modeled_durable_consume_projection_sink`,
  `GovernanceModeledDurableConsumeProjectionSink`,
  `FixtureModeledDurableConsumeProjectionSink`,
  `ProductionModeledDurableConsumeProjectionSink`,
  `MainNetModeledDurableConsumeProjectionSink`,
  `project_pipeline_outcome_to_consume_sink_intent`, `ConsumeSinkIntent`,
  `recover_modeled_durable_consume_projection_sink_window`,
  `ModeledDurableConsumeReceiptWindow`,
  `GovernanceModeledDurableConsumeSinkInput`,
  `GovernanceModeledDurableConsumeSinkExpectations`,
  `GovernanceModeledDurableConsumeSinkPolicy`,
  `GovernanceModeledDurableConsumeSinkSurface`,
  `GovernanceModeledDurableConsumeSinkEnvironmentBinding`,
  `GovernanceModeledDurableConsumeSinkRuntimeBinding`,
  `GovernanceModeledDurableConsumeSinkReplayBinding`,
  `GovernanceModeledDurableConsumeSinkPipelineBinding`,
  `ModeledDurableConsumeReceiptLedger`, `ModeledDurableConsumeReceiptRecord`,
  `ModeledDurableConsumeReceiptSnapshot`, `ModeledDurableConsumeReceiptDigest`,
  `ModeledDurableConsumeReceiptStatus`,
  `GovernanceModeledDurableConsumeSinkReceipt`,
  `ModeledDurableConsumeSinkKind`, `ModeledConsumeSinkFault`, the
  `GovernanceModeledDurableConsumeSinkOutcome` taxonomy with its `tag()` /
  predicate surface (`sink_outcome_authorizes_modeled_consume_receipt`,
  `sink_outcome_projects_to_durable_completion`), and all grep-verifiable
  invariant / fail-closed helpers from Run 248.
* **Release harness** —
  `scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh`.
  Builds `target/release/qbind-node` and the Run 249 helper; captures git
  commit, rustc/cargo versions, SHA-256 + ELF Build ID for both binaries; runs
  real-binary surface scenarios; runs the helper corpus in release mode; runs
  source- and helper-reachability greps for the Run 248 symbols; runs a denylist
  proving no active production/MainNet enablement claims; runs the regression
  test corpus; and writes generated evidence into the ignored evidence
  directory.
* **Evidence archive** —
  `docs/devnet/run_249_modeled_durable_consume_projection_sink_release_binary/`
  (tracks only `README.md`, `summary.txt`, `.gitignore`; generated artifacts are
  ignored, following the Run 245 / Run 247 convention).
* **Canonical report** — this file.

## Release-helper corpus

`crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs`
drives eight tables through the release-built Run 248 symbols
(280 checks total, all PASS):

* **accepted (47)** — a disabled sink policy and a disabled
  pipeline/evaluator/call-site policy preserve the legacy no-mutation,
  no-consume, no-receipt bypass with a zero sink-invocation count and an empty
  receipt ledger; DevNet and TestNet fixture pipelines that resolve to
  `ModeledApplierAppliedAndDurableConsumeAuthorized` project a consume-sink intent
  and record a receipt only after the modeled applier success, mutating only the
  in-memory `ModeledDurableConsumeReceiptLedger`; the only consume-authorizing
  pipeline outcome is `ModeledApplierAppliedAndDurableConsumeAuthorized`;
  production and MainNet sink kinds are reachable but unavailable; MainNet
  peer-driven apply is refused before pipeline projection and sink invocation;
  validator-set rotation and policy-change actions are unsupported.
* **rejection (116)** — wrong environment / chain / genesis / governance surface /
  candidate digest / decision digest / proposal id / decision id / authority
  sequence / lifecycle action, a malformed binding, every rejected durable replay
  state (stale / expired / consumed / superseded / backend-unavailable /
  deferred), a read-only validation surface, and a missing root before record are
  each rejected without consume and (when the rejection is before the sink stage)
  never reach the sink — zero invocation count, ledger unchanged; record failure,
  rollback, rollback failure, and the ambiguous window never consume; production /
  MainNet sink kinds remain unavailable; validator-set rotation and policy-change
  attempts are unsupported; local operator and peer majority cannot satisfy
  MainNet authority; every rejected path is non-mutating.
* **recovery (14)** — before-record recovers as rolled-back / no consume;
  after-record-before-report fails closed unless an explicit success report
  exists; after-report-success recovers as modeled recorded;
  after-report-ambiguous, rollback-failed, and unknown windows fail closed;
  production / MainNet recovery classification is unavailable; MainNet
  peer-driven apply refusal precedes recovery classification.
* **projection (25)** — only the Run 246
  `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome projects to a
  consume-sink intent; every other pipeline outcome (evaluator-rejected,
  replay-rejected, mutation-engine-rejected, applier-failed, rolled-back,
  rollback-failed, ambiguous, production/MainNet-unavailable,
  MainNet-peer-driven-refused, legacy-bypass, validator-set-rotation-unsupported,
  policy-change-unsupported) projects to no sink intent and records no receipt.
* **stage_ordering (14)** — MainNet peer-driven apply refusal precedes everything;
  the legacy disabled-policy bypass precedes pipeline projection; a successful
  pipeline outcome precedes pre-sink binding validation; pre-sink binding
  validation precedes sink invocation; sink record (receipt-identity +
  idempotency + equivocation gates) precedes consume authorization; a pipeline
  outcome other than `ModeledApplierAppliedAndDurableConsumeAuthorized` is
  individually insufficient to invoke the sink.
* **receipt_ledger (23)** — only `ConsumeReceiptRecorded` records a new modeled
  receipt; a duplicate identical receipt is idempotent (no second record); a
  same-id different-digest receipt fails closed as equivocation with no record;
  the receipt ledger snapshot / digest / status surface is stable; a record
  failure leaves the ledger unchanged.
* **non_mutation (18)** — every rejected path leaves the receipt ledger
  unchanged, performs no live trust swap, writes no marker, writes no sequence,
  evicts no session, performs no durable consume, and calls no Run 070; a
  rejection before the sink stage leaves the sink invocation count at zero; no
  fixture case mutates `LivePqcTrustState`.
* **reachability (23)** — every outcome / receipt-status / window `tag()` is
  stable; the sink trait classifies an input in release mode; and all
  grep-verifiable invariant / fail-closed helpers from Run 248 hold in release
  mode.

## Real release-binary surface scenarios

The harness runs the real `target/release/qbind-node`:

* **S1** — `--help` exposes no durable-consume-sink enablement banner or visible
  public flag drift (rc=0).
* **S2 / S3 / S4** — default DevNet / TestNet / MainNet startup parse/smoke
  surfaces emit no durable-consume-sink enablement claim (rc=0).
* **S5** — the hidden governance-execution selector still parses and remains
  silent on any durable-consume-sink enablement (rc=1, parse-only smoke without a
  network).
* **S6** — an invalid governance-execution selector fails closed before mutation
  (rc≠0) and prints the fail-closed banner (`no marker write; no sequence write;
  no live trust swap; no session eviction; no Run 070 call`).

No Run 248/249 hidden selector or helper-only path appears as a public
production enablement surface.

## Denylist

The harness proves the captured real-binary and helper logs contain no
active/enabled claims for: real durable consume backend, modeled durable-consume
sink production enabled, MainNet modeled sink, MainNet mutation engine, MainNet
governance, MainNet peer-driven apply, real production mutation engine, real
governance execution engine, real on-chain governance proof verifier, real
persistent replay backend, RocksDB/file replay backend, schema/storage-format
migration, KMS/HSM/RemoteSigner backend, validator-set rotation, policy-change
action, autonomous apply / apply-on-receipt, peer-majority authority, Run 070
apply / `LivePqcTrustState` mutation / real trust swap / session eviction /
marker write / sequence write / durable consume from the sink boundary, and
active DummySig/DummyKem/DummyAead. All 39 forbidden patterns are proven empty.

## Tests

All regression targets PASS (rc=0):

```
cargo build -p qbind-node --release --bin qbind-node
cargo build -p qbind-node --release --example run_249_modeled_durable_consume_projection_sink_release_binary_helper
bash scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh
cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests
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

* Rejected sink paths are non-mutating: no Run 070 call, no `LivePqcTrustState`
  mutation, no real trust swap, no session eviction, no sequence write, no marker
  write, no durable consume, and (for a rejection-before-sink) no sink
  invocation.
* A receipt is recorded only after a
  `ModeledApplierAppliedAndDurableConsumeAuthorized` pipeline outcome and a clean
  pre-sink binding validation; only `ConsumeReceiptRecorded` records a new
  modeled receipt.
* A duplicate identical receipt is idempotent (no second record) and a same-id
  different-digest receipt fails closed as equivocation.
* Failed record, rollback, rollback failure, ambiguous windows, unavailable
  production/MainNet paths, rejected replay states, and unsupported actions never
  consume.
* Production / MainNet sink kinds are reachable but always unavailable /
  fail-closed.
* MainNet peer-driven apply remains refused before any pipeline projection or
  sink invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The boundary changes no wire / marker / sequence / trust-bundle / storage
  format and introduces no RocksDB schema, file format, or database migration.

## Honest limitations

* The Run 248 durable-consume projection sink boundary is a pure, typed
  projection over the already-landed Run 246 modeled end-to-end pipeline outcome
  plus a mockable sink that records only the in-memory
  `ModeledDurableConsumeReceiptLedger`, exercised here through release-built
  library symbols (the same symbols a future production call site would use); it
  applies no real (live) durable consume and performs no I/O.
* The boundary specifies the ordering a real durable-consume sink would have to
  honour but implements none of that production behaviour: no real durable
  consume backend, no real persistent replay backend, no real production mutation
  engine, no real governance execution engine, no real on-chain governance proof
  verifier, no RocksDB backend, no file format, no schema, no database migration,
  and no storage-format change.
* The `FixtureModeledDurableConsumeProjectionSink` records only the modeled
  in-memory receipt ledger and performs no real durable consume; the
  `ProductionModeledDurableConsumeProjectionSink` and
  `MainNetModeledDurableConsumeProjectionSink` are always unavailable /
  fail-closed.
* No real KMS / HSM / RemoteSigner backend. No MainNet governance enablement, no
  MainNet peer-driven apply enablement, no validator-set rotation.
* Existing Run 247, Run 245, Run 243, and Run 241 release behaviour remains
  compatible.

## C4 / C5 status

Run 249 closes the Run 248 release-binary evidence gap only. **Full C4 remains
OPEN; C5 remains OPEN.** Run 249 makes no production mutating enablement claim.

## Suggested Run 250 next step

A source/test step that extends the Run 248 modeled durable-consume projection
sink with a typed, mockable durable-consume *receipt-acknowledgement / completion
reporter* — modelling how a future production call site would report the
after-record-only consume acknowledgement back to the Run 240 durable completion
semantics without enabling any real persistent backend — still source/test only,
still fail-closed, with no production mutating enablement, followed by a Run 251
release-binary evidence run mirroring this one.

## Contradiction crosscheck

Run 249 was crosschecked against Runs 050–248. No contradiction was found: Run
249 adds only a release-built example helper, a harness script, an evidence
archive, this canonical report, and narrow doc updates; it changes no production
source behaviour, enables no production mutation, and preserves every prior
fail-closed invariant (MainNet peer-driven apply refusal, pipeline-projection /
pre-sink-binding / receipt-record ordering, after-success-only durable consume,
receipt idempotency and equivocation fail-closed, and the non-mutating rejection
guarantees). A “no Run 249 contradiction” entry is recorded in
`docs/whitepaper/contradiction.md`.
