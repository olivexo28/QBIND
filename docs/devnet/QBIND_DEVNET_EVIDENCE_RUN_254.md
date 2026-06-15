# QBIND DevNet evidence — Run 254

**Title.** Source/test governance modeled durable-completion finalization
**attestation** projection boundary.

**Status.** PASS (source/test only). Run 254 extends the Run 252 modeled
durable-completion finalization projection with a mockable, in-memory
**attestation projection** layer that models how a future production call site
would **project** an after-finalization-only durable-completion acknowledgement
into a terminal **modeled durable-completion-attested** state, once the Run 252
finalization projection has recorded a `DurableCompletionFinalized` outcome. Run
252 proved that a modeled finalization is recorded only after the Run 250
reporter yields the single completion-report-authorizing outcome
`CompletionReportRecorded` (terminating in `DurableCompletionFinalized`). What
was still missing was a typed source/test boundary that models the
after-finalization-only attestation / ledger-commit acknowledgement step. Run
254 closes that source/test attestation-projection gap only.

Run 254 introduces an **attestation-projection layer**, **not** a replacement
for any existing module. It consumes the typed Run 252 finalization outcome as a
binding and projects it onto an attestation intent; only the Run 252
`DurableCompletionFinalized` outcome creates an attestation intent, and a Run 252
`DurableCompletionDuplicateIdempotent` may only match an already-attested
completion and never creates a new one. The attestor is a **model only**. It
implements **no** real persistent replay backend, **no** real durable consume
backend, **no** real completion-report backend, **no** real finalization
backend, **no** real attestation backend, **no** real audit ledger backend,
**no** real production mutation engine, **no** real governance execution engine,
**no** real on-chain governance proof verifier, **no** RocksDB backend, **no**
file format, **no** schema, **no** database migration, **no**
storage-format change, **no** KMS/HSM backend, **no** RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format.

## Strict scope

* Source/test evidence only. No release-binary harness in this run.
* Run 254 adds a modeled durable-completion finalization attestation projection
  boundary.
* It models how a future production call site would project an
  after-finalization-only acknowledgement into a modeled
  durable-completion-attested state.
* It does **not** implement a real persistent replay backend.
* It does **not** implement a real durable consume backend.
* It does **not** implement a real completion-report backend.
* It does **not** implement a real finalization backend.
* It does **not** implement a real attestation backend.
* It does **not** implement a real audit ledger backend.
* It does **not** add RocksDB / file / schema / migration / storage-format
  changes.
* It does **not** add wire / schema / marker / sequence / trust-bundle changes.
* It does **not** write authority markers.
* It does **not** write trust-bundle sequence files.
* It does **not** call Run 070.
* It does **not** mutate `LivePqcTrustState`.
* It does **not** perform a real trust swap.
* It does **not** evict sessions.
* It does **not** implement a real production mutation engine.
* It does **not** implement a real governance execution engine.
* It does **not** implement a real on-chain governance proof verifier.
* It does **not** add KMS/HSM/RemoteSigner backend.
* It does **not** enable MainNet governance.
* It does **not** enable MainNet peer-driven apply.
* It does **not** implement validator-set rotation.
* The fixture attestor mutates only modeled in-memory attestation state.
* Rejected attestor paths are non-mutating.
* Run 254 does not weaken any prior run (Runs 070, 130–253) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`

Run 254 adds a new source module (registered in `lib.rs`) that defines:

* typed attestor inputs / policy / bindings
  (`GovernanceModeledDurableCompletionAttestationInput`,
  `GovernanceModeledDurableCompletionAttestationPolicy`,
  `GovernanceModeledDurableCompletionAttestationExpectations`,
  `GovernanceModeledDurableCompletionAttestationRecord`) plus type aliases over
  the Run 244/246/248/250/252 bindings (`…Surface`, `…EnvironmentBinding`,
  `…RuntimeBinding`, `…ReplayBinding`, `…PipelineBinding`, `…SinkBinding`,
  `…ReporterBinding`, `…FinalizationBinding`);
* modeled in-memory attestation state
  (`ModeledDurableCompletionAttestationLedger`,
  `GovernanceModeledDurableCompletionAttestationRecord`,
  `ModeledDurableCompletionAttestationDigest`) — in-memory only; never touches
  RocksDB, files, markers, sequence files, or any production durable state. The
  attestation digest/identity binds the Run 248 `sink_decision_digest`, the Run
  250 `reporter_decision_digest`, and the Run 252 `finalization_decision_digest`;
* an explicit attestation outcome enum
  (`GovernanceModeledDurableCompletionAttestationOutcome`) whose only
  **new**-attestation authorizing variant is `DurableCompletionAttested`,
  including `LegacyBypassNoAttestation`,
  `RejectedBeforeFinalizationNoAttestation`,
  `FinalizationDidNotFinalizeNoAttestation`,
  `DurableCompletionAttestationDuplicateIdempotent`,
  `DurableCompletionAttestationRejectedBeforeRecord`,
  `DurableCompletionAttestationRecordFailedNoAttestation`,
  `DurableCompletionAttestationRolledBackNoAttestation`,
  `DurableCompletionAttestationRollbackFailedFatalNoAttestation`,
  `DurableCompletionAttestationAmbiguousFailClosedNoAttestation`,
  `ProductionAttestorUnavailableNoAttestation`,
  `MainNetAttestorUnavailableNoAttestation`,
  `MainNetPeerDrivenApplyRefusedNoAttestation`,
  `ValidatorSetRotationUnsupportedNoAttestation`, and
  `PolicyChangeUnsupportedNoAttestation`;
* a pure/mockable attestor trait
  (`GovernanceModeledDurableCompletionAttestor`) with
  `record_modeled_durable_completion_attestation`, plus source/test-only
  implementations (`FixtureModeledDurableCompletionAttestor` for DevNet/TestNet,
  and the reachable-but-unavailable
  `ProductionModeledDurableCompletionAttestor` /
  `MainNetModeledDurableCompletionAttestor`). The fixture attestor exposes an
  invocation counter so tests prove non-finalizing paths never invoke it;
* composition helpers
  (`project_finalization_outcome_to_attestation_intent`,
  `evaluate_modeled_durable_completion_attestation_projection`,
  `recover_modeled_durable_completion_attestation_window`);
* grep-verifiable invariant helpers (see below).

### Required ordering

1. MainNet peer-driven apply refusal happens **before** pipeline progression,
   **before** any sink invocation, **before** any reporter invocation, **before**
   any finalizer invocation, and **before** any attestor invocation.
2. A disabled attestation / finalization / reporter / sink / pipeline /
   evaluator-call-site policy preserves the legacy no-attestation bypass and
   never invokes the attestor.
3. Only the Run 252 `DurableCompletionFinalized` finalization outcome creates an
   attestation intent; `DurableCompletionDuplicateIdempotent` may only match an
   already-attested completion; every other finalization outcome maps to a
   no-attestation fail-closed outcome and never invokes the attestor.
4. Pre-attestor environment / chain / genesis / governance surface / mutation
   surface binding validation completes **before** the attestation is recorded;
   a mismatch fails closed with no attestor invocation.
5. The attestation record happens **after** the Run 252 durable-completion
   finalized state; the attestation-identity fields (including the sink, reporter,
   and finalization decision digests) must match exactly before any modeled
   attestation is recorded.
6. Only `DurableCompletionAttested` authorizes a **new** modeled
   durable-completion-attested state. A duplicate identical attestation is
   idempotent (no second attestation); the same attestation id with a different
   digest fails closed as equivocation.

### Grep-verifiable invariant helpers

* `modeled_attestation_rejection_is_non_mutating`
* `modeled_attestation_never_calls_run_070`
* `modeled_attestation_never_mutates_live_pqc_trust_state`
* `modeled_attestation_never_writes_sequence_or_marker`
* `modeled_attestation_no_rocksdb_file_schema_migration_change`
* `modeled_attestation_pipeline_success_required_before_attestation`
* `modeled_attestation_sink_receipt_required_before_attestation`
* `modeled_attestation_completion_report_required_before_attestation`
* `modeled_attestation_finalization_required_before_attestation`
* `modeled_attestation_record_required_before_durable_completion_attested`
* `modeled_attestation_failed_record_never_attests`
* `modeled_attestation_rollback_never_attests`
* `modeled_attestation_ambiguous_window_fails_closed`
* `modeled_attestation_mainnet_peer_driven_apply_refused_first`
* `modeled_attestation_production_mainnet_unavailable`
* `modeled_attestation_validator_set_rotation_unsupported`
* `modeled_attestation_policy_change_unsupported`
* `modeled_attestation_local_operator_cannot_satisfy_mainnet_authority`
* `modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority`

## Tests

`crates/qbind-node/tests/run_254_modeled_durable_completion_attestation_projection_tests.rs`
— 108 tests, all passing. The matrix covers:

* **Accepted / compatible:** disabled attestation / finalization / reporter /
  sink / pipeline / evaluator-call-site policy preserve the legacy no-attestation
  bypass and never invoke the attestor; DevNet and TestNet durable-completion
  finalized + attestor record success record exactly one modeled in-memory
  attestation; modeled add-root / retire-root / revoke-root /
  emergency-revoke-root / noop actions (modeled via distinct candidate digests)
  each record an attestation only after the Run 252 finalization record; a
  duplicate identical attestation is idempotent with no second attestation; a
  duplicate-idempotent finalization matches an already-attested completion only,
  and never creates a new one by itself; the production and MainNet attestor
  paths are reachable but unavailable/fail-closed and record no attestation;
  MainNet peer-driven apply is refused before pipeline progression, before any
  sink, reporter, finalizer, or attestor invocation; validator-set rotation and
  policy-change are unsupported and record no attestation.
* **Rejected / fail-closed:** every non-finalizing finalization outcome (legacy
  bypass, rejected-before-finalization, finalization-did-not-finalize,
  rejected-before-record, record-failure, rollback, rollback-failed, ambiguous
  window, production/MainNet unavailable) produces no attestation intent, no
  attestation, and zero attestor invocations; an attestation record failure,
  rollback, rollback-failed, and ambiguous window all fail closed without
  recording an attestation; the same attestation id with a different digest is
  rejected as equivocation and records no second attestation; wrong environment /
  chain / genesis / governance surface / mutation surface are rejected before
  attestor invocation (zero invocations); wrong attestation digest / finalization
  decision digest / reporter decision digest / sink decision digest / pipeline
  decision digest / proposal id / decision id / candidate digest / authority-domain
  sequence and a malformed attestation are rejected before record (attestor
  invoked, no record); local operator and peer majority cannot satisfy MainNet
  authority.
* **Recovery / crash-window:** before-pipeline,
  after-pipeline/sink/receipt/report/finalization intent-and-record windows fail
  closed with no attestation; after-attestation-record-before-attestation-success
  fails closed unless an explicit matching attestation success exists;
  after-attestation-success recovers as durable-completion attested;
  after-attestation-ambiguous, attestation-record-failed, rollback-completed,
  rollback-failed, and unknown windows fail closed with no attestation;
  production/MainNet recovery classification is unavailable; MainNet peer-driven
  apply refusal precedes recovery classification.
* **Projection / stage-ordering:** only `DurableCompletionFinalized` creates an
  attestation intent; `DurableCompletionDuplicateIdempotent` projects to
  idempotent-only; only `DurableCompletionAttested` authorizes a new modeled
  attestation; every no-attestation outcome does not project to durable
  completion attested; a rejection before the attestor stage leaves the attestor
  invocation count at zero; an attestation record failure does not invalidate the
  finalized binding but does not authorize attestation; one valid attestation
  inserts exactly one ledger record; the ledger snapshot/restore models a
  rollback with no drift.

### Validation commands

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_254_modeled_durable_completion_attestation_projection_tests`
  — `108 passed; 0 failed`.
* `cargo test -p qbind-node --test run_252_modeled_durable_completion_finalization_projection_tests`
  — `98 passed; 0 failed`.
* `cargo test -p qbind-node --test run_250_modeled_durable_consume_completion_reporter_tests`
  — `88 passed; 0 failed`.
* `cargo test -p qbind-node --test run_248_modeled_durable_consume_projection_sink_tests`
  — `68 passed; 0 failed`.
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

* Run 246 pipeline success is required before any sink intent can exist, and
  therefore before any attestation can be recorded.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report
  intent can exist, and therefore before any attestation can be recorded.
* Run 250 `CompletionReportRecorded` is required before any finalization intent
  can exist, and therefore before any attestation can be recorded.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent
  can exist; only that finalization outcome creates an attestation intent.
* `DurableCompletionAttested` is required before any new modeled
  durable-completion-attested state.
* Every non-finalized finalization outcome produces no attestor invocation and no
  attestation.
* A failed attestation record, rollback, rollback-failed, ambiguous window,
  unavailable production/MainNet path, rejected replay state, and unsupported
  action never attest.
* An attestor failure, rollback, rollback failure, or ambiguous attestation
  window never retroactively claims durable-completion attestation.
* A duplicate identical attestation is idempotent (no second attestation); the
  same attestation id with a different digest fails closed as equivocation; a
  duplicate-idempotent finalization never creates a new attestation by itself.
* Rejected attestor paths are non-mutating: no Run 070 call, no
  `LivePqcTrustState` mutation, no live trust swap, no session eviction, no
  sequence write, no marker write, no durable consume, and no attestor
  invocation where the rejection happens before the attestor stage.
* MainNet peer-driven apply is refused before pipeline progression, before any
  sink, reporter, finalizer, or attestor invocation.
* Validator-set rotation and policy-change actions remain unsupported.
* The fixture attestor mutates only modeled in-memory attestation state; no
  RocksDB / file / schema / migration / storage-format change; no wire / marker /
  sequence / trust-bundle change.

## Honest limitations

* Run 254 is source/test only and introduces an attestation-projection layer over
  a modeled in-memory ledger, not a real production attestation or audit ledger
  backend. No production mutating behavior is enabled.
* The fixture attestor records only modeled in-memory attestation state; it
  performs no real durable-completion attestation, and the production / MainNet
  attestors are deliberately reachable-but-unavailable.
* No real persistent replay backend, durable consume backend, completion-report
  backend, finalization backend, attestation backend, audit ledger backend,
  production mutation engine, governance execution engine, on-chain governance
  proof verifier, or KMS/HSM/RemoteSigner backend is implemented.

## C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 254 closes the source/test
modeled durable-completion attestation-projection gap only and does **not**
claim full C4 or C5 closure.

## Suggested Run 255 next step

Release-binary evidence for the Run 254 modeled durable-completion attestation
projection (mirroring the Run 241 / 243 / 245 / 247 / 249 / 251 / 253 pattern):
build the release binary, exercise the Run 246 pipeline → Run 248 consume-sink
projection → Run 250 completion-report projection → Run 252 finalization
projection → Run 254 attestation projection → fixture attestation recording path
through the source/test fixtures, and capture grep-verifiable evidence that a
modeled attestation is recorded only after a Run 252 durable-completion finalized
record, that every non-finalizing / record-failure / rollback / ambiguous /
equivocation path remains non-mutating and records no attestation, and that
production/MainNet attestor paths and MainNet peer-driven apply remain
refused/unavailable.