# QBIND DevNet evidence — Run 269

**Title.** Release-binary governance durable-completion settlement-finalization / settlement-receipt boundary evidence.

**Status.** PASS (release-binary evidence). Run 269 is the release-binary evidence run for the Run 268 source/test governance **durable-completion settlement-finalization / settlement-receipt boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_finalization.rs`.

Run 269 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_269_durable_completion_settlement_finalization_release_binary_helper.rs` that the Run 268 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionSettlementFinalizationLedger` through the DevNet/TestNet fixture settlement-finalization sink.

## What Run 269 states

* Run 269 is release-binary evidence for Run 268.
* No production mutating behavior is enabled.
* The durable-completion settlement-finalization / settlement-receipt boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 268 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture settlement-finalization sink mutates only modeled in-memory `DurableCompletionSettlementFinalizationLedger` state.
* Production settlement-finalization, MainNet settlement-finalization, and external settlement-finalization sinks remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication receipt request can exist.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement request can exist.
* Run 260 `AcknowledgementRecorded` is required before any acknowledgement-consumer request can exist.
* Run 262 `AcknowledgementConsumed` is required before any settlement-projection request can exist.
* Run 264 `SettlementProjectionRecorded` is required before any settlement-commitment request can exist.
* Run 266 `SettlementCommitmentRecorded` is required before any settlement-finalization request can exist.
* Only `SettlementFinalizationRecorded` authorizes a new modeled settlement-finalization / settlement-receipt state.
* Run 266 `SettlementCommitmentDuplicateIdempotent` may only match an already-recorded settlement-finalization record and never creates a new settlement-finalization record by itself.
* Every non-recorded settlement-commitment outcome produces no settlement-finalization request and no settlement-finalization record.
* Duplicate identical settlement-finalization record is idempotent and creates no second settlement-finalization record.
* Same settlement-finalization record id with a different digest fails closed as equivocation.
* Failed settlement-finalization record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external settlement-finalization paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, settlement-projection invocation, settlement-commitment invocation, and settlement-finalization invocation.
* Rejected settlement-finalization paths are non-mutating.
* The settlement-finalization boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, perform real settlement, implement real settlement finality, or write/produce a real settlement receipt.
* No real settlement backend, settlement-receipt backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 269 release helper drives projection exclusively from the Run 266 settlement-commitment outcome:

* `input.settlement_commitment_binding` -> `project_settlement_commitment_outcome_to_finalization_request`.

It does **not** project from the Run 264 settlement-projection, Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 266 `SettlementCommitmentRecorded` creates a settlement-finalization request; `SettlementCommitmentDuplicateIdempotent` is idempotent-only; legacy/no-commitment outcomes map to legacy/no-finalization; rejected-before-commitment / commitment-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-finalization fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoCommitment` -> `MainNetPeerDrivenApplyRefusedNoFinalization`; `ValidatorSetRotationUnsupportedNoCommitment` -> `ValidatorSetRotationUnsupportedNoFinalization`; `PolicyChangeUnsupportedNoCommitment` -> `PolicyChangeUnsupportedNoFinalization`.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 269 task resolves directly to an implemented Run 268 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_finalization.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

One naming note recorded honestly for fidelity: the Run 268 `Outcome` predicate that reports a non-recording (no-finalization) outcome is implemented as `DurableCompletionSettlementFinalizationOutcome::no_commitment(...)` (the prior-boundary name was retained in the Run 268 source); the helper calls the actual implemented `no_commitment()` method rather than inventing a `no_finalization()` alias. All other names map directly.

The Run 268 grep-verifiable invariant helpers carry the `durable_completion_settlement_finalization_*` prefix (for example `durable_completion_settlement_finalization_rejection_is_non_mutating`, `durable_completion_settlement_finalization_commitment_required`, `durable_completion_settlement_finalization_no_real_settlement`, `durable_completion_settlement_finalization_no_real_settlement_finality`, `durable_completion_settlement_finalization_no_real_settlement_receipt`, `durable_completion_settlement_finalization_record_required_before_finalized`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 268 outcome tags, policy/kind/fault/window variants, and the `Fixture`/`Production`/`MainNet`/`External` settlement-finalization sinks are exercised by the helper exactly as implemented. The carried Run 266 settlement-commitment binding type is `DurableCompletionSettlementFinalizationSettlementCommitmentBinding` and the input field is `settlement_commitment_binding`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, settlement_finalization_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.settlement_commitment_binding` via `project_settlement_commitment_outcome_to_finalization_request` over the attached `Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection -> Run266 settlement commitment -> Run268 settlement finalization` chain. The harness additionally proves source/helper reachability for every Run 268 symbol (settlement-finalization types, the `evaluate`/`recover`/`project` functions, the `settlement_finalization_outcome_authorizes_record`/`settlement_finalization_outcome_projects_to_recorded` predicates, the `GovernanceDurableCompletionSettlementFinalizationSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_settlement_finalization_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2-S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on settlement-finalization/settlement-receipt/settlement-finality/settlement/publication/confirmation production-enablement claims. The denylist (forbidden patterns) was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_269_durable_completion_settlement_finalization_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_268`, `run_266`, `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large or the change set is classified as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 269 closes only the Run 268 release-binary evidence gap. It does not implement or enable a production settlement backend, settlement-receipt backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.