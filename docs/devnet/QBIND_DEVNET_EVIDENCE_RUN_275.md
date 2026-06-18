# QBIND DevNet evidence — Run 275

**Title.** Release-binary governance durable-completion settlement-outcome publication boundary evidence.

**Status.** PASS (release-binary evidence). Run 275 is the release-binary evidence run for the Run 274 source/test governance **durable-completion settlement-outcome publication boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_publication.rs`.

Run 275 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_275_durable_completion_settlement_outcome_publication_release_binary_helper.rs` that the Run 274 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionSettlementOutcomePublicationLedger` through the DevNet/TestNet fixture settlement-outcome publication sink.

## What Run 275 states

* Run 275 is release-binary evidence for Run 274.
* No production mutating behavior is enabled.
* The durable-completion settlement-outcome publication boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 274 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture settlement-outcome publication sink mutates only modeled in-memory `DurableCompletionSettlementOutcomePublicationLedger` state.
* Production settlement-outcome publication, MainNet settlement-outcome publication, and external settlement-outcome publication sinks remain reachable but unavailable/fail-closed.
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
* Run 268 `SettlementFinalizationRecorded` is required before any settlement-receipt acknowledgement request can exist.
* Run 270 `SettlementReceiptAcknowledgementRecorded` is required before any settlement-outcome report request can exist.
* Run 272 `SettlementOutcomeReportRecorded` is required before any settlement-outcome publication request can exist.
* Only `SettlementOutcomePublicationRecorded` authorizes a new modeled settlement-outcome publication state.
* Run 272 `SettlementOutcomeReportDuplicateIdempotent` may only match an already-recorded settlement-outcome publication record and never creates a new settlement-outcome publication record by itself.
* Every non-recorded settlement-outcome report outcome produces no settlement-outcome publication request and no settlement-outcome publication record.
* Duplicate identical settlement-outcome publication record is idempotent and creates no second settlement-outcome publication record.
* Same settlement-outcome publication record id with a different digest fails closed as equivocation.
* Failed settlement-outcome publication record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external settlement-outcome publication paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, settlement-projection invocation, settlement-commitment invocation, settlement-finalization invocation, settlement-receipt acknowledgement invocation, settlement-outcome report invocation, and settlement-outcome publication invocation.
* Rejected settlement-outcome publication paths are non-mutating.
* The settlement-outcome publication boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, perform real settlement, implement real settlement finality, write/produce a real settlement receipt, implement real settlement-receipt acknowledgement, implement real settlement-finality projection, implement real settlement-outcome report, or implement real settlement-outcome publication.
* No real settlement backend, settlement-receipt backend, settlement-receipt acknowledgement backend, settlement-outcome report backend, settlement-outcome publication backend, settlement-finality projection backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 275 release helper drives projection exclusively from the Run 272 settlement-outcome report outcome:

* `input.settlement_outcome_report_binding` -> `project_settlement_outcome_report_outcome_to_outcome_publication_request`.

It does **not** project from the Run 270 settlement-receipt acknowledgement, Run 268 settlement-finalization, Run 266 settlement-commitment, Run 264 settlement-projection, Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 272 `SettlementOutcomeReportRecorded` creates a settlement-outcome publication request; `SettlementOutcomeReportDuplicateIdempotent` is idempotent-only; legacy/no-report outcomes map to legacy/no-outcome-publication; rejected-before-report / report-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-outcome-publication fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoOutcomeReport` -> `MainNetPeerDrivenApplyRefusedNoOutcomePublication`; `ValidatorSetRotationUnsupportedNoOutcomeReport` -> `ValidatorSetRotationUnsupportedNoOutcomePublication`; `PolicyChangeUnsupportedNoOutcomeReport` -> `PolicyChangeUnsupportedNoOutcomePublication`.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 275 task resolves directly to an implemented Run 274 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_publication.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

Two naming notes are recorded honestly for fidelity:

* The Run 274 `Outcome` predicate that reports a non-recording (no-outcome-publication) outcome is implemented as `DurableCompletionSettlementOutcomePublicationOutcome::no_commitment(...)` (the carried upstream-boundary predicate name was intentionally retained in the Run 274 source, per the carried known-naming note); the helper calls the actual implemented `no_commitment()` method rather than inventing a `no_outcome_publication()` alias.
* The Run 274 boundary exposes the prior-stage invariant helper as `durable_completion_settlement_outcome_publication_outcome_report_required` (the Run 272 boundary's analog was `..._receipt_acknowledgement_required`), and it retains `durable_completion_settlement_outcome_publication_finalization_projection_required`; the helper imports and the harness reachability greps use the actual implemented names.

The Run 274 grep-verifiable invariant helpers carry the `durable_completion_settlement_outcome_publication_*` prefix (for example `durable_completion_settlement_outcome_publication_rejection_is_non_mutating`, `durable_completion_settlement_outcome_publication_outcome_report_required`, `durable_completion_settlement_outcome_publication_no_real_settlement`, `durable_completion_settlement_outcome_publication_no_real_settlement_finality`, `durable_completion_settlement_outcome_publication_no_real_settlement_receipt`, `durable_completion_settlement_outcome_publication_no_real_settlement_finality_projection`, `durable_completion_settlement_outcome_publication_no_real_settlement_outcome_report`, `durable_completion_settlement_outcome_publication_no_real_settlement_outcome_publication`, `durable_completion_settlement_outcome_publication_no_real_audit_ledger`, `durable_completion_settlement_outcome_publication_record_required_before_reported`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 274 outcome tags, policy/kind/fault/window variants, and the `Fixture`/`Production`/`MainNet`/`External` settlement-outcome publication sinks are exercised by the helper exactly as implemented. The carried Run 272 settlement-outcome report binding type is `DurableCompletionSettlementOutcomePublicationSettlementOutcomeReportBinding` and the input field is `settlement_outcome_report_binding`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, settlement_outcome_publication_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.settlement_outcome_report_binding` via `project_settlement_outcome_report_outcome_to_outcome_publication_request` over the attached `Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection -> Run266 settlement commitment -> Run268 settlement finalization -> Run270 settlement-receipt acknowledgement -> Run272 settlement-outcome report -> Run274 settlement-outcome publication` chain. The harness additionally proves source/helper reachability for every Run 274 symbol (settlement-outcome publication types, the `evaluate`/`recover`/`project` functions, the settlement-outcome publication authorize/project predicates, the `GovernanceDurableCompletionSettlementOutcomePublicationSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_settlement_outcome_publication_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2-S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on settlement-outcome publication / settlement-outcome report / settlement-receipt acknowledgement / settlement-finality projection / settlement-finalization / settlement-receipt / settlement-finality / settlement / publication / confirmation production-enablement claims. The denylist of forbidden patterns was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_275_durable_completion_settlement_outcome_publication_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_274`, `run_272`, `run_270`, `run_268`, `run_266`, `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large, times out, tooling is unavailable, no changes are detected, or the checker classifies the change set as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 275 closes only the Run 274 release-binary evidence gap. It does not implement or enable a production settlement backend, settlement-receipt backend, settlement-receipt acknowledgement backend, settlement-outcome report backend, settlement-outcome publication backend, settlement-finality projection backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.
