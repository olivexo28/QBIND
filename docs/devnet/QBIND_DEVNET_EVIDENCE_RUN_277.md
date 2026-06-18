# QBIND DevNet evidence — Run 277

**Title.** Release-binary governance durable-completion external-publication-confirmation boundary evidence.

**Status.** PASS (release-binary evidence). Run 277 is the release-binary evidence run for the Run 276 source/test governance durable-completion settlement-outcome publication consumer / **external-publication-confirmation boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_confirmation.rs`.

Run 277 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_277_durable_completion_external_publication_confirmation_release_binary_helper.rs` that the Run 276 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionExternalPublicationConfirmationLedger` through the DevNet/TestNet fixture external-publication-confirmation sink.

## What Run 277 states

* Run 277 is release-binary evidence for Run 276.
* No production mutating behavior is enabled.
* The durable-completion external-publication-confirmation boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 276 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture external-publication-confirmation sink mutates only modeled in-memory `DurableCompletionExternalPublicationConfirmationLedger` state.
* Production external-publication-confirmation, MainNet external-publication-confirmation, and external external-publication-confirmation sinks remain reachable but unavailable/fail-closed.
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
* Run 274 `SettlementOutcomePublicationRecorded` is required before any external-publication-confirmation request can exist.
* Only `ExternalPublicationConfirmationRecorded` authorizes a new modeled external-publication-confirmation state.
* Run 274 `SettlementOutcomePublicationDuplicateIdempotent` may only match an already-recorded external-publication-confirmation record and never creates a new external-publication-confirmation record by itself.
* Every non-recorded settlement-outcome publication outcome produces no external-publication-confirmation request and no external-publication-confirmation record.
* Duplicate identical external-publication-confirmation record is idempotent and creates no second external-publication-confirmation record.
* Same external-publication-confirmation record id with a different digest fails closed as equivocation.
* Failed external-publication-confirmation record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external external-publication-confirmation paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, settlement-projection invocation, settlement-commitment invocation, settlement-finalization invocation, settlement-receipt acknowledgement invocation, settlement-outcome report invocation, settlement-outcome publication invocation, and external-publication-confirmation invocation.
* Rejected external-publication-confirmation paths are non-mutating.
* The external-publication-confirmation boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, perform real settlement, implement real settlement finality, write/produce a real settlement receipt, implement real settlement-receipt acknowledgement, implement real settlement-finality projection, implement real settlement-outcome report backend, or implement real settlement-outcome publication.
* No real settlement backend, settlement-receipt backend, settlement-receipt acknowledgement backend, settlement-outcome report backend, settlement-outcome publication backend, external-publication-confirmation backend, settlement-finality projection backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 277 release helper drives projection exclusively from the Run 274 settlement-outcome publication outcome:

* `input.settlement_outcome_publication_binding` -> `project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request`.

It does **not** project from the Run 272 settlement-outcome report, Run 270 settlement-receipt acknowledgement, Run 268 settlement-finalization, Run 266 settlement-commitment, Run 264 settlement-projection, Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 274 `SettlementOutcomePublicationRecorded` creates an external-publication-confirmation request; `SettlementOutcomePublicationDuplicateIdempotent` is idempotent-only; legacy/no-publication outcomes map to legacy/no-confirmation; rejected-before-publication / publication-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-confirmation fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoOutcomePublication` -> `MainNetPeerDrivenApplyRefusedNoConfirmation`; `ValidatorSetRotationUnsupportedNoOutcomePublication` -> `ValidatorSetRotationUnsupportedNoConfirmation`; `PolicyChangeUnsupportedNoOutcomePublication` -> `PolicyChangeUnsupportedNoConfirmation`.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 277 task resolves directly to an implemented Run 276 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_confirmation.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

A few naming notes are recorded honestly for fidelity:

* The Run 276 `Outcome` predicate that reports a non-recording (no-confirmation) outcome is implemented as `DurableCompletionExternalPublicationConfirmationOutcome::no_commitment(...)` (the carried upstream-boundary predicate name was intentionally retained in the Run 276 source); the helper calls the actual implemented `no_commitment()` method rather than inventing a `no_confirmation()` alias.
* The Run 276 boundary exposes the prior-stage invariant helper as `durable_completion_external_publication_confirmation_outcome_publication_required` (the Run 274 boundary's analog was `..._outcome_report_required`), and it retains `durable_completion_external_publication_confirmation_finalization_projection_required`; the helper imports and the harness reachability greps use the actual implemented names.
* The Run 276 `no_real_*` invariant set is `durable_completion_external_publication_confirmation_no_real_settlement`, `..._no_real_settlement_finality`, `..._no_real_settlement_receipt`, `..._no_real_settlement_outcome_publication`, `..._no_real_settlement_finality_projection`, and `..._no_real_external_publication_confirmation` (the Run 274 boundary's `..._no_real_settlement_outcome_report` was replaced by `..._no_real_external_publication_confirmation` at this rung); the helper and harness use the actual implemented names.
* Several no-confirmation `Outcome` variant identifiers carry the `...NoConfirmation` suffix (for example `ExternalPublicationConfirmationRecordFailedNoConfirmation`), while their human-readable `tag()` strings retain the carried `...-no-outcome-publication` suffix from the source. The helper asserts only the `external-publication-confirmation-recorded` tag and matches every other variant by its implemented identifier.

The Run 276 grep-verifiable invariant helpers carry the `durable_completion_external_publication_confirmation_*` prefix (for example `durable_completion_external_publication_confirmation_rejection_is_non_mutating`, `durable_completion_external_publication_confirmation_outcome_publication_required`, `durable_completion_external_publication_confirmation_no_real_settlement`, `durable_completion_external_publication_confirmation_no_real_settlement_finality`, `durable_completion_external_publication_confirmation_no_real_settlement_receipt`, `durable_completion_external_publication_confirmation_no_real_settlement_finality_projection`, `durable_completion_external_publication_confirmation_no_real_settlement_outcome_publication`, `durable_completion_external_publication_confirmation_no_real_external_publication_confirmation`, `durable_completion_external_publication_confirmation_no_real_audit_ledger`, `durable_completion_external_publication_confirmation_record_required_before_reported`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 276 outcome tags, policy/kind/fault/window variants, and the `Fixture`/`Production`/`MainNet`/`External` external-publication-confirmation sinks are exercised by the helper exactly as implemented. The carried Run 274 settlement-outcome publication binding type is `DurableCompletionExternalPublicationConfirmationSettlementOutcomePublicationBinding` and the input field is `settlement_outcome_publication_binding`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, external_publication_confirmation_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.settlement_outcome_publication_binding` via `project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request` over the attached `Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection -> Run266 settlement commitment -> Run268 settlement finalization -> Run270 settlement-receipt acknowledgement -> Run272 settlement-outcome report -> Run274 settlement-outcome publication -> Run276 external-publication confirmation` chain. The harness additionally proves source/helper reachability for every Run 276 symbol (external-publication-confirmation types, the `evaluate`/`recover`/`project` functions, the external-publication-confirmation authorize/project predicates, the `GovernanceDurableCompletionExternalPublicationConfirmationSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_external_publication_confirmation_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2-S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on external-publication-confirmation / external-publication / settlement-outcome publication / settlement-outcome report backend / settlement-receipt acknowledgement / settlement-finality projection / settlement-finalization / settlement-receipt / settlement-finality / settlement / publication / confirmation production-enablement claims. No new public CLI surface was added for Run 277. The denylist of forbidden patterns was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_277_durable_completion_external_publication_confirmation_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_276`, `run_274`, `run_272`, `run_270`, `run_268`, `run_266`, `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`. The canonical machine-readable run summary is regenerated into the (git-ignored) `summary.txt` of `docs/devnet/run_277_durable_completion_external_publication_confirmation_release_binary/`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large, times out, tooling is unavailable, no changes are detected, or the checker classifies the change set as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 277 is release-binary evidence only. It does not enable any production mutating behavior and does not implement any real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, audit-ledger acknowledgement, production backend, governance execution engine, on-chain proof verifier, KMS/HSM/RemoteSigner backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, or policy-change enablement. Run 277 closes only the Run 276 release-binary evidence gap. Full C4 remains **OPEN** and C5 remains **OPEN**.
