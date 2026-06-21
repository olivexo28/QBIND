# QBIND DevNet evidence — Run 283

**Title.** Release-binary governance durable-completion external-publication-audit-finalization boundary evidence.

**Status.** PASS (release-binary evidence). Run 283 is the release-binary evidence run for the Run 282 source/test governance durable-completion external-publication-acknowledgement consumer / **external-publication-audit-finalization boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_audit_finalization.rs`.

Run 283 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_283_durable_completion_external_publication_audit_finalization_release_binary_helper.rs` that the Run 282 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionExternalPublicationAuditFinalizationLedger` through the DevNet/TestNet fixture external-publication-audit-finalization sink.

## What Run 283 states

* Run 283 is release-binary evidence for Run 282.
* No production mutating behavior is enabled.
* The durable-completion external-publication-audit-finalization boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 282 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture external-publication-audit-finalization sink mutates only modeled in-memory `DurableCompletionExternalPublicationAuditFinalizationLedger` state.
* Production external-publication-audit-finalization, MainNet external-publication-audit-finalization, and external external-publication-audit-finalization sinks remain reachable but unavailable/fail-closed.
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
* Run 276 `ExternalPublicationConfirmationRecorded` is required before any external-publication-receipt request can exist.
* Run 278 `ExternalPublicationReceiptRecorded` is required before any external-publication-acknowledgement request can exist.
* Run 280 `ExternalPublicationAcknowledgementRecorded` is required before any external-publication-audit-finalization request can exist.
* Only `ExternalPublicationAuditFinalizationRecorded` authorizes a new modeled external-publication-audit-finalization state.
* Run 280 `ExternalPublicationAcknowledgementDuplicateIdempotent` may only match an already-recorded external-publication-audit-finalization record and never creates a new external-publication-audit-finalization record by itself.
* Every non-recorded external-publication-acknowledgement outcome produces no external-publication-audit-finalization request and no external-publication-audit-finalization record.
* Duplicate identical external-publication-audit-finalization record is idempotent and creates no second external-publication-audit-finalization record.
* Same external-publication-audit-finalization record id with a different digest fails closed as equivocation.
* Failed external-publication-audit-finalization record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external external-publication-audit-finalization paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, settlement-projection invocation, settlement-commitment invocation, settlement-finalization invocation, settlement-receipt acknowledgement invocation, settlement-outcome report invocation, settlement-outcome publication invocation, external-publication-confirmation invocation, external-publication-receipt invocation, external-publication-acknowledgement invocation, and external-publication-audit-finalization invocation.
* Rejected external-publication-audit-finalization paths are non-mutating.
* The C4/C5 matrix taxonomy clarification remains present.
* The C4/C5 matrix separates boundary readiness from production readiness.
* Yellow boundary rows do not equal production backend implementation.
* Red production backend rows remain Red until production implementation and release-binary evidence exist.
* The external-publication-audit-finalization boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, perform a real external-publication receipt, perform a real external-publication acknowledgement, perform a real external-publication audit finalization, write a real audit ledger, perform real settlement, implement real settlement finality, write/produce a real settlement receipt, implement real settlement-receipt acknowledgement, implement real settlement-finality projection, implement real settlement-outcome report backend, or implement real settlement-outcome publication.
* No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, external-publication receipt, external-publication acknowledgement, external-publication audit finalization, audit-ledger acknowledgement, audit-ledger finalization, production backend, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 283 release helper drives projection exclusively from the Run 280 external-publication acknowledgement outcome:

* `input.external_publication_acknowledgement_binding` -> `project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request`.

It does **not** project from the Run 278 external-publication receipt, Run 276 external-publication confirmation, Run 274 settlement-outcome publication, Run 272 settlement-outcome report, Run 270 settlement-receipt acknowledgement, Run 268 settlement-finalization, Run 266 settlement-commitment, Run 264 settlement-projection, Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 280 `ExternalPublicationAcknowledgementRecorded` creates an external-publication-audit-finalization request; `ExternalPublicationAcknowledgementDuplicateIdempotent` is idempotent-only; legacy/no-acknowledgement outcomes map to legacy/no-audit-finalization; rejected-before-acknowledgement / acknowledgement-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-audit-finalization fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoAcknowledgement` -> `MainNetPeerDrivenApplyRefusedNoAuditFinalization`; `ValidatorSetRotationUnsupportedNoAcknowledgement` -> `ValidatorSetRotationUnsupportedNoAuditFinalization`; `PolicyChangeUnsupportedNoAcknowledgement` -> `PolicyChangeUnsupportedNoAuditFinalization`. Every other non-recorded external-publication-acknowledgement outcome maps to a no-audit-finalization fail-closed outcome.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 283 task resolves directly to an implemented Run 282 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_audit_finalization.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

A few naming notes are recorded honestly for fidelity:

* The carried Run 280 external-publication acknowledgement binding is consumed through `input.external_publication_acknowledgement_binding`, and the modeled audit-finalization ledger is `DurableCompletionExternalPublicationAuditFinalizationLedger`. The helper and harness use the actual implemented names exactly as registered.
* Several no-audit-finalization `Outcome` variant identifiers carry the `...NoAuditFinalization` suffix (for example `ExternalPublicationAuditFinalizationRecordFailedNoAuditFinalization`); the helper asserts only the `external-publication-audit-finalization-recorded` tag and matches every other variant by its implemented identifier.
* The projection entry point retains the prior-stage `external_publication_acknowledgement` segment in its name (`project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request`) because it consumes the Run 280 acknowledgement outcome; the helper imports and the harness reachability greps use the actual implemented name.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, external_publication_audit_finalization_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.external_publication_acknowledgement_binding` via `project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request` over the attached `Run256 backend -> Run258 receipt -> Run260 acknowledgement -> Run262 consumer -> Run264 settlement projection -> Run266 settlement commitment -> Run268 settlement finalization -> Run270 settlement-receipt acknowledgement -> Run272 settlement-outcome report -> Run274 settlement-outcome publication -> Run276 external-publication confirmation -> Run278 external-publication receipt -> Run280 external-publication acknowledgement -> Run282 external-publication audit finalization` chain. The harness additionally proves source/helper reachability for every Run 282 symbol (external-publication-audit-finalization types, the `evaluate`/`recover`/`project` functions, the external-publication-audit-finalization authorize/project predicates, the `GovernanceDurableCompletionExternalPublicationAuditFinalizationSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_external_publication_audit_finalization_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2-S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on external-publication-audit-finalization / external-publication acknowledgement / external-publication receipt / external-publication confirmation / external publication / settlement-outcome publication / settlement-outcome report backend / settlement-receipt acknowledgement / settlement-finality projection / settlement-finalization / settlement-receipt / settlement-finality / settlement / publication / confirmation / receipt production-enablement claims. No new public CLI surface was added for Run 283. The denylist of forbidden patterns was empty across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; Yellow boundary rows do not equal production backend implementation; Red production backend rows remain Red until production implementation **and** release-binary evidence both exist. The modeled durable-completion pipeline / settlement / external-publication boundary stack remains Yellow only; real production RemoteSigner backend, real KMS / HSM / cloud-KMS / PKCS#11 custody backend, real custody attestation verifier, real on-chain governance proof verifier, governance execution engine, validator-set rotation / authority-set synchronization, and full MainNet release-binary evidence under production custody remain Red. Run 283 does not reinterpret the Run 278/280/282 matrix clarification as C4/C5 closure. The C4/C5 criteria header and Run 282 changelog references are corrected before evidence capture.

## Validation

The harness `bash scripts/devnet/run_283_durable_completion_external_publication_audit_finalization_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_282`, `run_280`, `run_278`, `run_276`, `run_274`, `run_272`, `run_270`, `run_268`, `run_266`, `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_283_durable_completion_external_publication_audit_finalization_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 80` / `total_fail: 0`, release-binary scenarios `S1_help=0 S2=1 S3=1 S4=1 S5=1 S6=1`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL: Run 283 adds a release-mode example helper plus a harness shell script and evidence/Markdown documentation, and does not change the production library surface; the CodeQL checker result is reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_283.md`. The underlying Run 282 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 283 is release-binary evidence only. It does not enable any production mutating behavior and does not implement any real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, external-publication receipt, external-publication acknowledgement, external-publication audit finalization, audit-ledger acknowledgement, audit-ledger finalization, production backend, governance execution engine, on-chain proof verifier, KMS/HSM/RemoteSigner backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, or policy-change enablement. Run 283 closes only the Run 282 release-binary evidence gap. Full C4 remains **OPEN** and C5 remains **OPEN**.
