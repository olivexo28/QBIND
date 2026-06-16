# QBIND DevNet evidence — Run 261

**Title.** Release-binary governance durable-completion audit-receipt acknowledgement / external-publication confirmation interface evidence.

**Status.** PASS (release-binary evidence). Run 261 is the release-binary evidence run for the Run 260 source/test governance **durable-completion audit-receipt acknowledgement / external-publication confirmation boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs`.

Run 261 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper.rs` that the Run 260 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionAuditReceiptAcknowledgementLedger` through the DevNet/TestNet fixture acknowledgement sink.

## What Run 261 states

* Run 261 is release-binary evidence for Run 260.
* No production mutating behavior is enabled.
* The durable-completion audit-receipt acknowledgement / external-publication confirmation boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 260 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture acknowledgement sink mutates only modeled in-memory `DurableCompletionAuditReceiptAcknowledgementLedger` state.
* Production audit-ledger acknowledgement, MainNet audit-ledger acknowledgement, and external-publication confirmation sinks remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication receipt request can exist.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement / confirmation request can exist.
* Only `AcknowledgementRecorded` authorizes a new modeled acknowledgement state.
* Run 258 `AuditReceiptDuplicateIdempotent` may only match an already-recorded acknowledgement and never creates a new acknowledgement by itself.
* Every non-recorded receipt outcome produces no acknowledgement request and no acknowledgement.
* Duplicate identical acknowledgement is idempotent and creates no second acknowledgement.
* Same acknowledgement record id with a different digest fails closed as equivocation.
* Failed acknowledgement record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external-publication paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, and acknowledgement invocation.
* Rejected acknowledgement paths are non-mutating.
* The acknowledgement boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, or write a real audit ledger.
* No real audit-receipt acknowledgement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, audit-publication receipt backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

No symbol substitutions were required. Every type, function, and trait named by the Run 261 task — including `DurableCompletionAuditReceiptAcknowledgementInput`, `...Policy`, `...Kind`, `...Identity`, `...Expectations`, `...Request`, `...Response`, `...Record`, `...Ledger`, `...LedgerRecord`, `...Digest`, `...TranscriptDigest`, `...Outcome`, the `GovernanceDurableCompletionAuditReceiptAcknowledgementSink` trait, the `Fixture...` / `ProductionAuditLedger...` / `MainNetAuditLedger...` / `ExternalPublicationDurableCompletionConfirmationSink` implementations, `project_audit_receipt_outcome_to_acknowledgement_request`, `evaluate_durable_completion_audit_receipt_acknowledgement`, and `recover_durable_completion_audit_receipt_acknowledgement_window` — resolves directly to an implemented Run 260 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs` (the production module declared in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

One naming note recorded for honesty: the Run 260 grep-verifiable invariant helpers carry the `durable_completion_audit_ack_*` prefix (for example `durable_completion_audit_ack_rejection_is_non_mutating`, `durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first`), not a `durable_completion_audit_receipt_*` prefix. The helper imports and the harness source/helper reachability greps use the actual implemented `durable_completion_audit_ack_*` names. All Run 260 outcome tags, policy/kind/fault/window variants, and sink types are exercised by the helper exactly as implemented.

## Release artifacts

From `docs/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary/summary.txt` (regenerated per run; absolute-path/ephemeral artifacts are git-ignored):

* `qbind-node` SHA-256: `2e24112f5b31018bd8851e49d4782331c8b05c59ab1229c21ea58c7a0364903e`.
* `qbind-node` Build ID: `BuildID[sha1]=c4b9c201d8b534b9b10b7e48de0e8e974ed264c4`.
* Run 261 helper SHA-256: `e68ffd57e74ec80a10c8e66ee0f8da66c2b233b7f524958565ecd1dc15018e5e`.
* Run 261 helper Build ID: `BuildID[sha1]=93d94cb84e2c6d5d7fc1c89186b426cd7c8fe9c0`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted `66/0`, rejection `50/0`, recovery `32/0`, projection `20/0`, stage_ordering `6/0`, acknowledgement_ledger `18/0`, non_mutation `28/0`, reachability `36/0`; total `256` pass, `0` fail.

## Real-binary scenarios

S1 `--help`, S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden selector parse, and S6 invalid selector fail-closed all completed with expected return codes (S5/S6 expected non-zero; the invalid selector fails closed before any mutation). The denylist (51 forbidden patterns) was empty across captured logs.

## Validation

The harness `bash scripts/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large or the change set is classified as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 261 closes only the Run 260 release-binary evidence gap. It does not implement or enable a production audit-receipt acknowledgement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, audit-publication receipt backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.
