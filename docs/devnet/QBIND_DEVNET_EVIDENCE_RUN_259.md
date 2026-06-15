# QBIND DevNet evidence — Run 259

**Title.** Release-binary governance durable-completion audit-publication receipt interface evidence.

**Status.** PASS (release-binary evidence). Run 259 is the release-binary evidence run for the Run 258 source/test governance **durable-completion audit-ledger / external-publication receipt boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_audit_publication_receipt.rs`.

Run 259 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_259_durable_completion_audit_publication_receipt_release_binary_helper.rs` that the Run 258 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionAuditPublicationReceiptLedger` through the DevNet/TestNet fixture receipt sink.

## What Run 259 states

* Run 259 is release-binary evidence for Run 258.
* No production mutating behavior is enabled.
* The durable-completion audit-publication receipt boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 258 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture receipt sink mutates only modeled in-memory `DurableCompletionAuditPublicationReceiptLedger` state.
* Production/MainNet/external-publication receipt sinks remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Run 256 `BackendSubmissionRecorded` is required before any audit-receipt request can exist.
* Only `AuditReceiptRecorded` authorizes a new modeled audit/publication receipt state.
* Run 256 duplicate-idempotent backend submission may only match an already-recorded receipt and never creates a new audit receipt by itself.
* Duplicate identical audit receipt is idempotent and creates no second receipt record.
* Same receipt record id with a different digest fails closed as equivocation.
* Every non-recording Run 256 backend outcome produces no audit-receipt request and no receipt record.
* Failed receipt record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external-publication paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, and receipt invocation.
* Rejected receipt paths are non-mutating.
* The receipt boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, or write a real audit ledger.
* No real audit-publication receipt backend, audit ledger backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

No symbol substitutions were required. Every symbol named by the Run 259 task resolves directly to an implemented Run 258 API name; `pqc_governance_durable_completion_audit_publication_receipt` is the production module declared in `crates/qbind-node/src/lib.rs`. The helper and harness use the real implemented names and no compatibility shims were added. The helper additionally touches the `DurableCompletionAuditPublicationReceiptSurface`, `DurableCompletionAuditPublicationReceiptEnvironment`, and `DurableCompletionAuditPublicationReceiptBinding` (and the per-stage `...ReplayBinding`/`...PipelineBinding`/`...SinkBinding`/`...ReporterBinding`/`...FinalizationBinding`/`...AttestationBinding`/`...BackendBinding`) type aliases and every `durable_completion_audit_receipt_*` invariant helper so that every Run 258 type the task enumerates is linked in release mode.

## Release artifacts

From `docs/devnet/run_259_durable_completion_audit_publication_receipt_release_binary/summary.txt` (regenerated per run; absolute-path/ephemeral artifacts are git-ignored):

* `qbind-node` SHA-256: `ebbde143c3974c79a794522aa10ea6be9cfa27ca87cd6db524746f94ca12fd1f`.
* `qbind-node` Build ID: `BuildID[sha1]=aa91b19560fa815dd912d87db0fe5c2b5de053eb`.
* Run 259 helper SHA-256: `6777f87561ad29f4364afb3ba646f7b96d56cb1e2e3c7616eb765b625d102d0d`.
* Run 259 helper Build ID: `BuildID[sha1]=74665626840bcb6ade4656be35a1816209e9fb68`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted `65/0`, rejection `120/0`, recovery `27/0`, projection `39/0`, stage_ordering `7/0`, receipt_ledger `56/0`, non_mutation `27/0`, reachability `37/0`; total `378` pass, `0` fail.

## Real-binary scenarios

S1 `--help`, S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden selector parse, and S6 invalid selector fail-closed all completed with expected return codes (S5/S6 expected non-zero; the invalid selector fails closed before any mutation). The denylist (50 forbidden patterns) was empty across captured logs.

## Validation

The harness `bash scripts/devnet/run_259_durable_completion_audit_publication_receipt_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 259 closes only the Run 258 release-binary evidence gap. It does not implement or enable a production audit-publication receipt backend, audit ledger backend, external publication backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend.