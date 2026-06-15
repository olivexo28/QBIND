# QBIND DevNet evidence — Run 257

**Title.** Release-binary governance durable-completion attestation backend interface evidence.

**Status.** PASS (release-binary evidence). Run 257 is the release-binary evidence run for the Run 256 source/test governance **production durable-completion attestation backend interface boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_attestation_backend.rs`.

Run 257 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_257_durable_completion_attestation_backend_release_binary_helper.rs` that the Run 256 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionAttestationBackendLedger` through the DevNet/TestNet fixture backend.

## What Run 257 states

* Run 257 is release-binary evidence for Run 256.
* No production mutating behavior is enabled.
* The durable-completion attestation backend interface boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 256 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture backend mutates only modeled in-memory `DurableCompletionAttestationBackendLedger` state.
* Production/MainNet/external-publication backends remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Only `BackendSubmissionRecorded` authorizes a new modeled backend-submitted state.
* Run 254 duplicate-idempotent attestation may only match an already-submitted backend record and never creates a new backend submission by itself.
* Duplicate identical backend submission is idempotent and creates no second backend submission.
* Same backend record id with a different digest fails closed as equivocation.
* Every non-attesting Run 254 outcome produces no backend request and no backend submission.
* Failed backend record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external-publication paths, rejected replay states, and unsupported actions never submit.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, and backend invocation.
* Rejected backend paths are non-mutating.
* The backend does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, or write a real audit ledger.
* No real production attestation backend, audit ledger backend, external publication backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, or validator-set rotation is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

No symbol substitutions were required. Every symbol named by the Run 257 task resolves directly to an implemented Run 256 API name; `pqc_governance_durable_completion_attestation_backend` is the production module declared in `crates/qbind-node/src/lib.rs`. The helper and harness use the real implemented names and no compatibility shims were added. The helper additionally touches the `DurableCompletionAttestationBackendSurface`, `DurableCompletionAttestationBackendEnvironment`, and `DurableCompletionAttestationBackendBinding` type aliases so that every Run 256 type the task enumerates is linked in release mode.

## Release artifacts

From `docs/devnet/run_257_durable_completion_attestation_backend_release_binary/summary.txt` (regenerated per run; absolute-path/ephemeral artifacts are git-ignored):

* `qbind-node` SHA-256: `bacd6f3bdb09e84af8fe845844b1bc018f0fd8ac31cff049a036a7821611b02b`.
* `qbind-node` Build ID: `BuildID[sha1]=664f2896c323abdee8bd4cddc4ad8985f14b536d`.
* Run 257 helper SHA-256: `b84afacb93c18956f031b297f135f4c39cda70d52a87bf5f6c7cb65df8dd2366`.
* Run 257 helper Build ID: `BuildID[sha1]=6aeefb87b691b15ce0b1dcfb8edb66731da7c073`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted `68/0`, rejection `153/0`, recovery `24/0`, projection `74/0`, stage_ordering `5/0`, backend_ledger `24/0`, non_mutation `24/0`, reachability `35/0`; total `407` pass, `0` fail.

## Real-binary scenarios

S1 `--help`, S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden selector parse, and S6 invalid selector fail-closed all completed with expected return codes (S5/S6 expected non-zero; the invalid selector fails closed before any mutation). The denylist (56 forbidden patterns) was empty across captured logs.

## Validation

The harness `bash scripts/devnet/run_257_durable_completion_attestation_backend_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 257 closes only the Run 256 release-binary evidence gap. It does not implement or enable a production attestation backend, audit ledger backend, external publication backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, or any persistent backend.