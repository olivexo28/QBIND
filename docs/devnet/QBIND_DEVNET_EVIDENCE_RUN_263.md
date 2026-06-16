# QBIND DevNet evidence — Run 263

**Title.** Release-binary governance durable-completion acknowledgement consumer / post-acknowledgement settlement interface evidence.

**Status.** PASS (release-binary evidence). Run 263 is the release-binary evidence run for the Run 262 source/test governance **durable-completion acknowledgement consumer / post-acknowledgement settlement interface boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_acknowledgement_consumer.rs`.

Run 263 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_263_durable_completion_acknowledgement_consumer_release_binary_helper.rs` that the Run 262 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionAcknowledgementConsumerLedger` through the DevNet/TestNet fixture consumer.

## What Run 263 states

* Run 263 is release-binary evidence for Run 262.
* No production mutating behavior is enabled.
* The durable-completion acknowledgement consumer / post-acknowledgement settlement boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 262 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture consumer mutates only modeled in-memory `DurableCompletionAcknowledgementConsumerLedger` state.
* Production settlement, MainNet settlement, and external settlement consumers remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication receipt request can exist.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement / confirmation request can exist.
* Run 260 `AcknowledgementRecorded` is required before any consumer / settlement request can exist.
* Only `AcknowledgementConsumed` authorizes a new modeled consumer state.
* Run 260 `AcknowledgementDuplicateIdempotent` may only match an already-recorded consumer record and never creates a new consumer record by itself.
* Every non-recorded acknowledgement outcome produces no consumer request and no consumer record.
* Duplicate identical consumer record is idempotent and creates no second consumer record.
* Same consumer record id with a different digest fails closed as equivocation.
* Failed consumer record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external settlement paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, and consumer invocation.
* Rejected consumer paths are non-mutating.
* The consumer boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, or perform real settlement.
* No real settlement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, audit-publication receipt backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, consumer implementation, and `Outcome` variant named by the Run 263 task resolves directly to an implemented Run 262 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_acknowledgement_consumer.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

The Run 262 grep-verifiable invariant helpers carry the `durable_completion_ack_consumer_*` prefix (for example `durable_completion_ack_consumer_rejection_is_non_mutating`, `durable_completion_ack_consumer_mainnet_peer_driven_apply_refused_first`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 262 outcome tags, policy/kind/fault/window variants, and consumer implementations are exercised by the helper exactly as implemented.

## Release artifacts

From `docs/devnet/run_263_durable_completion_acknowledgement_consumer_release_binary/summary.txt` (regenerated per run; absolute-path/ephemeral artifacts are git-ignored):

* `qbind-node` SHA-256: `452b7fe32de644ce125b7962682ebeaefd71010571aa07c926724e670216647e`.
* `qbind-node` Build ID: `BuildID[sha1]=7effe927394cfb8bfae3a09cb8ddeb4ae5c707d8`.
* Run 263 helper SHA-256: `81f5038fc2ab8932593912060b260c7682a9dcd8eb54d126ea599d5b1bb6d3d8`.
* Run 263 helper Build ID: `BuildID[sha1]=21bb1742edb46ff1f6c38377818ce11ab7422524`.

## Helper corpus results

<!-- Corpus table counts from the helper run. -->
Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `34/0`, recovery_crash_window `9/0`, projection `1/0`, stage_ordering `5/0`, consumer_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `71` pass, `0` fail. The release helper drives projection exclusively from `input.acknowledgement_binding` via `project_acknowledgement_outcome_to_consumer_request` over the attached `Run256 backend → Run258 receipt → Run260 acknowledgement → Run262 consumer` chain. The harness additionally proves source/helper reachability for every Run 262 symbol (consumer types, the `evaluate`/`recover`/`project` functions, the `GovernanceDurableCompletionAcknowledgementConsumer` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_ack_consumer_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2–S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on consumer/settlement/publication/confirmation production-enablement claims. The denylist (56 forbidden patterns) was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_263_durable_completion_acknowledgement_consumer_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large or the change set is classified as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 263 closes only the Run 262 release-binary evidence gap. It does not implement or enable a production settlement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, audit-publication receipt backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.
