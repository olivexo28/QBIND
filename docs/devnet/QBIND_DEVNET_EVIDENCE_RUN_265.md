# QBIND DevNet evidence — Run 265

**Title.** Release-binary governance durable-completion consumer settlement-projection sink boundary evidence.

**Status.** PASS (release-binary evidence). Run 265 is the release-binary evidence run for the Run 264 source/test governance **durable-completion consumer settlement-projection sink boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_consumer_settlement_projection.rs`.

Run 265 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_265_durable_completion_consumer_settlement_projection_release_binary_helper.rs` that the Run 264 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionConsumerSettlementProjectionLedger` through the DevNet/TestNet fixture settlement-projection sink.

## What Run 265 states

* Run 265 is release-binary evidence for Run 264.
* No production mutating behavior is enabled.
* The durable-completion consumer settlement-projection sink boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 264 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture settlement-projection sink mutates only modeled in-memory `DurableCompletionConsumerSettlementProjectionLedger` state.
* Production settlement-projection, MainNet settlement-projection, and external settlement-projection sinks remain reachable but unavailable/fail-closed.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Run 254 `DurableCompletionAttested` is required before any backend request can exist.
* Run 256 `BackendSubmissionRecorded` is required before any audit/publication receipt request can exist.
* Run 258 `AuditReceiptRecorded` is required before any acknowledgement request can exist.
* Run 260 `AcknowledgementRecorded` is required before any acknowledgement-consumer request can exist.
* Run 262 `AcknowledgementConsumed` is required before any settlement-projection request can exist.
* Only `SettlementProjectionRecorded` authorizes a new modeled settlement-projection state.
* Run 262 `AcknowledgementConsumerDuplicateIdempotent` may only match an already-recorded settlement-projection record and never creates a new settlement-projection record by itself.
* Every non-recorded consumer outcome produces no settlement-projection request and no settlement-projection record.
* Duplicate identical settlement-projection record is idempotent and creates no second settlement-projection record.
* Same settlement-projection record id with a different digest fails closed as equivocation.
* Failed settlement-projection record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external settlement-projection paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, and settlement-projection invocation.
* Rejected settlement-projection paths are non-mutating.
* The settlement-projection boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, or perform real settlement.
* No real settlement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 265 release helper drives projection exclusively from the Run 262 consumer outcome:

* `input.consumer_binding` → `project_consumer_outcome_to_settlement_projection_request`.

It does **not** project from the Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 262 `AcknowledgementConsumed` creates a settlement-projection request; `AcknowledgementConsumerDuplicateIdempotent` is idempotent-only; legacy/no-consumer outcomes map to legacy/no-projection; rejected-before-consumer / consumer-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-projection fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoConsumer` → `MainNetPeerDrivenApplyRefusedNoProjection`; `ValidatorSetRotationUnsupportedNoConsumer` → `ValidatorSetRotationUnsupportedNoProjection`; `PolicyChangeUnsupportedNoConsumer` → `PolicyChangeUnsupportedNoProjection`.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 265 task resolves directly to an implemented Run 264 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_consumer_settlement_projection.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

The Run 264 grep-verifiable invariant helpers carry the `durable_completion_settlement_projection_*` prefix (for example `durable_completion_settlement_projection_rejection_is_non_mutating`, `durable_completion_settlement_projection_mainnet_peer_driven_apply_refused_first`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 264 outcome tags, policy/kind/fault/window variants, and the `Fixture`/`Production`/`MainNet`/`External` settlement-projection sinks are exercised by the helper exactly as implemented.

## Release artifacts

From `docs/devnet/run_265_durable_completion_consumer_settlement_projection_release_binary/summary.txt` (regenerated per run; absolute-path/ephemeral artifacts are git-ignored):

* `qbind-node` SHA-256: `9713a57b74edd4ab98809f883d10a6596cb817c0cb3c8bb804a4953dbeb4f3a1`.
* Run 265 helper SHA-256: `8476610c40aadb0c93d9663c3854ee378c04986fc05e58d915e7a7158e2c1f55`.
* Build IDs and per-run hashes are captured in the regenerated `provenance.txt` and `summary.txt` (git-ignored because they carry absolute paths).

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, settlement_projection_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.consumer_binding` via `project_consumer_outcome_to_settlement_projection_request` over the attached `Run256 backend → Run258 receipt → Run260 acknowledgement → Run262 consumer → Run264 settlement projection` chain. The harness additionally proves source/helper reachability for every Run 264 symbol (settlement-projection types, the `evaluate`/`recover`/`project` functions, the `settlement_projection_outcome_authorizes_record`/`settlement_projection_outcome_projects_to_recorded` predicates, the `GovernanceDurableCompletionConsumerSettlementProjectionSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_settlement_projection_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2–S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on settlement-projection/settlement/publication/confirmation production-enablement claims. The denylist (58 forbidden patterns) was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_265_durable_completion_consumer_settlement_projection_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large or the change set is classified as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 265 closes only the Run 264 release-binary evidence gap. It does not implement or enable a production settlement backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.