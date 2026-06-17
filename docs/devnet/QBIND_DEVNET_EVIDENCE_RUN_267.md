# QBIND DevNet evidence — Run 267

**Title.** Release-binary governance durable-completion settlement-commitment / ledger-finalization boundary evidence.

**Status.** PASS (release-binary evidence). Run 267 is the release-binary evidence run for the Run 266 source/test governance **durable-completion settlement-commitment / ledger-finalization boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_commitment.rs`.

Run 267 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_267_durable_completion_settlement_commitment_release_binary_helper.rs` that the Run 266 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `DurableCompletionSettlementCommitmentLedger` through the DevNet/TestNet fixture settlement-commitment sink.

## What Run 267 states

* Run 267 is release-binary evidence for Run 266.
* No production mutating behavior is enabled.
* The durable-completion settlement-commitment / ledger-finalization boundary is release-evidenced, not production-enabled.
* The release helper exercises the Run 266 production library symbols in release mode.
* The release helper remains dead code from the production runtime.
* The fixture settlement-commitment sink mutates only modeled in-memory `DurableCompletionSettlementCommitmentLedger` state.
* Production settlement-commitment, MainNet settlement-commitment, and external settlement-commitment sinks remain reachable but unavailable/fail-closed.
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
* Only `SettlementCommitmentRecorded` authorizes a new modeled settlement-commitment state.
* Run 264 `SettlementProjectionDuplicateIdempotent` may only match an already-recorded settlement-commitment record and never creates a new settlement-commitment record by itself.
* Every non-recorded settlement-projection outcome produces no settlement-commitment request and no settlement-commitment record.
* Duplicate identical settlement-commitment record is idempotent and creates no second settlement-commitment record.
* Same settlement-commitment record id with a different digest fails closed as equivocation.
* Failed settlement-commitment record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet/external settlement-commitment paths, rejected replay states, and unsupported actions never record.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, attestor invocation, backend invocation, receipt invocation, acknowledgement invocation, consumer invocation, settlement-projection invocation, and settlement-commitment invocation.
* Rejected settlement-commitment paths are non-mutating.
* The settlement-commitment boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, write authority markers, perform external publication, perform a real external-publication confirmation, write a real audit ledger, perform real settlement, or implement real settlement finality.
* No real settlement backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain governance proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/schema/marker/sequence/trust-bundle change, MainNet governance enablement, MainNet peer-driven apply enablement, validator-set rotation, or policy change is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Projection rule

The Run 267 release helper drives projection exclusively from the Run 264 settlement-projection outcome:

* `input.settlement_projection_binding` → `project_settlement_projection_outcome_to_commitment_request`.

It does **not** project from the Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend outcomes directly. Run 264 `SettlementProjectionRecorded` creates a settlement-commitment request; `SettlementProjectionDuplicateIdempotent` is idempotent-only; legacy/no-projection outcomes map to legacy/no-commitment; rejected-before-projection / projection-did-not-record / record-failure / rollback / rollback-failed / ambiguous-window / production / MainNet / external outcomes map to the corresponding no-commitment fail-closed / unavailable outcomes; `MainNetPeerDrivenApplyRefusedNoProjection` → `MainNetPeerDrivenApplyRefusedNoCommitment`; `ValidatorSetRotationUnsupportedNoProjection` → `ValidatorSetRotationUnsupportedNoCommitment`; `PolicyChangeUnsupportedNoProjection` → `PolicyChangeUnsupportedNoCommitment`.

## Symbol substitutions

No symbol substitutions were required. Every type, function, trait, sink implementation, and `Outcome` variant named by the Run 267 task resolves directly to an implemented Run 266 symbol in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_commitment.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names and no compatibility shims were added.

The Run 266 grep-verifiable invariant helpers carry the `durable_completion_settlement_commitment_*` prefix (for example `durable_completion_settlement_commitment_rejection_is_non_mutating`, `durable_completion_settlement_commitment_mainnet_peer_driven_apply_refused_first`). The helper imports and the harness source/helper reachability greps use the actual implemented names. All Run 266 outcome tags, policy/kind/fault/window variants, and the `Fixture`/`Production`/`MainNet`/`External` settlement-commitment sinks are exercised by the helper exactly as implemented. The carried Run 264 settlement-projection binding type is `DurableCompletionSettlementCommitmentSettlementProjectionBinding` and the input field is `settlement_projection_binding`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `13/0`, rejection_fail_closed `41/0`, recovery_crash_window `9/0`, projection `3/0`, stage_ordering `5/0`, settlement_commitment_ledger `3/0`, non_mutation `5/0`, reachability `1/0`; total `80` pass, `0` fail. The release helper drives projection exclusively from `input.settlement_projection_binding` via `project_settlement_projection_outcome_to_commitment_request` over the attached `Run256 backend → Run258 receipt → Run260 acknowledgement → Run262 consumer → Run264 settlement projection → Run266 settlement commitment` chain. The harness additionally proves source/helper reachability for every Run 266 symbol (settlement-commitment types, the `evaluate`/`recover`/`project` functions, the `settlement_commitment_outcome_authorizes_record`/`settlement_commitment_outcome_projects_to_recorded` predicates, the `GovernanceDurableCompletionSettlementCommitmentSink` trait and its `Fixture`/`Production`/`MainNet`/`External` implementations, all `Outcome` variants, and every `durable_completion_settlement_commitment_*` invariant helper) by grepping the production module and the helper source.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes (S2–S5 exit non-zero on the parse/smoke surfaces; S6 fails closed before any mutation with the `invalid governance-execution policy selector` message). Every captured log was asserted silent on settlement-commitment/settlement-finality/settlement/publication/confirmation production-enablement claims. The denylist (63 forbidden patterns) was empty across captured logs and helper output (excluding the help text and helper summary).

## Validation

The harness `bash scripts/devnet/run_267_durable_completion_settlement_commitment_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_266`, `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Security scanning

Secret scanning was run over the changed files and reported no secrets. CodeQL: see the final task report for the honest result; if Rust CodeQL analysis is skipped because the database is too large or the change set is classified as trivial, that is stated explicitly and no CodeQL coverage is overclaimed.

## Honest limitations

Run 267 closes only the Run 266 release-binary evidence gap. It does not implement or enable a production settlement backend, settlement-finality backend, audit-ledger acknowledgement backend, external-publication confirmation backend, external publication backend, production attestation backend, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, policy change, or any persistent backend. Full C4 and C5 remain OPEN.