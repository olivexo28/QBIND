# QBIND DevNet evidence — Run 253

**Title.** Release-binary governance modeled durable-completion finalization-projection evidence.

**Status.** PASS (release-binary evidence). Run 253 is the release-binary evidence run for the Run 252 source/test governance **modeled durable-completion finalization-projection boundary** in `crates/qbind-node/src/pqc_governance_modeled_durable_completion_finalization_projection.rs`.

Run 253 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_253_modeled_durable_completion_finalization_projection_release_binary_helper.rs` that the Run 252 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `ModeledDurableCompletionFinalizationLedger` through the DevNet/TestNet fixture finalizer.

## What Run 253 states

* Run 253 is release-binary evidence for Run 252.
* No production mutating behavior is enabled.
* The modeled durable-completion finalization-projection boundary is release-evidenced, not production-enabled.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Only `DurableCompletionFinalized` authorizes a new modeled durable-completion-finalized state.
* `CompletionReportDuplicateIdempotent` may only match an already-finalized completion and never creates one by itself.
* Duplicate identical finalization is idempotent and creates no second finalization.
* Same finalization id with a different digest fails closed as equivocation.
* Every non-recording reporter outcome produces no finalizer invocation and no finalization.
* Failed finalization record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet paths, rejected replay states, and unsupported actions never finalize.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, and finalizer invocation.
* The finalizer does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, or write authority markers.
* No real finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

The Run 253 task named four symbols that differ from the implemented Run 252 API. The helper/harness use the real implemented names and no compatibility shims were added:

1. `GovernanceModeledDurableCompletionFinalization` → `GovernanceModeledDurableCompletionFinalizationRecord`.
2. `evaluate_modeled_durable_completion_finalization` → `evaluate_modeled_durable_completion_finalization_projection`.
3. `finalization_outcome_authorizes_modeled_finalization` → outcome method/function `authorizes_modeled_durable_completion()` / `finalization_outcome_authorizes_modeled_durable_completion`.
4. `finalization_outcome_projects_to_durable_completion_finalized` → outcome method/function `projects_to_durable_completion()` / `finalization_outcome_projects_to_durable_completion`.

## Release artifacts

From `docs/devnet/run_253_modeled_durable_completion_finalization_projection_release_binary/summary.txt`:

* `qbind-node` SHA-256: `03488617ab29cda4fbdd333d5576f3066889b0d68abc32d407a1cca29af17ced`.
* `qbind-node` Build ID: `BuildID[sha1]=b5890ae8beafc3c430b4680704232e567455a640`.
* Run 253 helper SHA-256: `2705d61a4334358f62e5d3d1365024ac3e1159f816b571e6416326ef3a46ca66`.
* Run 253 helper Build ID: `BuildID[sha1]=46f4d3fed4a1f0a6a93ddac8f93c7185e1fbfeab`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted `52/0`, rejection `132/0`, recovery `18/0`, projection `32/0`, stage_ordering `4/0`, finalization_ledger `10/0`, non_mutation `20/0`, reachability `24/0`; total `292` pass, `0` fail.

## Real-binary scenarios

S1 `--help`, S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden selector parse, and S6 invalid selector fail-closed all completed with expected return codes. The 43-pattern denylist was empty across captured logs.

## Validation

The harness `bash scripts/devnet/run_253_modeled_durable_completion_finalization_projection_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Honest limitations

Run 253 closes only the Run 252 release-binary evidence gap. It does not implement or enable production finalization, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, or any persistent backend.
