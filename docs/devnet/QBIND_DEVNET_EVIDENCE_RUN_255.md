# QBIND DevNet evidence — Run 255

**Title.** Release-binary governance modeled durable-completion attestation-projection evidence.

**Status.** PASS (release-binary evidence). Run 255 is the release-binary evidence run for the Run 254 source/test governance **modeled durable-completion attestation-projection boundary** in `crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`.

Run 255 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper.rs` that the Run 254 production library symbols are present and exercised in release mode. The helper remains dead code from the production runtime and mutates only the modeled in-memory `ModeledDurableCompletionAttestationLedger` through the DevNet/TestNet fixture attestor.

## What Run 255 states

* Run 255 is release-binary evidence for Run 254.
* No production mutating behavior is enabled.
* The modeled durable-completion attestation-projection boundary is release-evidenced, not production-enabled.
* Run 246 pipeline success is required before any sink intent can exist.
* Run 248 `ConsumeReceiptRecorded` is required before any completion-report intent can exist.
* Run 250 `CompletionReportRecorded` is required before any finalization intent can exist.
* Run 252 `DurableCompletionFinalized` is required before any attestation intent can exist.
* Only `DurableCompletionAttested` authorizes a new modeled durable-completion-attested state.
* `DurableCompletionAttestationDuplicateIdempotent` may only match an already-attested completion and never creates one by itself.
* Duplicate identical attestation is idempotent and creates no second attestation.
* Same attestation id with a different digest fails closed as equivocation.
* Every non-finalizing finalization outcome projects to no attestor invocation and no attestation.
* Failed attestation record, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet paths, rejected replay states, and unsupported actions never attest.
* MainNet peer-driven apply remains refused before pipeline progression, sink invocation, reporter invocation, finalizer invocation, and attestor invocation.
* The attestor does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write sequence files, or write authority markers.
* No real attestation, audit ledger, finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is implemented.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Symbol substitutions

No symbol substitutions were required. Every symbol named by the Run 255 task resolves directly to an implemented Run 254 API name; `pqc_governance_modeled_durable_completion_attestation_projection` is the production module declared in `crates/qbind-node/src/lib.rs`. The helper and harness use the real implemented names and no compatibility shims were added.

## Release artifacts

From `docs/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary/summary.txt`:

* `qbind-node` SHA-256: `6fcb8e72becc81922c9dbc2f0598e8178dcb05f0143515e7237596136328aaa1`.
* `qbind-node` Build ID: `BuildID[sha1]=53bd131bc435f852a37e67eb29b4142b6ae55036`.
* Run 255 helper SHA-256: `d9e9cd709abed17cff13233ca0c485bc22d863ce21abb2417278d9b09bbc6e26`.
* Run 255 helper Build ID: `BuildID[sha1]=21baf9173c1b977133dee6fbdc4fdc9a2c2d4766`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted `56/0`, rejection `125/0`, recovery `20/0`, projection `47/0`, stage_ordering `4/0`, attestation_ledger `18/0`, non_mutation `21/0`, reachability `24/0`; total `315` pass, `0` fail.

## Real-binary scenarios

S1 `--help`, S2 DevNet, S3 TestNet, S4 MainNet, S5 hidden selector parse, and S6 invalid selector fail-closed all completed with expected return codes. The denylist was empty across captured logs.

## Validation

The harness `bash scripts/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary.sh` passed and ran the required release builds plus regression corpus: `run_254`, `run_252`, `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`, `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`, `--lib pqc_authority`, and `--lib`, all `rc=0`.

## Honest limitations

Run 255 closes only the Run 254 release-binary evidence gap. It does not implement or enable production attestation, audit ledger, production mutation, MainNet governance, MainNet peer-driven apply, validator-set rotation, or any persistent backend.