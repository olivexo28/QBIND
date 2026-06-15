# Run 257 — Release-binary durable-completion attestation backend interface evidence

## Scope

Run 257 is the release-binary evidence run for the Run 256 source/test governance **production durable-completion attestation backend interface boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_attestation_backend.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_257_durable_completion_attestation_backend_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 256/254/252/250/248/.../224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_257_durable_completion_attestation_backend_release_binary.sh
```

## Honest limitations

Run 257 release-evidences the modeled backend interface boundary only. The fixture backend mutates only the in-memory `DurableCompletionAttestationBackendLedger`; production/MainNet/external-publication backends remain reachable but unavailable/fail-closed. No real attestation backend, audit ledger backend, external publication backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, or MainNet peer-driven apply is enabled. The backend does not call Run 070, does not mutate `LivePqcTrustState`, performs no real trust swap, evicts no sessions, writes no sequence or marker, performs no external publication, and writes no real audit ledger. Full C4 and C5 remain OPEN.