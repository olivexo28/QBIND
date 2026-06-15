# Run 255 — Release-binary modeled durable-completion attestation projection evidence

## Scope

Run 255 is the release-binary evidence run for the Run 254 source/test governance **modeled durable-completion attestation-projection boundary** in `crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 254/252/250/248/.../224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary.sh
```

## Honest limitations

Run 255 release-evidences the modeled boundary only. No real attestation backend, audit ledger backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, or MainNet peer-driven apply is enabled. Full C4 and C5 remain OPEN.
