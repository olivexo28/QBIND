# Run 263 — Release-binary durable-completion acknowledgement consumer evidence

## Scope

Run 263 is the release-binary evidence run for the Run 262 source/test durable-completion **acknowledgement consumer / post-acknowledgement settlement interface boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_acknowledgement_consumer.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_263_durable_completion_acknowledgement_consumer_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 262→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_263_durable_completion_acknowledgement_consumer_release_binary.sh
```

## Honest limitations

Run 263 release-evidences the modeled acknowledgement consumer boundary only. The fixture consumer mutates only the in-memory `DurableCompletionAcknowledgementConsumerLedger`; production settlement, MainNet settlement, and external settlement consumers remain reachable but unavailable/fail-closed. No real settlement, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.
