# Run 265 — Release-binary durable-completion consumer settlement-projection evidence

## Scope

Run 265 is the release-binary evidence run for the Run 264 source/test durable-completion **consumer settlement-projection sink boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_consumer_settlement_projection.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_265_durable_completion_consumer_settlement_projection_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 264→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_265_durable_completion_consumer_settlement_projection_release_binary.sh
```

## Honest limitations

Run 265 release-evidences the modeled settlement-projection sink boundary only. The fixture settlement-projection sink mutates only the in-memory `DurableCompletionConsumerSettlementProjectionLedger`; production settlement-projection, MainNet settlement-projection, and external settlement-projection sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 262 consumer outcome carried by `input.consumer_binding` through `project_consumer_outcome_to_settlement_projection_request`; only `SettlementProjectionRecorded` authorizes modeled settlement-projection state. No real settlement, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.
