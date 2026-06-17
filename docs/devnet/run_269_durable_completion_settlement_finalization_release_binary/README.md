# Run 269 — Release-binary durable-completion settlement-finalization evidence

## Scope

Run 269 is the release-binary evidence run for the Run 268 source/test durable-completion **settlement-finalization / settlement-receipt boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_finalization.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_269_durable_completion_settlement_finalization_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 268→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_269_durable_completion_settlement_finalization_release_binary.sh
```

## Honest limitations

Run 269 release-evidences the modeled settlement-finalization sink boundary only. The fixture settlement-finalization sink mutates only the in-memory `DurableCompletionSettlementFinalizationLedger`; production settlement-finalization, MainNet settlement-finalization, and external settlement-finalization sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 266 settlement-commitment outcome carried by `input.settlement_commitment_binding` through `project_settlement_commitment_outcome_to_finalization_request`; only `SettlementFinalizationRecorded` authorizes modeled settlement-finalization / settlement-receipt state. No real settlement, settlement finality, settlement receipt, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.