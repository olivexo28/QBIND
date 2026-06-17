# Run 271 — Release-binary durable-completion settlement-receipt acknowledgement / settlement-finality projection evidence

## Scope

Run 271 is the release-binary evidence run for the Run 270 source/test durable-completion **settlement-receipt acknowledgement / settlement-finality projection boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_receipt_acknowledgement.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_271_durable_completion_settlement_receipt_acknowledgement_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 270→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_271_durable_completion_settlement_receipt_acknowledgement_release_binary.sh
```

## Honest limitations

Run 271 release-evidences the modeled settlement-receipt acknowledgement / settlement-finality projection sink boundary only. The fixture settlement-receipt acknowledgement sink mutates only the in-memory `DurableCompletionSettlementReceiptAcknowledgementLedger`; production settlement-receipt acknowledgement, MainNet settlement-receipt acknowledgement, and external settlement-receipt acknowledgement sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 268 settlement-finalization outcome carried by `input.settlement_finalization_binding` through `project_settlement_finalization_outcome_to_receipt_acknowledgement_request`; only `SettlementReceiptAcknowledgementRecorded` authorizes modeled settlement-receipt acknowledgement / settlement-finality projection state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.