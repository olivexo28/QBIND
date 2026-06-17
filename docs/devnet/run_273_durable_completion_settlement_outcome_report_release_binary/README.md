# Run 273 — Release-binary durable-completion settlement-outcome report / settlement-finality projection evidence

## Scope

Run 273 is the release-binary evidence run for the Run 272 source/test durable-completion **settlement-outcome report / settlement-finality projection boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_report.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_273_durable_completion_settlement_outcome_report_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 272→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_273_durable_completion_settlement_outcome_report_release_binary.sh
```

## Honest limitations

Run 273 release-evidences the modeled settlement-outcome report / settlement-finality projection sink boundary only. The fixture settlement-outcome report sink mutates only the in-memory `DurableCompletionSettlementOutcomeReportLedger`; production settlement-outcome report, MainNet settlement-outcome report, and external settlement-outcome report sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 270 settlement-receipt acknowledgement outcome carried by `input.settlement_receipt_acknowledgement_binding` through `project_settlement_receipt_acknowledgement_outcome_to_outcome_report_request`; only `SettlementOutcomeReportRecorded` authorizes modeled settlement-outcome report / settlement-finality projection state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome publication, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.
