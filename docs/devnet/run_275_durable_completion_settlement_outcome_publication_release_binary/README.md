# Run 275 — Release-binary durable-completion settlement-outcome publication boundary evidence

## Scope

Run 275 is the release-binary evidence run for the Run 274 source/test durable-completion **settlement-outcome publication boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_outcome_publication.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_275_durable_completion_settlement_outcome_publication_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 274→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_275_durable_completion_settlement_outcome_publication_release_binary.sh
```

## Honest limitations

Run 275 release-evidences the modeled settlement-outcome publication sink boundary only. The fixture settlement-outcome publication sink mutates only the in-memory `DurableCompletionSettlementOutcomePublicationLedger`; production settlement-outcome publication, MainNet settlement-outcome publication, and external settlement-outcome publication sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 272 settlement-outcome report outcome carried by `input.settlement_outcome_report_binding` through `project_settlement_outcome_report_outcome_to_outcome_publication_request`; only `SettlementOutcomePublicationRecorded` authorizes modeled settlement-outcome publication state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.
