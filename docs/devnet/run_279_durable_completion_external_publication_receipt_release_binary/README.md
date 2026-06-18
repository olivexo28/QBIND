# Run 279 — Release-binary durable-completion external-publication-receipt boundary evidence

## Scope

Run 279 is the release-binary evidence run for the Run 278 source/test durable-completion external-publication confirmation consumer / **external-publication-receipt boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_receipt.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_279_durable_completion_external_publication_receipt_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 278→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_279_durable_completion_external_publication_receipt_release_binary.sh
```

## Honest limitations

Run 279 release-evidences the modeled external-publication-receipt sink boundary only. The fixture external-publication-receipt sink mutates only the in-memory `DurableCompletionExternalPublicationReceiptLedger`; production external-publication-receipt, MainNet external-publication-receipt, and external external-publication-receipt sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 276 external-publication confirmation outcome carried by `input.external_publication_confirmation_binding` through `project_external_publication_confirmation_outcome_to_external_publication_receipt_request`; only `ExternalPublicationReceiptRecorded` authorizes modeled external-publication-receipt state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, external-publication receipt, audit ledger, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.