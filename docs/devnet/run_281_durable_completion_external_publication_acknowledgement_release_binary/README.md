# Run 281 — Release-binary durable-completion external-publication-acknowledgement boundary evidence

## Scope

Run 281 is the release-binary evidence run for the Run 280 source/test durable-completion external-publication receipt consumer / **external-publication-acknowledgement boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_acknowledgement.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_281_durable_completion_external_publication_acknowledgement_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 280→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_281_durable_completion_external_publication_acknowledgement_release_binary.sh
```

## Honest limitations

Run 281 release-evidences the modeled external-publication-acknowledgement sink boundary only. The fixture external-publication-acknowledgement sink mutates only the in-memory `DurableCompletionExternalPublicationAcknowledgementLedger`; production external-publication-acknowledgement, MainNet external-publication-acknowledgement, and external external-publication-acknowledgement sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 278 external-publication receipt outcome carried by `input.external_publication_receipt_binding` through `project_external_publication_receipt_outcome_to_external_publication_acknowledgement_request`; only `ExternalPublicationAcknowledgementRecorded` authorizes modeled external-publication-acknowledgement state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, external-publication receipt, external-publication acknowledgement, audit ledger, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.