# Run 277 — Release-binary durable-completion external-publication-confirmation boundary evidence

## Scope

Run 277 is the release-binary evidence run for the Run 276 source/test durable-completion settlement-outcome publication consumer / **external-publication-confirmation boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_external_publication_confirmation.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_277_durable_completion_external_publication_confirmation_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 276→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_277_durable_completion_external_publication_confirmation_release_binary.sh
```

## Honest limitations

Run 277 release-evidences the modeled external-publication-confirmation sink boundary only. The fixture external-publication-confirmation sink mutates only the in-memory `DurableCompletionExternalPublicationConfirmationLedger`; production external-publication-confirmation, MainNet external-publication-confirmation, and external external-publication-confirmation sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 274 settlement-outcome publication outcome carried by `input.settlement_outcome_publication_binding` through `project_settlement_outcome_publication_outcome_to_external_publication_confirmation_request`; only `ExternalPublicationConfirmationRecorded` authorizes modeled external-publication-confirmation state. No real settlement, settlement finality, settlement receipt, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report backend, settlement-outcome publication, external publication, external-publication confirmation, audit ledger, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.