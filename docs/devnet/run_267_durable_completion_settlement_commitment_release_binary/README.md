# Run 267 — Release-binary durable-completion settlement-commitment evidence

## Scope

Run 267 is the release-binary evidence run for the Run 266 source/test durable-completion **settlement-commitment / ledger-finalization boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_settlement_commitment.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_267_durable_completion_settlement_commitment_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 266→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_267_durable_completion_settlement_commitment_release_binary.sh
```

## Honest limitations

Run 267 release-evidences the modeled settlement-commitment sink boundary only. The fixture settlement-commitment sink mutates only the in-memory `DurableCompletionSettlementCommitmentLedger`; production settlement-commitment, MainNet settlement-commitment, and external settlement-commitment sinks remain reachable but unavailable/fail-closed. Projection is driven exclusively from the Run 264 settlement-projection outcome carried by `input.settlement_projection_binding` through `project_settlement_projection_outcome_to_commitment_request`; only `SettlementCommitmentRecorded` authorizes modeled settlement-commitment state. No real settlement, settlement finality, audit ledger, external publication, external-publication confirmation, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.
