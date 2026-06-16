# Run 261 — Release-binary durable-completion audit-receipt acknowledgement evidence

## Scope

Run 261 is the release-binary evidence run for the Run 260 source/test durable-completion **audit-receipt acknowledgement boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 260→226 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary.sh
```

## Honest limitations

Run 261 release-evidences the modeled acknowledgement boundary only. The fixture acknowledgement sink mutates only the in-memory `DurableCompletionAuditReceiptAcknowledgementLedger`; production audit-ledger, MainNet audit-ledger, and external-publication-confirmation sinks remain reachable but unavailable/fail-closed. No real audit ledger, external publication, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.