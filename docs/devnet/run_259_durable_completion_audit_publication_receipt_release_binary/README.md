# Run 259 — Release-binary durable-completion audit/publication receipt evidence

## Scope

Run 259 is the release-binary evidence run for the Run 258 source/test durable-completion **audit-ledger / external-publication receipt boundary** in `crates/qbind-node/src/pqc_governance_durable_completion_audit_publication_receipt.rs`.

The harness builds real `target/release/qbind-node` plus the release helper `crates/qbind-node/examples/run_259_durable_completion_audit_publication_receipt_release_binary_helper.rs`, captures provenance, hashes, Build IDs, release-binary surface scenarios S1–S6, source/helper reachability, denylist evidence, helper corpus results, and the Run 258→224 regression corpus.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Generated logs, reachability files, helper tables, test logs, and provenance are regenerated and ignored.

## Reproduce

```bash
bash scripts/devnet/run_259_durable_completion_audit_publication_receipt_release_binary.sh
```

## Honest limitations

Run 259 release-evidences the modeled receipt boundary only. The fixture receipt sink mutates only the in-memory `DurableCompletionAuditPublicationReceiptLedger`; production audit-ledger, MainNet audit-ledger, and external-publication sinks remain reachable but unavailable/fail-closed. No real audit ledger, external publication, production backend, MainNet governance, MainNet peer-driven apply, validator-set rotation, storage/wire/schema change, Run 070 call, or `LivePqcTrustState` mutation is enabled. Full C4 and C5 remain OPEN.