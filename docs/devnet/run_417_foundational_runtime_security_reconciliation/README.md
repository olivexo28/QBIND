# Run 417 — Foundational Runtime-Security Reconciliation Audit (evidence archive)

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
**audit/evidence only** · **no production Rust behavior changed** · **no live seed published** ·
NOT public-DevNet launch-ready · M4 Yellow · M6 Yellow/Partial · S5 Yellow · S7 Yellow ·
**C4/C5 OPEN** · public DevNet **NO-GO**. **No private key material is committed.**

## What this archive is

This is a publish-safe, source-to-runtime **security reconciliation audit** of QBIND's four
foundational authentication boundaries, performed before any durable public DevNet seed is
provisioned:

1. Transaction authentication and authorization.
2. Consensus proposal / vote / timeout / new-view authentication.
3. Consensus sender identity binding to the authenticated KEMTLS peer.
4. Quorum-certificate validation and production signature-suite enforcement.

It is an **audit**, not a fix. Run 417 changed **no production Rust behavior**, added no
authentication bypass, published no live seed, and moved **no** readiness item Green.

## Overall result

- **Audit completeness:** `RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS`
- **Security verdict:** **`AUDIT-COMPLETE / NEGATIVE-FOR-RUNTIME-SECURITY`**

The deployed `qbind-node` consensus path (`crates/qbind-node/src/binary_consensus_loop.rs`,
driven by `main.rs`) emits **unsigned** proposals and votes with the **toy** suite id `0`,
performs **no** signature/membership/suite verification on inbound proposals and votes,
derives the engine sender from a **self-declared** `proposer_index`/`validator_index` rather
than the authenticated KEMTLS peer, and imports proposal-carried **QCs with empty signer
evidence**. Transaction empty-auth is fail-open in code but is **not reachable** from the
deployed binary today (no tx ingress, empty proposals, `apply_block` unwired).

## Files in this archive

- `README.md` — this file.
- `summary.txt` — machine-readable verdict, canonical Q1–Q7 answers, finding classifications.
- `source_trace.txt` — end-to-end file:line trace for domains A–D against the audited tree.
- `findings_matrix.txt` — labelled findings F1–F8 with the full required column set.
- `commands.txt` — exact commands run, with exit codes.
- `SHA256SUMS.txt` — sha256 of every tracked archive file except itself and `.gitignore`.
- `.gitignore` — backstop excluding any raw/private material from this directory.

## Canonical evidence records

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md` — the canonical Run 417 evidence record.
- `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` — the standing
  reconciliation document.

## Verify

```
cd docs/devnet/run_417_foundational_runtime_security_reconciliation
sha256sum -c SHA256SUMS.txt
scripts/devnet/run_417_foundational_runtime_security_reconciliation_audit.sh   # fail-closed
```

## Relationship to Run 416

Run 416 remains valid historical **external-reachability** evidence (external TCP + KEMTLS
mutual-auth static-root to a temporary, discarded seed identity). Run 417 audits a **different
boundary** — runtime authentication of consensus and transactions — and does **not** weaken or
delete Run 416. Run 416's captured transport provider value `sig_suite_id=100` is a
transport/KEMTLS suite id and is **not** proof that consensus messages or transactions are
signed with ML-DSA-44; deployed consensus uses suite `0`.
