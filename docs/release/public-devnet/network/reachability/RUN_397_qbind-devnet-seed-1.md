# Run 397 — Reachability Evidence: `qbind-devnet-seed-1` (PREFLIGHT BLOCKER NOTE)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim. **DevNet only.**
>
> **Verdict: NEGATIVE-FOR-EXTERNAL — Route A prerequisites unavailable; stopped
> early at preflight.** Run 397 pursued the **Route A** objective (deploy or
> validate a real externally reachable public DevNet seed under strict KEMTLS
> mutual-auth + PQC static-root, pin the Run 356 genesis, and prove external TCP +
> KEMTLS reachability from an **independent off-host vantage point**). The Run 397
> hard preflight found the mandatory Route A infrastructure prerequisites **absent**
> in this environment, so **no files were changed to claim reachability, no loopback
> Route C probe was re-run, and no live seed list was published.** This is a
> minimal, honest blocker note. **M4 stays Yellow.**

This record documents only the preflight decision. It deliberately does **not**
repeat the loopback / same-host probe that Runs 377/378/388/391/393 already
captured, because Run 397 was scoped to *external* reachability and instructed to
stop early rather than re-prove loopback.

## 1. Run id

`Run 397`.

## 2. Hard-preflight result (Route A prerequisites)

| # | Route A prerequisite | Present? |
|---|----------------------|----------|
| 1 | Durable operator-controlled DevNet seed host | **NO** |
| 2 | Real public IP or DNS name for the seed host | **NO** |
| 3 | P2P port openable inbound from the public internet | **NO** |
| 4 | Durable DevNet seed identity available/generatable | Partially (identity path exists; not provisioned into a live listener) |
| 5 | Strict KEMTLS / static-root material | Path exists; no durable operator material provisioned |
| 6 | Release `qbind-node` binary runnable on the seed host | Buildable locally, but no seed host to run on |
| 7 | Independent off-host vantage outside seed host/NAT/tunnel | **NO** |
| 8 | Vantage able to perform TCP + KEMTLS/static-root checks | **NO** (no independent vantage) |
| 9 | Publish-safe evidence capturable | N/A — no external endpoint to observe |

Prerequisites **1, 2, 3, 7, 8** fail. In this sandboxed CI environment there is no
external ingress path and no independent off-host vantage point; an outbound
connectivity check to a public host also did not complete, confirming there is no
usable public egress-to-ingress path to expose or dial a real endpoint. Per the
task's hard preflight, the run **stops early** and does **not** re-run a sandbox
loopback Route C probe.

## 3. What was NOT done (by design)

- No `qbind-node` P2P listener was booted (no loopback re-proof).
- No externally reachable port was opened; no NAT/firewall/LB rule was configured.
- No durable operator seed identity, ML-KEM leaf secret, or ML-DSA root/signing
  material was generated or committed.
- `docs/release/public-devnet/network/devnet-seeds.live.json` was **not** created.
- The committed candidate `devnet-seeds.live-candidate.json` stays at
  `status: planned` / `last_reachability_evidence: null` (unchanged).
- No readiness status was moved (M4 Yellow, M6 Yellow/Partial, S5/S7 Yellow,
  C4/C5 OPEN).

## 4. Conclusion

- `external_tcp_reachability=false`
- `external_kemtls_reachability=false`
- `live_reachability_claim=false`
- `m4_green_claim=false`
- `c4_c5_closure_claim=false`

**External reachability NOT proven; Route A prerequisites unavailable.** M4 remains
Yellow / launch-blocking. The Route A infrastructure prerequisites a real operator
must satisfy are recorded in
`docs/release/public-devnet/network/reachability/RUN_393_qbind-devnet-seed-1.md`
§15 and `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`;
they are unchanged by Run 397.

## 5. Redaction statement

Only publish-safe values appear here (OK/NO/NOT-PROVEN status lines and public
document references). No secret key, ML-DSA root signing key, KEM secret, mnemonic,
credential, token, raw log, raw metrics dump, data directory, private endpoint,
private hostname, or absolute build path is committed.
