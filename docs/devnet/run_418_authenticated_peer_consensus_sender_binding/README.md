# Run 418 — Authenticated KEMTLS peer → consensus sender binding (F6) — evidence archive

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
**code/test remediation of F6 only** · **no release-binary evidence** · no live seed published ·
NOT public-DevNet launch-ready · M4 Yellow · M6 Yellow/Partial · S5 Yellow · S7 Yellow ·
**RS1 OPEN / launch-blocking** · **C4/C5 OPEN** · public DevNet **NO-GO**.
**No private key material is committed.**

## What this archive is

This is a publish-safe evidence archive for the Run 418 **production-code security remediation**
of finding **F6** (authenticated KEMTLS peer → consensus sender binding) identified by the Run 417
foundational runtime-security audit.

F6 binds the authenticated KEMTLS peer identity — a full 32-byte certificate-derived `NodeId`
plus the peer's validator identity — to the sender a consensus message claims to be from, and
fails closed on any missing, unknown, ambiguous, or mismatched identity. F6 is
transport-session-to-consensus-sender binding and accountability **only**: it does not make
cryptographic proposal/vote/timeout/new-view/QC signatures meaningful and does not close
F3/F4/F5/F7/F8, RS1, C4, or C5.

## Overall result

- **Result:** `POSITIVE-FOR-F6-CODE-TEST-REMEDIATION`.
- **Security posture (unchanged):** `RS1-OPEN / PUBLIC-DEVNET-NO-GO`.
- **Evidence classification:** code + test remediation on the in-crate consensus-ingress path;
  **no release-binary evidence** (no live multi-node release-binary capture exists).

A bare `PASS` is intentionally never emitted so it cannot be misread as public-DevNet launch
readiness or as closure of any other finding.

## Files in this archive

- `README.md` — this file.
- `summary.txt` — machine-readable result, scope, acceptance-coverage map, preserved posture.
- `source_trace.txt` — file:line trace of the F6 remediation across the audited crates.
- `commands.txt` — exact commands run, with exit codes.
- `test_results.txt` — dedicated Run 418 unit + integration test results.
- `SHA256SUMS.txt` — sha256 of every tracked archive file except itself and `.gitignore`.
- `.gitignore` — backstop excluding any raw/private material from this directory.

## Canonical records

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_418.md` — the canonical Run 418 evidence record.
- `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` — the standing
  reconciliation document.
- `scripts/devnet/run_418_authenticated_peer_consensus_sender_binding.sh` — the fail-closed
  Run 418 harness with negative self-tests.

## Preserved current-state posture

F1–F5 and F7–F8 remain unresolved. RS1 remains OPEN / launch-blocking. M4 Yellow, M6
Yellow/Partial, S5/S7 Yellow, C4/C5 OPEN. Public DevNet is NO-GO. No `devnet-seeds.live.json`
exists; the candidate remains `planned` with null reachability evidence. TestNet and MainNet are
untouched.
