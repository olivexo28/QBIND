# QBIND DevNet Evidence — Run 396

Public DevNet **readiness-matrix canonicalization / stale-row cleanup** evidence. Run 396 is a
**documentation-consistency reconciliation only**. It makes
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` internally consistent after Runs 356–395 —
every checklist, status table, gap matrix, blocker summary, and next-run recommendation now agrees
with the canonical per-item status — **without changing any readiness semantics or adding any
functionality**.

The §10 current-status table and the §4/§5 checklists were already current and are treated as the
**source of truth**. The older §16 consolidated gap matrix and §17 summary carried legacy statuses
for items already updated by later runs; Run 396 reconciles those stale rows/summaries to match.

**Decision gate:** **Route A** — the source of truth (§10 status table + §4/§5 checklists) is clear,
so Run 396 updates only the stale readiness-matrix rows / summaries / next-run recommendations and
adds a verification harness. No section required a generated consistency summary (Route B) and no
status was unreconcilable from committed evidence (Route C).

Harness: `scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh`
(`RESULT=POSITIVE`, 60 checks, 0 failures).

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA · NOT
public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green · no S7 Green · no TestNet
readiness · no MainNet readiness · **C4/C5 OPEN**. Run 396 starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service, adds no CLI flag,
changes no Rust/`build.rs`/runtime behavior, changes no P2P wire format, weakens no peer admission,
enables no peer-driven apply, and mutates no trust/validator/epoch/sequence/marker state.

## 1. Exact verdict

**PASS / public-DevNet readiness matrix canonicalization POSITIVE.** The readiness criteria document
is internally consistent after Runs 356–395 and introduces no readiness overclaim. **M4 stays
Yellow / launch-blocking**, **M6 stays Yellow / Partial**, **S5 stays Yellow**, **S7 stays Yellow**,
all other tracked must-haves (M1–M3, M5, M7–M20) and should-haves (S1–S4, S6) are Green, public
DevNet remains **NOT launch-ready**, and **C4/C5 remain OPEN**. TestNet/MainNet untouched.

## 2. Files changed

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — Run 396 top note added; §12 launch-blocker
  summary, §16 consolidated gap matrix, and §17 summary reconciled to the canonical per-item status
  (no readiness semantics changed).
- `scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh` — new docs-only
  consistency/non-claim/secret verifier.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_396.md` — this evidence record.
- `docs/devnet/run_396_public_devnet_readiness_matrix_canonicalization/{README.md,summary.txt,.gitignore}`
  — archive (documentation only; generated outputs git-ignored).

## 3. Matrix inconsistency investigation

Before Run 396 the §16 consolidated gap matrix and parts of the §12/§17 summaries still reflected the
early-run baseline while §4/§5/§10/§11 had already been updated by Runs 356–395. The concrete stale
rows in §16 were:

| §16 row (item) | Stale status | Canonical status | Corrected by |
|----------------|--------------|------------------|--------------|
| seed nodes / bootnodes (M4) | 🔴 Red | 🟡 Yellow / launch-blocking | Run 357 (format) + Route-C external Runs 378/388/391/393 |
| validator onboarding (M5) | 🟡 Yellow | 🟢 Green | Run 358 |
| validator key-management guidance (M7) | 🟡 Yellow | 🟢 Green | Run 389 |
| trust-bundle bootstrap (M8) | 🟡 Yellow | 🟢 Green | Run 389 |
| PQC root / signing-key guidance (M9) | 🟡 Yellow | 🟢 Green | Run 389 |
| public P2P port posture (M10) | 🟡 Yellow | 🟢 Green | Run 360 |
| peer admission policy (M11) | 🟡 Yellow | 🟢 Green | Run 360 |
| abuse handling (M12) | 🟡 Yellow | 🟢 Green | Run 371 |
| telemetry / metrics (M13) | 🟡 Yellow | 🟢 Green | Run 379–381 |
| monitoring / alerting (M14) | 🟡 Yellow | 🟢 Green | Run 379–381 |
| public documentation (M17) | 🟡 Yellow | 🟢 Green | Run 358 |
| user-facing disclaimers (M18) | 🟡 Yellow | 🟢 Green | Run 358 |

Rows that were already correct and are preserved unchanged: validator identity (M6) 🟡, status page
(S5) 🟡, and the DevNet-authority-lifecycle / TestNet governance rows (Green-for-scope only). §12
carried an "As of Run 390" scope line and omitted the reconciled should-have statuses; §17 lacked an
unambiguous consolidated current-status statement.

## 4. Canonical status table (after Run 395, reconciled Run 396)

| Item | Status |
|------|--------|
| M1 | 🟢 Green |
| M2 | 🟢 Green |
| M3 | 🟢 Green |
| M4 | 🟡 Yellow / launch-blocking |
| M5 | 🟢 Green |
| M6 | 🟡 Yellow / Partial |
| M7 | 🟢 Green (Green-for-scope) |
| M8 | 🟢 Green (Green-for-scope) |
| M9 | 🟢 Green (Green-for-scope) |
| M10–M20 | 🟢 Green |
| S1–S4 | 🟢 Green |
| S5 | 🟡 Yellow |
| S6 | 🟢 Green |
| S7 | 🟡 Yellow |
| T1–T4, T7, T8 | ⚪ N/A / TestNet-deferred |
| T5, T6 | 🟡 Yellow (TestNet-deferred boundary-only) |
| N1–N4, N7 | 🔴 Red (MainNet-deferred) |
| N5 (C4) | 🔴 OPEN |
| N6 (C5) | 🔴 OPEN |

## 5. Harness checks

`scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh` asserts (60 checks, 0
failures, `RESULT=POSITIVE`):

1. No stale `None shipped` Red row remains for S6; S6 status row is Green.
2. No stale Red row remains for S1/S2/S3/S4/S6.
3. No stale Yellow row remains for M5/M7/M8/M9/M10/M11/M12/M13/M14/M15/M16/M17/M18/M19/M20 in either
   §10 or §16.
4. M4 remains Yellow / launch-blocking everywhere (§10 + §16).
5. M6 remains Yellow / Partial everywhere.
6. S5 remains Yellow everywhere.
7. S7 remains Yellow everywhere.
8. Public DevNet remains NOT launch-ready; no positive launch-ready claim.
9. C4/C5 remain OPEN; no closure claim.
10. No TestNet/MainNet readiness claim.
11. No new faucet/RPC/explorer/live-status-service deployment claim (negations excluded).
12. Changed files contain no secrets / raw material / host absolute paths.

## 6. Tests / checks run

- `bash scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh` → `RESULT=POSITIVE`.
- Markdown grep consistency + non-claim + secret scans are embedded in the harness above.
- **No Rust source / `build.rs` change** in this run, so `cargo test` is not applicable; recorded
  honestly as no-Rust-delta.

## 7. CodeQL

Docs + shell only; no Rust or `build.rs` change. CodeQL is **not meaningful / trivial** for this
change set (no compiled code paths added or modified). This is recorded honestly — not a
skipped/timed-out clean claim.

## 8. Honest limitations

- Run 396 changes documentation only; it neither proves nor advances any underlying readiness item.
  M4/M6 remain the launch blockers and S5/S7 remain M4-gated Yellow.
- The verifier is grep-based over the canonical document; it enforces the specific stale-row
  invariants above rather than a full semantic parse of every historical run note. Historical run
  notes are intentionally preserved verbatim.

## 9. Suggested Run 397

Advance a genuine blocker rather than documentation: pursue real external seed reachability for **M4**
(deploy a live, externally reachable seed/bootnode from an independent off-host vantage point and
capture off-host TCP + KEMTLS reachability evidence), which in turn unblocks the M4-gated **M6** live
registration path and **S5/S7** live-status/live-seed operations.
