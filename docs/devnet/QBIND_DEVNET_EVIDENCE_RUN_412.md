# QBIND DevNet Evidence — Run 412

Public DevNet **readiness table/checklist/blocker consistency lint** — a **read-only**, **docs
+ shell only** run that adds a lightweight **per-milestone** consistency lint verifying that the
public DevNet readiness matrix's §10 canonical current-status table agrees with its §4
must-have checklist (M1–M20) and §5 should-have checklist (S1–S7), and that the blocker
register (`docs/release/public-devnet/BLOCKER_REGISTER.md`) and launch go/no-go gate
(`docs/release/public-devnet/LAUNCH_GO_NO_GO.md`) agree with the frozen M4/M6/S5/S7 posture. It
extends consistency protection **beyond** the Run 411 cross-ledger run-narrative lint —
from cross-ledger run narratives to per-milestone status rows — **without** adding a feature
surface and **without** moving any readiness item.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes
**no C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.

## 1. Exact verdict

`RESULT=POSITIVE` — public-DevNet readiness table/checklist/blocker consistency lint. The
lint is documented, cross-checks the readiness matrix's §10 current-status table against its
§4/§5 checklists for every M1–M20 and S1–S7 item, confirms M4/M6/S5/S7 stay Yellow across the
matrix / blocker register / launch gate, confirms the launch decision stays NO-GO and C4/C5
stay OPEN, commits no generated/private material, and introduces no readiness overclaim.

## 2. Objective

Turn the implicit expectation that a milestone's status is stated the same way in every place
into an automated, fail-closed **per-milestone** check. The lint rejects: the §10 status table
disagreeing with the §4 must-have checklist on any M1–M20 status; the §10 table disagreeing
with the §5 should-have checklist on any S1–S7 status; M4 being anything other than
Yellow / launch-blocking, M6 anything other than Yellow / Partial, or S5/S7 anything other
than Yellow anywhere they appear; the blocker register omitting or resolving M4/M6/S5/S7; the
launch gate not staying NO-GO, not listing M4+M6 as must-have blockers, or not keeping S5/S7
M4-gated; and any table/checklist/blocker text claiming a live seed/bootnode/faucet/RPC/
explorer/status-service deployment, a live `devnet-seeds.live.json`, a C4/C5 closure,
TestNet/MainNet readiness, or a runtime mutation.

## 3. Decision gate route

**Route B.** Adding a per-milestone documentation-consistency lint over already-published
readiness documents is operator/reviewer-facing consistency work — **docs + shell only**, no
new CLI surface, no source change, no runtime change. Route A (deploy to change status) and
Route C (defer) were not taken.

## 4. What changed

Created:

- `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` — the safety-labelled
  status/blocker-lint guide.
- `scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh` — the read-only,
  fail-closed per-milestone lint harness (`RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_412.md` (this file).
- `docs/devnet/run_412_public_devnet_readiness_status_blocker_lint/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — added the Run 412 narrative row
  (no status change), and **reconciled the stale §4 M12 must-have checklist entry** (which
  still read "Yellow / Partial (Run 362)") to **Green (Run 371, Green-for-scope)** to match the
  §10 status table, §11 next-run recommendation, and §12 blocker summary that already record
  M12 Green — a documentation-consistency reconciliation of an already-historically-recorded
  status, **not** a new Green move.
- `docs/whitepaper/contradiction.md` — Run 412 entry.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` and
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — reference the status/blocker lint.
- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — companion pointer to
  the new per-milestone lint.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256 / byte size
  refreshed for exactly the two narrowly-edited anchor docs (`ARTIFACT_INDEX.md`,
  `OPERATOR_VERIFICATION_MAP.md`); no entry added/removed, no `status` changed.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 5. Status/blocker-lint guide contents

`READINESS_STATUS_BLOCKER_LINT.md` explains why the lint exists, which documents are compared,
why the §10 current-status table is the source of truth, how the must-have and should-have
checklists are checked against it, how the blocker register is checked against M4/M6/S5/S7,
why M4 remains Yellow / launch-blocking, why M6 remains Yellow / Partial, why S5/S7 remain
Yellow, why public DevNet remains NO-GO / NOT launch-ready, why C4/C5 remain OPEN, why
TestNet/MainNet remain untouched, how to update expectations when a future real Route A run
legitimately changes a status, why this is not launch evidence, and why this is not C4/C5
closure evidence.

## 6. Compared documents

The readiness matrix (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`: §10 current-status table,
§4 must-have checklist, §5 should-have checklist), the blocker register
(`BLOCKER_REGISTER.md`), and the launch go/no-go gate (`LAUNCH_GO_NO_GO.md`).

## 7. Current-status table coverage

The §10 table carries a status row for every must-have **M1–M20** and every should-have
**S1–S7**; the harness fails closed if any row is missing.

## 8. Must-have checklist consistency

For every **M1–M20**, the §10 table glyph (🟢/🟡/🔴) and the §4 must-have checklist's leading
bold status word agree, and both match the frozen truth (M1–M3/M5/M7–M20 Green, M4 Yellow, M6
Yellow, M12 Green-for-scope). The one prior disagreement — a stale §4 M12 entry at Yellow —
was reconciled to Green (Run 371) in this run.

## 9. Should-have checklist consistency

For every **S1–S7**, the §10 table glyph and the §5 should-have checklist's leading bold
status word agree, and both match the frozen truth (S1–S4/S6 Green, S5/S7 Yellow).

## 10. M4 consistency check

M4 is Yellow (`M4 seed/bootnodes | 🟡`) in the §10 table, "**Yellow**" in the §4 checklist,
"launch-blocking" in the matrix prose, and "**Yellow / launch-blocking**" in the blocker
register and launch gate — consistent everywhere.

## 11. M6 consistency check

M6 is Yellow (`M6 validator identity | 🟡`) in the §10 table, "**Yellow / Partial**" in the §4
checklist, and "Yellow / Partial" in the blocker register and launch gate — consistent
everywhere.

## 12. S5/S7 consistency check

S5 (`S5 status page | 🟡`) and S7 (`S7 seed-node runbook | 🟡`) are Yellow in the §10 table,
"**Yellow**" in the §5 checklist, and Yellow / M4-gated in the blocker register and launch
gate — consistent everywhere.

## 13. Blocker register consistency

The blocker register carries a row for each of M4/M6/S5/S7 with a Yellow (open/unresolved)
status column; the harness fails closed if any is marked resolved/closed/Green/non-blocking/
launch-complete, and requires the "no launch until every must-have is Green" launch rule to
remain intact.

## 14. Launch go/no-go consistency

The launch gate remains **NO-GO / NOT launch-ready**, lists **M4** (launch-blocking) and
**M6** (Yellow / Partial) as must-have blockers, and keeps **S5/S7** M4-gated / Yellow.

## 15. C4/C5 consistency

"C4 and C5 remain OPEN" in the readiness matrix, C4/C5 OPEN in the blocker register, and "C4
remains OPEN" + "C5 remains OPEN" in the launch gate — consistent and OPEN.

## 16. TestNet/MainNet non-claims

N1–N7 Red in the readiness matrix (`N1, N2, N3, N4, N7 Red`; `N5 (C4) OPEN / Red`; `N6 (C5)
OPEN / Red`) and the blocker register (`N1–N7 remain Red`); TestNet/MainNet untouched in the
launch gate.

## 17. devnet-seeds.live.json non-claim

Every mention of `devnet-seeds.live.json` in the table/checklists/blocker register is negated
or M4-gated / conditional (e.g. "no `devnet-seeds.live.json` published", "promote to a
schema-valid `devnet-seeds.live.json`" as an M4 Route-A prerequisite). No line claims a live
`devnet-seeds.live.json` exists or may be created without real M4 evidence.

## 18. Deployment / runtime non-claim

No line in the compared docs claims a live seed/bootnode/faucet/RPC/explorer/status-service
deployment, and no line claims a validator/epoch/sequence/marker/`LivePqcTrustState` mutation;
every mention carries a negation or an M4/deferred qualifier on the same line.

## 19. Generated-output behavior

The harness writes only a transient `summary.txt` into a staging directory **outside** the
repository tree (runner temp). Nothing generated is committed; the working-tree snapshot is
identical before and after the run.

## 20. Non-claim checks

The normalized non-claim grep over the Run 412-authored docs (guide + this evidence) finds no
launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment /
runtime-mutation claim.

## 21. Security scans

Secret / private-material scan and absolute-path scan over the Run 412 docs are clean; no
keys/certs/KEM/signing/API material, no data dirs, no raw logs/metrics, no private identity,
no absolute path.

## 22. Runtime mutation check

**NONE.** Run 412 is docs + shell only: it opens no port, starts no node, applies no trust
bundle, and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 23. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain
OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched. The M12
§4-checklist reconciliation records an already-existing Green (Run 371); it does not move M12.

## 24. Tests / checks

- `bash scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh` →
  `RESULT=POSITIVE`.
- Two targeted negative tests confirmed fail-closed behavior (a §10-table/§5-checklist S6
  disagreement and a "Resolved" M4 blocker status both abort the harness), then reverted.
- Re-ran the Run 411 cross-ledger lint, the Run 410 stale-prose lint, and the Run 405
  full-tree integrity verifier as a regression after refreshing the two anchor entries — all
  `RESULT=POSITIVE`.
- No Rust source changed → no `cargo test` delta; CodeQL is docs/shell-only (not meaningful).

## 25. Honest limitations

- The lint compares the **committed** text of the readiness documents; it does not model
  their full natural-language meaning, only the per-item status glyph / bold word and the
  fixed M4/M6/S5/S7/NO-GO/C4-C5 phrases.
- The lint encodes the **current** frozen status vector (M1–M20 / S1–S7 as recorded; M4/M6/S5/
  S7 Yellow; NO-GO; C4/C5 OPEN; N1–N7 Red). A legitimate future readiness change must update
  the §10 table, the §4/§5 checklist, the blocker register, the launch gate, this guide, and
  the harness's posture assertions in the same change, as documented in the guide.
- The repository is a squashed/shallow clone, so status presence is verified from the on-disk
  documents rather than by isolating individual historical commits.