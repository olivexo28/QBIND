# QBIND DevNet Evidence — Run 414

Public DevNet **readiness cross-section coverage lint** — a **read-only**, **docs + shell only**
run that extends the Run 412/413 status consistency lints (which compare the *values* of the rows
that exist) to the **coverage** dimension — the *set* of rows that must exist — so the public DevNet
readiness matrix's status-bearing views (**§11 next-run recommendation table** and **§16
consolidated gap matrix**) cannot silently **drop** a milestone row that its **§10 canonical
current-status table** (the source of truth) still carries. It adds **no** feature surface and moves
**no** readiness item.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes **no
C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.

## 1. Exact verdict

`RESULT=POSITIVE` — public-DevNet readiness cross-section coverage lint. The lint is documented,
confirms §10 covers M1–M20 + S1–S7 exactly once, §11 covers every must-have M1–M20 row exactly once
and stays must-have-only, §16 covers all 25 required mapped labels exactly once with every
status-bearing row mapping to a known item, the S6/S7 coverage exceptions are explicit and safely
protected, no Run 413 scoped §16 row was removed, §10/§11/§16 status values still agree, M4/M6/S5/S7
stay Yellow, the launch decision stays NO-GO, C4/C5 stay OPEN, and the three fail-closed self-tests
(§11 row deletion, §16 row deletion, §16 unmapped label) all abort as intended. It commits no
generated/private material and introduces no readiness overclaim.

## 2. Files changed

Created:

- `docs/release/public-devnet/READINESS_CROSS_SECTION_COVERAGE_LINT.md` — the safety-labelled
  cross-section coverage lint guide.
- `scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh` — the read-only,
  fail-closed lint harness (`RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_414.md` (this file).
- `docs/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — added the Run 414 narrative row (no
  status change).
- `docs/whitepaper/contradiction.md` — Run 414 entry.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` and
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — reference the cross-section coverage lint.
- `docs/release/public-devnet/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md` — companion pointer to
  the new coverage lint.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256 / byte size
  refreshed for exactly the two narrowly-edited anchor docs (`ARTIFACT_INDEX.md`,
  `OPERATOR_VERIFICATION_MAP.md`); no entry added/removed, no `status` changed.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B.** Adding a cross-section coverage documentation-consistency lint over already-published
readiness documents is operator/reviewer-facing consistency work — **docs + shell only**, no new
CLI surface, no source change, no runtime change. Route A (deploy to change status) and Route C
(defer) were not taken.

## 4. Cross-section coverage lint guide contents

`READINESS_CROSS_SECTION_COVERAGE_LINT.md` explains why the lint exists, which documents and
sections are compared, why the §10 current-status table remains the source of truth, how §11
coverage is checked for M1–M20, why §11 is must-have-only unless explicitly changed, how the §16
label-to-item coverage is checked, how the §16 coverage exceptions work, how this extends Runs 412
and 413, why row deletion differs from status mutation and must fail closed, why M4 remains Yellow /
launch-blocking, why M6 remains Yellow / Partial, why S5/S7 remain Yellow and M4-gated, why public
DevNet remains NO-GO / NOT launch-ready, why C4/C5 remain OPEN, why TestNet/MainNet remain
untouched, how to update expectations when a future real Route A run legitimately changes a status
or section coverage, why this is not launch evidence, and why this is not C4/C5 closure evidence.

## 5. Compared sections/documents

The readiness matrix (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`): its §10 current-status table
(source of truth), its §11 next-run recommendation table, and its §16 consolidated gap matrix.

## 6. §10 source-of-truth coverage

The harness extracts §10's M/S item codes and fails closed unless every **M1–M20** and every
**S1–S7** row is present **exactly once** (no missing row, no duplicate row).

## 7. §11 must-have coverage

The harness extracts §11's `| M# |` rows and fails closed unless every **M1–M20** row is present
**exactly once**. This closes the "a §11 must-have row was deleted" gap that Run 413's per-value
check could not catch on its own.

## 8. §11 scope boundary

§11 is the "exact next run recommendation for each Red/Yellow must-have" — a **must-have-only**
view. The harness fails closed if a §11 `| S# |` row appears without a documented scope change; the
guide documents the must-have-only boundary.

## 9. §16 label-to-item coverage map

The harness carries an explicit **label-to-item map** (also published in the guide §9), in two
layers: a **required** map of the 25 scoped M/S labels §16 must carry (M1–M20 + S1–S5) and a
**full** map that additionally recognizes every other status-bearing §16 label — TestNet-track
(faucet→T1, RPC gateway→T2, RPC rate limiting→T3, explorer→T4, governance proof status→T5,
validator-set rotation status→T6), MainNet-track (runtime wiring for authority lifecycle→N3,
MainNet custody→N1, MainNet authority rotation/revocation→N2), the DevNet authority-lifecycle
boundary row, and C4 / C5.

## 10. §16 mapped-row coverage

The harness fails closed unless each of the 25 required mapped labels is present in §16 **exactly
once** (no missing, no duplicate mapped row).

## 11. §16 unmapped-label check

Every status-bearing §16 row (any row whose status column carries a 🟢/🟡/🔴/⚪ glyph) must have a
descriptive label present in the full label-to-item map; a status-bearing row with an unknown /
renamed label fails closed.

## 12. §16 coverage exceptions

Exactly two §10 M/S items are not given a distinct §16 mapped row and are recorded as explicit,
stable coverage exceptions with an item code, a reason, and the §10 protection source: **S6**
(alert rules / scrape config — the same shipped observability package already represented by the
§16 "monitoring / alerting" (M14) row; reconciled Green Run 395) and **S7** (seed-node runbook —
live seed operation is gated on the M4 launch blocker already tracked by the §16 "seed nodes /
bootnodes" (M4) row). The harness verifies the exception set equals exactly the §10 items not
covered by a §16 mapped label, that each row has a reason + §10 protection source, and that S7
keeps its Yellow / M4-gated protection.

## 13. Existing Run 413 scoped-row preservation

The harness asserts every one of the 25 Run 413 scoped §16 mapped labels is still present; a silent
removal of any of them fails closed.

## 14. Status consistency preservation

For every represented item the §11 and §16 status glyphs still equal the §10 glyph and match the
frozen truth (M1–M3/M5/M7–M20 Green, M4 Yellow, M6 Yellow, S1–S4/S6 Green, S5/S7 Yellow) — the
Run 413 status protection is preserved alongside the new coverage protection.

## 15. M4 consistency check

**Yellow / launch-blocking** in §10, §11, and §16 (§16 "seed nodes / bootnodes" keeps its **Launch
blocker** posture). No view marks M4 resolved/Green/non-blocking.

## 16. M6 consistency check

**Yellow / Partial / M4-gated** in §10, §11, and §16 (§16 "validator identity" keeps its **M4-gated**
posture). No view marks M6 fully-Green / no-longer-Partial.

## 17. S5/S7 consistency check

S5 is Yellow / M4-gated in the §16 "status page" row and Yellow in §10; S7 is Yellow in §10 and a
documented Yellow / M4-gated §16 coverage exception.

## 18. Public DevNet NO-GO consistency

Neither §11 nor §16 claims public DevNet is launch-ready / GO; the readiness matrix keeps "public
DevNet remains NOT launch-ready" and the launch gate remains **NO-GO / NOT launch-ready**.

## 19. C4/C5 consistency

The §16 gap matrix keeps the C4 and C5 rows at 🔴 / **OPEN**; no §11/§16 text claims a C4/C5
closure; the readiness matrix keeps "C4 and C5 remain OPEN".

## 20. TestNet/MainNet non-claims

Neither §11 nor §16 claims TestNet/MainNet readiness; the readiness matrix keeps N1–N7 Red (`N1, N2,
N3, N4, N7 Red`; `N5 (C4) OPEN / Red`; `N6 (C5) OPEN / Red`); TestNet/MainNet untouched.

## 21. devnet-seeds.live.json non-claim

Every mention of `devnet-seeds.live.json` in §11/§16 is negated or M4-gated / conditional. No line
claims a live `devnet-seeds.live.json` exists or may be created without real M4 evidence.

## 22. Deployment/runtime non-claim

No line in §11/§16 claims a live seed/bootnode/faucet/RPC/explorer/status-service deployment, and no
line claims a validator/epoch/sequence/marker/`LivePqcTrustState` mutation; every mention carries a
negation or an M4/deferred/blocker qualifier on the same line.

## 23. Generated-output behavior

The harness writes only a transient `summary.txt` and extracted-section / self-test scratch files
into a staging directory **outside** the repository tree (runner temp). Nothing generated is
committed; the working-tree snapshot is identical before and after the run.

## 24. Non-claim checks

The normalized non-claim grep over the Run 414-authored docs (guide + this evidence) finds no
launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment /
runtime-mutation claim.

## 25. Security scans

Secret / private-material scan and absolute-path scan over the Run 414 docs are clean; no
keys/certs/KEM/signing/API material, no data dirs, no raw logs/metrics, no private identity, no
absolute path.

## 26. Runtime mutation check

**NONE.** Run 414 is docs + shell only: it opens no port, starts no node, applies no trust bundle,
and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 27. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain OPEN;
MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.

## 28. M4 status

**Yellow / launch-blocking.** No real, externally reachable seed with off-host reachability evidence
exists (Route-C finding, Runs 378/388/391/393); no `devnet-seeds.live.json` is published.

## 29. M6 status

**Yellow / Partial.** Generation/verification + `register-check` are Green-for-scope; live
registration is M4-gated and operator-root reuse/rotation/revocation is C4/C5-deferred.

## 30. S5/S7 status

**Yellow.** S5 (status page) live health view is M4-gated; S7 (seed-node runbook) live seed
operation is M4-gated.

## 31. Public DevNet status

**NOT launch-ready / NO-GO.** At least one must-have (M4) is not Green.

## 32. C4/C5

**C4 OPEN. C5 OPEN.** MainNet authority rotation/revocation remains Red.

## 33. TestNet/MainNet non-claims

No TestNet or MainNet readiness is claimed; N1–N7 remain Red; TestNet/MainNet untouched.

## 34. Tests run

- `bash scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh` →
  `RESULT=POSITIVE`.
- Three built-in fail-closed self-tests confirmed the coverage checks abort on: a deleted §11 M7
  row, a deleted §16 "peer admission policy" (M11) row, and a §16 row renamed to an unmapped label
  — each run against a temporary copy **outside** the repository tree, with the working tree left
  clean.
- Re-ran the Run 413 recommendation/gap-matrix lint, the Run 412 status/blocker lint, the Run 411
  cross-ledger lint, the Run 410 stale-prose lint, and the Run 405 full-tree integrity verifier as
  regressions after refreshing the two anchor entries — all `RESULT=POSITIVE`.
- No Rust source changed → no `cargo test` delta.

## 35. CodeQL

Docs/shell only → CodeQL is not meaningful (no Rust/`build.rs`/`Cargo.toml`/source change).

## 36. Honest limitations

- The lint compares the **committed** text of the readiness matrix; it verifies the *presence and
  uniqueness* of the per-item rows and the label-to-item mapping, not the full natural-language
  meaning of each row.
- §16 rows are keyed by descriptive label, not item code; the harness carries an explicit
  label-to-item map. A future §16 row renamed away from its mapped label is reported as a
  missing/unmapped row (fail-closed), which is the intended safe behavior but requires the map to be
  updated alongside a legitimate rename.
- The coverage exception set (S6, S7) is frozen; a legitimate future change that adds a distinct
  §16 row for S6 or S7, or that widens §11 to should-haves, must update the §10 table, the §11/§16
  rows, this guide, and the harness's coverage assertions in the same change.
- The repository is a squashed/shallow clone, so coverage is verified from the on-disk documents
  rather than by isolating individual historical commits.

## 37. Suggested Run 415

A **cross-package cross-reference lint** that asserts every readiness-matrix `docs/release/...`
artifact path named in §9/§10/§16 actually exists on disk (and vice-versa, that every published
public-DevNet artifact is referenced by the matrix or the ARTIFACT_INDEX), closing the residual gap
that a status row could cite an evidence path that was moved or renamed without detection.
