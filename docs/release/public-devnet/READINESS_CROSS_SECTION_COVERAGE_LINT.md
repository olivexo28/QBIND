# QBIND Public DevNet — Readiness Cross-Section Coverage Lint (Run 414)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **cross-section coverage lint** that keeps the QBIND public DevNet
readiness matrix's status-bearing views — its **§11 next-run recommendation table** and its **§16
consolidated gap matrix** — from silently **dropping** a milestone row that the **§10
current-status table** (the canonical per-item status ledger / source of truth) still carries.

It is a **read-only** verifier: it reads the readiness matrix and **fails closed** if §10 omits or
duplicates any M/S row, if §11 omits or duplicates any must-have M row (or gains an S row without a
documented scope change), if §16 omits any item required by its explicit label-to-item coverage
map, if a §16 status-bearing row's descriptive label no longer maps to a known readiness item, if
an existing Run 413 scoped §16 row is removed, or if any coverage exception is malformed or is used
to hide the frozen M4/M6/S5/S7 / NO-GO / C4-C5-OPEN posture.

It is **docs + shell only**: running the lint deploys nothing, starts no node, opens no port, adds
no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Compared documents:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical readiness matrix.
  Its **§10 current-status table** is the **source of truth**; its **§11 next-run recommendation
  table** (M1–M20) and its **§16 consolidated gap matrix** (per-item rows) are checked for
  **coverage** against it.

Companion files:

- `docs/release/public-devnet/READINESS_ARTIFACT_PATH_REFERENCE_LINT.md` — the Run 415
  artifact **path / reference** consistency lint. Run 414 protects which status-bearing rows must
  exist; Run 415 protects that the file paths those rows and the artifact index name actually
  resolve on disk, and that every published public-DevNet artifact is discoverable.
- `docs/release/public-devnet/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md` — the Run 413
  recommendation/gap-matrix **status** consistency lint (checks the §11/§16 status *glyphs* against
  §10). This Run 414 lint is its **coverage** companion: Run 413 protects the *values* of the rows
  that exist; Run 414 protects the *set of rows* that must exist, so a status-bearing row cannot be
  **removed** (rather than mutated) without detection.
- `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` — the Run 412 per-**milestone**
  status/blocker lint (§10 table vs §4/§5 checklists + blocker register + launch gate).
- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — the Run 411
  cross-**ledger** run-narrative lint.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the M4/M6/S5/S7 blocker register.
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the launch decision gate (**NO-GO**).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — the per-run protocol contradiction ledger.
- `scripts/devnet/run_414_public_devnet_readiness_cross_section_coverage_lint.sh` — the Run 414
  harness / lint.

## 1. Why this lint exists

Run 412 keeps the §10 status table in step with the §4/§5 checklists, the blocker register, and the
launch gate. Run 413 keeps the **status glyph** in §11 and §16 equal to the §10 glyph for every
row those views **contain**. But both Run 412 and Run 413 only compare rows that are **present**:
if a future edit **deleted** the §11 M4 recommendation row, or dropped the §16 "seed nodes /
bootnodes" (M4) gap row entirely, the per-value checks would have nothing to compare and could pass
while a launch-blocking item silently vanished from a status-bearing view. Row **deletion** is a
different failure mode from status **mutation**, and it must also fail closed. Run 414 adds a
lightweight **coverage** lint so the *set* of status-bearing rows cannot shrink below what §10
requires without either updating §10 too or recording an explicit, linted coverage exception.

## 2. Which documents and sections are compared

One document, three sections:

1. the **§10 current-status table** — the canonical per-item status ledger (**source of truth**),
   which must carry every **M1–M20** and **S1–S7** row exactly once;
2. the **§11 next-run recommendation table** — the **must-have** recommendation view, which must
   carry every **M1–M20** row exactly once; and
3. the **§16 consolidated gap matrix** — one row per gap item, keyed by a **descriptive label**,
   whose label-to-item coverage is checked against §10 by an explicit map.

## 3. Why the §10 current-status table remains the source of truth

The §10 "Current status per item" table carries exactly one status glyph (🟢 Green · 🟡 Yellow ·
🔴 Red · ⚪ N/A) and a one-line basis for **every** M1–M20 and S1–S7 item, and the launch gate and
blocker register cite it as "source of truth for item status". §11 and §16 are **derived** views.
Coverage is therefore defined **relative to §10**: every M/S item §10 records must be represented
in §11 (must-haves) and in §16 (by mapped label or by explicit exception). When a view is missing a
row §10 still carries, the **view** is what is wrong, and the lint fails closed.

## 4. How §11 coverage is checked for M1–M20

The §11 table is keyed by item code (`| M4 | 🟡 | … |`). The lint asserts §11 contains **each of
M1–M20 exactly once** — no missing must-have row and no duplicate must-have row. This closes the
"a §11 M-row was deleted" gap that the Run 413 per-value check could not catch on its own.

## 5. Why §11 is must-have-only unless explicitly changed

§11 is, by title, the "**exact next run recommendation for each Red/Yellow must-have**" — a
**must-have (M1–M20)** view. It is **not** required to carry S1–S7 rows. The lint enforces this
boundary: it fails closed if a §11 `| S# |` row appears **without** a documented scope change (a
matching narrative note that §11 was intentionally widened to should-haves). This prevents a
should-have from being quietly smuggled into (or, conversely, an unexpected S-row from masking a
missing M-row in) the must-have recommendation view. If a future run legitimately widens §11's
scope, it must say so in the matrix and update this guide and the harness in the same change.

## 6. How §16 label-to-item coverage is checked

The §16 gap matrix is keyed by a **descriptive label** (`| seed nodes / bootnodes | DevNet |
network | 🟡 | … |`), not by item code. The harness carries an explicit **label-to-item map** (also
reproduced in §9 below). It has two layers:

- a **required** map of the 25 scoped M/S labels that §16 must carry — M1–M20 plus S1–S5 — each of
  which must be present **exactly once** and map to a known readiness item; and
- a **full** map that additionally recognizes every other status-bearing §16 label — the
  TestNet-track rows (faucet → T1, RPC gateway → T2, RPC rate limiting → T3, explorer → T4,
  governance proof status → T5, validator-set rotation status → T6), the MainNet-track rows
  (runtime wiring for authority lifecycle → N3, MainNet custody → N1, MainNet authority
  rotation/revocation → N2), the DevNet authority-lifecycle boundary row, and the C4 / C5 rows.

The lint **fails closed** if a required §16 mapped label is missing or duplicated, or if **any**
status-bearing §16 row carries a descriptive label that is **not** in the full map (an unknown /
renamed label that no longer maps to a known M/S/N/C/T item).

## 7. How §16 coverage exceptions work

The preferred outcome is that §16 covers every M1–M20 and S1–S7 item exactly once by mapped label.
Two should-haves are intentionally **not** given their own distinct §16 row, because they do not
add a separate gap-matrix line item; each is recorded as an explicit, stable **§16 coverage
exception** with an item code, a reason, and the document/section that protects the item instead:

| Item | §16 status | Reason it is not a distinct §16 mapped row | Protected instead by |
|------|-----------|--------------------------------------------|----------------------|
| S6 | Green | The alert-rule / scrape-config artifacts are the **same shipped observability package** already represented by the §16 "monitoring / alerting" (M14) row; S6 was reconciled Green against that package (Run 395) with no content duplicated, so it needs no separate gap line. | §10 S6 row (🟢) + §5 should-have checklist |
| S7 | Yellow / M4-gated | Operating a live seed is **gated on the M4 launch blocker** already tracked by the §16 "seed nodes / bootnodes" (M4) row; only the seed-node runbook / M4 Route-A checklist / reachability-evidence template docs are published. | §10 S7 row (🟡, M4-gated) + §5 should-have checklist |

The lint verifies that the exception set is **exactly** the set of §10 M/S items not covered by a
§16 mapped label (currently S6 and S7), that each exception row carries a non-empty reason and
protection source, and that the **S7** exception keeps its **Yellow / M4-gated** protection (a
coverage exception may never be used to hide M4/M6/S5/S7 without that Yellow / M4-gated protection
being explicit). No existing Run 413 scoped §16 row may be silently converted into an exception.

## 8. How this extends Runs 412 and 413

- **Run 412** protects the §10 table against the §4/§5 checklists, the blocker register, and the
  launch gate (per-milestone **status**).
- **Run 413** protects the §11 recommendation table and the §16 gap matrix against the §10 table
  (per-row **status glyph**) — for the rows that **exist**.
- **Run 414** protects the **coverage** — the *set of rows that must exist* — so §10 cannot omit or
  duplicate a row, §11 cannot drop a must-have row, and §16 cannot drop a mapped status-bearing row
  or carry an unmapped label. Together the three runs make every status-bearing section of the
  readiness matrix fail closed on both **status drift** and **row deletion**.

## 9. §16 label-to-item coverage map

Required (must be present in §16 exactly once): `genesis package`→M1, `release binary
provenance`→M2, `release reproducibility / SHA / BuildID`→M3, `seed nodes / bootnodes`→M4,
`validator onboarding`→M5, `validator identity`→M6, `validator key-management guidance`→M7,
`trust-bundle bootstrap`→M8, `PQC root / signing-key guidance`→M9, `public P2P port posture`→M10,
`peer admission policy`→M11, `abuse handling`→M12, `telemetry / metrics`→M13, `monitoring /
alerting`→M14, `reset policy`→M15, `incident response`→M16, `public documentation`→M17,
`user-facing disclaimers`→M18, `network parameter publication`→M19, `genesis hash
publication`→M20, `snapshot / backup / restore`→S1, `data retention`→S2, `upgrade procedure`→S3,
`rollback procedure`→S4, `status page`→S5.

Additional recognized (full map, non-scoped): `faucet`→T1, `RPC gateway`→T2, `RPC rate
limiting`→T3, `explorer`→T4, `governance proof status`→T5, `validator-set rotation status`→T6,
`runtime wiring for authority lifecycle`→N3, `MainNet custody`→N1, `MainNet authority
rotation/revocation`→N2, `DevNet authority lifecycle`→authority-lifecycle boundary (Green-for-scope
only), `C4`→C4, `C5`→C5.

Coverage exceptions (in §10 but intentionally not a distinct §16 mapped label): **S6**, **S7** (see
§7).

## 10. Why row deletion is different from status mutation and must fail closed

A status **mutation** changes a row's glyph in place (e.g. M4 🟡 → 🟢); Runs 412/413 catch that. A
row **deletion** removes the row entirely, so a per-value comparison has nothing to compare and can
pass. Deleting the §11 M4 recommendation row or the §16 "seed nodes / bootnodes" (M4) row would
make the launch blocker **disappear from a status-bearing view** while §10 still carries it — an
overclaim by omission. Coverage checking closes this gap: the *set* of required rows is asserted
independently of their values, so a silent deletion fails closed.

## 11. Why M4 remains Yellow / launch-blocking

**M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally reachable public
DevNet seed with independent off-host reachability evidence exists (Runs 378/388/391/393 all reached
the Route C finding — no independent off-host vantage in the sandbox — so external TCP + KEMTLS
reachability is **NOT proven** and **no `devnet-seeds.live.json` is published**). A coverage check
proves nothing about external reachability; M4 remains the primary launch blocker, present in §10,
in the §11 recommendation ("no Green move"), and in the §16 gap matrix ("Launch blocker").

## 12. Why M6 remains Yellow / Partial

**M6 (validator identity)** stays **Yellow / Partial**: the generation + verification and the
non-mutating `register-check` halves are Green-for-scope, but the **live-registration** half is
**M4-gated** (there is no live network to register into) and operator-supplied durable-root
reuse / rotation / revocation is **C4/C5-deferred**. §10, §11, and §16 keep M6 🟡 and M4-gated.

## 13. Why S5 / S7 remain Yellow and M4-gated

- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred until
  M4 / a live network; only a publish-safe static decision + schema is published. §16 keeps the
  status-page (S5) row 🟡 / "live status M4-gated".
- **S7 (seed-node runbook)** stays **Yellow**: the runbook + M4 Route-A checklist + evidence
  template are published, but operating a real live seed is **M4-gated**. S7 has no distinct §16
  row; it is a documented §16 coverage exception (see §7), protected by the §10 S7 row and the §5
  checklist and gated on the M4 launch blocker already tracked by the §16 seed/bootnodes row.

## 14. Why public DevNet remains NO-GO / NOT launch-ready

Per the launch gate's go/no-go rule, launch requires **every** must-have (M1–M20) Green **and**
launch explicitly in scope. Because **M4** is Yellow and **M6** is Yellow / Partial, and launch is
**not** in scope for Run 414 (docs + shell only), the decision remains **NO-GO / NOT launch-ready**
(`LAUNCH_GO_NO_GO.md`). No section of the readiness matrix may state otherwise.

## 15. Why C4 / C5 remain OPEN

A coverage check closes, advances, or reinterprets **nothing** about the protocol contradictions.
**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains **Red**. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria. The §16 C4/C5 rows stay
🔴 / OPEN; the lint only verifies the readiness documents keep saying so — it cannot make them
closed.

## 16. Why TestNet / MainNet remain untouched

TestNet and MainNet remain **untouched**; readiness items **N1–N7 remain Red** (with N5 tied to C4
OPEN / Red and N6 tied to C5 OPEN / Red). **No TestNet readiness and no MainNet readiness is
claimed** in §10, §11, §16, this guide, or the lint harness. The §16 TestNet-track (T1–T6) and
MainNet-track (N1–N3, C4, C5) rows are recognized by the full label-to-item map only so the
unmapped-label check can tell a known deferred row from an unknown / renamed one.

## 17. How to update expectations when a future real Route A run changes a status or section coverage

The lint encodes the **current** frozen posture (M4/M6/S5/S7 Yellow; the M1–M20 / S1–S7 status
vector; NO-GO; C4/C5 OPEN; N1–N7 Red) **and** the current section coverage (§11 must-have-only; the
§16 label-to-item map; the S6/S7 coverage exceptions). A real readiness change happens only via a
genuine **Route A** deployment with evidence — never via a docs run. When a future run legitimately
changes a **status** or intentionally changes **section coverage**:

- update the **§10 current-status table** first (it is the source of truth), then the matching §11
  recommendation row and the matching §16 gap-matrix row / coverage exception, in the **same**
  change, so they never disagree and no required row is dropped;
- update the §4/§5 checklists, the blocker register, and the launch go/no-go gate to match (per the
  Run 412 guide) and keep the §11/§16 status glyphs in step (per the Run 413 guide);
- update this guide and the **coverage assertions in the harness** (the §11 must-have set, the §16
  required + full label-to-item map, and the S6/S7 exception set) in the same change, so the lint
  tracks the new coverage.

Until such a change lands, the lint's expectations are frozen and any drift or deletion fails the
build. The lint never itself moves a readiness item or changes coverage; it only checks that §11
and §16 still cover what §10 requires.

## 18. Why this is not launch evidence

Passing the lint proves only that the §11 recommendation table and the §16 gap matrix still
**cover** the M/S items the §10 table carries. It does **not** deploy a seed, bootnode, faucet,
RPC, explorer, or status service; it opens no port, starts no node, applies no trust bundle, and
mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the lint is **not** a
launch and does not make public DevNet launch-ready. The launch decision remains **NO-GO / NOT
launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 19. Why this is not C4/C5 closure evidence

A cross-section coverage check closes, advances, or reinterprets **nothing** about C4 or C5. **C4
remains OPEN. C5 remains OPEN.** The lint only verifies that the readiness documents continue to say
so — it does not and cannot make them closed.