# QBIND Public DevNet — Readiness Status/Blocker Consistency Lint (Run 412)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **per-milestone status/blocker consistency lint** that keeps the
QBIND public DevNet readiness matrix internally consistent — and consistent with the launch
decision gate and the blocker register — at the level of **individual milestone status rows**.

It is a **read-only** verifier: it reads the readiness matrix, the blocker register, and the
launch go/no-go gate and **fails closed** if the matrix's canonical current-status table
disagrees with its must-have/should-have checklists, or if the blocker register or launch
gate disagree with the frozen M4/M6/S5/S7 posture.

It is **docs + shell only**: running the lint deploys nothing, starts no node, opens no
port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Compared documents:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical readiness matrix.
  Its **§10 current-status table** is the **source of truth**; its **§4 must-have checklist**
  (M1–M20) and **§5 should-have checklist** (S1–S7) are checked against it.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the itemized M4/M6/S5/S7 blocker
  register (owner / action / evidence-needed / status).
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the launch decision gate (**NO-GO**).

Companion files:

- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — the Run 411
  cross-**ledger** run-narrative lint; this Run 412 lint is its per-**milestone** companion
  (Run 411 keeps the readiness matrix and the contradiction ledger consistent on the per-run
  narratives; Run 412 keeps the readiness matrix's status table, checklists, and the blocker
  register consistent on the per-milestone status rows).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` — the Run 410
  package-integrity stale-prose lint.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — the per-run protocol contradiction ledger.
- `scripts/devnet/run_412_public_devnet_readiness_status_blocker_lint.sh` — the Run 412
  harness / lint.

## 1. Why this lint exists

The readiness matrix records each milestone's status in **several places** — the §10
current-status table, the §4 must-have checklist, the §5 should-have checklist, the §11
next-run recommendation, and the §12 blocker summary — and the same posture is echoed by the
launch go/no-go gate and the blocker register. These are edited **independently, run after
run**. Nothing structurally forced a single milestone's status to stay in step across all of
them, and it **did** drift: the §4 M12 checklist entry stayed at "Yellow / Partial (Run 362)"
long after the §10 table, §11 recommendation, and §12 summary had recorded **M12 Green
(Run 371)**. Run 412 reconciles that one stale entry to Green (a documentation reconciliation
of an already-historically-recorded status, **not** a new Green move) and then adds a lint so
a future edit cannot advance, soften, or forget a per-milestone status in one place without
the others agreeing.

Run 411 already protects the **cross-ledger run narratives** (readiness matrix vs
contradiction ledger). Run 412 extends the same fail-closed protection **down to the
per-milestone status rows** — table vs checklist vs blocker register vs launch gate.

## 2. Which documents are compared

Three documents are compared:

1. the **readiness matrix** — its §10 current-status table, its §4 must-have checklist, and
   its §5 should-have checklist;
2. the **blocker register** — its M4/M6/S5/S7 rows and their status column; and
3. the **launch go/no-go gate** — its NO-GO decision, its must-have blocker list, and its
   S5/S7 M4-gated statements.

## 3. Why the §10 current-status table is the source of truth

The §10 "Current status per item" table is the readiness matrix's **canonical** per-item
status ledger: it carries one status glyph (🟢 Green · 🟡 Yellow · 🔴 Red · ⚪ N/A) and a
one-line basis for **every** M1–M20 and S1–S7 item, and it is the table the launch gate and
blocker register cite as "source of truth for item status". The §4/§5 checklists are the
human-facing, prose-heavy views of the same statuses; when a checklist entry and the §10
table disagree, the **table** is treated as correct and the checklist is what gets
reconciled. The lint therefore compares each checklist entry **against** the §10 table.

## 4. How the must-have and should-have checklists are checked against it

For every must-have **M1–M20** and should-have **S1–S7** item, the lint:

- extracts the item's status glyph from the **§10 current-status table** (🟢 → Green, 🟡 →
  Yellow, 🔴 → Red);
- extracts the item's leading bold status word from the **§4 must-have checklist** (M1–M20)
  or **§5 should-have checklist** (S1–S7) — the `**Green` / `**Yellow` / `**Red` token
  immediately after the item's `— ` em-dash; and
- **fails closed** if the two disagree for any item.

It additionally asserts the table itself covers all of M1–M20 and S1–S7, the must-have
checklist covers M1–M20, and the should-have checklist covers S1–S7 — so a missing row cannot
hide a disagreement.

## 5. How the blocker register is checked against M4/M6/S5/S7

The lint requires the blocker register to:

- contain a row for **each** of M4, M6, S5, and S7; and
- keep every one of them **open / unresolved** — it fails closed if any M4/M6/S5/S7 blocker
  row is marked resolved, closed, Green, non-blocking, or launch-complete.

It also requires the register to keep its launch rule ("no launch until every must-have is
Green and launch is explicitly in scope") and to remain the itemized companion of the launch
gate, so the register's owner/action/evidence-needed/status rows stay aligned with the NO-GO
decision.

## 6. The frozen per-milestone posture this lint encodes

The lint treats the following as the **current frozen truth** and fails on any drift from it:

- **M4 (seed/bootnodes)** — **Yellow / launch-blocking** everywhere it appears (§10 table,
  §4 checklist, blocker register, launch gate).
- **M6 (validator identity)** — **Yellow / Partial** everywhere it appears.
- **S5 (status page)** — **Yellow** everywhere it appears.
- **S7 (seed-node runbook)** — **Yellow** everywhere it appears.
- **M1–M3, M5, M7–M20** — **Green** (M12 Green is Green-for-scope, Run 371).
- **S1–S4, S6** — **Green**.
- **Public DevNet** — **NO-GO / NOT launch-ready**; the launch gate must keep M4 and M6 as
  must-have blockers and keep S5/S7 M4-gated or Yellow.
- **C4 / C5** — **OPEN**; **TestNet / MainNet** — untouched; **N1–N7** — Red.

## 7. Why M4 remains Yellow / launch-blocking

**M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally reachable
public DevNet seed with independent off-host reachability evidence exists (Runs 378/388/391/393
all reached the Route C finding — no independent off-host vantage in the sandbox — so external
TCP + KEMTLS reachability is **NOT proven** and **no `devnet-seeds.live.json` is published**).
Checking the status rows proves nothing about external reachability; M4 remains the primary
launch blocker.

## 8. Why M6 remains Yellow / Partial

**M6 (validator identity)** stays **Yellow / Partial**: the generation + verification and the
non-mutating `register-check` halves are Green-for-scope, but the **live-registration** half
is **M4-gated** (there is no live network to register into) and operator-supplied durable-root
reuse / rotation / revocation is **C4/C5-deferred**.

## 9. Why S5 / S7 remain Yellow

- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred
  until M4 / a live network; only a publish-safe static decision + schema is published.
- **S7 (seed-node runbook)** stays **Yellow**: the runbook + M4 Route-A checklist + evidence
  template are published, but operating a real live seed is **M4-gated**.

## 10. Why public DevNet remains NO-GO / NOT launch-ready

Per the launch gate's go/no-go rule, launch requires **every** must-have (M1–M20) Green
**and** launch explicitly in scope. Because **M4** is Yellow and **M6** is Yellow / Partial,
and launch is **not** in scope for Run 412 (docs + shell only), the decision remains
**NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 11. Why C4 / C5 remain OPEN

A per-milestone status/blocker consistency check closes, advances, or reinterprets
**nothing** about the protocol contradictions. **C4 remains OPEN. C5 remains OPEN.** MainNet
authority rotation/revocation remains **Red**. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria. The lint only
verifies that the readiness documents continue to say C4/C5 are OPEN — it cannot make them
closed.

## 12. Why TestNet / MainNet remain untouched

TestNet and MainNet remain **untouched**; readiness items **N1–N7 remain Red** (with N5 tied
to C4 OPEN / Red and N6 tied to C5 OPEN / Red). **No TestNet readiness and no MainNet
readiness is claimed** anywhere in this guide, the lint harness, or the compared documents.

## 13. How to update expectations when a future real Route A run changes a status

The lint encodes the **current** frozen posture (M4/M6/S5/S7 Yellow; the M1–M20 / S1–S7
status vector; NO-GO; C4/C5 OPEN; N1–N7 Red). A real readiness change happens only via a
genuine **Route A** deployment with evidence — never via a docs run. When such a change
legitimately lands:

- update the **§10 current-status table** and the matching **§4/§5 checklist** entry to
  record the new status, with its evidence, in the **same** change (so they never disagree);
- update the **blocker register** and the **launch go/no-go gate** to match (e.g. clear the
  M4 blocker row and update the go/no-go decision only once M4 is genuinely Green);
- update this guide and the **posture assertions in the harness** (the per-item expected
  status vector and the M4/M6/S5/S7/NO-GO/C4-C5 expectations) in the same change, so the lint
  tracks the new truth.

Until such a change lands, the lint's expectations are frozen and any drift fails the build.
The lint never itself moves a readiness item; it only checks that the status rows agree.

## 14. Why this is not launch evidence

Passing the lint proves only that the readiness status rows are internally consistent at
check time. It does **not** deploy a seed, bootnode, faucet, RPC, explorer, or status
service; it opens no port, starts no node, applies no trust bundle, and mutates no
validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the lint is **not** a
launch and does not make public DevNet launch-ready. The launch decision remains **NO-GO /
NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 15. Why this is not C4/C5 closure evidence

A status/blocker consistency check closes, advances, or reinterprets **nothing** about C4 or
C5. **C4 remains OPEN. C5 remains OPEN.** The lint only verifies that the readiness documents
continue to say so — it does not and cannot make them closed.
