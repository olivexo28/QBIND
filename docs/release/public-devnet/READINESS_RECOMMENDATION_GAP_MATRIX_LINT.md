# QBIND Public DevNet — Readiness Recommendation/Gap-Matrix Consistency Lint (Run 413)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **recommendation/gap-matrix consistency lint** that keeps the QBIND
public DevNet readiness matrix's **§11 next-run recommendation table** and its **§16 consolidated
gap matrix** from drifting away from the **§10 current-status table** (the canonical per-item
status ledger), the §4/§5 checklists, the blocker register, and the launch go/no-go gate.

It is a **read-only** verifier: it reads the readiness matrix and **fails closed** if the §11
recommendation table or the §16 gap matrix disagrees with the §10 current-status table on any
M1–M20 / S1–S7 item they mention, or if either table softens, resolves, or overclaims the frozen
M4/M6/S5/S7 / NO-GO / C4-C5-OPEN posture.

It is **docs + shell only**: running the lint deploys nothing, starts no node, opens no port,
adds no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Compared documents:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical readiness matrix.
  Its **§10 current-status table** is the **source of truth**; its **§11 next-run
  recommendation table** (M1–M20) and its **§16 consolidated gap matrix** (per-item rows) are
  checked against it.

Companion files:

- `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` — the Run 412 per-**milestone**
  status/blocker lint (§10 table vs §4/§5 checklists + blocker register + launch gate); this
  Run 413 lint is its **recommendation/gap-matrix** extension (Run 412 protects the §10 table
  against the checklists/blocker register; Run 413 protects the §10 table against the §11
  next-run recommendation table and the §16 consolidated gap matrix).
- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — the Run 411
  cross-**ledger** run-narrative lint.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the M4/M6/S5/S7 blocker register.
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the launch decision gate (**NO-GO**).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — the per-run protocol contradiction ledger.
- `scripts/devnet/run_413_public_devnet_readiness_recommendation_gap_matrix_lint.sh` — the
  Run 413 harness / lint.

## 1. Why this lint exists

The readiness matrix records each milestone's status in **several places** — the §10
current-status table, the §4 must-have checklist, the §5 should-have checklist, the **§11
next-run recommendation table**, the §12 blocker summary, and the **§16 consolidated gap
matrix**. Run 412 already forces the §10 table, the §4/§5 checklists, the blocker register, and
the launch gate to stay in step at the per-milestone level. But §11 (the "exact next run
recommendation for each Red/Yellow must-have") and §16 (the "consolidated gap matrix") each carry
their **own** status glyph per item, and each is edited independently run after run. Nothing
structurally forced §11's or §16's status glyph for an item to stay equal to the §10 table's
glyph for that same item. A future edit could, for example, mark M4 🟢 or "Done" in §11 or in the
§16 status column while §10 still holds M4 🟡, silently overclaiming readiness. Run 413 adds a
fail-closed lint so §11 and §16 cannot drift away from the §10 source of truth.

## 2. Which documents and sections are compared

One document, three sections:

1. the **§10 current-status table** — the canonical per-item status ledger (**source of truth**);
2. the **§11 next-run recommendation table** — one status glyph + a next-run recommendation for
   every M1–M20; and
3. the **§16 consolidated gap matrix** — one row per gap item (`item · stage · category · status
   · evidence · blocker · risk · next run`), including the M1–M20 and S1–S7 items it names.

## 3. Why the §10 current-status table remains the source of truth

The §10 "Current status per item" table is the readiness matrix's **canonical** per-item status
ledger: it carries exactly one status glyph (🟢 Green · 🟡 Yellow · 🔴 Red · ⚪ N/A) and a
one-line basis for **every** M1–M20 and S1–S7 item, and the launch gate and blocker register cite
it as "source of truth for item status". §11 and §16 are **derived** views — a next-run
recommendation and a consolidated gap matrix — of the same statuses. When §11 or §16 disagrees
with §10, the **§10 table** is treated as correct and §11/§16 is what gets reconciled. The lint
therefore compares §11 and §16 **against** the §10 table, exactly as Run 412 compares the §4/§5
checklists against it.

## 4. How §11 next-run recommendation rows are checked against §10

The §11 table is keyed by the item code (`| M4 | 🟡 | … |`). For every must-have **M1–M20** row
present in §11 the lint:

- extracts the §11 row's status glyph (column 2 → 🟢 Green / 🟡 Yellow / 🔴 Red);
- extracts the same item's status glyph from the **§10 current-status table**; and
- **fails closed** if the two disagree, or if either differs from the frozen expected status.

It also asserts §11 covers all of M1–M20 and that no §11 row marks **M4** resolved / Green /
non-blocking / launch-complete / "not launch-blocking", that the §11 M4 row keeps its
"external reachability NOT proven / no Green move" follow-up posture, and that no §11 row claims
public DevNet is launch-ready / GO, that C4/C5 are closed, that TestNet/MainNet are ready, or that
a live seed/bootnode/faucet/RPC/explorer/status service / `devnet-seeds.live.json` / runtime
mutation exists.

## 5. How §16 consolidated gap matrix rows are checked against §10

The §16 gap matrix is keyed by a descriptive label (`| seed nodes / bootnodes | DevNet | network
| 🟡 | … |`), not by item code. The lint maps each scoped §16 label to its M/S item code (e.g.
"seed nodes / bootnodes" → M4, "validator identity" → M6, "status page" → S5, "snapshot / backup /
restore" → S1) and, for every mapped row:

- extracts the §16 row's status glyph (column 4);
- extracts the same item's status glyph from the **§10 current-status table**; and
- **fails closed** if the two disagree, or if either differs from the frozen expected status.

It also asserts the §16 **seed nodes / bootnodes** (M4) row keeps its **Launch blocker** gap
posture, the §16 **validator identity** (M6) and **status page** (S5) rows keep their **M4-gated**
posture, the §16 **C4** and **C5** rows stay 🔴 / **OPEN**, and no §16 row overclaims launch /
C4-C5-closure / TestNet-MainNet-readiness / deployment / `devnet-seeds.live.json` / runtime
mutation.

## 6. How this extends Run 412

Run 412 protects the §10 current-status table against the §4 must-have checklist, the §5
should-have checklist, the blocker register, and the launch gate. Run 413 extends the **same
fail-closed protection** to the two remaining status-bearing views of the readiness matrix — the
**§11 next-run recommendation table** and the **§16 consolidated gap matrix** — so that no
status-bearing section of the readiness matrix can advance, soften, or overclaim a per-item status
without the §10 source of truth agreeing.

## 7. Why M4 remains Yellow / launch-blocking

**M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally reachable public
DevNet seed with independent off-host reachability evidence exists (Runs 378/388/391/393 all
reached the Route C finding — no independent off-host vantage in the sandbox — so external TCP +
KEMTLS reachability is **NOT proven** and **no `devnet-seeds.live.json` is published**). Checking
that §11 and §16 agree with §10 proves nothing about external reachability; M4 remains the primary
launch blocker in the §11 recommendation ("no Green move") and the §16 gap matrix ("Launch
blocker").

## 8. Why M6 remains Yellow / Partial

**M6 (validator identity)** stays **Yellow / Partial**: the generation + verification and the
non-mutating `register-check` halves are Green-for-scope, but the **live-registration** half is
**M4-gated** (there is no live network to register into) and operator-supplied durable-root
reuse / rotation / revocation is **C4/C5-deferred**. §11 and §16 keep M6 🟡 and M4-gated.

## 9. Why S5 / S7 remain Yellow and M4-gated

- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred until
  M4 / a live network; only a publish-safe static decision + schema is published. §16 keeps the
  status-page row 🟡 / "live status M4-gated".
- **S7 (seed-node runbook)** stays **Yellow**: the runbook + M4 Route-A checklist + evidence
  template are published, but operating a real live seed is **M4-gated**. (§11 and §16 do not add
  an S7 status row; the §10 table and §5 checklist remain S7's source of truth, protected by
  Run 412.)

## 10. Why public DevNet remains NO-GO / NOT launch-ready

Per the launch gate's go/no-go rule, launch requires **every** must-have (M1–M20) Green **and**
launch explicitly in scope. Because **M4** is Yellow and **M6** is Yellow / Partial, and launch is
**not** in scope for Run 413 (docs + shell only), the decision remains **NO-GO / NOT launch-ready**
(`LAUNCH_GO_NO_GO.md`). Neither §11 nor §16 may state otherwise.

## 11. Why C4 / C5 remain OPEN

A recommendation/gap-matrix consistency check closes, advances, or reinterprets **nothing** about
the protocol contradictions. **C4 remains OPEN. C5 remains OPEN.** MainNet authority
rotation/revocation remains **Red**. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the
closure criteria. The §16 C4/C5 rows stay 🔴 / OPEN; the lint only verifies the readiness
documents keep saying so — it cannot make them closed.

## 12. Why TestNet / MainNet remain untouched

TestNet and MainNet remain **untouched**; readiness items **N1–N7 remain Red** (with N5 tied to C4
OPEN / Red and N6 tied to C5 OPEN / Red). **No TestNet readiness and no MainNet readiness is
claimed** in §11, in §16, in this guide, or in the lint harness.

## 13. How to update expectations when a future real Route A run changes a status

The lint encodes the **current** frozen posture (M4/M6/S5/S7 Yellow; the M1–M20 / S1–S7 status
vector; NO-GO; C4/C5 OPEN; N1–N7 Red). A real readiness change happens only via a genuine **Route
A** deployment with evidence — never via a docs run. When such a change legitimately lands:

- update the **§10 current-status table** first (it is the source of truth), then the matching
  **§11 next-run recommendation** row and the matching **§16 gap-matrix** row, in the **same**
  change, so they never disagree;
- update the §4/§5 checklists, the blocker register, and the launch go/no-go gate to match (per
  the Run 412 guide);
- update this guide and the **posture assertions in the harness** (the per-item expected status
  vector, the §16 label→item map, and the M4/M6/S5/S7 / NO-GO / C4-C5 expectations) in the same
  change, so the lint tracks the new truth.

Until such a change lands, the lint's expectations are frozen and any drift fails the build. The
lint never itself moves a readiness item; it only checks that §11 and §16 agree with §10.

## 14. Why this is not launch evidence

Passing the lint proves only that the §11 recommendation table and the §16 gap matrix are
internally consistent with the §10 status table at check time. It does **not** deploy a seed,
bootnode, faucet, RPC, explorer, or status service; it opens no port, starts no node, applies no
trust bundle, and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state. Running
the lint is **not** a launch and does not make public DevNet launch-ready. The launch decision
remains **NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 15. Why this is not C4/C5 closure evidence

A recommendation/gap-matrix consistency check closes, advances, or reinterprets **nothing** about
C4 or C5. **C4 remains OPEN. C5 remains OPEN.** The lint only verifies that the readiness
documents continue to say so — it does not and cannot make them closed.
