# QBIND Public DevNet — Readiness/Contradiction Ledger Consistency Lint (Run 411)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **cross-ledger consistency lint** that keeps QBIND's two
canonical public DevNet ledgers in agreement:

- the **canonical readiness matrix** —
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`; and
- the **protocol contradiction ledger** — `docs/whitepaper/contradiction.md`.

It is a **read-only** verifier: it reads both ledgers (plus the launch gate, the blocker
register, and the C4/C5 closure criteria for corroboration) and **fails closed** if they
drift apart on the public DevNet run narratives, the fixed readiness posture, or the
standing non-claims.

It is **docs + shell only**: running the lint deploys nothing, starts no node, opens no
port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Companion files:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical readiness matrix
  and fixed-posture status table.
- `docs/whitepaper/contradiction.md` — the per-run protocol contradiction ledger.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` — the Run 410
  package-integrity stale-prose lint; this Run 411 lint is its **cross-ledger** companion
  (Run 410 keeps the package-integrity prose internally consistent; Run 411 keeps the two
  readiness ledgers consistent with each other).
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — the launch decision gate (**NO-GO**).
- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the M4/M6/S5/S7 blocker register.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh` — the Run 411
  harness / lint.

## 1. Why this lint exists

The readiness matrix and the contradiction ledger are written and updated **independently**,
run after run. They describe the same underlying reality — which milestones are Green, which
are Yellow, which contradictions remain OPEN, and what is explicitly **not** claimed — but
nothing structurally forced them to stay in step. Run 409 and Run 410 showed that
independent documents in this package **do** drift: a stale count in one guide, a denied
refresh in another. The package-integrity stale-prose lint (Run 410) closed that gap for the
package-integrity prose. This Run 411 lint extends the same protection **across the two
readiness ledgers**, so a future run cannot advance the posture in one ledger (or quietly
soften a non-claim) without the other ledger agreeing.

## 2. Which ledgers are compared

Exactly two ledgers are compared against each other:

1. the **readiness matrix** — its per-run `Updated Run N —` narratives and its canonical
   fixed-posture status table; and
2. the **contradiction ledger** — its per-run `Run N —` entries.

The launch gate, blocker register, and C4/C5 closure criteria are read only to **corroborate**
the NO-GO decision and the OPEN C4/C5 state; they are not themselves cross-compared.

## 3. Which runs are in scope

At minimum, Runs **402–410** — the current public DevNet launch-gate / package-integrity
documentation chain:

| Run | Narrative |
| --- | --- |
| 402 | launch go/no-go gate + blocker register |
| 403 | artifact index + operator verification map |
| 404 | package integrity manifest |
| 405 | full-tree package integrity verifier |
| 406 | full-tree CI artifacts + anchor drift |
| 407 | machine-readable anchor drift + retention |
| 408 | retained drift-history comparator |
| 409 | integrity-doc consistency reconciliation |
| 410 | package-integrity stale-prose lint |

For each scoped run, the lint requires that:

- the readiness matrix contains an `Updated Run N` narrative;
- the contradiction ledger contains a corresponding `Run N` entry with an explicit
  no-contradiction / no-protocol-contradiction statement;
- both ledgers agree that **no readiness item moved Green** for that run (none of Runs
  402–410 moved any item Green);
- both ledgers agree that **M4/M6/S5/S7 remain unchanged** and public DevNet remains **NOT
  launch-ready**;
- both ledgers agree that **C4/C5 remain OPEN** and TestNet/MainNet remain untouched;
- the docs-only / shell-only / schema-only / YAML-only runs are **not** described as runtime
  or launch evidence (each is recorded as a Route B run).

## 4. What statements must stay aligned

The lint fails closed if the two ledgers disagree on any of the following current public
DevNet posture statements:

1. M4 remains Yellow / launch-blocking.
2. M6 remains Yellow / Partial.
3. S5 remains Yellow.
4. S7 remains Yellow.
5. Public DevNet remains NOT launch-ready / NO-GO.
6. C4 remains OPEN.
7. C5 remains OPEN.
8. TestNet/MainNet remain untouched.
9. N1–N7 remain Red.
10. No seed/bootnode/faucet/RPC/explorer/status-service deployment is claimed.
11. No public launch is claimed.
12. No runtime mutation is claimed.
13. No validator/epoch/sequence/marker/`LivePqcTrustState` mutation is claimed.
14. No C4/C5 closure is claimed.
15. No TestNet/MainNet readiness is claimed.

## 5. Why the lint is intentionally narrow and grep/check based

The lint is deliberately a small, deterministic, grep/extraction-based check — not a natural
language model, not a semantic diff. It extracts each scoped run's narrative block from the
readiness matrix and each run's line from the contradiction ledger, and confirms the fixed
posture phrases are present and consistent in both. This keeps the lint:

- **auditable** — every assertion is a literal string / regex an operator can re-run;
- **stable** — it encodes the *current* frozen posture and fails on any drift from it;
- **cheap** — it needs only `bash`, `grep`, and `awk`; it starts nothing and mutates nothing.

It is not a substitute for reading the ledgers; it is a tripwire that fires when they
disagree.

## 6. How to update expectations when a future run legitimately moves readiness

The lint encodes the **current** frozen posture (M4/M6/S5/S7 Yellow; NO-GO; C4/C5 OPEN;
N1–N7 Red). A real readiness change happens only via a genuine Route A deployment with
evidence — never via a docs run. When such a change legitimately lands:

- update the **fixed-posture status table** in the readiness matrix and the matching
  per-run narrative to record the Green move, with its evidence;
- update the corresponding **contradiction-ledger entry** to agree;
- update this guide and the **posture assertions in the harness** (the M4/M6/S5/S7/NO-GO/
  C4-C5 expectations and the scoped-run list) in the *same* change, so the lint tracks the
  new truth.

Until such a change lands, the lint's expectations are frozen and any drift fails the build.
The lint never itself moves a readiness item; it only checks that the two ledgers agree.

## 7. Why this is not launch evidence

Passing the lint proves only that the two readiness ledgers are internally consistent at
check time. It does **not** deploy a seed, bootnode, faucet, RPC, explorer, or status
service; it opens no port, starts no node, applies no trust bundle, and mutates no
validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the lint is **not** a
launch and does not make the public DevNet launch-ready. The launch decision remains
**NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 8. Why this is not C4/C5 closure evidence

A cross-ledger consistency check closes, advances, or reinterprets **nothing** about the
contradiction ledger. **C4 remains OPEN. C5 remains OPEN.** MainNet authority
rotation/revocation remains **Red**. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for
the closure criteria and `docs/whitepaper/contradiction.md` for the ledger. The lint only
verifies that both ledgers continue to say C4/C5 are OPEN — it does not and cannot make them
closed.

## 9. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally reachable
  public DevNet seed with independent off-host reachability evidence exists. Linting the
  ledgers proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: generation + verification +
  non-mutating `register-check` are Green-for-scope; the live-registration half is M4-gated
  and durable-root reuse/rotation/revocation is C4/C5-deferred.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred
  until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains M4-gated.

## 10. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide, the
lint harness, or the two ledgers' Run 411 entries.
