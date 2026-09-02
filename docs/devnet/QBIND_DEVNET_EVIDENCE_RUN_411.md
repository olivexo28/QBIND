# QBIND DevNet Evidence — Run 411

Public DevNet **readiness/contradiction ledger consistency lint** — a **read-only**, **docs +
shell only** run that adds a lightweight cross-**ledger** lint verifying QBIND's two canonical
public DevNet ledgers — the readiness matrix
(`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`) and the contradiction ledger
(`docs/whitepaper/contradiction.md`) — agree on the public DevNet run narratives, the fixed
readiness posture, and the standing non-claims. It extends consistency protection **beyond**
the Run 410 package-integrity stale-prose lint **without** adding a feature surface and
**without** moving any readiness item.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes
**no C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.

## 1. Exact verdict

`RESULT=POSITIVE` — public-DevNet readiness/contradiction ledger consistency lint. The lint
is documented, cross-checks Runs 402–410 between the readiness matrix and the contradiction
ledger, confirms the fixed posture / C4-C5 / TestNet-MainNet non-claims remain aligned,
commits no generated/private material, and introduces no readiness overclaim.

## 2. Objective

Turn the implicit expectation that the readiness matrix and the contradiction ledger stay in
step into an automated, fail-closed cross-ledger check. The lint rejects: a scoped run
(402–410) missing from either ledger; the two ledgers disagreeing that M4/M6/S5/S7 remain
Yellow, that public DevNet remains NOT launch-ready, or that C4/C5 remain OPEN; a
docs/shell/schema/YAML-only run described as launch or runtime evidence; a readiness item
moving Green for a scoped run (none did); and any deployment / runtime-mutation /
TestNet-MainNet-readiness / C4-C5-closure claim in the Run 411 docs.

## 3. Decision gate route

**Route B.** Adding a documentation-consistency lint over the two already-published readiness
ledgers is operator/reviewer-facing consistency work — **docs + shell only**, no new CLI
surface, no source change, no runtime change. Route A (deploy to change status) and Route C
(defer) were not taken.

## 4. What changed

Created:

- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — the safety-labelled
  ledger-lint guide.
- `scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh` — the
  read-only, fail-closed cross-ledger lint harness (`RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_411.md` (this file).
- `docs/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — Run 411 narrative row (no status
  change).
- `docs/whitepaper/contradiction.md` — Run 411 entry.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` and
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — reference the ledger lint.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` — companion pointer to
  the new cross-ledger lint.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256 / byte size
  refreshed for exactly the two narrowly-edited anchor docs (`ARTIFACT_INDEX.md`,
  `OPERATOR_VERIFICATION_MAP.md`); no entry added/removed, no `status` changed.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 5. Ledger-lint guide contents

`READINESS_CONTRADICTION_LEDGER_LINT.md` explains why the lint exists, which ledgers are
compared, which runs are in scope (402–410), what statements must stay aligned, why the lint
is intentionally narrow and grep/check based, how to update expectations when a future run
legitimately moves readiness status, why this is not launch evidence, why this is not C4/C5
closure evidence, why M4/M6/S5/S7 remain unchanged, and why TestNet/MainNet remain untouched.

## 6. Run-row consistency scope

Runs **402–410** — the current public DevNet launch-gate / package-integrity documentation
chain (402 launch go/no-go gate; 403 artifact index + operator verification map; 404 package
integrity manifest; 405 full-tree package integrity verifier; 406 full-tree CI artifacts +
anchor drift; 407 machine-readable anchor drift + retention; 408 retained drift-history
comparator; 409 integrity-doc consistency reconciliation; 410 stale-prose lint). For each, the
harness verifies both ledgers carry the run narrative, agree no readiness item moved Green,
agree M4/M6/S5/S7 stay Yellow and public DevNet stays NOT launch-ready, agree C4/C5 stay OPEN,
agree TestNet/MainNet remain untouched, and record the run as a docs/shell-only Route B run
(not launch/runtime evidence).

## 7. Readiness-matrix presence checks

All of Runs 402–410 carry an `Updated Run N —` narrative in
`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`, each extracted as a block and checked for the
fixed posture phrases.

## 8. Contradiction-ledger presence checks

All of Runs 402–410 carry a single-line `Run N —` entry in `contradiction.md`, each with an
explicit "no protocol contradiction found" statement and the fixed posture phrases.

## 9. M4 consistency check

M4 is `🟡` in the readiness matrix status table (`M4 seed/bootnodes | 🟡`) and "M4 stays
Yellow" in the contradiction ledger for every scoped run — consistent.

## 10. M6 consistency check

M6 is `🟡` in the readiness matrix (`M6 validator identity | 🟡`) and "M6 stays
Yellow/Partial" in the contradiction ledger — consistent.

## 11. S5/S7 consistency check

S5 (`S5 status page | 🟡`) and S7 (`S7 seed-node runbook | 🟡`) are `🟡` in the readiness
matrix and "S5/S7 stay Yellow" in the contradiction ledger — consistent.

## 12. Public DevNet NO-GO consistency check

"public DevNet remains NOT launch-ready" in the readiness matrix, "NOT launch-ready" in the
contradiction ledger, and NO-GO / NOT launch-ready in `LAUNCH_GO_NO_GO.md` — consistent.

## 13. C4/C5 consistency check

"C4 and C5 remain OPEN" in the readiness matrix, "C4 remains OPEN" + "C5 remains OPEN" in the
contradiction ledger, and C4/C5 documented in `QBIND_C4_C5_CLOSURE_CRITERIA.md` — consistent
and OPEN.

## 14. TestNet/MainNet non-claim consistency check

N1–N7 Red in the readiness matrix (`N1, N2, N3, N4, N7 Red`; `N5 (C4) OPEN / Red`; `N6 (C5)
OPEN / Red`) and "TestNet/MainNet untouched" in the contradiction ledger — consistent.

## 15. Deployment / runtime-mutation non-claim consistency check

Neither ledger claims a seed/bootnode/faucet/RPC/explorer/status-service deployment, and
neither claims a validator/epoch/sequence/marker/`LivePqcTrustState` mutation.

## 16. Generated-output behavior

The harness writes only a transient `summary.txt` into a staging directory **outside** the
repository tree (runner temp). Nothing generated is committed; the working-tree snapshot is
identical before and after the run.

## 17. Non-claim checks

The normalized non-claim grep over the Run 411-authored docs (guide + this evidence) finds no
launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment /
runtime-mutation claim.

## 18. Security scans

Secret / private-material scan and absolute-path scan over the Run 411 docs are clean; no
keys/certs/KEM/signing/API material, no data dirs, no raw logs/metrics, no private identity.

## 19. Runtime mutation check

**NONE.** Run 411 is docs + shell only: it opens no port, starts no node, applies no trust
bundle, and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 20. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain
OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.

## 21. Tests / checks

- `bash scripts/devnet/run_411_public_devnet_readiness_contradiction_ledger_lint.sh` →
  `RESULT=POSITIVE`.
- Re-ran the Run 410 stale-prose lint and the Run 405 full-tree integrity verifier as a
  regression after refreshing the two anchor entries — both `RESULT=POSITIVE`.
- Readiness-matrix / contradiction-ledger run-presence checks, posture consistency grep,
  deployment/runtime non-claim grep, generated-output non-commit check, non-claim grep, and
  secret/private-material scan — all clean.
- No Rust source changed → no `cargo test` delta; CodeQL is docs/shell-only (not meaningful).

## 22. Honest limitations

- The lint compares the **committed** text of the two ledgers; it does not model their full
  natural-language meaning, only the fixed posture phrases and per-run presence.
- The lint encodes the **current** frozen posture (M4/M6/S5/S7 Yellow; NO-GO; C4/C5 OPEN;
  N1–N7 Red). A legitimate future readiness change must update the ledgers and the harness's
  posture assertions in the same change, as documented in the guide.
- The repository is a squashed/shallow clone, so run presence is verified from the on-disk
  ledgers rather than by isolating individual historical commits.
