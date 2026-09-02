# QBIND DevNet Evidence — Run 409

Public DevNet **integrity-doc consistency reconciliation** — a **read-only**,
**docs + shell only** run that reconciles narrow documentation inconsistencies surfaced
across Runs 406–408 **without** adding functionality and **without** moving any readiness
item. It corrects the stale Run 408 evidence claim about the anchor manifest and the stale
"exactly three" CI-artifact wording that predated the Run 407 JSON drift report.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes
**no C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

## 1. Objective

Resolve narrow documentation inconsistencies from Runs 406–408:

1. Whether `PACKAGE_INTEGRITY_MANIFEST.example.json` (the Run 404 curated anchor manifest)
   was refreshed in Run 408.
2. The stale Run 406 CI-artifacts wording that still said "exactly three" current artifacts
   after Run 407 expanded the workflow to four artifacts.
3. Any adjacent package-integrity docs that disagreed about artifact counts, anchor
   refreshes, or generated-output behavior.

No new functionality is added and no readiness status changes.

## 2. What changed

Created:

- `scripts/devnet/run_409_public_devnet_integrity_doc_consistency.sh` — read-only
  documentation-consistency verifier (18 checks; `RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_409.md` (this file).
- `docs/devnet/run_409_public_devnet_integrity_doc_consistency/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_408.md` — corrected the anchor-manifest statement
  (the manifest **was** refreshed for exactly the two edited anchor docs, not "not edited").
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — §1 now describes the four
  download-only artifacts; the fail-list references "four" publish-safe names.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — added a Run 409 narrative row
  (no status change).
- `docs/whitepaper/contradiction.md` — added the Run 409 entry.

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B.** Reconciling documentation over already-recorded Run 404–408 integrity artifacts
is purely operator/reviewer-facing consistency work — **docs + shell only**, no new CLI
surface, no source change, no runtime change. Route A (deploy to change status) and Route C
(defer) were not taken.

## 4. Anchor manifest change finding

Ground truth is the on-disk package tree. Run 408 narrowly edited two curated **anchor**
docs — `ARTIFACT_INDEX.md` and `OPERATOR_VERIFICATION_MAP.md` — to reference the retained
anchor-drift comparator. Because editing any of the 16 curated anchor files requires
refreshing that entry's SHA-256/byte size in `PACKAGE_INTEGRITY_MANIFEST.example.json` (or
Run 405/406/407 fail), the Run 404 anchor manifest **was** refreshed for exactly those two
entries. The harness re-hashes every manifest entry and confirms all 16 entries match the
on-disk tree, with `ARTIFACT_INDEX.md` and `OPERATOR_VERIFICATION_MAP.md` present exactly
once each — **no entry added or removed, no `status` changed**.

## 5. Anchor-refresh reconciliation

Before Run 409, the readiness matrix (Run 408 row) and the `contradiction.md` Run 408 entry
already stated the manifest was refreshed for exactly `ARTIFACT_INDEX.md` and
`OPERATOR_VERIFICATION_MAP.md`, but `QBIND_DEVNET_EVIDENCE_RUN_408.md` said the manifest was
"not edited this run". That was the sole outlier and is factually wrong given Run 408 edited
two anchor docs. Run 409 corrects the evidence to match; the canonical statement is now:
**"the Run 404 anchor manifest was refreshed for exactly the two narrowly-edited anchor docs
(`ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`); no entry added/removed; no status
changed."**

## 6. CI artifact-count reconciliation

The current workflow (`.github/workflows/public-devnet-package-integrity.yml`) uploads
**four** download-only artifacts:

1. `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`
2. `ANCHOR_DRIFT_REPORT.md`
3. `ANCHOR_DRIFT_REPORT.json`
4. `PACKAGE_INTEGRITY_CI_SUMMARY.txt`

`PACKAGE_INTEGRITY_CI_ARTIFACTS.md` §1 previously said "exactly three" (stale Run 406
behavior, before Run 407 added the JSON report) and listed only three items; its fail-list
referenced "three publish-safe names". Run 409 updates both to **four** and adds the
`ANCHOR_DRIFT_REPORT.json` item, matching `PACKAGE_INTEGRITY_CI_RETENTION.md` (already
four). Generated artifacts remain staged **outside** the repo/package tree, are **never
committed**, and retention is convenience/audit usability only — **not** binary provenance
and **not** launch evidence. No readiness item moves.

## 7. Cross-document consistency

- The four artifact names appear consistently in the CI artifacts guide and the retention
  guide; `ANCHOR_DRIFT_REPORT.json` is referenced by the operator verification map and the
  artifact index.
- No package-integrity doc claims the Run 404 anchor manifest was "not edited" in Run 408.
- The readiness matrix carries a Run 409 row with **no** status change.

## 8. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain
OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.

## 9. Tests / checks

- `bash scripts/devnet/run_409_public_devnet_integrity_doc_consistency.sh` → `RESULT=POSITIVE`
  (18 checks).
- Consistency greps for anchor-refresh statements and three-vs-four artifact wording.
- Non-claim grep over the Run 409-authored/updated docs.
- Secret / private-material scan (clean).
- No Rust source changed → no `cargo test` delta; CodeQL is docs/shell-only (not meaningful).

## 10. Honest limitations

- This run reconciles documentation only; it does not verify the live CI upload at runtime,
  only the committed workflow definition and guides.
- The repository is a squashed/shallow clone, so the anchor-manifest truth was determined
  from the on-disk tree + the package-integrity refresh rule rather than isolating the Run
  408 commit.