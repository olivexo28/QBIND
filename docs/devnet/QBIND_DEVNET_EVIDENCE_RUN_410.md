# QBIND DevNet Evidence — Run 410

Public DevNet **package-integrity stale-prose lint** — a **read-only**, **docs + shell +
YAML only** run that adds a lightweight cross-document lint into the package-integrity
verification path so future docs runs **fail closed** if CI artifact counts, artifact
names, anchor-refresh wording, or generated-output claims drift again. It prevents
recurrence of the Run 406→409 documentation drift **without** adding a feature surface and
**without** moving any readiness item.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes
**no C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.

## 1. Exact verdict

`RESULT=POSITIVE` — public-DevNet package-integrity stale-prose lint. The lint is
documented, runs in CI after the existing verifier/wrapper, detects the Run 409-class drift
conditions, preserves least privilege, commits no generated/private material, and
introduces no readiness overclaim.

## 2. Objective

Turn the manual Run 409 reconciliation into an automated, fail-closed check. The lint
rejects: a stale "exactly three" current-artifact count; inconsistent artifact names across
the enumerating guides and the workflow; a missing `ANCHOR_DRIFT_REPORT.json`; a conflicting
or denied Run 408 anchor-refresh statement; a non-existent or mismatched manifest anchor; a
claim that a generated artifact is committed source; a claim that a download-only artifact
is binary provenance / a signed attestation / launch or readiness evidence; and any prose
implying M4/M6/S5/S7 Green, C4/C5 closure, TestNet/MainNet readiness, a deployment, or a
runtime mutation.

## 3. Decision gate route

**Route B.** Adding a documentation-consistency lint over already-recorded Run 404–409
package-integrity artifacts is operator/reviewer-facing consistency work — **docs + shell +
YAML only**, no new CLI surface, no source change, no runtime change. Route A (deploy to
change status) and Route C (defer) were not taken.

## 4. What changed

Created:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` — the safety-labelled
  lint guide.
- `scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh` — the
  read-only, fail-closed lint harness (`RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_410.md` (this file).
- `docs/devnet/run_410_public_devnet_package_integrity_stale_prose_lint/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `.github/workflows/public-devnet-package-integrity.yml` — runs the Run 410 lint after the
  Run 407 verifier/wrapper; still least-privilege (`contents: read`, no secrets, no
  deploy/release/tag/push/commit).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md`,
  `PACKAGE_INTEGRITY_CI_RETENTION.md`, `PACKAGE_INTEGRITY_DRIFT_HISTORY.md`,
  `PACKAGE_INTEGRITY.md`, `ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md` — reference the
  lint and (for the index/map) enumerate the current four artifact names.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256/byte size
  refreshed for exactly the three narrowly-edited anchor docs (`ARTIFACT_INDEX.md`,
  `OPERATOR_VERIFICATION_MAP.md`, `PACKAGE_INTEGRITY.md`); no entry added/removed, no
  `status` changed.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — Run 410 narrative row (no status
  change).
- `docs/whitepaper/contradiction.md` — Run 410 entry.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 5. Stale-prose lint guide contents

`PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` explains why the lint exists, the Run 409 drift it
prevents from recurring, the current four artifact names, the canonical Run 408
anchor-refresh statement, the forbidden stale phrases, what changes require updating the
lint expectations, and why the lint is not package integrity itself, not binary provenance,
and not launch evidence, plus why M4/M6/S5/S7 remain unchanged and C4/C5 remain OPEN.

## 6. Current artifact-count lint

The workflow uploads **exactly four** download-only artifacts
(`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`,
`ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`). The lint fails closed if the
workflow upload count is not four, or if any package-integrity doc carries stale "exactly
three" current-artifact wording.

## 7. Artifact-name consistency lint

The lint requires all four names to appear in the CI artifacts guide, the retention guide,
the operator verification map, the artifact index, and the workflow, and guards
`ANCHOR_DRIFT_REPORT.json` explicitly so it cannot be silently dropped.

## 8. Anchor-refresh consistency lint

Canonical statement: the Run 404 anchor manifest **was** refreshed in Run 408 for **exactly**
`ARTIFACT_INDEX.md` and `OPERATOR_VERIFICATION_MAP.md`; no entry added/removed; no status
changed. The lint fails closed if any doc denies the refresh or disagrees about which
anchors were refreshed.

## 9. Anchor manifest hash/size re-check

The lint re-hashes all 16 curated anchors against the on-disk tree and confirms every
SHA-256 + byte size matches and that `ARTIFACT_INDEX.md` and `OPERATOR_VERIFICATION_MAP.md`
each appear exactly once — no entry added or removed.

## 10. Generated-output non-commit lint

The lint confirms the CI artifacts guide, retention guide, and drift-history guide each
assert the generated full-tree manifest and drift reports are **never committed**, and fails
closed if any doc claims a generated artifact is a committed source artifact.

## 11. CI workflow integration + safety

The Run 410 lint runs **after** the Run 407 verifier/wrapper in
`.github/workflows/public-devnet-package-integrity.yml`. The workflow remains
least-privilege: `permissions: contents: read`, no secrets, no deploy/release/tag/push/commit
step, and a final guard that fails if the working tree is dirty after the checks. Nothing
generated is committed.

## 12. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain
OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.

## 13. Tests / checks

- `bash scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh` →
  `RESULT=POSITIVE`.
- Re-ran the Run 405 full-tree integrity verifier and the Run 409 consistency verifier as a
  regression after refreshing the three anchor entries — both `RESULT=POSITIVE`.
- Anchor manifest hash/size re-check, artifact count/name consistency grep, anchor-refresh
  consistency grep, generated-output non-commit grep, non-claim grep, and
  secret/private-material scan — all clean.
- No Rust source changed → no `cargo test` delta; CodeQL is docs/shell/YAML-only (not
  meaningful).

## 14. Honest limitations

- This run lints the **committed** workflow definition and guides; it does not observe the
  live CI upload at runtime.
- The lint encodes the **current** expected state (four artifacts, the canonical Run 408
  refresh, the Yellow M4/M6/S5/S7 posture). A legitimate future change to that state must
  update the lint's expectations in the same change, as documented in the guide.
- The repository is a squashed/shallow clone, so the anchor-manifest truth was determined
  from the on-disk tree + the package-integrity refresh rule rather than isolating a single
  historical commit.