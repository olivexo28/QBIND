# QBIND DevNet Evidence — Run 415

Public DevNet **readiness artifact path/reference consistency lint** — a **read-only**,
**docs + shell only** run that extends the Run 412/413/414 status/coverage consistency lints (which
protect the readiness *rows*) to the **path/reference** layer beneath them, so the file paths and
verification commands that the readiness matrix, the artifact index, the operator verification map,
and the blocker register / launch gate name for public DevNet artifacts cannot silently drift away
from the actual publish-safe files under `docs/release/public-devnet`. It adds **no** feature
surface and moves **no** readiness item.

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes **no
C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.

## 1. Exact verdict

`RESULT=POSITIVE` — public-DevNet readiness artifact path/reference lint. The lint is documented and
confirms that every readiness-matrix §9/§10/§11/§16 `docs/release/…` evidence path, every
`ARTIFACT_INDEX.md` / `OPERATOR_VERIFICATION_MAP.md` `docs/release/public-devnet/…` package path
(that is not marked generated/transient), every named `scripts/devnet/run_*.sh` verification
command, and every matrix/ledger `docs/devnet/…` committed-evidence `.md` path resolves on disk;
that every package directory under `docs/release/public-devnet` is represented in the artifact index;
that every tracked publish-safe file is discoverable through the index / operator map / an indexed
package README/VERIFY / a documented exception; that the documented exceptions are well-formed and
safely protected; and that the three fail-closed self-tests (a moved readiness-matrix evidence path,
a package directory absent from the index, an undiscoverable public-DevNet file) all abort as
intended. It commits no generated/private material and introduces no readiness overclaim.

## 2. Files changed

Created:

- `docs/release/public-devnet/READINESS_ARTIFACT_PATH_REFERENCE_LINT.md` — the safety-labelled
  path/reference consistency lint guide.
- `scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh` — the read-only,
  fail-closed lint harness (`RESULT=POSITIVE`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_415.md` (this file).
- `docs/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint/{README.md,summary.txt,.gitignore}`.

Updated narrowly:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — added the Run 415 narrative row (no
  status change).
- `docs/whitepaper/contradiction.md` — Run 415 entry.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` and
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — reference the path/reference lint.
- `docs/release/public-devnet/READINESS_CROSS_SECTION_COVERAGE_LINT.md` — companion pointer to the
  new path/reference lint.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256 / byte size
  refreshed for exactly the two narrowly-edited anchor docs (`ARTIFACT_INDEX.md`,
  `OPERATOR_VERIFICATION_MAP.md`); no entry added/removed, no `status` changed.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B.** Adding a path/reference documentation-consistency lint over already-published readiness
documents is operator/reviewer-facing consistency work — **docs + shell only**, no new CLI surface,
no source change, no runtime change. Route A (deploy to change status) and Route C (defer) were not
taken.

## 4. Path/reference lint guide contents

`READINESS_ARTIFACT_PATH_REFERENCE_LINT.md` explains why the lint exists, which documents are
checked, which path classes are validated (readiness-matrix `docs/release/…` evidence paths,
index/operator-map `docs/release/public-devnet/…` package paths, named `scripts/devnet/run_*.sh`
verification commands, and matrix/ledger `docs/devnet/…` committed-evidence `.md` paths), how
generated/download-only/transient artifact names are excluded from the resolve check, how the
public-DevNet package tree is checked for discoverability, how exceptions work, how this extends
Runs 412–414, why M4 remains Yellow / launch-blocking, why M6 remains Yellow / Partial, why S5/S7
remain Yellow and M4-gated, why public DevNet remains NO-GO / NOT launch-ready, why C4/C5 remain
OPEN, why TestNet/MainNet remain untouched, how to update expectations when a future real Route A
run legitimately adds/moves/removes an artifact, why this is not launch evidence, and why this is
not C4/C5 closure evidence.

## 5. Checked documents

The readiness matrix (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`), the artifact index
(`ARTIFACT_INDEX.md`), the operator verification map (`OPERATOR_VERIFICATION_MAP.md`), the blocker
register (`BLOCKER_REGISTER.md`) and launch gate (`LAUNCH_GO_NO_GO.md`) where they name public
DevNet artifacts, the contradiction ledger (`contradiction.md`) for committed evidence paths, and
the actual publish-safe file tree under `docs/release/public-devnet`.

## 6. Readiness-matrix evidence-path check

The harness extracts every full `docs/release/…` token from the readiness matrix §9/§10/§11/§16 and
fails closed unless each resolves on disk. Bare filenames (relative to nearby package context) and
`crates/…` source paths are intentionally not validated as release artifacts.

## 7. Artifact-index package-path check

The harness extracts every `docs/release/public-devnet/…` token from the artifact index and fails
closed unless each resolves on disk **or** its line explicitly marks it generated / download-only /
transient / not committed.

## 8. Operator-map reference check

The harness applies the same `docs/release/public-devnet/…` resolve check (with the same
generated/transient allowance) to the operator verification map.

## 9. Script-reference check

Every `scripts/devnet/run_*.sh` command named in the artifact index or operator verification map
must resolve on disk; a named verification command that does not exist fails closed.

## 10. Evidence `.md` path check

Every `docs/devnet/…` committed-evidence `.md` token named in the readiness matrix or the
contradiction ledger must resolve on disk. Transient run-directory subpaths (which the ledger
mentions but never commits) are outside this file-token check.

## 11. Package-tree representation check

Every package directory under `docs/release/public-devnet` (the directories that hold a
README/VERIFY group) is represented in the artifact index, so a whole published package group cannot
be dropped from the index without detection.

## 12. Discoverability check

Every tracked publish-safe file under `docs/release/public-devnet` is discoverable: its basename
appears in the artifact index **or** the operator verification map, **or** it is covered by an
indexed package README/VERIFY, **or** it is a documented exception. A tracked file that is
discoverable through none of these fails closed.

## 13. Exception model

The guide §11 exception table lists exactly the files that are intentionally not named directly in
the index / operator map. Each row carries a relative path, a reason, and the indexed parent that
protects it. The harness parses the table and fails closed if a row is malformed (missing path /
reason / protecting parent).

## 14. Exception-set exactness

The set of tracked publish-safe files that are **not** discoverable via the index / operator map /
an indexed package README/VERIFY must equal **exactly** the documented exception set — a stale
exception (for a file that is now discoverable or deleted) or a missing exception (for a new
undiscoverable file) both fail closed. The current exception set is the six
`network/reachability/RUN_*_qbind-devnet-seed-1.md` seed-reachability evidence templates, each
protected by the `ARTIFACT_INDEX.md` §6 network group and
`SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`.

## 15. Exception blocker-safety

Any exception row that names an M4/M6/S5/S7 path must also carry `Yellow` / `M4-gated` /
`launch-blocking`, and any row that names a C4/C5 path must carry `OPEN`, so an exception cannot
quietly hide a launch-blocking or open-blocker artifact. The six reachability rows each carry M4 /
Yellow / launch-blocking.

## 16. Launch NO-GO consistency

Neither the artifact index nor the operator map claims public DevNet is launch-ready / GO; the
readiness matrix keeps "public DevNet remains NOT launch-ready" and the launch gate remains
**NO-GO / NOT launch-ready**.

## 17. C4/C5 consistency

No checked document claims a C4/C5 closure; the guide and this evidence keep **C4 remains OPEN** and
**C5 remains OPEN**; the readiness matrix keeps "C4 and C5 remain OPEN".

## 18. TestNet/MainNet non-claims

No checked or Run 415-authored document claims TestNet/MainNet readiness; the readiness matrix keeps
N1–N7 Red; TestNet/MainNet untouched.

## 19. No live devnet-seeds.live.json claim

No Run 415-authored line claims a live `devnet-seeds.live.json` exists or may be created without
real M4 evidence.

## 20. Deployment/runtime non-claim

No Run 415-authored line claims a live seed/bootnode/faucet/RPC/explorer/status-service deployment,
and no line claims a validator/epoch/sequence/marker/`LivePqcTrustState` mutation.

## 21. Generated-output behavior

The harness writes only a transient `summary.txt`, extracted path lists, and self-test scratch
copies into a staging directory **outside** the repository tree (runner temp). Nothing generated is
committed; the working-tree snapshot is identical before and after the run.

## 22. Non-claim checks

The normalized non-claim grep over the Run 415-authored docs (guide + this evidence) finds no
launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment /
runtime-mutation claim.

## 23. Security scans

Secret / private-material scan and absolute-path scan over the Run 415 docs are clean; no
keys/certs/KEM/signing/API material, no data dirs, no raw logs/metrics, no private identity, no
absolute path.

## 24. Runtime mutation check

**NONE.** Run 415 is docs + shell only: it opens no port, starts no node, applies no trust bundle,
and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state.

## 25. Readiness delta

**None.** M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet remains NOT launch-ready / NO-GO; C4/C5 remain OPEN;
MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.

## 26. M4 status

**Yellow / launch-blocking.** No real, externally reachable seed with off-host reachability evidence
exists (Route-C finding, Runs 378/388/391/393); no `devnet-seeds.live.json` is published.

## 27. M6 status

**Yellow / Partial.** Generation/verification + `register-check` are Green-for-scope; live
registration is M4-gated and operator-root reuse/rotation/revocation is C4/C5-deferred.

## 28. S5/S7 status

**Yellow.** S5 (status page) live health view is M4-gated; S7 (seed-node runbook) live seed
operation is M4-gated.

## 29. Public DevNet status

**NOT launch-ready / NO-GO.** At least one must-have (M4) is not Green.

## 30. C4/C5

**C4 OPEN. C5 OPEN.** MainNet authority rotation/revocation remains Red.

## 31. TestNet/MainNet non-claims

No TestNet or MainNet readiness is claimed; N1–N7 remain Red; TestNet/MainNet untouched.

## 32. Discoverability exceptions

The only publish-safe files not named directly in the index / operator map are the six
`network/reachability/RUN_*_qbind-devnet-seed-1.md` seed-reachability evidence templates, protected
by the `ARTIFACT_INDEX.md` §6 network group and `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`; each is an
M4 / Yellow / launch-blocking artifact and is recorded as such in the guide §11 exception table.

## 33. Anchor manifest refresh

Exactly the two narrowly-edited anchor docs — `ARTIFACT_INDEX.md` and `OPERATOR_VERIFICATION_MAP.md`
— had their SHA-256 and byte-size refreshed in `PACKAGE_INTEGRITY_MANIFEST.example.json`; no entry
was added/removed and no `status` field changed, so the Run 404/405 package-integrity checks stay
consistent.

## 34. Tests run

- `bash scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh` →
  `RESULT=POSITIVE`.
- Three built-in fail-closed self-tests confirmed the checks abort on: a moved/renamed
  readiness-matrix evidence path, a package directory absent from the index, and an undiscoverable
  public-DevNet file — each run against a temporary copy **outside** the repository tree, with the
  working tree left clean.
- Re-ran the Run 414 cross-section coverage lint, the Run 413 recommendation/gap-matrix lint, the
  Run 412 status/blocker lint, the Run 411 cross-ledger lint, the Run 410 stale-prose lint, and the
  Run 405 full-tree integrity verifier as regressions after refreshing the two anchor entries — all
  `RESULT=POSITIVE`.
- No Rust source changed → no `cargo test` delta.

## 35. CodeQL

Docs/shell only → CodeQL is not meaningful (no Rust/`build.rs`/`Cargo.toml`/source change).

## 36. Honest limitations

- The lint verifies that named paths **resolve** and that published files are **discoverable**; it
  does not verify the natural-language accuracy of each reference beyond path existence and
  basename discoverability.
- Discoverability is keyed by basename appearing in the index / operator map / an indexed package
  README/VERIFY / a documented exception; a legitimately new undiscoverable file requires either a
  reference or a new exception row in the same change.
- The exception set (the six reachability evidence templates) is frozen; a legitimate future change
  that makes one discoverable, deletes one, or adds a new intentional exception must update the
  guide §11 table (and hence the harness's exception-set assertion) in the same change.
- The generated/download-only/transient allowance is line-scoped; a package path that is genuinely
  committed but sits on a line that also mentions a transient sibling could be skipped — the
  guide documents the wording the allowance keys on.
- The repository is a squashed/shallow clone, so path resolution is verified from the on-disk tree
  rather than by isolating individual historical commits.

## 37. Suggested Run 416

A **verification-command coverage lint** that asserts every `scripts/devnet/run_*.sh` harness under
`scripts/devnet` that is meant to be operator-runnable is named by at least one of the readiness
matrix / artifact index / operator verification map (and vice-versa), closing the residual gap
between "the referenced scripts resolve" (Run 415) and "every publish-relevant script is
referenced" — still **docs + shell only**, still moving no readiness item and keeping C4/C5 OPEN.
