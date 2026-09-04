# QBIND Public DevNet — Readiness Artifact Path / Reference Consistency Lint (Run 415)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **artifact path / reference consistency lint** that keeps the QBIND
public DevNet release package's cross-document **references** in step with the files that actually
exist on disk. Runs 411–414 keep the readiness **status** and **coverage** views internally
consistent; this Run 415 lint protects the layer beneath them — the **paths** those documents name.
It catches path/reference **drift** between:

- the readiness matrix (`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`);
- the public DevNet artifact index (`ARTIFACT_INDEX.md`);
- the operator verification map (`OPERATOR_VERIFICATION_MAP.md`);
- the blocker register / launch gate where they name public DevNet artifacts; and
- the actual publish-safe files under `docs/release/public-devnet`.

It is a **read-only** verifier: it reads the committed documents and **fails closed** if a
readiness-matrix evidence path, an artifact-index package path, an operator-map verification
reference, or a named verification script no longer resolves on disk, if a published public-DevNet
artifact is not discoverable through the index / operator map / an indexed package README/VERIFY / a
documented exception, or if any reference introduces a readiness / launch / deployment / runtime /
C4-C5-closure overclaim.

It is **docs + shell only**: running the lint deploys nothing, starts no node, opens no port, adds
no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Compared documents:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical readiness matrix. Its
  **§9 owner / source file / evidence location**, **§10 current-status table**, **§11 next-run
  recommendation table**, and **§16 consolidated gap matrix** name `docs/release/…` evidence paths
  that must resolve on disk.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` — the navigation index: its package paths and
  named verification commands must resolve, and every package directory must be represented.
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — the verification map: its read-order
  and verification references must resolve.
- `docs/release/public-devnet/BLOCKER_REGISTER.md` and
  `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — checked to exist and to keep the NO-GO /
  M4/M6/S5/S7 posture where they name public DevNet artifacts.
- `docs/whitepaper/contradiction.md` — the per-run contradiction ledger; its `docs/devnet/…`
  committed-evidence references are checked to resolve.

Companion files:

- `docs/release/public-devnet/READINESS_CROSS_SECTION_COVERAGE_LINT.md` — the Run 414
  cross-**section coverage** lint (the *set* of status-bearing rows that must exist). This Run 415
  lint is its path/reference companion: Run 414 protects which rows must exist; Run 415 protects
  that the file paths those rows and the package index name actually resolve.
- `docs/release/public-devnet/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md` — the Run 413 §11/§16
  **status** lint.
- `docs/release/public-devnet/READINESS_STATUS_BLOCKER_LINT.md` — the Run 412 per-**milestone**
  status/blocker lint.
- `docs/release/public-devnet/READINESS_CONTRADICTION_LEDGER_LINT.md` — the Run 411 cross-**ledger**
  run-narrative lint.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh` — the Run 415
  harness / lint.

## 1. Why this lint exists

The public DevNet package is now a web of cross-references: the readiness matrix cites evidence
paths, the artifact index lists package paths and verification commands, and the operator map
points reviewers at specific files. Runs 411–414 keep the **status** and **coverage** of the
readiness rows consistent, but none of them checks that a cited **path** still exists. A file that
is moved or renamed — or a package that is added — without updating every document that names it
would leave a **dangling reference** or an **undiscoverable artifact**: an operator following the
matrix or the index would hit a missing file, or a published file would never be reachable from the
index. Run 415 adds a lightweight **path/reference** lint so this drift fails closed: every
readiness-matrix evidence path and artifact-index package path must resolve on disk, and every
published public-DevNet artifact must be discoverable through the index, the operator map, an
indexed package README/VERIFY, or an explicitly documented exception.

## 2. Which documents are checked

- the **readiness matrix** — its §9 / §10 / §11 / §16 `docs/release/…` evidence paths;
- the **artifact index** — its `docs/release/public-devnet/…` package paths, its
  `scripts/devnet/run_*.sh` verification commands, and its package-directory coverage;
- the **operator verification map** — its `docs/release/public-devnet/…` references and any
  `scripts/devnet/run_*.sh` verification commands;
- the **blocker register** and **launch go/no-go gate** — checked to exist and to keep the NO-GO /
  M4/M6/S5/S7 posture;
- the **contradiction ledger** — its `docs/devnet/…` committed-evidence `.md` references.

## 3. Which path classes are validated

Only **repository-relative** paths are validated. In scope:

- `docs/release/…` and `docs/release/public-devnet/…` paths named as release artifacts;
- `scripts/devnet/run_*.sh` paths named as verification commands;
- `docs/devnet/…` `.md` evidence paths named by the readiness matrix or the contradiction ledger.

Explicitly **out of scope**: external URLs; absolute filesystem paths (which are forbidden anyway);
generated / download-only / transient artifact names that the surrounding prose clearly marks as
**not committed source** (e.g. `ANCHOR_DRIFT_REPORT.json`,
`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`,
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json`, the CI summary); and `crates/…` or other source paths
that are not release artifacts. The lint never executes any referenced script except the Run 415
harness itself and the explicitly listed regressions.

## 4. How readiness-matrix evidence paths are checked

The harness extracts the §9, §10, §11, and §16 section blocks from the readiness matrix and pulls
every `docs/release/…` token (file or directory). Each must resolve on disk (a directory token such
as `docs/release/public-devnet/network/` must be an existing directory; a file token must be an
existing file). A missing evidence path fails closed. Bare filenames written relative to a nearby
package path (e.g. `RELEASE_PROVENANCE.md` inside a `docs/release/public-devnet/binary/` context)
are intentionally **not** treated as repository-relative paths and are not validated here.

## 5. How artifact-index paths are checked

The harness pulls every `docs/release/public-devnet/…` token from `ARTIFACT_INDEX.md`. Each must
resolve on disk, **unless** the same line explicitly describes it as generated / download-only /
transient / never committed — in which case it is a valid reference to an intentionally-uncommitted
artifact and is allowed to be absent. Every package **directory** under `docs/release/public-devnet`
must additionally be represented in the index (its `name/` path listed); a package directory that
is silently absent from the index fails closed.

## 6. How operator-map verification references are checked

The harness pulls every `docs/release/public-devnet/…` token from `OPERATOR_VERIFICATION_MAP.md`.
Each must resolve on disk under the same generated/transient allowance as the index. This keeps the
recommended read orders and the exact verification map pointing at files that exist.

## 7. How script references are checked

Every `scripts/devnet/run_*.sh` token named as a verification command in `ARTIFACT_INDEX.md` or
`OPERATOR_VERIFICATION_MAP.md` must resolve on disk. (The operator map's `run_NNN…` shorthand — an
ellipsis, not a full filename — is prose, not a repository-relative path, and is not validated as a
file; only fully-qualified `scripts/devnet/run_*.sh` paths are.) The lint does **not** execute these
scripts.

## 8. How generated / download-only / transient artifact names are handled

Some referenced names are **not** committed source: they are produced transiently by a verifier or
uploaded as download-only CI artifacts and are deliberately absent from the tree. The lint treats a
`docs/release/public-devnet/…` path that fails to resolve as an **allowed** reference only when the
nearby prose clearly marks it generated / download-only / transient / never committed. It never
requires such an artifact to exist in the repository, and it never treats one being absent as
drift. It also never requires transient manifests, transient drift reports, or CI downloads to be
committed.

## 9. How public-DevNet package-tree discoverability is checked

Every publish-safe file currently tracked under `docs/release/public-devnet` must be **discoverable**
through at least one of:

1. the `ARTIFACT_INDEX.md` path / group listing (its basename or containing package path appears in
   the index);
2. the `OPERATOR_VERIFICATION_MAP.md` verification map or cross-reference (its basename appears in
   the map);
3. a package-level README / VERIFY file that is itself indexed; or
4. an explicit linted exception in the exception table (§11 below).

A tracked publish-safe file that is reachable by none of these fails closed — it would be an
orphaned artifact no operator could find from the index.

## 10. How exceptions work

Discoverability exceptions are **narrow** and **documented**. Each exception row records:

- the **relative path** (under `docs/release/public-devnet`) it covers;
- the **reason** the file is intentionally not individually listed in the top-level index; and
- the **protecting indexed parent document** through which the file is still reachable.

Acceptable exceptions are things like per-record evidence files or schema/example files that are
intentionally referenced by their containing package guide rather than individually enumerated in
the top-level index. An exception may **never** be used to hide a blocker-critical artifact path for
M4, M6, S5, S7, C4, or C5 without explicit Yellow / OPEN protection: if an exception row names one
of M4/M6/S5/S7 it must also carry the Yellow / M4-gated / launch-blocking qualifier, and if it names
C4/C5 it must also carry OPEN. A malformed exception (missing path, reason, or protecting parent)
fails closed.

## 11. Discoverability exception table

| Relative path | Reason not individually indexed | Protecting indexed parent document |
|---------------|--------------------------------|------------------------------------|
| `network/reachability/RUN_377_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |
| `network/reachability/RUN_378_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |
| `network/reachability/RUN_388_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |
| `network/reachability/RUN_391_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |
| `network/reachability/RUN_393_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |
| `network/reachability/RUN_397_qbind-devnet-seed-1.md` | Per-seed reachability **evidence record** for the M4 Route-C investigation; referenced collectively by the network package, not individually enumerated in the top-level index. **M4 stays Yellow / launch-blocking**; no live seed. | `ARTIFACT_INDEX.md` §6 network group (lists `network/reachability/`) + `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` |

All six exceptions are M4 evidence records under the **indexed** `network/reachability/` path; each
keeps M4 explicitly **Yellow / launch-blocking**, so none of them hides a blocker-critical artifact
without protection. No other public-DevNet file needs an exception today: every other tracked file's
basename (or containing package path) already appears in the artifact index or the operator map.

## 12. How this extends Runs 412–414

- **Run 412** keeps the §10 status table in step with the §4/§5 checklists, the blocker register,
  and the launch gate (per-milestone **status**).
- **Run 413** keeps the §11 recommendation and §16 gap-matrix status glyphs equal to §10
  (per-row **status**).
- **Run 414** keeps the *set* of status-bearing §11/§16 rows complete against §10 (**coverage**).
- **Run 415** keeps the **paths** those documents name resolvable, and keeps every published
  public-DevNet artifact **discoverable** (**path/reference** integrity). Together the four runs
  make the readiness documents fail closed on status drift, row deletion, **and** dangling / orphan
  file references.

## 13. Why M4 remains Yellow / launch-blocking

**M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally reachable public
DevNet seed with independent off-host reachability evidence exists (Runs 378/388/391/393 all reached
the Route C finding — no independent off-host vantage in the sandbox — so external TCP + KEMTLS
reachability is **NOT proven** and **no `devnet-seeds.live.json` is published**). A path/reference
check proves nothing about external reachability; it only checks that the M4 evidence files the
matrix cites exist. M4 remains the primary launch blocker.

## 14. Why M6 remains Yellow / Partial

**M6 (validator identity)** stays **Yellow / Partial**: the generation + verification and the
non-mutating `register-check` halves are Green-for-scope, but the **live-registration** half is
**M4-gated** and operator-supplied durable-root reuse / rotation / revocation is **C4/C5-deferred**.
This lint validates the M6 identity-package paths resolve; it moves nothing.

## 15. Why S5 / S7 remain Yellow and M4-gated

- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred until
  M4 / a live network; only a publish-safe static decision + schema is published.
- **S7 (seed-node runbook)** stays **Yellow**: the runbook + M4 Route-A checklist + evidence
  template are published, but operating a real live seed is **M4-gated**. The S7 reachability
  evidence records are the documented §11 exceptions, each kept explicitly M4 / Yellow.

## 16. Why public DevNet remains NO-GO / NOT launch-ready

Per the launch gate's go/no-go rule, launch requires **every** must-have (M1–M20) Green **and**
launch explicitly in scope. Because **M4** is Yellow and **M6** is Yellow / Partial, and launch is
**not** in scope for Run 415 (docs + shell only), the decision remains **NO-GO / NOT launch-ready**
(`LAUNCH_GO_NO_GO.md`). No checked document may state otherwise.

## 17. Why C4 / C5 remain OPEN

A path/reference check closes, advances, or reinterprets **nothing** about the protocol
contradictions. **C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. The lint only verifies the readiness
documents keep saying so — it cannot make them closed.

## 18. Why TestNet / MainNet remain untouched

TestNet and MainNet remain **untouched**; readiness items **N1–N7 remain Red** (with N5 tied to C4
OPEN / Red and N6 tied to C5 OPEN / Red). **No TestNet readiness and no MainNet readiness is
claimed** in any checked document, this guide, or the lint harness.

## 19. How to update expectations when a future real Route A run adds / removes / moves artifacts

The lint encodes the **current** file layout and the **current** frozen posture (M4/M6/S5/S7 Yellow;
NO-GO; C4/C5 OPEN; N1–N7 Red). A real readiness change happens only via a genuine **Route A**
deployment with evidence — never via a docs run. When a future run legitimately **adds, removes, or
moves** a public-DevNet artifact:

- add / rename / remove the file **and** update every document that names it — the readiness matrix
  evidence path, the artifact index package listing, the operator verification map, and any package
  README/VERIFY — in the **same** change, so no reference dangles and no new file is undiscoverable;
- if the new file is intentionally not enumerated in the top-level index, add a narrow
  **exception** row to §11 with its relative path, reason, and protecting indexed parent (and, if it
  touches M4/M6/S5/S7/C4/C5, keep the explicit Yellow / OPEN protection);
- if an edited file is one of the 16 curated package-integrity anchors, refresh exactly that
  anchor's SHA-256 / byte size in `PACKAGE_INTEGRITY_MANIFEST.example.json` (per the package
  integrity guides), without adding or removing manifest entries.

Until such a change lands, the lint's expectations are frozen and any dangling reference,
undiscoverable file, or missing package row fails the build.

## 20. Why this is not launch evidence

Passing the lint proves only that the readiness documents' cited paths resolve and that every
published public-DevNet artifact is discoverable. It does **not** deploy a seed, bootnode, faucet,
RPC, explorer, or status service; it opens no port, starts no node, applies no trust bundle, and
mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the lint is **not** a
launch and does not make public DevNet launch-ready. The launch decision remains **NO-GO / NOT
launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 21. Why this is not C4/C5 closure evidence

A path/reference consistency check closes, advances, or reinterprets **nothing** about C4 or C5.
**C4 remains OPEN. C5 remains OPEN.** The lint only verifies that the readiness documents continue
to say so — it does not and cannot make them closed.