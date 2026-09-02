# QBIND Public DevNet — Full-Tree Integrity CI Artifacts & Anchor Drift (Run 406)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **download-only CI artifacts** emitted by the public
DevNet package-integrity workflow. It extends the Run 405 **full-tree package
integrity verifier** (`PACKAGE_INTEGRITY_FULL_TREE.md`) so a reviewer can **download
and inspect** the generated full-tree manifest and a publish-safe **anchor-drift
report** from a CI run — **without** any generated output being committed to the
repository and **without** changing any readiness status.

It is **docs + shell + YAML only**: emitting these artifacts deploys nothing, starts
no node, opens no port, adds no CLI flag, changes no runtime behavior, and moves
**no** readiness item Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY.md` — the Run 404 **anchor** manifest
  guide (one `VERIFY.md` per group + the top-level docs; 16 curated anchors).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md` — the Run 405
  **full-tree** verifier guide (hashes every publish-safe file, transiently).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json` — the
  full-tree manifest JSON Schema (draft-07).
- `scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh` — the
  Run 406 harness / CI artifact wrapper.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` — the
  Run 407 **machine-readable** JSON anchor-drift report schema (draft-07).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` — the Run 407 CI
  artifact **retention** policy (download-only; convenience/audit usability only).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` +
  `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` +
  `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh` — the Run 408
  **local, non-mutating historical comparator** for two retained `ANCHOR_DRIFT_REPORT.json`
  artifacts (manual download; no auto-fetch; no token/secret; nothing committed).
- `.github/workflows/public-devnet-package-integrity.yml` — the least-privilege CI
  workflow that runs the verifier and uploads the artifacts.

> **Run 407 update:** the workflow now also emits a machine-readable
> `ANCHOR_DRIFT_REPORT.json` (validated against
> `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`) alongside the Markdown report —
> **four** download-only artifacts in total. Retention (`retention-days`) is
> convenience/audit usability only; see `PACKAGE_INTEGRITY_CI_RETENTION.md`.

## 1. What CI artifacts are emitted

The workflow uploads exactly **four** publish-safe, download-only artifacts, all
generated under the runner temp / staging directory (never under the repository
tree):

1. `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json` — the transiently-generated
   full-tree manifest produced by the Run 405 verifier: `manifest_version`,
   `generated_for_run`, `scope`, `coverage: full-tree`, the safety labels,
   `package_root`, `file_count`, and one minimal `relative_path` / `sha256` /
   `byte_size` entry per publish-safe file, plus the eleven non-claim booleans (all
   `false`).
2. `ANCHOR_DRIFT_REPORT.md` — a publish-safe Markdown report comparing the Run 404
   curated **anchor** manifest against the Run 405/406 **full-tree** file set (see
   §3–§4).
3. `ANCHOR_DRIFT_REPORT.json` — the machine-readable JSON counterpart of the Markdown
   report (Run 407), validated against
   `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`.
4. `PACKAGE_INTEGRITY_CI_SUMMARY.txt` — a short OK/POSITIVE status summary of the
   run (counts, pass/fail lines only).

## 2. Why they are download-only inspection artifacts, not committed source

The full-tree manifest and the anchor-drift report are **derived** from the on-disk
tree at verification time. Committing them would recreate the exact drift problem the
Run 405 guide already documents: a committed full-tree manifest would go stale on the
next docs edit, would have to hash itself, and would have to be regenerated and
re-committed in lockstep. The anchor-drift report is likewise a **point-in-time**
diff. Both are therefore produced into the runner temp / staging directory and
uploaded as **CI artifacts for download-only inspection** — the reviewer fetches them
from the workflow run, inspects them, and discards them. Only the **schema**, the
**guides**, and the **harness** are committed; there is no committed generated output
to drift.

## 3. How to interpret anchor drift

The anchor-drift report compares two coverage levels:

- the Run 404 **anchor** manifest (`PACKAGE_INTEGRITY_MANIFEST.example.json`) — a
  **curated** list of 16 stable anchors (one `VERIFY.md` per group + the top-level
  docs); and
- the Run 405/406 **full-tree** generated file set — **every** publish-safe file
  under `docs/release/public-devnet`.

For each anchor entry the report records whether it is:

- **present and matching** — the anchor's `sha256` + `byte_size` equal the full-tree
  entry for the same path (unchanged);
- **present but hash/size changed** — a mismatch, which is a **failure** *unless* the
  anchor manifest was **deliberately refreshed in the same run and documented** (see
  §4); or
- **missing from the full tree** — the anchor path is not present in the full-tree
  set, which is always a **failure**.

Separately, every full-tree file that is **not** represented in the curated anchor
manifest is listed as **full-tree-only** drift.

## 4. Why full-tree-only files are expected

The anchor manifest is **curated on purpose**: it lists one representative anchor per
artifact group plus the top-level package documents, not every file. The full-tree
set is exhaustive. Therefore **full-tree-only files are the expected, normal state**
— they are reported as **expected curated-anchor drift, not a failure**. A hash change
on an anchor file is only acceptable when that anchor file was narrowly edited in the
same change **and** its anchor entry was refreshed and documented in the same run
(the anchor manifest then matches the on-disk file, so the report shows it as
matching and notes it as a documented deliberate refresh). An **undocumented**
mismatch, or an anchor file that has disappeared from the full tree, is a failure.

## 5. What conditions fail the check

The check **fails** if:

- the Run 405 full-tree verifier does not pass;
- the generated full-tree manifest does not validate against the schema;
- the full-tree manifest omits (or adds) a publish-safe file, or any SHA-256 /
  byte-size does not match on-disk;
- an anchor entry is **missing** from the full-tree set;
- an anchor entry's hash/size mismatches the full-tree set **without** a documented
  deliberate refresh in the same run;
- the CI workflow requests more than `contents: read`, references a secret, or
  contains a deploy / release / tag / commit / push step;
- the workflow uploads an artifact whose name is not one of the four publish-safe
  names above;
- the working tree is dirty after the verifier (i.e. something generated was left in
  the tree);
- a non-claim / secret / private-material scan trips.

## 6. Why this is not binary provenance

These artifacts cover the **documentation package tree** under
`docs/release/public-devnet`. They answer *"are the documented package files present
and unchanged, and how does the curated anchor set relate to the full tree?"*. They
are **not** binary provenance. The release **binary** is covered separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384). No artifact here embeds a
binary or asserts a signed release or SLSA provenance.

## 7. Why this is not launch evidence

Uploading a manifest and a drift report as CI artifacts proves only that the
documentation tree hashes cleanly and that the curated anchors relate to the full
tree as expected, at verification time. It does **not** deploy a seed, bootnode,
faucet, RPC, explorer, or status service; it opens no port, starts no node, applies
no trust bundle, and mutates no validator/epoch/sequence/marker/`LivePqcTrustState`
state. Producing these artifacts is **not** a launch and does not make the public
DevNet launch-ready. The launch decision remains **NO-GO / NOT launch-ready**
(`LAUNCH_GO_NO_GO.md`).

## 8. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence
  exists. Emitting CI artifacts proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: generation + verification +
  non-mutating `register-check` are Green-for-scope; the live-registration half is
  M4-gated and durable-root reuse/rotation/revocation is C4/C5-deferred.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is
  deferred until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains
  M4-gated.

## 9. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. Emitting download-only integrity artifacts closes, advances, or reinterprets
nothing about the contradiction ledger. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the ledger.

## 10. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide,
the generated manifest, the anchor-drift report, or the CI workflow.