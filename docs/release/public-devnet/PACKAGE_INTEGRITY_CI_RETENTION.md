# QBIND Public DevNet — CI Artifact Retention Policy (Run 407)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains **retention** of the **download-only CI artifacts** emitted by
the public DevNet package-integrity workflow. It extends the Run 406 CI-artifacts guide
(`PACKAGE_INTEGRITY_CI_ARTIFACTS.md`) with a machine-readable **JSON** anchor-drift
report (`ANCHOR_DRIFT_REPORT.json`) alongside the existing Markdown report and states
what "retention" does — and does **not** — mean.

It is **docs + schema + shell + YAML only**: it deploys nothing, starts no node, opens
no port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness item
Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — the Run 406 guide to
  the download-only CI artifacts.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` — the
  Run 407 JSON anchor-drift report schema (draft-07).
- `scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh` — the Run 407
  harness / CI artifact wrapper.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` +
  `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` +
  `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh` — the Run 408
  **local, non-mutating historical comparator** for two retained `ANCHOR_DRIFT_REPORT.json`
  artifacts (manual download; no auto-fetch; no token/secret; nothing committed).
- `.github/workflows/public-devnet-package-integrity.yml` — the least-privilege CI
  workflow that runs the verifier and uploads the artifacts.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md` +
  `scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh` — the Run 410
  **stale-prose lint** that fails closed if this guide or the workflow drifts on the current
  four download-only artifact names, the "exactly four" count, the canonical Run 408
  anchor-refresh statement, or any readiness/closure/launch/provenance/runtime overclaim.

## 1. Which CI artifacts are retained

The workflow uploads exactly **four** publish-safe, download-only artifacts, all
generated under the runner temp / staging directory (never under the repository tree):

1. `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json` — the transiently-generated
   full-tree manifest (Run 405/406).
2. `ANCHOR_DRIFT_REPORT.md` — the human-readable Markdown anchor-drift report (Run 406).
3. `ANCHOR_DRIFT_REPORT.json` — the machine-readable JSON anchor-drift report (Run 407),
   validated against `PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`.
4. `PACKAGE_INTEGRITY_CI_SUMMARY.txt` — a short OK/POSITIVE status summary.

When the `actions/upload-artifact` action supports it, the workflow sets an explicit
`retention-days` value so a reviewer has a bounded window to download and inspect these
artifacts. That value is a convenience knob only (see §5–§7).

## 2. Retention is download-only and provider-dependent

Retention keeps the uploaded artifacts **downloadable** from the workflow run for a
bounded period. It is **download-only**: nothing is written back to the repository, no
release or tag is created, and no artifact is committed. The exact retention window is
**not** guaranteed by this repository — it depends on the CI provider's settings
(organization/repository retention caps, storage quotas, and manual deletion). The
`retention-days` value in the workflow is an upper bound the provider may further
restrict; treat any retained artifact as ephemeral.

## 3. How the JSON and Markdown drift reports differ

Both reports describe the **same** comparison — the Run 404 curated **anchor** manifest
against the Run 405/406 **full-tree** file set — and are produced from the same
classification, so their counts always agree.

- `ANCHOR_DRIFT_REPORT.md` is **human-readable**: prose summary, per-file bullet lists,
  and an explicit Failures section for reviewers reading the report directly.
- `ANCHOR_DRIFT_REPORT.json` is **machine-readable**: a schema-validated object with
  `counts` (`anchor_total`, `anchors_present_matching`, `anchors_missing`,
  `undocumented_mismatches`, `documented_refreshes`, `full_tree_only`) and the matching
  string arrays, plus `safety_labels` and eleven `non_claims` booleans (all `false`).
  It is intended for automated diffing, dashboards, or reviewer tooling.

The JSON report's `counts` equal the lengths of its arrays and equal the Markdown
summary counts; the harness fails if they disagree.

## 4. How to compare reports across runs manually

Because the reports are **not** committed, comparison is manual and download-based:

1. Open two workflow runs (for example, a base run and a candidate run).
2. Download each run's `ANCHOR_DRIFT_REPORT.json` artifact while it is still retained.
3. Diff the two JSON files (for example with `diff` or `jq`), focusing on the `counts`
   object and the `undocumented_mismatches` / `anchors_missing` arrays — both must stay
   empty for a POSITIVE report — and on the `full_tree_only` array to see which
   publish-safe files were added or removed between runs.
4. The Markdown report can be diffed the same way for a human-readable view.

There is no committed history to diff against; retention is what makes cross-run
comparison possible at all, within the provider's window.

## 5. Why retained artifacts are not committed source artifacts

The full-tree manifest and both drift reports are **derived** from the on-disk tree at
verification time. Committing them would recreate the drift problem the full-tree guide
already documents: a committed report would go stale on the next docs edit and would
have to be regenerated and re-committed in lockstep. Retaining them as **download-only**
CI artifacts keeps them inspectable **without** turning them into committed, drift-prone
source. Only the **schema**, the **guides**, and the **harness** are committed.

## 6. Why retention is not binary provenance

Retention keeps documentation-tree integrity reports downloadable; it says nothing about
the release **binary**. These artifacts embed no binary and assert no signed release or
SLSA provenance. Binary provenance is covered separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384). A retained CI artifact is
**not** a signed attestation and **not** provenance.

## 7. Why retention is not launch evidence

Retaining a manifest and drift reports as CI artifacts proves only that the
documentation tree hashes cleanly and that the curated anchors relate to the full tree
as expected, at verification time. It does **not** deploy a seed, bootnode, faucet, RPC,
explorer, or status service; it opens no port, starts no node, applies no trust bundle,
and mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state. Retention is
**not** a launch and does not make the public DevNet launch-ready. The launch decision
remains **NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 8. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence exists.
  Retaining CI artifacts proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: generation + verification +
  non-mutating `register-check` are Green-for-scope; the live-registration half is
  M4-gated and durable-root reuse/rotation/revocation is C4/C5-deferred.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is
  deferred until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains M4-gated.

## 9. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. Retaining download-only integrity artifacts closes, advances, or reinterprets
nothing about the contradiction ledger. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the ledger.

## 10. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide, the
generated manifest, the drift reports, or the CI workflow.