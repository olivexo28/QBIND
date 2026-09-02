# QBIND Public DevNet — Retained Anchor-Drift History Comparator (Run 408)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **local, non-mutating historical comparator** for **retained**
`ANCHOR_DRIFT_REPORT.json` artifacts. It lets an operator/reviewer compare **two**
downloaded Run 407-style JSON drift reports (a *base* and a *candidate*) and produce a
**publish-safe transient diff summary** — **without** fetching CI artifacts automatically,
**without** using any token or secret, **without** committing generated output, and
**without** changing any readiness status.

It is **docs + schema + shell only**: it deploys nothing, starts no node, opens no port,
adds no CLI flag, changes no runtime behavior, and moves **no** readiness item Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` — the Run 407 CI artifact
  **retention** policy (download-only; convenience/audit usability only).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — the Run 406 guide to the
  download-only CI artifacts (full-tree manifest + Markdown/JSON anchor-drift reports).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json` — the
  Run 407 **input** report schema (draft-07); both comparator inputs must validate.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json` — the
  Run 408 **diff** schema (draft-07); the comparator output validates against it.
- `scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh` — the Run 408
  harness / local comparator.

## 1. How to download two retained `ANCHOR_DRIFT_REPORT.json` artifacts manually

The JSON drift reports are **not** committed; they are **download-only** CI artifacts
retained for a bounded, provider-dependent window (see `PACKAGE_INTEGRITY_CI_RETENTION.md`).
To compare two of them:

1. Open the workflow run you want as the **base** (for example, an older run of the
   public DevNet package-integrity workflow), open its **Artifacts** section in the CI web
   UI, and **download** the `ANCHOR_DRIFT_REPORT.json` artifact by hand.
2. Open the workflow run you want as the **candidate** (for example, the latest run) and
   download **its** `ANCHOR_DRIFT_REPORT.json` the same way.
3. Save the two files to a scratch directory **outside** the repository tree (for example
   under your system temp directory), e.g. `base/ANCHOR_DRIFT_REPORT.json` and
   `candidate/ANCHOR_DRIFT_REPORT.json`.

The download is **manual and interactive**. The comparator never fetches artifacts for
you: it takes no repository/run identifiers, performs no network call, and requires **no**
GitHub token or secret. Retained artifacts are **provider-dependent and may expire**; if a
run's artifact has aged out of the provider's retention window, it can no longer be
compared.

## 2. How to run the local comparator

Point the harness at a scratch directory outside the repository tree. With no
pre-supplied inputs it **generates** two Run 407-style fixture reports (and reuses the
Run 407 wrapper to prove input-schema compatibility); to compare **your** two downloaded
reports, place them where the harness expects (or pass a base and candidate path if you
adapt the invocation) and re-run:

```bash
bash scripts/devnet/run_408_public_devnet_retained_drift_history_comparator.sh
```

The harness validates both inputs against
`PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json`, compares their `counts` and path
arrays, emits a transient `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json` **outside** the
repository tree, validates that diff against
`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`, prints the verdict, and exits non-zero
if the verdict is any of the three negative verdicts. Nothing it generates is committed.

## 3. How to interpret added / removed full-tree-only paths

The diff's `path_delta.added_full_tree_only` lists publish-safe files present in the
**candidate** report's `full_tree_only` array but not the **base** report's;
`path_delta.removed_full_tree_only` lists files present in the base but not the candidate.
These are files that entered or left the **full-tree** set between the two runs while
**not** being curated anchors — for example, a new package document added since the base
run, or a document that was renamed/removed.

## 4. Why full-tree-only drift can be expected

The Run 404 anchor manifest is **curated on purpose**: it lists one representative anchor
per artifact group plus the top-level package documents, not every file. The full-tree set
is exhaustive. So the package tree legitimately grows and changes between runs, and
`full_tree_only` legitimately changes with it. Added/removed full-tree-only paths are
therefore **reported as expected curated-anchor drift** in the diff and are **not** a
failure by themselves. The comparator surfaces them for a reviewer's eyes; it does not
fail on them.

## 5. Why missing anchors or undocumented mismatches remain failures

A **new missing anchor** (a curated anchor present in the candidate's `anchors_missing`
but not the base's) means a documented anchor file has disappeared from the full tree. A
**new undocumented mismatch** (a curated anchor present in the candidate's
`undocumented_mismatches` but not the base's) means an anchor file's hash/size changed
**without** a documented deliberate refresh. Both are **failures** in the source Run 407
reports, and both make the historical diff **fail closed**: the verdict becomes
`negative-new-missing-anchor` or `negative-new-undocumented-mismatch` and the comparator
exits non-zero. A report that itself has invalid input (schema-invalid, `non_claims` not
all false, or an unsafe/private path) yields `negative-invalid-input` and also fails
closed.

## 6. Why the comparator is not binary provenance

The comparator compares **documentation-tree** anchor-drift reports under
`docs/release/public-devnet`. It answers *"how did the curated-anchor-vs-full-tree drift
change between two runs?"*. It embeds no binary and asserts no signed release or SLSA
provenance. The release **binary** is covered separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384). A drift-history diff is **not** a
signed attestation and **not** provenance.

## 7. Why the comparator is not launch evidence

Comparing two retained drift reports proves only that the documentation-tree drift
classification changed (or did not change) as expected between two verification times. It
does **not** deploy a seed, bootnode, faucet, RPC, explorer, or status service; it opens
no port, starts no node, applies no trust bundle, and mutates no
validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the comparator is
**not** a launch and does not make the public DevNet launch-ready. The launch decision
remains **NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 8. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence exists.
  Diffing retained drift reports proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: generation + verification +
  non-mutating `register-check` are Green-for-scope; the live-registration half is
  M4-gated and durable-root reuse/rotation/revocation is C4/C5-deferred.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred
  until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains M4-gated.

## 9. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. Comparing download-only integrity reports closes, advances, or reinterprets
nothing about the contradiction ledger. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure criteria and
`docs/whitepaper/contradiction.md` for the ledger.

## 10. Retained artifacts are provider-dependent and may expire

Cross-run comparison is only possible while **both** reports are still retained. The
`retention-days` value is an upper bound the CI provider may further restrict, and
manual deletion or storage-quota policy can remove an artifact sooner. Treat any retained
`ANCHOR_DRIFT_REPORT.json` as **ephemeral**: if either the base or candidate artifact has
expired, that historical comparison can no longer be performed. The comparator never
re-fetches or reconstructs an expired artifact.

## 11. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide, the
diff schema, the generated diff, or the comparator.
