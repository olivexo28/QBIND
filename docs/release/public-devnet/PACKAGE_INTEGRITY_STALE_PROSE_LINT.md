# QBIND Public DevNet — Package-Integrity Stale-Prose Lint (Run 410)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document explains the **cross-document stale-prose lint** that guards the public
DevNet **package-integrity** documentation and its CI workflow against silent drift. It
is a **read-only** verifier: it reads the committed guides, the anchor manifest, the
readiness matrix, the contradiction ledger, and the workflow, and **fails closed** if any
of them drift on the current CI artifact set, the canonical Run 408 anchor-refresh
statement, or the fixed readiness posture.

It is **docs + shell + YAML only**: running the lint deploys nothing, starts no node,
opens no port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness
item Green.

Companion files:

- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` — the Run 406 guide to
  the download-only CI artifacts.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md` — the Run 407 CI artifact
  retention policy.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_DRIFT_HISTORY.md` — the Run 408 retained
  drift-history comparator guide.
- `docs/release/public-devnet/ARTIFACT_INDEX.md` +
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — the navigation index and the
  operator verification map.
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — the Run 404
  curated **anchor** manifest (16 anchors).
- `.github/workflows/public-devnet-package-integrity.yml` — the least-privilege CI
  workflow that runs the verifier and, after it, this lint.
- `scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh` — the Run 410
  harness / lint.

## 1. Why this lint exists

The package-integrity documentation set grew across Runs 404–408 (anchor manifest →
full-tree verifier → download-only CI artifacts → machine-readable JSON drift report +
retention → retained drift-history comparator). Each expansion changed **counts**,
**artifact names**, and **anchor-refresh wording**, and the prose in one guide could — and
did — fall out of step with the others. Run 409 had to reconcile two concrete drifts by
hand. This lint turns that manual reconciliation into an automated, fail-closed check so
the same class of drift cannot silently return.

## 2. The Run 409 drift this lint prevents from recurring

Run 409 corrected two stale statements:

1. **Stale artifact count.** `PACKAGE_INTEGRITY_CI_ARTIFACTS.md` still said the workflow
   emitted **"exactly three"** current artifacts — the Run 406 behavior — even though
   Run 407 had already expanded the workflow to **four** artifacts by adding
   `ANCHOR_DRIFT_REPORT.json`.
2. **Stale anchor-refresh claim.** `QBIND_DEVNET_EVIDENCE_RUN_408.md` said the Run 404
   anchor manifest was **"not edited this run"**, contradicting the readiness matrix and
   the Run 408 contradiction entry, which correctly recorded that the manifest **was**
   refreshed for exactly the two narrowly-edited anchor docs.

This lint fails closed on both: it rejects any "exactly three" current-artifact wording,
requires the four current artifact names to be consistent across the enumerating guides
and the workflow, and rejects any statement that the anchor manifest was "not edited" in
Run 408.

## 3. The current four artifact names

The workflow uploads **exactly four** publish-safe, download-only artifacts, all
generated under the runner temp / staging directory (never under the repository tree):

1. `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`
2. `ANCHOR_DRIFT_REPORT.md`
3. `ANCHOR_DRIFT_REPORT.json`
4. `PACKAGE_INTEGRITY_CI_SUMMARY.txt`

The lint requires all four names to appear in `PACKAGE_INTEGRITY_CI_ARTIFACTS.md`,
`PACKAGE_INTEGRITY_CI_RETENTION.md`, `OPERATOR_VERIFICATION_MAP.md`, `ARTIFACT_INDEX.md`,
and the workflow, and requires the workflow to upload exactly these four (no more, no
fewer).

## 4. The canonical Run 408 anchor-refresh statement

The one canonical statement, which every doc must agree with, is:

> The Run 404 anchor manifest (`PACKAGE_INTEGRITY_MANIFEST.example.json`) **was** refreshed
> in Run 408 for **exactly** the two narrowly-edited anchor docs — `ARTIFACT_INDEX.md` and
> `OPERATOR_VERIFICATION_MAP.md`. **No entry was added or removed. No `status` changed.**

The lint fails closed if any doc denies that Run 408 refreshed the manifest, if any doc
disagrees about **which** anchors were refreshed, or if the on-disk manifest no longer
matches (any listed anchor file missing, or any SHA-256 / byte size mismatched).

## 5. What stale phrases are forbidden

The lint rejects, in the package-integrity docs:

- any "exactly three" (or "one of the three publish-safe") **current**-artifact wording;
- any claim denying that Run 408 refreshed the anchor manifest;
- any claim that a **generated** artifact (the full-tree manifest, either anchor-drift
  report, or the drift-history diff) is a **committed** source artifact;
- any claim that a **retained / download-only** artifact is **binary provenance**, a
  **signed attestation**, **launch evidence**, or **readiness evidence**;
- any claim that M4 / M6 / S5 / S7 moved **Green**;
- any claim that C4 / C5 is **closed**;
- any claim of **TestNet** or **MainNet** readiness;
- any claim that a seed / bootnode / faucet / RPC / explorer / status service was
  **deployed**, or that a port was opened or a node started;
- any claim of **runtime mutation** (validator set / epoch / sequence / marker /
  `LivePqcTrustState`).

## 6. What changes require updating the lint expectations

The lint encodes the **current** expected state. If a future run legitimately changes that
state, the lint's expectations must be updated in the same change:

- **Adding or removing a CI artifact** changes the count and the name set: update the
  four-name list and the "exactly four" count here and in the enumerating guides, the
  workflow, and the `ART*` constants in the harness.
- **A new deliberate anchor refresh** (editing any of the 16 curated anchor files) changes
  the canonical anchor-refresh statement and the manifest SHA-256 / byte size: update the
  statement here and refresh `PACKAGE_INTEGRITY_MANIFEST.example.json`.
- **A readiness change** (only ever via a real Route A deployment, not a docs run) would
  change the M4 / M6 / S5 / S7 / C4 / C5 expectations: update the readiness assertions.

Until such a change lands, the lint's expectations are frozen and drift fails the build.

## 7. Why this is not package integrity itself

Package integrity — the Run 404 anchor manifest and the Run 405 full-tree verifier —
answers *"are the documented package files present and unchanged?"* by hashing file
**bytes**. This lint answers a different question: *"does the package-integrity **prose**
still describe the current artifacts, counts, and anchor-refresh state consistently?"*. It
checks **wording consistency across documents**, not file-byte integrity. It re-hashes the
anchor manifest only to confirm the prose's anchor-refresh claim still matches the tree; it
does not replace the integrity verifiers.

## 8. Why this is not binary provenance

The lint reads **documentation** under `docs/release/public-devnet` and the workflow. It
embeds no binary and asserts no signed release or SLSA provenance. The release **binary**
is covered separately by
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` /
`RELEASE_ARTIFACT_MANIFEST.example.json` (Run 383/384). A prose-consistency lint is **not**
a signed attestation and **not** provenance.

## 9. Why this is not launch evidence

Passing the lint proves only that the package-integrity documentation and workflow are
internally consistent at check time. It does **not** deploy a seed, bootnode, faucet, RPC,
explorer, or status service; it opens no port, starts no node, applies no trust bundle, and
mutates no validator/epoch/sequence/marker/`LivePqcTrustState` state. Running the lint is
**not** a launch and does not make the public DevNet launch-ready. The launch decision
remains **NO-GO / NOT launch-ready** (`LAUNCH_GO_NO_GO.md`).

## 10. Why M4 / M6 / S5 / S7 remain unchanged

- **M4 (seed/bootnodes)** stays **Yellow / launch-blocking**: no real, externally
  reachable public DevNet seed with independent off-host reachability evidence exists.
  Linting documentation proves nothing about external reachability.
- **M6 (validator identity)** stays **Yellow / Partial**: generation + verification +
  non-mutating `register-check` are Green-for-scope; the live-registration half is M4-gated
  and durable-root reuse/rotation/revocation is C4/C5-deferred.
- **S5 (status page)** stays **Yellow**: a live status / aggregate health view is deferred
  until M4 / a live network.
- **S7 (seed-node runbook)** stays **Yellow**: operating a live seed remains M4-gated.

## 11. Why C4 / C5 remain OPEN

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation/revocation remains
**Red**. A documentation-prose lint closes, advances, or reinterprets nothing about the
contradiction ledger. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` for the closure
criteria and `docs/whitepaper/contradiction.md` for the ledger.

## 12. TestNet / MainNet non-claim

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
**No TestNet readiness and no MainNet readiness is claimed** anywhere in this guide, the
lint harness, or the CI workflow.
