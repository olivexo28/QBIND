# Run 406 evidence archive — public DevNet full-tree integrity CI artifact + anchor drift

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh` and
contains only publish-safe values: the CI artifacts guide SHA-256, the file-count,
and the OK / POSITIVE status lines. **No secret key, private material, generated
identity, data dir, raw log, raw metrics dump, private endpoint, or absolute path is
committed.** The generated full-tree manifest, the anchor-drift report, and the CI
summary are written to a staging directory **outside** the package tree (runner temp)
and are **never** committed — they are download-only CI artifacts.

Regenerate locally with:

```bash
bash scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh
```

**Decision gate = Route B** (docs + shell + YAML only; no production Rust source
change). Run 406 extends the Run 405 full-tree package integrity verifier so CI can
emit, as **download-only** artifacts:

- `PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json` — the transient full-tree
  manifest (produced by the Run 405 verifier);
- `ANCHOR_DRIFT_REPORT.md` — a publish-safe report comparing the Run 404 curated
  anchor manifest against the Run 405/406 full-tree file set;
- `PACKAGE_INTEGRITY_CI_SUMMARY.txt` — a short OK/POSITIVE status summary.

It adds `docs/release/public-devnet/PACKAGE_INTEGRITY_CI_ARTIFACTS.md` (the guide),
the harness, and updates the least-privilege
`.github/workflows/public-devnet-package-integrity.yml` to run the Run 406 wrapper and
upload only those three publish-safe artifacts (`permissions: contents: read`; no
secrets; no deploy/release/tag/commit/push).

The harness verifies (26 checks): the CI artifacts guide exists + is safety-labelled;
the Run 405 full-tree verifier still passes; the generated full-tree manifest
validates against the schema, covers every publish-safe file, and matches every
SHA-256 + byte size; the anchor-drift report is generated; every anchor entry exists
in the full-tree set; anchor hashes/sizes match or are documented deliberate
refreshes; full-tree-only files are reported as **expected curated-anchor drift**, not
a failure; the CI workflow uses `permissions: contents: read`, references no secrets,
has no deploy/release/tag/commit/push step, and uploads only the three publish-safe
artifact names; generated artifacts stay outside the tree and are never committed; the
working tree stays clean; the readiness matrix still shows **M4 🟡; M6 🟡; S5 🟡; S7
🟡**; the guide states public DevNet **NOT launch-ready** and **C4/C5 OPEN**; the
non-claim grep passes; and no secret / private material / absolute path / private
endpoint is committed.

The Run 404 anchor manifest (`PACKAGE_INTEGRITY_MANIFEST.example.json`) had its
SHA-256 + byte size **refreshed for exactly the three narrowly-edited anchor docs**
(`PACKAGE_INTEGRITY.md`, `ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`) so the
committed anchor manifest continues to match the on-disk tree — a documented
deliberate refresh, no entry added or removed, no `status` changed. The newly added
`PACKAGE_INTEGRITY_CI_ARTIFACTS.md` is a **full-tree-only** file (covered by the
full-tree manifest but intentionally not part of the 16 curated anchors), reported as
expected curated-anchor drift.

This run adds audit/reviewer usability **only**. It starts no node, opens no
externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status
service, changes no wire format, weakens no peer admission, enables no peer-driven
apply, adds no CLI flag, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No** readiness item
moves Green. **M4** stays Yellow/launch-blocking, **M6** stays Yellow/Partial, **S5**
and **S7** stay Yellow, public DevNet remains **NOT launch-ready**, and **C4/C5 remain
OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_406.md`.