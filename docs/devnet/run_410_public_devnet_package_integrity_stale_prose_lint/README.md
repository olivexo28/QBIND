# Run 410 evidence archive — public DevNet package-integrity stale-prose lint

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh` and contains
only publish-safe values: OK / POSITIVE / NONE status lines for each lint check. **No
secret key, private material, generated identity, data dir, raw log, raw metrics dump,
private endpoint, or absolute path is committed.**

The Run 410 harness is a **read-only**, fail-closed cross-document lint over the public
DevNet package-integrity documentation and its CI workflow. It guards against the drift
class that Run 409 reconciled by hand: it rejects stale "exactly three" artifact wording,
inconsistent artifact names, a conflicting Run 408 anchor-refresh statement, non-existent
or mismatched manifest anchors, and any readiness/closure/launch/provenance/runtime
overclaim. It generates nothing under the repository tree; any transient output is written
to a staging directory **outside** the package tree (runner temp) and is **never**
committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_410_public_devnet_package_integrity_stale_prose_lint.sh
```

**Decision gate = Route B** (docs + shell + YAML only; no production Rust source change, no
`build.rs` change, no `Cargo.toml` change, no CLI flag, no runtime change).

## What the lint checks

- The stale-prose lint guide (`PACKAGE_INTEGRITY_STALE_PROSE_LINT.md`) exists and is
  safety-labelled.
- The workflow uploads **exactly four** download-only artifacts
  (`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`,
  `ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`) and the four names are
  consistent across the CI artifacts guide, retention guide, operator verification map,
  artifact index, and the workflow.
- No stale "exactly three" current-artifact wording remains.
- The canonical Run 408 anchor-refresh statement (the Run 404 manifest was refreshed for
  exactly `ARTIFACT_INDEX.md` + `OPERATOR_VERIFICATION_MAP.md`; no entry added/removed) is
  consistent and no doc denies it.
- All 16 manifest anchors exist and every SHA-256 + byte size matches on-disk.
- Generated output is stated never-committed; download-only/retention, not-binary-provenance,
  and not-launch-evidence wording is consistent.
- The lint runs after the verifier in a least-privilege workflow (contents:read, no secrets,
  no deploy/release/tag/push/commit) that fails on a dirty tree.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7
stay Yellow, M1–M3/M5/M7–M20 remain Green, public DevNet remains NOT launch-ready. C4/C5
remain OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.