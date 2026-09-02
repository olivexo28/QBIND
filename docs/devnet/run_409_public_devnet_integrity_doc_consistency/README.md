# Run 409 evidence archive — public DevNet integrity-doc consistency reconciliation

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_409_public_devnet_integrity_doc_consistency.sh` and contains only
publish-safe values: OK / POSITIVE status lines for each consistency check. **No secret
key, private material, generated identity, data dir, raw log, raw metrics dump, private
endpoint, or absolute path is committed.**

The Run 409 harness is a **read-only** documentation-consistency verifier: it re-hashes the
committed anchor manifest against the on-disk tree, checks the reconciled artifact-count and
anchor-refresh wording across the package-integrity docs, and confirms no readiness item
moves. It generates nothing under the repository tree; any transient output is written to a
staging directory **outside** the package tree (runner temp) and is **never** committed.

Regenerate locally with:

```bash
bash scripts/devnet/run_409_public_devnet_integrity_doc_consistency.sh
```

**Decision gate = Route B** (docs + shell only; no production Rust source change, no
`build.rs` change, no `Cargo.toml` change, no CLI flag, no runtime change).

## Reconciliation summary

- **Anchor manifest:** Run 408 narrowly edited two curated anchor docs
  (`ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`), so the Run 404 anchor manifest
  **was** refreshed for exactly those two entries — no entry added/removed, no `status`
  changed. The stale "not edited this run" statement in
  `QBIND_DEVNET_EVIDENCE_RUN_408.md` was corrected to match the readiness matrix and the
  `contradiction.md` Run 408 entry.
- **CI artifact count:** the current workflow uploads **four** download-only artifacts
  (`PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json`, `ANCHOR_DRIFT_REPORT.md`,
  `ANCHOR_DRIFT_REPORT.json`, `PACKAGE_INTEGRITY_CI_SUMMARY.txt`). The stale "exactly three"
  current wording in `PACKAGE_INTEGRITY_CI_ARTIFACTS.md` was updated to four.

## Readiness

**No item moves Green.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S5/S7
stay Yellow, M1–M3/M5/M7–M20 remain Green, public DevNet remains NOT launch-ready. C4/C5
remain OPEN; MainNet authority rotation/revocation remains Red; TestNet/MainNet untouched.