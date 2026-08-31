# Run 385 evidence archive — public DevNet CI release-artifact manifest (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh` and contains
only publish-safe values: the workflow path, the reused Run 384 harness path, the
workflow safety-lint results, the canonical injected provenance tokens
(`QBIND_GIT_COMMIT` short commit + the canonical `QBIND_BUILD_ID`), the build
command line, the release-binary SHA-256, the ELF `.note.gnu.build-id`, the
`Cargo.lock` SHA-256, the target triple, the list of staged CI artifacts, and the
OK / POSITIVE status lines (no secret, key, data dir, raw log, private hostname,
git branch, dirty-state string, absolute build path, or raw `/metrics` dump).
**No sensitive material is committed.**

Regenerate locally (this is the dry-run that proves the exact commands CI runs):

```bash
bash scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh
```

The generated `RELEASE_ARTIFACT_MANIFEST.json` is a **CI artifact**, uploaded by
`.github/workflows/public-devnet-release-artifact-manifest.yml` — it is **never**
committed. The staged `ci-artifacts/` bundle, the reused Run 384 output under
`run384/`, node data dirs, node logs, and raw `/metrics` scrape dumps are written
under a temporary output directory and are gitignored here as a backstop. The
**committed**, publish-safe example manifest remains
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json`; the
contract it satisfies is
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json`.

**Decision gate = Route A (CI/workflow + harness/docs only).** Run 384 (accepted
PASS) added the canonical, publish-safe release-artifact manifest package
(`RELEASE_ARTIFACT_MANIFEST.schema.json` + `.example.json` + the harness) and proved
the manifest is generated from the real canonical injected build and a live loopback
`qbind_node_build_info` scrape, schema-valid, and cross-checked. Run 385 wires that
generation into CI **without** any production Rust source change, `build.rs` change,
runtime behaviour change, or new CLI flag, and **without committing any generated CI
output**:

- **CI workflow.** `.github/workflows/public-devnet-release-artifact-manifest.yml`
  is manual (`workflow_dispatch`) or release-track (version-tag) scoped, uses
  least-privilege `permissions: contents: read`, references **no** secrets, builds
  the canonical injected artifact
  (`QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"`,
  `QBIND_BUILD_ID="qbind-devnet-<version>-<short-commit>"`,
  `cargo build -p qbind-node --release --locked --bin qbind-node`), generates the
  manifest from the actual binary + live scrape, validates it against the committed
  schema, and uploads the publish-safe bundle as a CI artifact. It creates **no**
  release, tag, deployment, seed, endpoint, or public-network claim, and commits /
  pushes nothing.
- **Local dry-run wrapper.** `scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh`
  runs the same commands the workflow runs: it lints the workflow YAML (valid YAML,
  manual/release trigger, `permissions == {contents: read}`, no secrets, no
  release/commit), reuses the Run 384 harness (`RESULT=POSITIVE`) to build + generate
  + schema-validate + live-cross-check, stages **only** publish-safe CI artifacts
  (`RELEASE_ARTIFACT_MANIFEST.json`, `qbind-node.sha256`,
  `MANIFEST_VALIDATION_SUMMARY.txt`, `BUILDID.txt`), asserts the staged directory
  excludes raw logs / metrics / data dirs and carries no absolute path / host /
  endpoint / secret / raw `/metrics` dump, confirms `signed_release=false` /
  `slsa_grade=false`, confirms no new CLI flag, and confirms the generated manifest
  is not tracked in git.

The metrics endpoint stays **disabled** unless `QBIND_METRICS_HTTP_ADDR` is set and
binds to loopback (no new CLI flag). No metric/alert/scrape change was required; the
Run 381 `qbind_node_data_dir_free_bytes` gauge and the `QbindNodeDiskSpaceLow` alert
are unchanged. No launch / M4-Green / M6-Green / TestNet / MainNet / C4 / C5 claim is
made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (CI-generated, schema-validated release-artifact
manifests widen operator/CI auditability and preserve the Run 379/380/381/382/383/384
guarantees), and **M12 remains Green**. **M4 stays Yellow** (external seed
reachability unproven), **M6 remains Yellow/Partial**, the public DevNet remains
**NOT launch-ready**, and **C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`.
