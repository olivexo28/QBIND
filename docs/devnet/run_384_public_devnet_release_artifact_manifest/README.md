# Run 384 evidence archive — public DevNet CI/release-artifact manifest (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh` and contains
only publish-safe values: the canonical injected provenance tokens
(`QBIND_GIT_COMMIT` short commit + the canonical `QBIND_BUILD_ID`), the build
command line, the release-binary SHA-256, the ELF `.note.gnu.build-id`, the live
`qbind_node_build_info` label line, the `Cargo.lock` SHA-256, the toolchain, the
target triple, loopback ephemeral ports, and the OK / POSITIVE status lines (no
secret, key, data dir, raw log, private hostname, git branch, dirty-state string,
absolute build path, or raw `/metrics` dump). **No sensitive material is
committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh
```

All per-run artifacts (node data dirs, node logs, the raw `/metrics` scrape dumps,
and the generated `manifest.json`) are written under a temporary output directory
that is removed on exit and is gitignored here as a backstop. The **committed**,
publish-safe example manifest is
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json`; the
contract it satisfies is
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json`.

**Decision gate = Route A (docs/harness/schema only).** Run 383 (accepted PASS)
wired the Run 382 `crates/qbind-node/build.rs` provenance bridge to **canonical
injected** values (`QBIND_GIT_COMMIT` / `QBIND_BUILD_ID`) for a published release
artifact and proved the injected build is **same-input reproducible**. Run 384
records a canonical, publish-safe **release-artifact manifest** for that exact
canonical injected build **without** any production source change, `build.rs`
change, runtime behaviour change, or new CLI flag:

- **Generated from the real artifact.** The harness builds the canonical injected
  release binary (`QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"`,
  `QBIND_BUILD_ID="qbind-devnet-<pkg-version>-<short-commit>"`), then generates the
  manifest from the actual binary (SHA-256, ELF BuildID), a **live loopback**
  `qbind_node_build_info` scrape (metric `build_id` / `git_commit`), the `Cargo.lock`
  hash, and the recorded toolchain / target triple.
- **Schema-validated.** The generated manifest and the committed example both
  validate against `RELEASE_ARTIFACT_MANIFEST.schema.json`.
- **Cross-checked.** The manifest's `binary_sha256`, `elf_build_id`,
  `metric_build_id`, and `metric_git_commit` are asserted equal to the real build /
  live scrape; the metric `build_id` is kept a **separate field** from and asserted
  **distinct** from the ELF BuildID.
- **Publish-safe.** The manifest embeds no absolute path, private hostname,
  external endpoint, secret, credential, or raw `/metrics` dump; the non-claim
  fields are all present and true; the reproducibility scope is **same-host /
  per-input** only and **references** Run 383 without overclaiming cross-host or
  SLSA-grade provenance.

The metrics endpoint stays **disabled** unless `QBIND_METRICS_HTTP_ADDR` is set and
binds to loopback (no new CLI flag). No metric/alert/scrape change was required; the
Run 381 `qbind_node_data_dir_free_bytes` gauge and the `QbindNodeDiskSpaceLow`
alert are unchanged. No launch / M4-Green / TestNet / MainNet / C4 / C5 claim is
made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (a canonical release-artifact manifest widens
operator/CI auditability and preserves the Run 379/380/381/382/383 guarantees), and
**M12 remains Green**. **M4 stays Yellow** (external seed reachability unproven),
**M6 remains Yellow/Partial**, the public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`.
