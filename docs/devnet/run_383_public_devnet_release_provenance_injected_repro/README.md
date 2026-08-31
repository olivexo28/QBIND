# Run 383 evidence archive — public DevNet canonical injected release provenance + reproducibility (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh` and
contains only publish-safe values: the canonical injected provenance tokens
(`QBIND_GIT_COMMIT` short commit + the canonical `QBIND_BUILD_ID`), the build
command line, the release-binary SHA-256 for the canonical build / both same-input
reproducibility builds / the changed-input build, the ELF `.note.gnu.build-id`, the
toolchain, loopback ephemeral ports, the emitted `qbind_node_build_info` label line,
and the OK / POSITIVE status lines (no secret, key, data dir, raw log, private
hostname, git branch, dirty-state string, or raw `/metrics` dump). **No sensitive
material is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh
```

All per-run artifacts (node data dirs, node logs, the raw `/metrics` scrape dumps,
and the isolated reproducibility `CARGO_TARGET_DIR`s) are written under a temporary
output directory that is removed on exit and is gitignored here as a backstop.

**Decision gate = Route A (docs/harness only).** Run 382 (accepted PASS) added
`crates/qbind-node/build.rs`, which bridges `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID`
into the compile-time `qbind_node_build_info` labels (`git_commit` auto-derived or
`QBIND_GIT_COMMIT`-overridable; `build_id` harness/CI-injected only; both render
`unknown` when absent). Run 382 proved a single injected build; it did **not** wire
a canonical injected release build by default, and did **not** prove same-input
reproducibility of the injected build. Run 383 closes exactly that gap **without**
any production source change or new CLI flag:

- **Canonical injected provenance.** The release harness injects
  `QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"` (the expected short commit)
  and a canonical, low-cardinality, non-secret
  `QBIND_BUILD_ID="qbind-devnet-<pkg-version>-<short-commit>"` so a published
  artifact ships populated `git_commit` / `build_id` by default. The `build_id` is
  **injected** — never derived inside `build.rs` from git or the ELF — and is
  intentionally **not** the ELF BuildID.
- **Same-input reproducibility.** Two clean `--locked` builds in isolated
  `CARGO_TARGET_DIR`s with the same source, lockfile, toolchain, and injected
  provenance produce a **byte-identical** binary on the reference host (`cmp -s`
  exit 0; identical SHA-256 and ELF BuildID), matched by the default-target build.
- **Changed-input sensitivity.** Rebuilding with a **different** injected `build_id`
  changes the binary SHA-256, recorded as the expected difference.
- **Missing-injection fallback.** A build with no `QBIND_BUILD_ID` does not embed
  the canonical id; the metric renders `build_id="unknown"` (Run 382 regression
  preserved).

**ELF BuildID vs metric `build_id`.** These are distinct provenance planes and the
harness captures them separately. The ELF `.note.gnu.build-id` (from `readelf -n`)
is a linker-computed binary identity recorded in the binary provenance docs
(`docs/release/public-devnet/binary/BUILDINFO.md`). The `qbind_node_build_info`
`build_id` label is an operator-facing, harness-injected canonical release identity.
The harness asserts the two are not equal.

The metrics endpoint stays **disabled** unless `QBIND_METRICS_HTTP_ADDR` is set and
binds to loopback (no new CLI flag). No metric/alert/scrape change was required; the
Run 381 `qbind_node_data_dir_free_bytes` gauge and the `QbindNodeDiskSpaceLow` alert
are unchanged. No launch / M4-Green / TestNet / MainNet / C4 / C5 claim is made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (canonical release provenance widens operator
auditability and preserves the Run 379/380/381/382 guarantees), and **M12 remains
Green**. **M4 stays Yellow** (external seed reachability unproven), **M6 remains
Yellow/Partial**, the public DevNet remains **NOT launch-ready**, and **C4/C5 remain
OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`.