# Run 382 evidence archive — public DevNet build-info provenance injection (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_382_public_devnet_build_info_provenance.sh` and contains only
publish-safe values: the release-binary SHA-256, the ELF `.note.gnu.build-id`, the
toolchain, loopback ephemeral ports, the observed free-bytes value, the emitted
`qbind_node_build_info` label lines (default + injected), the non-secret injected
provenance tokens, and the OK / POSITIVE status lines (no secret, key, data dir,
raw log, private hostname, git branch, dirty-state string, or raw `/metrics`
dump). **No sensitive material is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_382_public_devnet_build_info_provenance.sh
```

All per-run artifacts (node data dirs, node logs, the raw `/metrics` scrape dumps)
are written under a temporary output directory that is removed on exit and is
gitignored here as a backstop.

**Decision gate = Route B (minimal build-time provenance bridge).** Run 381 left
`qbind_node_build_info` emitting `build_id="unknown"` / `git_commit="unknown"`
unless the environment injected `QBIND_BUILD_ID` / `QBIND_GIT_COMMIT`. Run 382 adds
`crates/qbind-node/build.rs`, a small build script that bridges release provenance
into those two compile-time `option_env!` labels **without** any runtime change or
new CLI flag:

- `git_commit` — an explicit `QBIND_GIT_COMMIT` env (CI / release harness) wins,
  otherwise a **short git commit hash** is derived at build time. Missing →
  `unknown`. Only the abbreviated commit hash is ever exposed — never a branch,
  tag, remote, dirty-state string, path, hostname, or username.
- `build_id` — a stable **harness/CI-injected** `QBIND_BUILD_ID` only. It is never
  derived from git or the ELF. Missing → `unknown`.

Both label values are sanitized to `[A-Za-z0-9._-]` in `build.rs` and **again** at
render time by `sanitize_info_label` in `metrics.rs`; any provenance failure
degrades safely to `unknown` (the build never panics).

**ELF BuildID vs metric `build_id`.** These are distinct provenance planes and the
harness captures them separately. The ELF `.note.gnu.build-id` (from `readelf -n`)
is a linker-computed binary identity recorded in the binary provenance docs
(`docs/release/public-devnet/binary/BUILDINFO.md`). The `qbind_node_build_info`
`build_id` label is an operator-facing, harness-injected release identity. The
harness asserts the two are not equal.

The metrics endpoint stays **disabled** unless `QBIND_METRICS_HTTP_ADDR` is set and
binds to loopback (no new CLI flag). The Run 381 `qbind_node_data_dir_free_bytes`
gauge and the `QbindNodeDiskSpaceLow` alert are unchanged. No launch / M4-Green /
TestNet / MainNet / C4 / C5 claim is made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (release provenance widens operator visibility
and preserves the Run 379/380/381 guarantees), and **M12 remains Green**. **M4
stays Yellow** (external seed reachability unproven), **M6 remains Yellow/Partial**,
the public DevNet remains **NOT launch-ready**, and **C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md`.