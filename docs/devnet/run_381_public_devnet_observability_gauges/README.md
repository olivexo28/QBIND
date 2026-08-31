# Run 381 evidence archive — public DevNet observability gauge hardening (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_381_public_devnet_observability_gauges.sh` and contains only
publish-safe values: the release-binary SHA-256, BuildID, toolchain, loopback
ephemeral ports, the observed free-bytes value, the emitted `qbind_node_build_info`
label line, and the OK / POSITIVE status lines (no secret, key, data dir, raw log,
private hostname, or raw `/metrics` dump). **No sensitive material is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_381_public_devnet_observability_gauges.sh
```

All per-run artifacts (node data dirs, node logs, the raw `/metrics` scrape dump)
are written under a temporary output directory that is removed on exit and is
gitignored here as a backstop.

**Decision gate = Route B (minimal read-only metrics source change).** Run 381
extends the Run 379/380 observability baseline with two low-cardinality,
secret-free series exposed by the **release** `qbind-node` binary:

- `qbind_node_build_info{version,build_id,git_commit,env,chain_id} 1` — a static
  node/build/chain info gauge (labels only; value `1`). Unknown values render as
  `unknown` (never a panic). It carries **no** path, hostname, or private-endpoint
  label. `build_id`/`git_commit` are populated only when injected at build time via
  `QBIND_BUILD_ID` / `QBIND_GIT_COMMIT`, otherwise `unknown`.
- `qbind_node_data_dir_free_bytes <value>` — a qbind-owned free-space gauge derived
  from `statvfs(3)` on the `--data-dir` filesystem. Value only — **no** path,
  mount, or hostname label. Emitted only when `--data-dir` is set and the syscall
  succeeds (unix); otherwise the gauge is honestly omitted.

On this evidence the disk alert `QbindNodeDiskSpaceLow` is promoted **future →
enabled** against `qbind_node_data_dir_free_bytes`; the only remaining
future/not-enabled rule (`QbindStateSizeHigh`) backs the still-absent legacy
`qbind_state_size_bytes` gauge. The metrics endpoint stays **disabled** unless
`QBIND_METRICS_HTTP_ADDR` is set and binds to loopback (no new CLI flag). No
launch / M4-Green / TestNet / MainNet / C4 / C5 claim is made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (the additions widen operator visibility and
preserve the Run 379/380 guarantees), and **M12 remains Green**. **M4 stays
Yellow** (external seed reachability unproven), the public DevNet remains **NOT
launch-ready**, and **C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`.
