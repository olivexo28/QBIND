# Run 379 evidence archive — public DevNet observability baseline (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_379_public_devnet_observability_baseline.sh` and contains
only publish-safe values: the release-binary SHA-256, BuildID, toolchain, and the
OK / POSITIVE status lines (no metric values, no labels, no data dir, no log).
**No secret, key, data dir, raw log, or metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_379_public_devnet_observability_baseline.sh
```

All per-run artifacts (node data dir, node log, the raw `/metrics` scrape dump)
are written under a temporary output directory that is removed on exit and is
gitignored here as a backstop.

**Decision gate = Route B (docs + harness + machine-readable examples).** Run 379
publishes the operator-facing observability package under
`docs/release/public-devnet/observability/` and proves, against the **release**
`qbind-node` binary, that:

- the pre-existing `metrics_http` endpoint starts on loopback via
  `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` (no new CLI flag, no production
  source change),
- `/metrics` scrapes over loopback (HTTP 200),
- the required baseline metric families are actually present,
- the example Prometheus scrape config and alert rules parse as YAML,
- alerts on metrics absent from the scrape (`qbind_net_per_peer_drops_total`,
  `qbind_state_size_bytes`) are kept in a **future / not-enabled** group,
- no launch / M4-Green / TestNet / MainNet / C4 / C5 claim is made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) move Yellow → Green. **M4 stays Yellow** (external seed
reachability unproven — Run 377/378), the public DevNet remains **NOT
launch-ready**, and **C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`.
