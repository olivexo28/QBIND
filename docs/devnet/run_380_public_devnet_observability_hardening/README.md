# Run 380 evidence archive — public DevNet observability hardening (M13/M14)

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_380_public_devnet_observability_hardening.sh` and contains
only publish-safe values: the release-binary SHA-256, BuildID, toolchain,
loopback ephemeral ports, the induced per-peer drop count, and the OK / POSITIVE
status lines (no secret, key, data dir, raw log, private hostname, or raw
`/metrics` dump). **No sensitive material is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_380_public_devnet_observability_hardening.sh
```

All per-run artifacts (node data dirs, node logs, the raw `/metrics` scrape dump,
the KEMTLS flood helper outputs) are written under a temporary output directory
that is removed on exit and is gitignored here as a backstop.

**Decision gate = Route A (per-peer drop metric) + Route C (build-info / disk
gauges).** Run 380 deepens the Run 379 observability baseline and proves, against
the **release** `qbind-node` binary, that:

- the pre-existing `metrics_http` endpoint stays **disabled** unless
  `QBIND_METRICS_HTTP_ADDR` is set, and binds to loopback when it is (no new CLI
  flag, no production source change),
- a clean `/metrics` scrape shows `qbind_net_per_peer_drops_total` **absent**,
- an induced over-budget KEMTLS-admitted flood (the Run 371–373 helper path) trips
  the deployed `TcpKemTlsP2pService::read_loop` per-peer limiter and a re-scrape
  exposes `qbind_net_per_peer_drops_total{reason="rate_limit"}` **present** (> 0),
- the per-peer drop does **not** increment `qbind_p2p_connection_rate_drop_total`,
  and a connection-rate flood leaves the per-peer metric absent (controls
  independent),
- no qbind-owned build-info or free-disk gauge is present (Route C — the disk
  alert stays future; use node-exporter),
- the example Prometheus scrape config and alert rules parse as YAML, with the
  per-peer alert `QbindPerPeerRateLimitDropsSustained` **promoted future →
  enabled** and only the absent disk metric left in the future / not-enabled
  group,
- no launch / M4-Green / TestNet / MainNet / C4 / C5 claim is made.

On this evidence **M13** (telemetry / metrics baseline) and **M14** (monitoring /
alerting baseline) **remain Green** (hardening preserves the Run 379 guarantees),
and **M12 remains Green**. **M4 stays Yellow** (external seed reachability
unproven — Run 377/378), the public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`.