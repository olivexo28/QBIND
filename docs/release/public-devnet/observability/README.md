# QBIND Public DevNet — Observability Baseline

**Scope:** operator-facing telemetry (M13) and monitoring/alerting (M14) baseline
for the **public DevNet** only. This package documents how a DevNet operator
exposes, verifies, scrapes, and alerts on the metrics that the **release**
`qbind-node` binary already emits.

> **Safety label:** DevNet · experimental · **no value** · resettable · localhost
> metrics by default · **NOT public-DevNet launch-ready** · no TestNet readiness ·
> no MainNet readiness · no C4/C5 closure. Observability landing does **not** imply
> launch, TestNet, MainNet, C4, or C5 readiness.

## What this package is

- A **docs + verification** package (Run 379, decision gate **Route B**; Run 380
  hardening, decision gate **Route A** for the per-peer drop metric + **Route C**
  for node/build-info and disk gauges; Run 381 hardening, decision gate **Route B**
  — a minimal read-only source change adds `qbind_node_build_info` and the
  qbind-owned `qbind_node_data_dir_free_bytes` gauge; Run 382 provenance, decision
  gate **Route B** — a minimal build-time provenance bridge
  (`crates/qbind-node/build.rs`) that auto-fills the `qbind_node_build_info`
  `git_commit` label with a short git commit hash and passes through a
  harness/CI-injected `QBIND_BUILD_ID`, so release provenance is visible without a
  runtime change). It adds **no** new CLI flag;
  the metrics endpoint is the pre-existing `metrics_http` server gated by the
  `QBIND_METRICS_HTTP_ADDR` environment variable
  (`crates/qbind-node/src/metrics_http.rs`, `crates/qbind-node/src/main.rs`).
- Every metric name listed here was **verified against the release binary** by
  scraping `/metrics` over loopback — see [`VERIFY.md`](./VERIFY.md), the Run 379
  evidence record `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`, the Run 380
  hardening record `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`, the Run 381
  hardening record `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`, and the Run 382
  provenance record `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md`.
- Alert rules that reference a metric **not present in any verified scrape** are
  clearly marked **FUTURE / not enabled** rather than shipped as active. The
  per-peer drop alert `QbindPerPeerRateLimitDropsSustained` was promoted to
  **enabled** in Run 380; the disk alert `QbindNodeDiskSpaceLow` was promoted to
  **enabled** in Run 381 against the qbind-owned `qbind_node_data_dir_free_bytes`
  gauge. The future group now carries only the still-absent legacy
  `qbind_state_size_bytes` gauge (`QbindStateSizeHigh`).

## What this package is NOT

- Not a public status page, uptime page, or external communications artifact.
- Not a dashboard implementation or vendor/product selection.
- Not an SLO/SLA or availability promise.
- Not a claim that the public DevNet is launch-ready, or that M4 (external seed
  reachability) is Green. It is not a live-network deployment.

## Files

| File | Purpose |
|---|---|
| [`METRICS.md`](./METRICS.md) | Metric families the release binary emits; which are required vs best-effort; which are absent. |
| [`SCRAPE_CONFIG.md`](./SCRAPE_CONFIG.md) | How to enable and scrape `/metrics` safely; annotated Prometheus scrape config. |
| [`ALERT_RULES.md`](./ALERT_RULES.md) | Alert rules with severity (page/ticket/observe) and future-marked rules for absent metrics. |
| [`RUNBOOK.md`](./RUNBOOK.md) | Operator response action for each alert. |
| [`VERIFY.md`](./VERIFY.md) | Exact commands to prove the endpoint is live and the configs parse. |
| [`prometheus-scrape.example.yml`](./prometheus-scrape.example.yml) | Machine-readable example scrape config (loopback). |
| [`prometheus-alerts.example.yml`](./prometheus-alerts.example.yml) | Machine-readable example alert rules. |

## Golden rules for DevNet operators

1. **Bind metrics to loopback.** Use `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>`.
   Never bind `/metrics` to `0.0.0.0` or a public interface. It has no
   authentication or TLS.
2. **No public exposure without a fenced proxy.** If a central Prometheus must
   reach a node, front it with a reverse proxy that adds auth/TLS and a firewall
   allow-list — never expose the raw endpoint on the public internet.
3. **Default is off.** When `QBIND_METRICS_HTTP_ADDR` is unset the server does not
   start; enabling it is an explicit, opt-in operator action.
4. **DevNet has no value.** Metrics, keys, data dirs, and the chain itself are
   experimental and resettable. Do not treat any DevNet signal as a
   production/MainNet guarantee.

## Cross-references

- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` — the canonical internal
  monitoring/alerting baseline this package operationalizes for public DevNet.
- `docs/ops/QBIND_INCIDENT_RESPONSE.md` — what to do when an alert fires.
- `docs/release/public-devnet/operator/QUICKSTART.md` — operator bring-up.
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md` — the M12 connection-rate
  and per-peer rate-limit controls whose drop counters appear here.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M13/M14 readiness.