# QBIND Public DevNet — Scrape Configuration (M13/M14)

How to **enable, verify, and scrape** the release `qbind-node` metrics endpoint
safely. No production source change and no new CLI flag: exposure is controlled
entirely by the pre-existing `QBIND_METRICS_HTTP_ADDR` environment variable
(`crates/qbind-node/src/metrics_http.rs`, `crates/qbind-node/src/main.rs`).

## 1. Enable metrics safely

```bash
# Loopback-only. The endpoint has NO auth and NO TLS.
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  qbind-node --network-mode p2p --enable-p2p \
             --p2p-listen-addr 127.0.0.1:<p2p_port> \
             --validator-id <id> --data-dir <dir>
```

- **Unset by default:** if `QBIND_METRICS_HTTP_ADDR` is not set, the metrics HTTP
  server does not start (`[metrics] Metrics HTTP server disabled ...`). Enabling
  it is an explicit opt-in.
- **Bind to loopback:** always `127.0.0.1:<port>`. **Never** `0.0.0.0` or a public
  address — there is no authentication or transport security on `/metrics`.
- **Invalid address fails safe:** a malformed `QBIND_METRICS_HTTP_ADDR` logs a
  warning and leaves the server disabled; it does not crash the node.

## 2. No public internet exposure without a fenced proxy

If a central Prometheus must reach a node it does not share a host with, place a
**reverse proxy that adds authentication + TLS** in front of the loopback endpoint
and restrict it with a **firewall allow-list** to the Prometheus source only. Do
**not** publish the raw `/metrics` port on the public internet, and do not add it
to any public status page. DevNet has no value and is resettable; still, an open
metrics port is an information-leak and abuse-amplification surface.

## 3. Verify the endpoint is live

```bash
curl -s http://127.0.0.1:9100/metrics | head
# Non-GET or unknown paths are rejected (405 / 404); only GET /metrics returns 200.
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/metrics   # -> 200
```

A successful scrape is itself the primary liveness signal — Prometheus records
`up == 1` for the target. See [`VERIFY.md`](./VERIFY.md) for the full,
release-binary-backed verification sequence.

## 4. Prometheus scrape config

The canonical, machine-readable example is
[`prometheus-scrape.example.yml`](./prometheus-scrape.example.yml). Key points:

- `metrics_path: /metrics`, `scheme: http`.
- Targets are **loopback / RFC 5737** documentation examples only; replace with
  your fenced internal targets.
- `scrape_interval: 15s` is a reasonable DevNet default; the counters here are
  cumulative and safe to scrape at any interval.
- `rule_files:` references
  [`prometheus-alerts.example.yml`](./prometheus-alerts.example.yml).
- The exposition format has **no `# TYPE`/`# HELP` metadata** — recording rules
  and alerts must not depend on it.

## 5. What you should see

After the node has run for a few seconds you should observe (values non-zero as
progress accrues):

- `qbind_consensus_committed_height` advancing,
- `qbind_consensus_current_view` / `qbind_consensus_view_number` advancing,
- `qbind_p2p_connections_current`, `qbind_p2p_connection_rate_drop_total`,
- the PQC trust-bundle families (`qbind_p2p_pqc_trust_bundle_*`).

See [`METRICS.md`](./METRICS.md) for the full verified family list, and which are
required, best-effort, conditional, or absent.
