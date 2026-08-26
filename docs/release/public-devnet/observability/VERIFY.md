# QBIND Public DevNet — Observability Verification (M13/M14)

Reproducible, release-binary-backed verification for the observability baseline.
The one-command path is the Run 379 harness:

```bash
bash scripts/devnet/run_379_public_devnet_observability_baseline.sh
```

It writes publish-safe results to
`docs/devnet/run_379_public_devnet_observability_baseline/summary.txt` and the
canonical record is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`.

## What the harness proves

1. **Release build:** `cargo build -p qbind-node --release --bin qbind-node`
   succeeds; captures SHA-256, BuildID, toolchain.
2. **No new CLI flag:** `qbind-node --help` exposes **no** new observability flag
   (`metrics`/`observability`/`scrape`/`prometheus`/`telemetry`); exposure remains
   env-only via `QBIND_METRICS_HTTP_ADDR`.
3. **Endpoint starts on loopback:** a release node boots with
   `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` and logs `[metrics_http] Listening
   on 127.0.0.1:<port>`.
4. **`/metrics` scrapes over loopback:** `GET /metrics` returns `200`; the body is
   Prometheus text.
5. **Baseline families present:** the scrape contains the required families —
   `qbind_consensus_committed_height`, `qbind_p2p_connections_current`,
   `qbind_p2p_connection_rate_drop_total`, and `qbind_p2p_pqc_trust_bundle_*`.
6. **No public exposure:** the endpoint is bound to `127.0.0.1`; a non-loopback
   bind is never used, and no auth/TLS is added (so it must stay loopback).
7. **Scrape config parses as YAML:** `prometheus-scrape.example.yml`.
8. **Alert rules parse as YAML:** `prometheus-alerts.example.yml`, including the
   `*-future-not-enabled` group.
9. **Docs list only real metrics:** every enabled alert expression's metric is
   grep-confirmed present in the fresh scrape.
10. **Absent-metric alerts are future:** `qbind_net_per_peer_drops_total` and
    `qbind_state_size_bytes` are confirmed **absent** from the scrape, and their
    alerts live only in the future/not-enabled group.
11. **No live seed / M4 claim:** the harness asserts the summary makes no
    launch/live-seed/M4-Green claim.
12. **No TestNet/MainNet/C4/C5 claim:** the harness asserts no such claim.

## Manual verification (optional)

```bash
# 1. Build
cargo build -p qbind-node --release --bin qbind-node

# 2. No new observability CLI flag
./target/release/qbind-node --help | grep -Ei 'metrics-|--observ|--scrape|--prometheus|--telemetry' || echo "no observability CLI flag (env-only)"

# 3-4. Start on loopback and scrape
PORT=9100
QBIND_METRICS_HTTP_ADDR=127.0.0.1:$PORT ./target/release/qbind-node \
  --network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:0 \
  --validator-id 0 --data-dir /tmp/qbind-obs &
sleep 8
curl -s -o /tmp/metrics.txt -w 'http=%{http_code}\n' http://127.0.0.1:$PORT/metrics

# 5. Required families present
grep -E '^qbind_consensus_committed_height|^qbind_p2p_connections_current|^qbind_p2p_connection_rate_drop_total' /tmp/metrics.txt

# 10. Absent metrics stay future
grep -c '^qbind_net_per_peer_drops_total' /tmp/metrics.txt   # -> 0 in a clean scrape

# 7-8. Config YAML parses (dependency-free)
python3 -c "import sys;              \
 import importlib.util as u;         \
 print('yaml' if u.find_spec('yaml') else 'no-pyyaml')"
```

If PyYAML is unavailable, the harness falls back to a strict, dependency-free
structural parse of the two example YAML files.

## Non-claims

This verification demonstrates **operator-facing metrics exposure and alerting on
a valueless, resettable DevNet**. It does **not** launch a public DevNet, prove
M4 external seed reachability, move M6 fully Green, or approach TestNet / MainNet
readiness, and it closes neither C4 nor C5.