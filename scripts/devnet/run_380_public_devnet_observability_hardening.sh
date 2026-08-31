#!/usr/bin/env bash
# Run 380: public DevNet observability HARDENING harness (M13 telemetry / M14
# monitoring & alerting — deepening the Run 379 baseline).
#
# This harness produces the Run 380 acceptance evidence (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`). It drives the RELEASE
# `target/release/qbind-node` binary directly and proves, with HONEST, BOUNDED
# evidence, that the per-peer rate-limit drop counter can be made PRESENT on a
# release-binary `/metrics` scrape after an induced per-peer drop — reusing the
# Run 371-373 KEMTLS live-socket helper path — so its example alert can be
# promoted FUTURE -> ENABLED.
#
# DECISION GATE:
#   * Route A for the per-peer drop metric `qbind_net_per_peer_drops_total`:
#     the existing source already emits it after a real per-peer drop over the
#     deployed KEMTLS live socket. NO production Rust source change.
#   * Route C for node/build-info and disk/free-space gauges: qbind-node emits no
#     owned build-info or free-disk gauge; their alerts stay FUTURE (recommend
#     node-exporter). No invasive production change is made.
#
# What it proves (mirrors QBIND_DEVNET_EVIDENCE_RUN_380.md §"Required evidence"):
#   1. `cargo build -p qbind-node --release --bin qbind-node` + the Run 371 helper;
#   2. `/metrics` stays DISABLED unless QBIND_METRICS_HTTP_ADDR is set;
#   3. `/metrics` binds to loopback (127.0.0.1) in the harness;
#   4. a clean scrape works (HTTP 200) and qbind_net_per_peer_drops_total ABSENT;
#   5. an induced over-budget KEMTLS flood makes
#      qbind_net_per_peer_drops_total{reason="rate_limit"} PRESENT (> 0);
#   6. the per-peer drop does NOT increment qbind_p2p_connection_rate_drop_total;
#   7. a connection-rate flood does NOT increment the per-peer metric;
#   8. no qbind-owned build-info / free-disk gauge is present (Route C honesty);
#   9. `qbind-node --help` exposes NO new observability CLI flag (env-only);
#  10. `prometheus-scrape.example.yml` parses as YAML;
#  11. `prometheus-alerts.example.yml` parses as YAML;
#  12. the per-peer alert is now in the ENABLED group (not the future group);
#  13. the future group only carries the (absent) disk metric;
#  14. no launch-ready / M4-Green / TestNet / MainNet / C4-C5-closure claim.
#
# Run 380 opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/
# explorer/status page, changes NO wire format, weakens NO peer admission, and
# mutates NO trust/validator/epoch/sequence/marker/LivePqcTrustState. All metrics
# endpoints bind to loopback (127.0.0.1). Temporary data dirs, node logs, and raw
# scrape dumps are removed on exit; no secret, key, data dir, or raw metrics dump
# is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run380-public-devnet-observability-hardening}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_NAME="run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper"
HELPER_BIN="${REPO_ROOT}/target/release/examples/${HELPER_NAME}"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

# Per-peer live-socket flood parameters (identical shape to Run 371).
PP_MAX=5           # --p2p-max-messages-per-second
PP_BURST=5         # --p2p-burst-allowance
PP_OVER_FRAMES=60  # over-budget frame count
PP_OVER_PACE=8     # ms between over-budget frames

log()  { printf '[run380] %s\n' "$*"; }
fail() { printf '[run380] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

NODE_PIDS=()
cleanup() {
  local pid
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "${pid}" ] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  rm -rf "${OUTDIR}/nodes" "${OUTDIR}/clean_metrics.txt" 2>/dev/null || true
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Scrape a plain (label-less) metric value; prints MISSING if absent.
scrape_metric() {
  local mport="$1" name="$2"
  curl -fsS --max-time 2 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v n="${name}" '$1==n {print $2; found=1} END{ if(!found) print "MISSING" }'
}

# Sum every qbind_net_per_peer_drops_total{...,reason="rate_limit"} counter.
scrape_per_peer_drops() {
  local mport="$1"
  curl -fsS --max-time 2 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk '/^qbind_net_per_peer_drops_total/ && /reason="rate_limit"/ {sum+=$NF; found=1} END{ if(found) print sum; else print "MISSING" }'
}

scrape_all() {
  local mport="$1" out="$2"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" -o "${out}"
}

drive_tcp_connections() {
  local port="$1" count="$2"
  python3 - "$port" "$count" <<'PY'
import socket, sys
port = int(sys.argv[1]); count = int(sys.argv[2])
for _ in range(count):
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
PY
}

wait_for_transport_up() {
  local logf="$1" tries="${2:-60}" i=0
  while [ "${i}" -lt "${tries}" ]; do
    if grep -qE 'P2P transport up|listen=127' "${logf}" 2>/dev/null; then
      return 0
    fi
    if grep -qE 'FATAL|panic' "${logf}" 2>/dev/null; then
      return 1
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

launch_p2p_node() {
  local label="$1"; shift
  local metrics_env="$1"; shift
  local p2p_port metrics_port data_dir logf
  p2p_port="$(free_port)"
  metrics_port="$(free_port)"
  data_dir="${OUTDIR}/nodes/${label}/data"
  logf="${OUTDIR}/nodes/${label}/node.log"
  mkdir -p "${data_dir}" "$(dirname "${logf}")"
  (
    cd "${REPO_ROOT}"
    if [ "${metrics_env}" = "with-metrics" ]; then
      QBIND_METRICS_HTTP_ADDR="127.0.0.1:${metrics_port}" \
        timeout 90 "${NODE_BIN}" \
          --env devnet --network-mode p2p --enable-p2p \
          --p2p-listen-addr "127.0.0.1:${p2p_port}" \
          --validator-id 0 --data-dir "${data_dir}" "$@"
    else
      timeout 90 "${NODE_BIN}" \
        --env devnet --network-mode p2p --enable-p2p \
        --p2p-listen-addr "127.0.0.1:${p2p_port}" \
        --validator-id 0 --data-dir "${data_dir}" "$@"
    fi
  ) > "${logf}" 2>&1 &
  LAST_NODE_PID=$!
  NODE_PIDS+=("${LAST_NODE_PID}")
  LAST_P2P_PORT="${p2p_port}"
  LAST_METRICS_PORT="${metrics_port}"
  LAST_NODE_LOG="${logf}"
  log "launched ${label} pid=${LAST_NODE_PID} p2p=${p2p_port} metrics=${metrics_port} (${metrics_env})"
}

stop_node() {
  local pid="$1"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# 1. Build the release binary + the Run 371 KEMTLS live-socket helper.
# ---------------------------------------------------------------------------
log "building qbind-node (release) + Run 371 helper"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --example "${HELPER_NAME}" ) \
  || fail "cargo build --example ${HELPER_NAME} (release) failed"
[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 380 release-binary observability hardening evidence ==="
emit "decision_gate=Route A (per-peer drop metric, no source change) + Route C (build-info/disk gauges stay future)"
emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
emit "release_binary_build_id=$(build_id "${NODE_BIN}")"
emit "helper_binary=OK sha256=$(sha256_file "${HELPER_BIN}")"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 2. --help exposes NO new observability CLI flag (env-only exposure).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry'; then
  fail "unexpected observability CLI flag present in --help (exposure must stay env-only)"
fi
emit "no_new_observability_cli_flag=OK (exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 3-6. Boot the per-peer-limited node WITH metrics; clean scrape → per-peer ABSENT.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: booting per-peer-limited node with QBIND_METRICS_HTTP_ADDR (loopback)"
launch_p2p_node "kemtls_per_peer" "with-metrics" \
  --p2p-max-messages-per-second "${PP_MAX}" \
  --p2p-burst-allowance "${PP_BURST}"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  tail -20 "${LAST_NODE_LOG}" >&2; fail "kemtls_per_peer node did not come up"
fi
grep -q "\[metrics_http\] Listening on 127.0.0.1:${LAST_METRICS_PORT}" "${LAST_NODE_LOG}" \
  || fail "metrics endpoint did not log loopback bind"
KP_P2P_PORT="${LAST_P2P_PORT}"
KP_METRICS_PORT="${LAST_METRICS_PORT}"
KP_PID="${LAST_NODE_PID}"
sleep 1

scrape_all "${KP_METRICS_PORT}" "${OUTDIR}/clean_metrics.txt" \
  || fail "clean loopback scrape of /metrics failed"
emit "metrics_endpoint_scrape=OK http=200 bind=127.0.0.1:${KP_METRICS_PORT} lines=$(wc -l < "${OUTDIR}/clean_metrics.txt")"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

PP_START="$(scrape_per_peer_drops "${KP_METRICS_PORT}")"
[ "${PP_START}" = "MISSING" ] || fail "per-peer drop family present before any flood (got ${PP_START})"
emit "per_peer_clean_scrape=ABSENT (qbind_net_per_peer_drops_total absent until first per-peer drop)"

# ---------------------------------------------------------------------------
# 5. Induced over-budget KEMTLS flood → per-peer drop metric PRESENT (> 0).
# ---------------------------------------------------------------------------
log "LIVE SOCKET: inducing over-budget KEMTLS per-peer flood (deployed read loop)"
OVER_LISTEN="127.0.0.1:$(free_port)"
"${HELPER_BIN}" dial-flood "0@127.0.0.1:${KP_P2P_PORT}" "${OVER_LISTEN}" 1 \
  "${PP_OVER_FRAMES}" "${PP_OVER_PACE}" "${OUTDIR}/kemtls_over.txt" \
  > "${OUTDIR}/kemtls_over_stdout.txt" 2>&1 || fail "over-budget dial-flood failed to connect/flood"
grep -q '^connected: true' "${OUTDIR}/kemtls_over.txt" \
  || fail "over-budget peer did not complete the KEMTLS handshake"
sleep 1
PP_OVER="$(scrape_per_peer_drops "${KP_METRICS_PORT}")"
[ "${PP_OVER}" != "MISSING" ] \
  || fail "over-budget KEMTLS flood did NOT surface any per-peer drops on live /metrics"
[ "${PP_OVER}" -gt 0 ] \
  || fail "over-budget KEMTLS flood per-peer drops not > 0 (got ${PP_OVER})"
emit "per_peer_induced_scrape=PRESENT qbind_net_per_peer_drops_total{reason=\"rate_limit\"}=${PP_OVER} (release binary, live socket)"

# 6. Per-peer drop must NOT increment the connection-rate counter.
KP_CONN_METRIC="$(scrape_metric "${KP_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${KP_CONN_METRIC}" = "0" ] \
  || fail "per-peer KEMTLS flood incremented the connection-rate counter (${KP_CONN_METRIC})"
emit "independence_per_peer_side=OK per-peer flood left qbind_p2p_connection_rate_drop_total=0"

# ---------------------------------------------------------------------------
# 8. Route C honesty: no qbind-owned build-info / free-disk gauge present.
# ---------------------------------------------------------------------------
for m in qbind_node_build_info qbind_node_data_dir_free_bytes qbind_disk_free_bytes qbind_state_size_bytes; do
  if grep -qE "^${m}([ {]|$)" "${OUTDIR}/clean_metrics.txt"; then
    fail "unexpected metric present (Route C assumed absent): ${m}"
  fi
done
emit "route_c_absent_gauges=OK (no qbind-owned build-info/free-disk gauge; disk alert stays future → node-exporter)"

stop_node "${KP_PID}"

# ---------------------------------------------------------------------------
# 7. Independence (reverse): a pure connection-rate flood leaves per-peer ABSENT.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: connection-rate flood independence check"
CR_MAX=3
launch_p2p_node "connection_rate" "with-metrics" \
  --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms 60000 \
  --p2p-connection-rate-max "${CR_MAX}"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  tail -20 "${LAST_NODE_LOG}" >&2; fail "connection_rate node did not come up"
fi
grep -q 'connection-rate limiter ENABLED' "${LAST_NODE_LOG}" \
  || fail "connection_rate node did not log the limiter as ENABLED"
drive_tcp_connections "${LAST_P2P_PORT}" 10
sleep 1
CR_OVER="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${CR_OVER}" != "MISSING" ] && [ "${CR_OVER}" -gt 0 ] \
  || fail "connection-rate flood did not increment qbind_p2p_connection_rate_drop_total (got ${CR_OVER})"
PP_ON_CONN="$(scrape_per_peer_drops "${LAST_METRICS_PORT}")"
[ "${PP_ON_CONN}" = "MISSING" ] \
  || fail "connection-rate flood unexpectedly surfaced a per-peer drop metric: ${PP_ON_CONN}"
emit "independence_conn_side=OK connection-rate flood → qbind_p2p_connection_rate_drop_total=${CR_OVER}; per-peer metric ABSENT"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 2 (default disabled). No env ⇒ NO metrics endpoint bind.
# ---------------------------------------------------------------------------
log "default: node without QBIND_METRICS_HTTP_ADDR does not bind /metrics"
launch_p2p_node "no_metrics_env" "no-metrics"
sleep 6
if grep -q "\[metrics_http\] Listening" "${LAST_NODE_LOG}"; then
  fail "metrics endpoint bound WITHOUT QBIND_METRICS_HTTP_ADDR (must be disabled by default)"
fi
emit "metrics_disabled_by_default=OK (no QBIND_METRICS_HTTP_ADDR ⇒ no /metrics bind logged)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 10-13. YAML parses; per-peer alert ENABLED; future group carries only disk.
# ---------------------------------------------------------------------------
yaml_check() {
  local f="$1"
  python3 - "$f" <<'PY' || return 1
import sys
path = sys.argv[1]
try:
    import yaml
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    assert doc is not None, "empty YAML"
    print(f"pyyaml_ok {path}")
except ModuleNotFoundError:
    with open(path) as fh:
        lines = fh.readlines()
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent]:
            raise SystemExit(f"tab indentation at {path}:{i}")
        if ":" not in line and not line.lstrip().startswith("- "):
            raise SystemExit(f"non-mapping/non-sequence line at {path}:{i}: {line}")
    print(f"structural_ok {path}")
PY
}
yaml_check "${SCRAPE_YML}" || fail "scrape config YAML parse failed"
emit "scrape_config_yaml=OK ($(basename "${SCRAPE_YML}"))"
yaml_check "${ALERTS_YML}" || fail "alert rules YAML parse failed"
emit "alert_rules_yaml=OK ($(basename "${ALERTS_YML}"))"

# The per-peer alert must be ENABLED (in the enabled group), not in the future
# group. Assert it appears BEFORE the future-group marker in the file.
ENABLED_LINE="$(grep -n -- '- alert: QbindPerPeerRateLimitDropsSustained' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
FUTURE_LINE="$(grep -n -- '- name: qbind-devnet-observability-future-not-enabled' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
[ -n "${ENABLED_LINE}" ] || fail "per-peer alert missing from alert rules"
[ -n "${FUTURE_LINE}" ]  || fail "future/not-enabled group missing from alert rules"
[ "${ENABLED_LINE}" -lt "${FUTURE_LINE}" ] \
  || fail "per-peer alert is NOT in the enabled group (appears at/after the future marker)"
emit "per_peer_alert_enabled=OK (QbindPerPeerRateLimitDropsSustained promoted future → enabled)"

# The future group must only carry the (absent) disk metric.
if awk "NR > ${FUTURE_LINE}" "${ALERTS_YML}" | grep -q 'qbind_net_per_peer_drops_total'; then
  fail "per-peer metric still referenced inside the future/not-enabled group"
fi
awk "NR > ${FUTURE_LINE}" "${ALERTS_YML}" | grep -q 'QbindNodeDiskSpaceLow' \
  || fail "disk alert missing from the future/not-enabled group"
emit "future_group_absent_only=OK (future group carries only the absent disk metric; use node-exporter)"

# ---------------------------------------------------------------------------
# 14. No launch / M4-Green / TestNet / MainNet / C4/C5 claim in the docs package.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow)' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in observability docs)"

emit "committed_private_material=NONE (node-data dirs + scrape dumps removed on exit)"
emit ""
emit "RESULT=POSITIVE (Route A: per-peer drop scrape landed on the release binary; per-peer alert promoted future → enabled; connection-rate independence preserved; Route C: build-info/disk gauges stay future; M12/M13/M14 remain Green; M4 stays Yellow; C4/C5 OPEN; no launch/TestNet/MainNet claim)"
log "summary written to ${SUMMARY}"
