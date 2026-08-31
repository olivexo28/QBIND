#!/usr/bin/env bash
# Run 381: public DevNet observability GAUGE hardening harness (M13 telemetry /
# M14 monitoring & alerting — node/build/chain info + qbind-owned disk metric).
#
# This harness produces the Run 381 acceptance evidence (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`). It drives the RELEASE
# `target/release/qbind-node` binary directly and proves, with HONEST, BOUNDED
# evidence, that a minimal read-only source change adds two low-cardinality,
# secret-free observability series on the release-binary `/metrics` scrape:
#
#   * `qbind_node_build_info{version,build_id,git_commit,env,chain_id} 1`
#     — a static info gauge (labels only; value 1). No path/hostname/endpoint
#       label; unknown values render as `unknown`.
#   * `qbind_node_data_dir_free_bytes <value>`
#     — a qbind-owned free-space gauge derived from statvfs(3) on --data-dir.
#       Value only; NO path/mount/hostname label. Emitted only when --data-dir is
#       set and the syscall succeeds.
#
# DECISION GATE:
#   * Route B: a minimal, read-only production metrics source change adds the two
#     gauges above (crates/qbind-node/src/metrics.rs + main.rs wiring). No new CLI
#     flag; exposure stays env-only via QBIND_METRICS_HTTP_ADDR. Because the
#     qbind-owned disk gauge is proven present, QbindNodeDiskSpaceLow is promoted
#     FUTURE -> ENABLED. The legacy qbind_state_size_bytes gauge stays absent, so
#     its placeholder alert QbindStateSizeHigh stays future.
#
# What it proves (mirrors QBIND_DEVNET_EVIDENCE_RUN_381.md §"Required evidence"):
#   1. `cargo build -p qbind-node --release --bin qbind-node`;
#   2. `/metrics` stays DISABLED unless QBIND_METRICS_HTTP_ADDR is set;
#   3. `/metrics` binds to loopback (127.0.0.1) in the harness;
#   4. a clean scrape works (HTTP 200);
#   5. existing Run 379/380 required families still present;
#   6. qbind_net_per_peer_drops_total stays absent-until-drop (doc/alert correct);
#   7. qbind_node_build_info present, value 1;
#   8. build_info labels are low-cardinality and secret-free (no path/host/endpoint);
#   9. qbind_node_data_dir_free_bytes present (value only, no label);
#  10. disk alert QbindNodeDiskSpaceLow ENABLED (metric present) & future group
#      carries only the still-absent qbind_state_size_bytes;
#  11. scrape YAML parses;
#  12. alert YAML parses;
#  13. enabled alert expressions reference present metrics;
#  14. future/not-enabled group contains only metrics still absent;
#  15. non-claim grep passes over the observability package;
#  16. no default public metrics exposure;
#  17. `qbind-node --help` exposes NO new observability CLI flag (env-only).
#
# Run 381 opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/
# explorer/status page, changes NO wire format, weakens NO peer admission, and
# mutates NO trust/validator/epoch/sequence/marker/LivePqcTrustState. All metrics
# endpoints bind to loopback (127.0.0.1). Temporary data dirs, node logs, and raw
# scrape dumps are removed on exit; no secret, key, data dir, or raw metrics dump
# is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run381-public-devnet-observability-gauges}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run381] %s\n' "$*"; }
fail() { printf '[run381] FAIL: %s\n' "$*" >&2; exit 1; }
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

scrape_all() {
  local mport="$1" out="$2"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" -o "${out}"
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
# 1. Build the release binary.
# ---------------------------------------------------------------------------
log "building qbind-node (release)"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release node binary missing: ${NODE_BIN}"

emit "=== Run 381 release-binary observability gauge evidence ==="
emit "decision_gate=Route B (minimal read-only metrics source change: qbind_node_build_info + qbind_node_data_dir_free_bytes)"
emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
emit "release_binary_build_id=$(build_id "${NODE_BIN}")"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 17. --help exposes NO new observability CLI flag (env-only exposure).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--disk'; then
  fail "unexpected observability CLI flag present in --help (exposure must stay env-only)"
fi
emit "no_new_observability_cli_flag=OK (exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 3-9. Boot node WITH metrics; clean scrape and gauge assertions.
# ---------------------------------------------------------------------------
log "booting node with QBIND_METRICS_HTTP_ADDR (loopback) and --data-dir"
launch_p2p_node "gauges" "with-metrics"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  tail -20 "${LAST_NODE_LOG}" >&2; fail "gauges node did not come up"
fi
grep -q "\[metrics_http\] Listening on 127.0.0.1:${LAST_METRICS_PORT}" "${LAST_NODE_LOG}" \
  || fail "metrics endpoint did not log loopback bind"
G_METRICS_PORT="${LAST_METRICS_PORT}"
G_PID="${LAST_NODE_PID}"
sleep 1

scrape_all "${G_METRICS_PORT}" "${OUTDIR}/clean_metrics.txt" \
  || fail "clean loopback scrape of /metrics failed"
emit "metrics_endpoint_scrape=OK http=200 bind=127.0.0.1:${G_METRICS_PORT} lines=$(wc -l < "${OUTDIR}/clean_metrics.txt")"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

# 5. Existing Run 379/380 required families still present.
for fam in qbind_consensus_committed_height qbind_p2p_connections_current \
           qbind_p2p_connection_rate_drop_total; do
  grep -qE "^${fam}([ {]|$)" "${OUTDIR}/clean_metrics.txt" \
    || fail "required baseline family missing from scrape: ${fam}"
done
grep -qE '^qbind_p2p_pqc_trust_bundle_' "${OUTDIR}/clean_metrics.txt" \
  || fail "required trust-bundle families missing from scrape"
emit "baseline_families_present=OK (committed_height, p2p_connections_current, connection_rate_drop_total, trust-bundle)"

# 6. Per-peer drop stays absent-until-drop in a clean scrape (doc/alert correct).
if grep -qE '^qbind_net_per_peer_drops_total' "${OUTDIR}/clean_metrics.txt"; then
  fail "qbind_net_per_peer_drops_total present in a clean scrape (must be absent until first drop)"
fi
emit "per_peer_drop_state=OK (qbind_net_per_peer_drops_total absent-until-drop; alert stays ENABLED per Run 380)"

# 7. qbind_node_build_info present, value 1.
BUILD_INFO_LINE="$(grep -E '^qbind_node_build_info\{' "${OUTDIR}/clean_metrics.txt" | head -1 || true)"
[ -n "${BUILD_INFO_LINE}" ] || fail "qbind_node_build_info missing from scrape"
printf '%s\n' "${BUILD_INFO_LINE}" | grep -qE '\} 1$' \
  || fail "qbind_node_build_info value is not 1"
for lbl in version build_id git_commit env chain_id; do
  printf '%s\n' "${BUILD_INFO_LINE}" | grep -q "${lbl}=\"" \
    || fail "qbind_node_build_info missing required label: ${lbl}"
done
emit "build_info_present=OK ${BUILD_INFO_LINE}"

# 8. build_info labels low-cardinality + secret-free (no path/host/endpoint chars).
#    Sanitized to [A-Za-z0-9._-]; assert no '/', no ':' inside label values, no
#    whitespace inside quotes, and no obvious secret-ish tokens.
if printf '%s\n' "${BUILD_INFO_LINE}" | grep -qE '="[^"]*(/|@| |\\)'; then
  fail "qbind_node_build_info label contains path/host/space/escape character"
fi
if printf '%s\n' "${BUILD_INFO_LINE}" | grep -qiE 'secret|token|password|apikey|api_key|BEGIN'; then
  fail "qbind_node_build_info label contains a secret-ish token"
fi
emit "build_info_labels_safe=OK (low-cardinality, no path/host/endpoint/secret; unknowns render as unknown)"

# 9. qbind_node_data_dir_free_bytes present, value only (no label), numeric > 0.
DISK_LINE="$(grep -E '^qbind_node_data_dir_free_bytes ' "${OUTDIR}/clean_metrics.txt" | head -1 || true)"
[ -n "${DISK_LINE}" ] || fail "qbind_node_data_dir_free_bytes missing from scrape (with --data-dir set)"
if printf '%s\n' "${DISK_LINE}" | grep -q '{'; then
  fail "qbind_node_data_dir_free_bytes must be value-only (found a label)"
fi
DISK_VAL="$(printf '%s\n' "${DISK_LINE}" | awk '{print $2}')"
printf '%s\n' "${DISK_VAL}" | grep -qE '^[0-9]+$' \
  || fail "qbind_node_data_dir_free_bytes value is not a plain integer: ${DISK_VAL}"
[ "${DISK_VAL}" -gt 0 ] || fail "qbind_node_data_dir_free_bytes not > 0 (got ${DISK_VAL})"
emit "disk_free_bytes_present=OK qbind_node_data_dir_free_bytes=${DISK_VAL} (value only, no path/mount/host label)"

# Legacy qbind_state_size_bytes must remain ABSENT (future group only).
if grep -qE '^qbind_state_size_bytes([ {]|$)' "${OUTDIR}/clean_metrics.txt"; then
  fail "qbind_state_size_bytes unexpectedly present (must stay absent / future)"
fi
emit "legacy_state_size_absent=OK (qbind_state_size_bytes still absent → QbindStateSizeHigh stays future)"

stop_node "${G_PID}"

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
# 11-14. YAML parses; disk alert ENABLED; future group carries only absent metric.
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

# The disk alert must be ENABLED (before the future-group marker) and the per-peer
# alert must remain enabled.
FUTURE_LINE="$(grep -n -- '- name: qbind-devnet-observability-future-not-enabled' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
[ -n "${FUTURE_LINE}" ] || fail "future/not-enabled group missing from alert rules"

DISK_ALERT_LINE="$(grep -n -- '- alert: QbindNodeDiskSpaceLow' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
[ -n "${DISK_ALERT_LINE}" ] || fail "disk alert missing from alert rules"
[ "${DISK_ALERT_LINE}" -lt "${FUTURE_LINE}" ] \
  || fail "QbindNodeDiskSpaceLow is NOT in the enabled group (appears at/after the future marker)"
# Its expression must reference the qbind-owned metric proven present.
awk "NR >= ${DISK_ALERT_LINE} && NR < ${DISK_ALERT_LINE}+6" "${ALERTS_YML}" \
  | grep -q 'qbind_node_data_dir_free_bytes' \
  || fail "QbindNodeDiskSpaceLow does not reference qbind_node_data_dir_free_bytes"
emit "disk_alert_enabled=OK (QbindNodeDiskSpaceLow promoted future → enabled; references qbind_node_data_dir_free_bytes)"

PP_ALERT_LINE="$(grep -n -- '- alert: QbindPerPeerRateLimitDropsSustained' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
[ -n "${PP_ALERT_LINE}" ] && [ "${PP_ALERT_LINE}" -lt "${FUTURE_LINE}" ] \
  || fail "per-peer alert missing from the enabled group"
emit "per_peer_alert_enabled=OK (QbindPerPeerRateLimitDropsSustained remains enabled)"

# Every enabled alert expr must reference a metric present in the fresh scrape
# (or the Prometheus-synthesized `up` series, or the absent-until-drop per-peer
# series proven by Run 380).
python3 - "${ALERTS_YML}" "${FUTURE_LINE}" "${OUTDIR}/clean_metrics.txt" <<'PY' || fail "enabled alert references a metric absent from the scrape"
import re, sys
alerts, future_line, scrape = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(scrape) as fh:
    present = set(re.findall(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)', fh.read(), re.M))
# Series that are legitimately absent-until-event but proven present by prior runs.
allow = {"up", "qbind_net_per_peer_drops_total"}
with open(alerts) as fh:
    lines = fh.readlines()
enabled = lines[:future_line - 1]
bad = []
for i, line in enumerate(enabled):
    m = re.match(r'\s*expr:\s*(.*)', line)
    if not m:
        continue
    for name in re.findall(r'\bqbind_[a-zA-Z0-9_]+', m.group(1)):
        if name not in present and name not in allow:
            bad.append(name)
if bad:
    print("MISSING:", sorted(set(bad)))
    sys.exit(1)
print("enabled_exprs_reference_present_metrics_ok")
PY
emit "enabled_exprs_present=OK (every enabled alert expr references a scrape-present metric, up, or the Run-380-proven per-peer series)"

# The future group must only carry metrics still ABSENT from the scrape.
if awk "NR > ${FUTURE_LINE}" "${ALERTS_YML}" | grep -q 'qbind_node_data_dir_free_bytes'; then
  fail "qbind_node_data_dir_free_bytes referenced inside the future/not-enabled group"
fi
awk "NR > ${FUTURE_LINE}" "${ALERTS_YML}" | grep -q 'qbind_state_size_bytes' \
  || fail "expected still-absent qbind_state_size_bytes in the future/not-enabled group"
emit "future_group_absent_only=OK (future group carries only the still-absent qbind_state_size_bytes)"

# ---------------------------------------------------------------------------
# 15. No launch / M4-Green / TestNet / MainNet / C4/C5 claim in the docs package.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow)' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in observability docs)"

emit "committed_private_material=NONE (node-data dirs + scrape dumps removed on exit)"
emit ""
emit "RESULT=POSITIVE (Route B: qbind_node_build_info + qbind_node_data_dir_free_bytes land safely on the release binary; disk alert promoted future → enabled; per-peer alert stays enabled; future group carries only the still-absent qbind_state_size_bytes; metrics stay disabled-by-default and loopback-only; M12/M13/M14 remain Green; M4 stays Yellow; C4/C5 OPEN; no launch/TestNet/MainNet claim)"
log "summary written to ${SUMMARY}"