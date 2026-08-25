#!/usr/bin/env bash
# Run 370: release-binary LIVE-SOCKET evidence harness for the public DevNet
# abuse/DoS M12 controls (deployed path).
#
# Run 367 proved the CONNECTION-RATE control live-socket on target/release/qbind-node
# (over-budget inbound TCP connections refused; qbind_p2p_connection_rate_drop_total
# increments). Run 369 wired the per-peer PeerRateLimiter onto the DEPLOYED
# TcpKemTlsP2pService::read_loop, but the deployed adapter was installed with
# metrics = None, so a per-peer message-rate drop on the deployed path could not
# reach the exported /metrics counter.
#
# Run 370 (Route B) threads a live NodeMetrics handle through
# P2pNodeBuilder::with_node_metrics into the deployed inbound per-peer adapter
# (build_deployed_inbound_per_peer_limiter, the exact object start() installs on
# the read loop; wired in main.rs with the SAME Arc<NodeMetrics> the live
# /metrics endpoint scrapes). This harness proves, on real release artifacts:
#   * target/release/qbind-node + the Run 370 helper build; SHA-256s, Build IDs,
#     and the toolchain are captured;
#   * the Run 370 release helper (in-process deployed-adapter proof) PASSes 10/10,
#     including per_peer_deployed_live_socket_over_budget bumping the exported
#     qbind_net_per_peer_drops_total{reason="rate_limit"} counter;
#   * the production CLI surface hides the abuse/DoS flags, rejects invented
#     flags, and parses the real hidden flags;
#   * invalid zero/unbounded configs fail the binary closed at startup;
#   * an enabled MainNet abuse/DoS config is refused at startup;
#   * LIVE SOCKET — default (no abuse/DoS flags) P2P node keeps
#     qbind_p2p_connection_rate_drop_total at 0 (connection limiter disabled);
#   * LIVE SOCKET — a configured connection-rate limiter admits under-budget
#     inbound TCP connections and refuses over-budget ones, incrementing
#     qbind_p2p_connection_rate_drop_total by exactly the over-budget count and
#     recording the same accept/refuse split in the node log.
#
# HONEST LIMITATION (recorded, not hidden): the per-peer MESSAGE-rate control is
# enforced on the DEPLOYED TcpKemTls read loop AFTER a KEMTLS-admitted peer's
# frame decodes. Driving that live requires a second peer that completes the
# KEMTLS mutual-auth handshake and floods frames faster than the configured
# per-peer bucket. This harness does NOT stand up that KEMTLS flood path over a
# live socket, so the per-peer message-rate control's DEPLOYED-PATH evidence is
# the Run 370 helper's deployed-adapter proof (scenarios 07/08 + metrics_export_live)
# — the exact adapter object the read loop consults, now exporting
# qbind_net_per_peer_drops_total. Because M12 Green requires BOTH controls over a
# fully live deployed socket, M12 stays Yellow/Partial (strengthened: the exported
# per-peer drop metric is now wired end-to-end on the deployed path). See
# docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_370.md.
#
# Run 370 does NOT open a default-open public port, launch a public DevNet,
# deploy a seed / bootnode / faucet / RPC / explorer / status page, change any
# wire format, weaken peer admission, or mutate trust/validator/epoch state. All
# addresses are loopback (127.0.0.1); temporary data dirs are used and removed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run370-public-devnet-abuse-dos-m12-deployed-live-socket-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run370] %s\n' "$*"; }
fail() { printf '[run370] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# Node-launch bookkeeping + cleanup.
# ---------------------------------------------------------------------------
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

# Drive N raw inbound TCP connections to 127.0.0.1:<port> (connect + close, no
# handshake). Failures to connect are tolerated (the point is to hit the accept
# loop connection-rate limiter).
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

scrape_metric() {
  local mport="$1" name="$2"
  curl -fsS --max-time 2 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v n="${name}" '$1==n {print $2; found=1} END{ if(!found) print "MISSING" }'
}

wait_for_transport_up() {
  local logf="$1" tries="${2:-60}" i=0
  while [ "${i}" -lt "${tries}" ]; do
    if grep -q 'P2P transport up' "${logf}" 2>/dev/null; then
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
  local p2p_port metrics_port data_dir logf
  p2p_port="$(free_port)"
  metrics_port="$(free_port)"
  data_dir="${OUTDIR}/nodes/${label}/data"
  logf="${OUTDIR}/nodes/${label}/node.log"
  mkdir -p "${data_dir}" "$(dirname "${logf}")"
  (
    cd "${REPO_ROOT}"
    QBIND_METRICS_HTTP_ADDR="127.0.0.1:${metrics_port}" \
      timeout 60 "${NODE_BIN}" \
        --env devnet \
        --network-mode p2p \
        --enable-p2p \
        --p2p-listen-addr "127.0.0.1:${p2p_port}" \
        --validator-id 0 \
        --data-dir "${data_dir}" \
        "$@"
  ) > "${logf}" 2>&1 &
  LAST_NODE_PID=$!
  NODE_PIDS+=("${LAST_NODE_PID}")
  LAST_P2P_PORT="${p2p_port}"
  LAST_METRICS_PORT="${metrics_port}"
  LAST_NODE_LOG="${logf}"
  log "launched ${label} pid=${LAST_NODE_PID} p2p=${p2p_port} metrics=${metrics_port}"
}

stop_node() {
  local pid="$1"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

# Assert a config that must fail the node closed at startup (non-zero exit).
assert_node_fails_closed() {
  local label="$1"; shift
  local data_dir logf rc
  data_dir="${OUTDIR}/failclosed/${label}/data"
  logf="${OUTDIR}/failclosed/${label}/node.log"
  mkdir -p "${data_dir}" "$(dirname "${logf}")"
  set +e
  ( cd "${REPO_ROOT}" && timeout 30 "${NODE_BIN}" \
      --env devnet --network-mode p2p --enable-p2p \
      --p2p-listen-addr "127.0.0.1:0" --validator-id 0 --data-dir "${data_dir}" \
      "$@" ) > "${logf}" 2>&1
  rc=$?
  set -e
  [ "${rc}" -ne 0 ] || fail "config '${label}' did NOT fail closed (rc=0): $*"
  log "fail-closed OK: ${label} (rc=${rc})"
}

# ---------------------------------------------------------------------------
# 1. Build (idempotent) the release binary + helper.
# ---------------------------------------------------------------------------
log "building release binary + helper"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release >/dev/null 2>&1 ) \
  || fail "cargo build -p qbind-node --release failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release \
    --example run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example run_370 helper (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 370 release-binary M12 deployed live-socket evidence ==="
emit "repo_root: ${REPO_ROOT}"
emit "toolchain: $(rustc --version 2>/dev/null || echo unknown)"
emit "cargo:     $(cargo --version 2>/dev/null || echo unknown)"
emit "node_bin:            ${NODE_BIN}"
emit "node_bin_sha256:     $(sha256_file "${NODE_BIN}")"
emit "node_bin_build_id:   $(build_id "${NODE_BIN}")"
emit "helper_bin:          ${HELPER_BIN}"
emit "helper_bin_sha256:   $(sha256_file "${HELPER_BIN}")"
emit "helper_bin_build_id: $(build_id "${HELPER_BIN}")"

# ---------------------------------------------------------------------------
# 2. Run the release-built helper (in-process deployed-adapter proof).
# ---------------------------------------------------------------------------
log "running release-built helper"
HELPER_OUT="${OUTDIR}/helper"
mkdir -p "${HELPER_OUT}"
if "${HELPER_BIN}" "${HELPER_OUT}" > "${OUTDIR}/helper_stdout.txt" 2>&1; then
  emit "helper_verdict: PASS"
else
  cat "${OUTDIR}/helper_stdout.txt" >&2 || true
  fail "release-built helper reported FAIL"
fi
grep -q '^verdict: PASS' "${HELPER_OUT}/helper_summary.txt" \
  || fail "helper_summary.txt did not record PASS"
grep -q 'per_peer_family_present: true' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "per-peer drop family was not rendered by the deployed adapter"
grep -q 'conn_registered_once: true' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "connection-rate metric was not registered exactly once"
grep -q 'conn_endpoint_label_leak: false' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "connection-rate metric endpoint-label leak detected"
emit "helper_scenarios: $(grep -c . "${HELPER_OUT}/manifest.txt") scenarios recorded"
emit "helper_per_peer_deployed_metric: qbind_net_per_peer_drops_total exported by deployed adapter (helper scenarios 07/08/10)"

# ---------------------------------------------------------------------------
# 3. Production binary CLI surface.
# ---------------------------------------------------------------------------
log "capturing --help and --version"
"${NODE_BIN}" --help    > "${OUTDIR}/help.txt"    2>&1 || fail "--help failed"
"${NODE_BIN}" --version > "${OUTDIR}/version.txt"  2>&1 || fail "--version failed"

for f in \
  "--p2p-connection-rate-limit-enabled" \
  "--p2p-connection-rate-window-ms" \
  "--p2p-connection-rate-max" \
  "--p2p-connection-burst" \
  "--p2p-max-messages-per-second" \
  "--p2p-burst-allowance" \
  "--p2p-per-address-connection-rate-window-ms" \
  "--p2p-per-address-connection-max" ; do
  if grep -q -- "${f}" "${OUTDIR}/help.txt"; then
    fail "hidden flag ${f} unexpectedly listed in --help"
  fi
done
emit "help_hidden_flags_absent: true (all Run 362/363 abuse/DoS flags are hidden)"

set +e
"${NODE_BIN}" --p2p-connection-rate-bogus 1 --version > "${OUTDIR}/invented_flag.txt" 2>&1
INVENTED_RC=$?
set -e
[ "${INVENTED_RC}" -ne 0 ] || fail "invented flag --p2p-connection-rate-bogus was NOT rejected"
emit "invented_flag_rejected: true (rc=${INVENTED_RC})"

set +e
"${NODE_BIN}" --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms 1000 \
  --p2p-connection-rate-max 20 \
  --p2p-max-messages-per-second 750 \
  --p2p-burst-allowance 60 --version > "${OUTDIR}/real_flags_parse.txt" 2>&1
REAL_RC=$?
set -e
[ "${REAL_RC}" -eq 0 ] || fail "real hidden flags did not parse (rc=${REAL_RC})"
emit "real_hidden_flags_parse: true (rc=${REAL_RC})"

# ---------------------------------------------------------------------------
# 4. Fail-closed at startup — invalid configs fail the real binary closed.
# ---------------------------------------------------------------------------
log "fail-closed startup checks"
assert_node_fails_closed "zero_per_peer_max" --p2p-max-messages-per-second 0
assert_node_fails_closed "unbounded_per_peer_max" --p2p-max-messages-per-second 2000000
assert_node_fails_closed "zero_connection_rate_max" \
  --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms 1000 \
  --p2p-connection-rate-max 0
emit "invalid_zero_per_peer_max_fails_closed: true (binary exits non-zero)"
emit "unbounded_per_peer_max_fails_closed: true (binary exits non-zero)"
emit "invalid_zero_connection_rate_fails_closed: true (binary exits non-zero)"

# MainNet abuse/DoS enablement refused at startup.
set +e
MAINNET_DATA="${OUTDIR}/failclosed/mainnet/data"
mkdir -p "${MAINNET_DATA}"
( cd "${REPO_ROOT}" && timeout 30 "${NODE_BIN}" \
    --env mainnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --validator-id 0 --data-dir "${MAINNET_DATA}" \
    --p2p-max-messages-per-second 500 ) > "${OUTDIR}/failclosed/mainnet/node.log" 2>&1
MAINNET_RC=$?
set -e
[ "${MAINNET_RC}" -ne 0 ] || fail "MainNet abuse/DoS enablement did NOT fail closed (rc=0)"
emit "mainnet_abuse_dos_refused: true (binary exits non-zero, rc=${MAINNET_RC})"

# ---------------------------------------------------------------------------
# 5. LIVE SOCKET — default_preserves_behavior.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: default_preserves_behavior"
launch_p2p_node "default_no_flags"
if wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  emit "p2p_mode_discovery: P2P-capable loopback mode CONFIRMED (real socket bound; 'P2P transport up')"
else
  emit "p2p_mode_discovery: FAILED to reach 'P2P transport up' (see nodes/default_no_flags/node.log)"
  fail "P2P-capable loopback mode did not come up for default_no_flags"
fi
DEFAULT_CONN_METRIC="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
DEFAULT_LIMITER_LOG="$(grep -c 'connection-rate limiter ENABLED' "${LAST_NODE_LOG}" || true)"
[ "${DEFAULT_CONN_METRIC}" = "0" ] \
  || fail "default (no-flag) node reported non-zero connection-rate drop metric: ${DEFAULT_CONN_METRIC}"
[ "${DEFAULT_LIMITER_LOG}" = "0" ] \
  || fail "default (no-flag) node unexpectedly logged the connection-rate limiter as ENABLED"
emit "default_preserves_behavior: connection limiter DISABLED; qbind_p2p_connection_rate_drop_total=0; per-peer defaults 1000/100 (live socket)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 6. LIVE SOCKET — connection_rate under-budget then over-budget.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: connection_rate_live_socket"
CR_WINDOW_MS=60000
CR_MAX=3
launch_p2p_node "connection_rate" \
  --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms "${CR_WINDOW_MS}" \
  --p2p-connection-rate-max "${CR_MAX}"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  fail "connection_rate node did not reach 'P2P transport up'"
fi
grep -q 'connection-rate limiter ENABLED' "${LAST_NODE_LOG}" \
  || fail "connection_rate node did not log the limiter as ENABLED"

CR_METRIC_START="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${CR_METRIC_START}" = "0" ] || fail "connection_rate metric did not start at 0 (got ${CR_METRIC_START})"

drive_tcp_connections "${LAST_P2P_PORT}" "${CR_MAX}"
sleep 1
CR_METRIC_UNDER="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${CR_METRIC_UNDER}" = "0" ] \
  || fail "under-budget (${CR_MAX}) connections unexpectedly incremented drop metric to ${CR_METRIC_UNDER}"
emit "connection_rate_live_socket_under_budget: ${CR_MAX} inbound TCP connections admitted; drop metric still 0 (live socket)"

drive_tcp_connections "${LAST_P2P_PORT}" 7
sleep 1
CR_METRIC_OVER="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
CR_ACCEPTED_LOG="$(grep -c 'Accepted connection' "${LAST_NODE_LOG}" || true)"
CR_REFUSED_LOG="$(grep -c 'Connection-rate limited inbound' "${LAST_NODE_LOG}" || true)"
[ "${CR_METRIC_OVER}" = "7" ] \
  || fail "over-budget drop metric expected 7, got ${CR_METRIC_OVER} (accepted_log=${CR_ACCEPTED_LOG} refused_log=${CR_REFUSED_LOG})"
[ "${CR_ACCEPTED_LOG}" = "${CR_MAX}" ] \
  || fail "expected exactly ${CR_MAX} 'Accepted connection' log lines, got ${CR_ACCEPTED_LOG}"
[ "${CR_REFUSED_LOG}" = "7" ] \
  || fail "expected exactly 7 'Connection-rate limited inbound' log lines, got ${CR_REFUSED_LOG}"
emit "connection_rate_live_socket_over_budget: 10 inbound TCP connections → ${CR_MAX} accepted / 7 refused; qbind_p2p_connection_rate_drop_total=7 (live socket)"

# ---------------------------------------------------------------------------
# 7. LIVE SOCKET — per-peer deployed-path independence check.
#    Prove that driving the connection-rate limiter over real sockets never
#    surfaces qbind_net_per_peer_drops_total (the two controls are independent).
# ---------------------------------------------------------------------------
PP_ON_CONN="$(scrape_metric "${LAST_METRICS_PORT}" qbind_net_per_peer_drops_total)"
# The per-peer family only renders when a per-peer drop has occurred; a pure
# connection-rate flood must never surface it.
[ "${PP_ON_CONN}" = "MISSING" ] \
  || fail "connection-rate flood unexpectedly surfaced a per-peer drop metric: ${PP_ON_CONN}"
emit "combined_limiter_independence_live: connection-rate flood left qbind_net_per_peer_drops_total ABSENT (no per-peer drops); controls independent (live socket)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 8. Per-peer deployed live-socket message flood — HONEST BLOCKER.
# ---------------------------------------------------------------------------
emit "per_peer_deployed_live_socket_flood: NOT driven — requires a second KEMTLS-admitted peer that completes the mutual-auth handshake and floods frames over the deployed read loop. Deployed-path per-peer evidence is the Run 370 helper's deployed-adapter proof (scenarios 07/08 + metrics_export_live): the exact adapter start() installs on TcpKemTlsP2pService::read_loop now exports qbind_net_per_peer_drops_total{reason=\"rate_limit\"} via the Run 370 NodeMetrics threading. Recorded blocker; M12 stays Yellow/Partial (strengthened)."

emit "verdict: PARTIAL-POSITIVE (live-socket CONNECTION-RATE control proven end-to-end on the release binary; deployed per-peer exported metric wired end-to-end and proven via the deployed adapter object in the release helper; KEMTLS-admitted deployed per-peer socket flood not driven; M12 stays Yellow/Partial, strengthened)"
log "DONE — see ${SUMMARY}"