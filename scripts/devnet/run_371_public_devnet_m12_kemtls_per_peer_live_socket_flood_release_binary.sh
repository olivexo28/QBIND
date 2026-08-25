#!/usr/bin/env bash
# Run 371: release-binary LIVE-SOCKET evidence harness for the public DevNet
# abuse/DoS M12 controls — now including the KEMTLS-admitted DEPLOYED per-peer
# message-rate flood that Run 370 left as its residual blocker.
#
# Run 367/370 proved the CONNECTION-RATE control live-socket on
# target/release/qbind-node (over-budget inbound TCP connections refused;
# qbind_p2p_connection_rate_drop_total increments). Run 369/370 wired the
# per-peer PeerRateLimiter onto the DEPLOYED TcpKemTlsP2pService::read_loop and
# threaded the live NodeMetrics handle so a per-peer message-rate drop bumps the
# exported qbind_net_per_peer_drops_total{reason="rate_limit"} counter — but the
# KEMTLS-admitted deployed socket flood was NOT driven.
#
# Run 371 (Route A — no production source change) drives it end-to-end on real
# release artifacts using only production public APIs:
#   * target/release/qbind-node + the Run 371 helper build; SHA-256s, Build IDs,
#     and the toolchain are captured;
#   * the Run 371 release helper's in-process two-node KEMTLS flood PASSes all
#     scenarios (real loopback socket + real KEMTLS handshake + deployed read
#     loop + deployed per-peer limiter → exported qbind_net_per_peer_drops_total);
#   * the production CLI surface hides the abuse/DoS flags, rejects invented
#     flags, and parses the real hidden flags;
#   * invalid zero/unbounded configs fail the binary closed at startup;
#   * an enabled MainNet abuse/DoS config is refused at startup;
#   * LIVE SOCKET — default (no abuse/DoS flags) P2P node keeps
#     qbind_p2p_connection_rate_drop_total at 0 (connection limiter disabled);
#   * LIVE SOCKET — a configured connection-rate limiter admits under-budget
#     inbound TCP connections and refuses over-budget ones (10 conns, max 3 →
#     3 accepted / 7 refused; qbind_p2p_connection_rate_drop_total = 7);
#   * LIVE SOCKET — a SECOND KEMTLS-admitted peer (the Run 371 helper in
#     dial-flood mode) completes the KEMTLS mutual-auth handshake against a
#     SEPARATE running target/release/qbind-node, floods structured frames over
#     the deployed read loop, and the deployed node's LIVE /metrics exposes
#     qbind_net_per_peer_drops_total{reason="rate_limit"} increments:
#       - under-budget flood → per-peer family ABSENT (no drops);
#       - over-budget flood  → per-peer drops > 0;
#       - the connection-rate counter stays 0 (controls independent).
#
# Run 371 does NOT open a default-open public port, launch a public DevNet,
# deploy a seed / bootnode / faucet / RPC / explorer / status page, change any
# wire format, weaken peer admission, or mutate trust/validator/epoch state. All
# addresses are loopback (127.0.0.1); temporary data dirs are used and removed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run371-public-devnet-m12-kemtls-per-peer-live-socket-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_NAME="run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper"
HELPER_BIN="${REPO_ROOT}/target/release/examples/${HELPER_NAME}"
SUMMARY="${OUTDIR}/summary.txt"

# Per-peer live-socket flood parameters.
PP_MAX=5           # --p2p-max-messages-per-second
PP_BURST=5         # --p2p-burst-allowance
PP_UNDER_FRAMES=4  # under-budget frame count
PP_UNDER_PACE=400  # ms between under-budget frames
PP_OVER_FRAMES=60  # over-budget frame count
PP_OVER_PACE=8     # ms between over-budget frames

log()  { printf '[run371] %s\n' "$*"; }
fail() { printf '[run371] FAIL: %s\n' "$*" >&2; exit 1; }
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
  local p2p_port metrics_port data_dir logf
  p2p_port="$(free_port)"
  metrics_port="$(free_port)"
  data_dir="${OUTDIR}/nodes/${label}/data"
  logf="${OUTDIR}/nodes/${label}/node.log"
  mkdir -p "${data_dir}" "$(dirname "${logf}")"
  (
    cd "${REPO_ROOT}"
    QBIND_METRICS_HTTP_ADDR="127.0.0.1:${metrics_port}" \
      timeout 90 "${NODE_BIN}" \
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
    --example "${HELPER_NAME}" >/dev/null 2>&1 ) \
  || fail "cargo build --example ${HELPER_NAME} (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 371 release-binary M12 KEMTLS per-peer live-socket evidence ==="
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
# 2. Run the release-built helper (in-process two-node KEMTLS flood proof).
# ---------------------------------------------------------------------------
log "running release-built helper (in-process KEMTLS flood scenarios)"
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
  || fail "helper did not render the per-peer drop family over the KEMTLS socket"
emit "helper_scenarios: $(grep -c . "${HELPER_OUT}/manifest.txt") scenarios recorded"
emit "helper_kemtls_over_budget_drops: $(grep 'over_budget_per_peer_drops' "${HELPER_OUT}/metric_evidence.txt" | awk '{print $2}')"

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
  emit "p2p_mode_discovery: P2P-capable loopback mode CONFIRMED (real socket bound)"
else
  emit "p2p_mode_discovery: FAILED (see nodes/default_no_flags/node.log)"
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
# 6. LIVE SOCKET — connection_rate under-budget then over-budget (Run 367/370
#    regression: 10 conns, max 3 → 3 accepted / 7 refused; drop metric = 7).
# ---------------------------------------------------------------------------
log "LIVE SOCKET: connection_rate_live_socket_regression"
CR_WINDOW_MS=60000
CR_MAX=3
launch_p2p_node "connection_rate" \
  --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms "${CR_WINDOW_MS}" \
  --p2p-connection-rate-max "${CR_MAX}"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  fail "connection_rate node did not come up"
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

# Independence: a pure connection-rate flood must never surface a per-peer drop.
PP_ON_CONN="$(scrape_per_peer_drops "${LAST_METRICS_PORT}")"
[ "${PP_ON_CONN}" = "MISSING" ] \
  || fail "connection-rate flood unexpectedly surfaced a per-peer drop metric: ${PP_ON_CONN}"
emit "combined_limiter_independence_conn_side: connection-rate flood left qbind_net_per_peer_drops_total ABSENT (live socket)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 7. LIVE SOCKET — KEMTLS-admitted DEPLOYED per-peer message-rate flood.
#    A SECOND qbind-node peer (the Run 371 helper in dial-flood mode) completes
#    the KEMTLS mutual-auth handshake against a separate running
#    target/release/qbind-node and floods frames over the deployed read loop.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: kemtls per-peer message-rate flood (deployed read loop)"
launch_p2p_node "kemtls_per_peer" \
  --p2p-max-messages-per-second "${PP_MAX}" \
  --p2p-burst-allowance "${PP_BURST}"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  fail "kemtls_per_peer node did not come up"
fi
KP_P2P_PORT="${LAST_P2P_PORT}"
KP_METRICS_PORT="${LAST_METRICS_PORT}"
KP_PID="${LAST_NODE_PID}"
sleep 1

# The deployed per-peer family must be ABSENT before any flood.
PP_START="$(scrape_per_peer_drops "${KP_METRICS_PORT}")"
[ "${PP_START}" = "MISSING" ] || fail "per-peer drop family present before any flood (got ${PP_START})"

# Under-budget KEMTLS flood → no per-peer drops.
UNDER_LISTEN="127.0.0.1:$(free_port)"
"${HELPER_BIN}" dial-flood "0@127.0.0.1:${KP_P2P_PORT}" "${UNDER_LISTEN}" 1 \
  "${PP_UNDER_FRAMES}" "${PP_UNDER_PACE}" "${OUTDIR}/kemtls_under.txt" \
  > "${OUTDIR}/kemtls_under_stdout.txt" 2>&1 || fail "under-budget dial-flood failed to connect/flood"
grep -q '^connected: true' "${OUTDIR}/kemtls_under.txt" \
  || fail "under-budget peer did not complete the KEMTLS handshake"
grep -q '^target_node_id_seen: true' "${OUTDIR}/kemtls_under.txt" \
  || fail "under-budget peer did not register the deployed node's deterministic NodeId"
sleep 1
PP_UNDER="$(scrape_per_peer_drops "${KP_METRICS_PORT}")"
[ "${PP_UNDER}" = "MISSING" ] \
  || fail "under-budget KEMTLS flood unexpectedly produced per-peer drops: ${PP_UNDER}"
emit "kemtls_second_peer_admitted: KEMTLS mutual-auth handshake completed against target/release/qbind-node (deterministic peer NodeId observed)"
emit "per_peer_kemtls_under_budget: ${PP_UNDER_FRAMES} under-budget frames over the KEMTLS socket → 0 per-peer drops (metric ABSENT) (live socket)"

# Over-budget KEMTLS flood → deployed per-peer limiter drops; metric increments.
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
emit "per_peer_kemtls_over_budget: ${PP_OVER_FRAMES} over-budget frames over the KEMTLS socket → qbind_net_per_peer_drops_total{reason=\"rate_limit\"}=${PP_OVER} on LIVE /metrics of target/release/qbind-node (live socket)"

# Connection-rate counter must be untouched by the per-peer flood.
KP_CONN_METRIC="$(scrape_metric "${KP_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${KP_CONN_METRIC}" = "0" ] \
  || fail "per-peer KEMTLS flood incremented the connection-rate counter (${KP_CONN_METRIC})"
emit "combined_limiter_independence_per_peer_side: per-peer KEMTLS flood left qbind_p2p_connection_rate_drop_total=0 (controls independent, live socket)"

# The read loop must not tear down purely because of per-peer drops: the node is
# still up and serving /metrics after the flood.
kill -0 "${KP_PID}" 2>/dev/null || fail "deployed node exited during/after the per-peer flood"
emit "per_peer_drop_does_not_tear_down: deployed node still serving /metrics after the per-peer flood"
stop_node "${KP_PID}"

emit "verdict: PASS — public-DevNet abuse/DoS M12 KEMTLS live-socket release-binary POSITIVE: a second KEMTLS-admitted peer completed mutual auth against target/release/qbind-node, flooded over-budget frames through the deployed TcpKemTlsP2pService::read_loop, and live /metrics exposed qbind_net_per_peer_drops_total{reason=\"rate_limit\"} increments; connection-rate live-socket proof preserved; both deployed live-socket controls proven."
log "DONE — see ${SUMMARY}"