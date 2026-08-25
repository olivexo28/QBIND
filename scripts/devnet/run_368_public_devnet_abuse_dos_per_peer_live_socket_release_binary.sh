#!/usr/bin/env bash
# Run 368: release-binary evidence harness for the public DevNet abuse/DoS M12
# per-peer message-rate control over an ADMITTED-PEER live socket.
#
# Run 367 proved the CONNECTION-RATE control end-to-end on the real
# `target/release/qbind-node` (over-budget inbound TCP connections refused;
# `qbind_p2p_connection_rate_drop_total` increments) but kept M12 Yellow/Partial
# because the PER-PEER MESSAGE-RATE control was only proven through the DEPLOYED
# builder construction path (a synchronous `PeerRateLimiter::allow()` call),
# never over an admitted peer's real socket receive loop.
#
# Run 368 strengthens that: the Run 368 release helper stands up a real loopback
# TCP socket pair, registers one side as an ADMITTED PEER on a live
# `AsyncPeerManagerImpl` (the component that owns the per-peer
# `PeerRateLimiter`), floods length-prefixed `NetMessage` frames from the other
# side, and proves over a real socket:
#   * under-budget messages accepted (0 per-peer drops);
#   * over-budget messages dropped by the live `PeerRateLimiter`;
#   * `NodeMetrics::peer_network().total_rate_limit_drops()` /
#     `peer_rate_limit_drop_count(peer)` reflect the drops;
#   * the connection-rate counter (`P2pMetrics`) does NOT move for per-peer
#     drops (independence);
#   * defaults, fail-closed validation, MainNet refusal, and the hidden CLI
#     surface are preserved.
#
# This harness also RE-RUNS the Run 367 CONNECTION-RATE live-socket proof as a
# regression on the real release binary (under-budget admitted / over-budget
# refused / metric increments).
#
# HONEST BLOCKER (recorded, not hidden; Run 368 decision gate = Route C): the
# admitted-peer receive loop that enforces the per-peer limiter is
# `AsyncPeerManagerImpl::peer_reader_task`. The DEPLOYED `qbind-node` binary's
# live inbound path is `TcpKemTlsP2pService::subscribe()` -> `P2pInboundDemuxer`
# -> handlers (see `p2p_node_builder.rs`), and that path does NOT consult the
# `PeerRateLimiter`; `build_deployed_peer_manager()` is construction-path-only
# and is never spawned by `main.rs`. So the per-peer message-rate proof here is
# at the `AsyncPeerManagerImpl` layer (via the Run 368 helper), NOT the deployed
# TcpKemTls receive path, and the admitted peer is plain-TCP, not a full KEMTLS
# mutual-auth handshake. Because M12 Green requires BOTH controls over the
# DEPLOYED live socket, M12 stays Yellow/Partial. See
# docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md.
#
# Run 368 does NOT open a default-open public port, launch a public DevNet,
# deploy a seed / bootnode / faucet / RPC / explorer / status page, change any
# wire format, weaken peer admission, or mutate trust/validator/epoch state. All
# addresses are loopback (127.0.0.1); temporary data dirs are used and removed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run368-public-devnet-abuse-dos-per-peer-live-socket-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run368] %s\n' "$*"; }
fail() { printf '[run368] FAIL: %s\n' "$*" >&2; exit 1; }
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

# Drive N raw inbound TCP connections to 127.0.0.1:<port> (connect + close).
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

# ---------------------------------------------------------------------------
# 1. Build (idempotent) the release binary + helper.
# ---------------------------------------------------------------------------
log "building release binary + helper"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release >/dev/null 2>&1 ) \
  || fail "cargo build -p qbind-node --release failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release \
    --example run_368_public_devnet_abuse_dos_per_peer_live_socket_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example run_368 helper (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 368 release-binary admitted-peer per-peer message-rate live-socket evidence ==="
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
# 2. Run the release-built helper (real-socket admitted-peer per-peer proof).
# ---------------------------------------------------------------------------
log "running release-built helper (admitted-peer real-socket per-peer proof)"
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
  || fail "per-peer rate-limit drop metric family not present"
grep -q 'conn_registered_once: true' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "connection-rate metric was not registered exactly once"
grep -q 'conn_endpoint_label_leak: false' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "connection-rate metric endpoint-label leak detected"
HELPER_PP_DROPS="$(awk -F': ' '/per_peer_drops_observed/ {print $2; exit}' "${HELPER_OUT}/metric_evidence.txt")"
[ "${HELPER_PP_DROPS:-0}" -ge 1 ] \
  || fail "helper did not observe any per-peer message-rate drops (${HELPER_PP_DROPS})"
emit "helper_scenarios: $(grep -c . "${HELPER_OUT}/manifest.txt") scenarios recorded"
emit "helper_per_peer_live_socket_drops: ${HELPER_PP_DROPS} (AsyncPeerManagerImpl layer, real loopback socket)"

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
"${NODE_BIN}" --p2p-message-flood-bogus 1 --version > "${OUTDIR}/invented_flag.txt" 2>&1
INVENTED_RC=$?
set -e
[ "${INVENTED_RC}" -ne 0 ] || fail "invented flag --p2p-message-flood-bogus was NOT rejected"
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
# 4. LIVE SOCKET — default_preserves_behavior.
#    P2P-capable loopback node with NO abuse/DoS flags: binds a real socket and
#    the connection-rate metric is a registered, zero-valued counter.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: default_preserves_behavior"
launch_p2p_node "default_no_flags"
if wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  emit "p2p_mode_discovery: P2P-capable loopback mode CONFIRMED (real socket bound; 'P2P transport up')"
else
  emit "p2p_mode_discovery: FAILED to reach 'P2P transport up' (see nodes/default_no_flags/node.log)"
  fail "P2P-capable loopback mode did not come up for default_no_flags"
fi
DEFAULT_METRIC="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
DEFAULT_LIMITER_LOG="$(grep -c 'connection-rate limiter ENABLED' "${LAST_NODE_LOG}" || true)"
[ "${DEFAULT_METRIC}" = "0" ] \
  || fail "default (no-flag) node reported non-zero connection-rate drop metric: ${DEFAULT_METRIC}"
[ "${DEFAULT_LIMITER_LOG}" = "0" ] \
  || fail "default (no-flag) node unexpectedly logged the connection-rate limiter as ENABLED"
emit "default_preserves_behavior: connection limiter DISABLED; qbind_p2p_connection_rate_drop_total=0 (live socket)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 5. LIVE SOCKET — connection_rate_regression (Run 367 parity).
#    Tiny global connection-rate bucket (window 60s, max 3, burst 0). Drive real
#    inbound TCP connections and prove first 3 admitted (0 drops); a further 7
#    (total 10) refused → metric == 7, log shows 3 accepted / 7 rate-limited.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: connection_rate_regression"
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
emit "connection_rate_under_budget: ${CR_MAX} inbound TCP connections admitted; drop metric still 0 (live socket)"

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
emit "connection_rate_over_budget: 10 inbound TCP connections → ${CR_MAX} accepted / 7 refused; qbind_p2p_connection_rate_drop_total=7 (live socket)"
emit "connection_rate_regression: PASS (Run 367 connection-rate proof re-run on the release binary)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 6. Per-peer message-rate over the DEPLOYED live socket — HONEST BLOCKER.
#    The per-peer message-rate limiter enforces inside
#    AsyncPeerManagerImpl::peer_reader_task, which the DEPLOYED qbind-node inbound
#    path (TcpKemTlsP2pService::subscribe -> P2pInboundDemuxer -> handlers) does
#    NOT invoke. build_deployed_peer_manager() is construction-path-only and is
#    never spawned by main.rs. So per-peer message-rate live-socket proof exists
#    only at the AsyncPeerManagerImpl layer (Run 368 helper scenarios 02/03/04),
#    NOT on the deployed TcpKemTls receive path. Recorded honestly; NOT claimed as
#    deployed-binary live-socket evidence. This is the exact remaining M12 blocker.
# ---------------------------------------------------------------------------
emit "per_peer_message_rate_deployed_live_socket: NOT driven — deployed inbound path (TcpKemTls->demuxer) does not consult PeerRateLimiter; proven at AsyncPeerManagerImpl layer via Run 368 helper (real socket, ${HELPER_PP_DROPS} drops). Remaining M12 blocker: wire PeerRateLimiter onto the deployed TcpKemTls receive path."

# ---------------------------------------------------------------------------
# 7. Fail-closed + MainNet refusal + independence — proven by the release helper,
#    which links and calls the exact production validation fn
#    CliArgs::abuse_dos_runtime_config() and the live AsyncPeerManagerImpl.
# ---------------------------------------------------------------------------
emit "invalid_config_fail_closed: proven via release helper (scenario 07; production validation fn CliArgs::abuse_dos_runtime_config)"
emit "mainnet_abuse_dos_refused: proven via release helper (scenario 08; production validation fn CliArgs::abuse_dos_runtime_config)"
emit "combined_limiter_independence: proven via release helper (scenario 06; conn metric vs per-peer counter distinct)"

emit "verdict: PARTIAL-POSITIVE (per-peer MESSAGE-rate proven over a real admitted-peer socket at the AsyncPeerManagerImpl layer; CONNECTION-rate re-proven live-socket on the release binary; deployed TcpKemTls receive path does NOT yet enforce the per-peer limiter, so M12 stays Yellow/Partial, strengthened)"
log "DONE — see ${SUMMARY}"
