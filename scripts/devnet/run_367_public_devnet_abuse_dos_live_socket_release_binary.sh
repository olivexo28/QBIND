#!/usr/bin/env bash
# Run 367: release-binary LIVE-SOCKET evidence harness for the public DevNet
# abuse/DoS M12 controls.
#
# Run 366 kept M12 Yellow/Partial because its harness launched `qbind-node`
# WITHOUT `--network-mode p2p`, so the node ran in LocalMesh and the live inbound
# socket path was never driven. Run 367 fixes that: it launches a real
# `target/release/qbind-node` in a P2P-capable loopback mode
# (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`) and
# drives REAL inbound TCP sockets against the accept-loop connection-rate limiter
# (`p2p_tcp::spawn_accept_loop` -> `PublicDevnetAbuseDosRuntimeState::should_admit`),
# scraping the live `/metrics` endpoint for `qbind_p2p_connection_rate_drop_total`.
#
# This harness proves, on real release artifacts:
#   * `target/release/qbind-node` + the Run 367 helper build; SHA-256s, Build IDs,
#     and the toolchain are captured;
#   * the Run 367 release helper (in-process runtime-symbol proof) PASSes 8/8;
#   * the production CLI surface hides the abuse/DoS flags, rejects invented
#     flags, and parses the real hidden flags;
#   * LIVE SOCKET — default (no abuse/DoS flags) P2P node keeps
#     `qbind_p2p_connection_rate_drop_total` at 0 (connection limiter disabled);
#   * LIVE SOCKET — a configured connection-rate limiter admits under-budget
#     inbound TCP connections and refuses over-budget ones, incrementing
#     `qbind_p2p_connection_rate_drop_total` by exactly the over-budget count and
#     recording the same accept/refuse split in the node log;
#   * LIVE SOCKET — under-budget-only inbound TCP connections never increment the
#     drop metric.
#
# HONEST LIMITATION (recorded, not hidden): the per-peer MESSAGE-rate control is
# enforced on the ADMITTED-peer receive path inside `AsyncPeerManagerImpl` and
# therefore requires a second KEMTLS peer that completes the handshake and floods
# messages faster than the configured per-peer bucket. This harness does NOT
# stand up that second-peer flood path over a live socket, so the per-peer
# message-rate control is proven only through the DEPLOYED builder path in the
# Run 367 helper (scenarios 03/04). Because M12 Green requires BOTH controls over
# a live socket, M12 therefore stays Yellow/Partial (strengthened with live
# connection-rate socket evidence). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md.
#
# Run 367 does NOT open a default-open public port, launch a public DevNet,
# deploy a seed / bootnode / faucet / RPC / explorer / status page, change any
# wire format, weaken peer admission, or mutate trust/validator/epoch state. All
# addresses are loopback (127.0.0.1); temporary data dirs are used and removed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run367-public-devnet-abuse-dos-live-socket-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_367_public_devnet_abuse_dos_live_socket_helper"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run367] %s\n' "$*"; }
fail() { printf '[run367] FAIL: %s\n' "$*" >&2; exit 1; }
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

# Pick a free loopback TCP port.
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Drive N raw inbound TCP connections to 127.0.0.1:<port> (connect + close,
# no handshake). Prints nothing; failures to connect are tolerated (the point is
# to hit the accept loop).
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

# Launch a bounded P2P-capable loopback node. Args after the fixed ones are
# extra flags (e.g. the connection-rate limiter family). Sets LAST_NODE_PID,
# LAST_P2P_PORT, LAST_METRICS_PORT, LAST_NODE_LOG.
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
    --example run_367_public_devnet_abuse_dos_live_socket_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example run_367 helper (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 367 release-binary live-socket evidence ==="
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
# 2. Run the release-built helper (in-process runtime-symbol proof).
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
grep -q 'registered_once: true' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "metric was not registered exactly once"
grep -q 'endpoint_label_leak: false' "${HELPER_OUT}/metric_evidence.txt" \
  || fail "metric endpoint-label leak detected"
emit "helper_scenarios: $(grep -c . "${HELPER_OUT}/manifest.txt") scenarios recorded"

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
# 4. LIVE SOCKET — p2p_mode_discovery + default_preserves_behavior.
#    Launch a P2P-capable loopback node with NO abuse/DoS flags. Prove it binds
#    a real socket ("P2P transport up") and the connection-rate metric is a
#    registered, zero-valued counter (limiter disabled by default).
# ---------------------------------------------------------------------------
log "LIVE SOCKET: p2p_mode_discovery + default_preserves_behavior"
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
# 5. LIVE SOCKET — connection_rate_live_socket (under-budget then over-budget).
#    Configure a tiny global connection-rate bucket (window 60s, max 3, burst 0)
#    so the token count is deterministic within the harness window. Drive real
#    inbound TCP connections and prove:
#      * first 3 admitted, 0 drops;
#      * a further 7 (total 10) refused → metric == 7 and log shows 3 accepted /
#        7 connection-rate limited.
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

# 5a. Under-budget: drive exactly CR_MAX connections → no drops.
drive_tcp_connections "${LAST_P2P_PORT}" "${CR_MAX}"
sleep 1
CR_METRIC_UNDER="$(scrape_metric "${LAST_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${CR_METRIC_UNDER}" = "0" ] \
  || fail "under-budget (${CR_MAX}) connections unexpectedly incremented drop metric to ${CR_METRIC_UNDER}"
emit "connection_rate_under_budget: ${CR_MAX} inbound TCP connections admitted; drop metric still 0 (live socket)"

# 5b. Over-budget: drive 7 more (total 10) → 7 refusals.
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
emit "connection_rate_metric_on_allowed: metric stayed 0 across the first ${CR_MAX} allowed connections (live socket)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 6. Per-peer message-rate live path — HONEST BLOCKER.
#    The per-peer message-rate limiter enforces on the ADMITTED-peer receive
#    path inside AsyncPeerManagerImpl and needs a second KEMTLS peer that
#    completes the handshake and floods messages over the configured bucket.
#    This harness does not stand up that second-peer flood path, so the per-peer
#    message-rate control is proven only through the DEPLOYED builder path in the
#    Run 367 helper (scenarios 03/04). Recorded honestly; NOT claimed as
#    live-socket evidence.
# ---------------------------------------------------------------------------
emit "per_peer_message_rate_live_socket: NOT driven — requires a second admitted KEMTLS peer flood harness (proven via DEPLOYED builder path in Run 367 helper scenarios 03/04; recorded blocker)"

# ---------------------------------------------------------------------------
# 7. Fail-closed + MainNet refusal — proven by the release helper, which links
#    and calls the exact production validation fn CliArgs::abuse_dos_runtime_config().
# ---------------------------------------------------------------------------
emit "invalid_config_fail_closed: proven via release helper (scenario 05; production validation fn CliArgs::abuse_dos_runtime_config)"
emit "mainnet_abuse_dos_refused: proven via release helper (scenario 06; production validation fn CliArgs::abuse_dos_runtime_config)"

emit "verdict: PARTIAL-POSITIVE (live-socket CONNECTION-RATE control proven end-to-end on the release binary; per-peer MESSAGE-rate live path not driven; M12 stays Yellow/Partial, strengthened)"
log "DONE — see ${SUMMARY}"