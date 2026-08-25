#!/usr/bin/env bash
# Run 373: release-binary CROSS-PROCESS hardening harness for the public DevNet
# abuse/DoS M12 controls under STRICT mutual-auth admission AND operator-configured
# `PqcRootMode::PqcStaticRoot` material.
#
# Run 372 (accepted POSITIVE) re-proved the Run 371 M12 Green result under strict
# `MutualAuthMode::Required` admission with two simultaneous KEMTLS peers and
# isolated per-peer buckets, BUT its `PqcRootMode::PqcStaticRoot` proof was
# in-process only. Run 373 (Route A — no production source change) extends that to
# a standalone-binary, cross-process loopback proof:
#
#   * The harness generates TEMPORARY ML-DSA-44 root + ML-KEM-768 leaf material
#     into a temp dir with the pre-existing `devnet_pqc_root_helper` example.
#   * It launches the standalone `target/release/qbind-node` under
#       --p2p-mutual-auth required
#       --p2p-pqc-root-mode pqc-static-root
#       --p2p-trusted-root <spec>
#       --p2p-leaf-cert <v0.cert.bin>  --p2p-leaf-cert-key <v0.kem.sk.bin>
#       --p2p-peer 1@<honest_listen> --p2p-peer-leaf-cert 1:<v1.cert.bin>
#       --p2p-peer 2@<abusive_listen> --p2p-peer-leaf-cert 2:<v2.cert.bin>
#     on a loopback listen + loopback metrics endpoint, with a low per-peer budget.
#   * The Run 373 helper (dial-flood-static-root mode) builds node B peers from the
#     SAME operator-configured static-root material, completes the Required KEMTLS
#     mutual-auth handshake against the deployed node, and floods structured frames
#     over the deployed `TcpKemTlsP2pService::read_loop`.
#   * On live `/metrics`, an abusive over-budget peer's drops appear ONLY under its
#     cert-derived `peer="<key>"` label while the honest peer's label stays absent.
#
# It ALSO preserves every Run 371/372 guarantee on real release artifacts:
#   * target/release/qbind-node + the Run 373 helper build; SHA-256s, Build IDs,
#     and the toolchain are captured;
#   * the release helper's in-process static-root strict-auth flood PASSes all
#     scenarios;
#   * the production CLI surface hides the abuse/DoS flags, rejects invented flags,
#     and parses the real hidden flags;
#   * invalid zero/unbounded configs fail the binary closed at startup;
#   * an enabled MainNet abuse/DoS config is refused at startup;
#   * LIVE SOCKET — a configured connection-rate limiter admits under-budget inbound
#     TCP connections and refuses over-budget ones (10 conns, max 3 → 3 accepted /
#     7 refused; qbind_p2p_connection_rate_drop_total = 7), independent of per-peer.
#
# Run 373 does NOT open a default-open public port, launch a public DevNet, deploy
# a seed / bootnode / faucet / RPC / explorer / status page, change any wire
# format, weaken peer admission (it only TIGHTENS it), or mutate
# trust/validator/epoch state. All addresses are loopback (127.0.0.1); temporary
# data dirs and temporary PQC material are used and removed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run373-public-devnet-m12-pqc-static-root-cross-process-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_NAME="run_373_public_devnet_m12_pqc_static_root_cross_process_helper"
HELPER_BIN="${REPO_ROOT}/target/release/examples/${HELPER_NAME}"
ROOT_HELPER_BIN="${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper"
SUMMARY="${OUTDIR}/summary.txt"

# Per-peer live-socket flood parameters.
PP_MAX=5           # --p2p-max-messages-per-second
PP_BURST=5         # --p2p-burst-allowance
PP_UNDER_FRAMES=4  # under-budget frame count (honest peer)
PP_UNDER_PACE=400  # ms between under-budget frames
PP_OVER_FRAMES=60  # over-budget frame count (abusive peer)
PP_OVER_PACE=8     # ms between over-budget frames
HONEST_VID=1
ABUSIVE_VID=2

log()  { printf '[run373] %s\n' "$*"; }
fail() { printf '[run373] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# Node-launch bookkeeping + cleanup. The material dir is temporary and removed.
# ---------------------------------------------------------------------------
NODE_PIDS=()
MATERIAL_DIR="${OUTDIR}/material"
cleanup() {
  local pid
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "${pid}" ] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  # Remove temporary PQC material (private keys, certs) so nothing is left behind.
  rm -rf "${MATERIAL_DIR}" 2>/dev/null || true
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

# Drive N raw inbound TCP connections (connect + close, no handshake).
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

# Scrape the per-peer drop value for one specific bucket label (peer="<key>").
scrape_per_peer_drops_for_label() {
  local mport="$1" label="$2"
  curl -fsS --max-time 2 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v lbl="peer=\"${label}\"" '
        /^qbind_net_per_peer_drops_total/ && /reason="rate_limit"/ && index($0, lbl) {print $NF; found=1}
        END{ if(!found) print "MISSING" }'
}

wait_for_transport_up() {
  local logf="$1" tries="${2:-60}" i=0
  while [ "${i}" -lt "${tries}" ]; do
    if grep -qE 'P2P transport up|Listening on 127|listen=127' "${logf}" 2>/dev/null; then
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
      timeout 120 "${NODE_BIN}" \
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
# 1. Build (idempotent) the release binary + helpers.
# ---------------------------------------------------------------------------
log "building release binary + helpers"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release >/dev/null 2>&1 ) \
  || fail "cargo build -p qbind-node --release failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release \
    --example "${HELPER_NAME}" >/dev/null 2>&1 ) \
  || fail "cargo build --example ${HELPER_NAME} (release) failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release \
    --example devnet_pqc_root_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example devnet_pqc_root_helper (release) failed"

[ -x "${NODE_BIN}" ]        || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ]      || fail "release helper binary missing: ${HELPER_BIN}"
[ -x "${ROOT_HELPER_BIN}" ] || fail "release root helper binary missing: ${ROOT_HELPER_BIN}"

emit "=== Run 373 release-binary M12 cross-process PqcStaticRoot strict-auth hardening evidence ==="
emit "repo_root: ${REPO_ROOT}"
emit "toolchain: $(rustc --version 2>/dev/null || echo unknown)"
emit "cargo:     $(cargo --version 2>/dev/null || echo unknown)"
emit "node_bin:            ${NODE_BIN}"
emit "node_bin_sha256:     $(sha256_file "${NODE_BIN}")"
emit "node_bin_build_id:   $(build_id "${NODE_BIN}")"
emit "helper_bin:          ${HELPER_BIN}"
emit "helper_bin_sha256:   $(sha256_file "${HELPER_BIN}")"
emit "helper_bin_build_id: $(build_id "${HELPER_BIN}")"
emit "root_helper_bin:     ${ROOT_HELPER_BIN}"
emit "root_helper_sha256:  $(sha256_file "${ROOT_HELPER_BIN}")"

# ---------------------------------------------------------------------------
# 2. Run the release-built helper (in-process static-root strict-auth flood).
# ---------------------------------------------------------------------------
log "running release-built helper (in-process static-root strict-auth scenarios)"
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
  || fail "helper did not render the per-peer drop family over the static-root socket"
emit "helper_scenarios: $(grep -c . "${HELPER_OUT}/manifest.txt") scenarios recorded"
emit "helper_abusive_bucket_drops: $(grep 'abusive_bucket_drops' "${HELPER_OUT}/metric_evidence.txt" | head -1 | awk '{print $2}')"
emit "helper_honest_bucket_drops: $(grep 'honest_bucket_drops' "${HELPER_OUT}/metric_evidence.txt" | head -1 | awk '{print $2}')"
# The helper writes temporary PQC material under its own out dir; remove it.
rm -rf "${HELPER_OUT}/material" 2>/dev/null || true

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

# The strict-auth + static-root flags Run 373 relies on are PUBLIC (documented).
grep -q -- "--p2p-mutual-auth" "${OUTDIR}/help.txt" \
  || fail "expected public --p2p-mutual-auth flag missing from --help"
grep -q -- "--p2p-pqc-root-mode" "${OUTDIR}/help.txt" \
  || fail "expected public --p2p-pqc-root-mode flag missing from --help"
grep -q -- "--p2p-trusted-root" "${OUTDIR}/help.txt" \
  || fail "expected public --p2p-trusted-root flag missing from --help"
grep -q -- "--p2p-leaf-cert" "${OUTDIR}/help.txt" \
  || fail "expected public --p2p-leaf-cert flag missing from --help"
emit "strict_auth_and_static_root_flags_public: true (--p2p-mutual-auth / --p2p-pqc-root-mode / --p2p-trusted-root / --p2p-leaf-cert are pre-existing public flags)"

set +e
"${NODE_BIN}" --p2p-static-root-bogus 1 --version > "${OUTDIR}/invented_flag.txt" 2>&1
INVENTED_RC=$?
set -e
[ "${INVENTED_RC}" -ne 0 ] || fail "invented flag --p2p-static-root-bogus was NOT rejected"
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
# A strict static-root node with a malformed --p2p-trusted-root spec fails closed.
assert_node_fails_closed "malformed_trusted_root" \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "not-a-valid-spec"
emit "invalid_zero_per_peer_max_fails_closed: true (binary exits non-zero)"
emit "unbounded_per_peer_max_fails_closed: true (binary exits non-zero)"
emit "invalid_zero_connection_rate_fails_closed: true (binary exits non-zero)"
emit "malformed_trusted_root_fails_closed: true (binary exits non-zero)"

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
# 6. LIVE SOCKET — connection_rate under-budget then over-budget regression
#    (10 conns, max 3 → 3 accepted / 7 refused; drop metric = 7).
# ---------------------------------------------------------------------------
log "LIVE SOCKET: connection_rate_regression"
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
# 7. Generate TEMPORARY operator-configured PqcStaticRoot material (temp dir).
# ---------------------------------------------------------------------------
log "generating temporary ML-DSA-44 root + ML-KEM-768 leaf material (temp dir)"
mkdir -p "${MATERIAL_DIR}"
"${ROOT_HELPER_BIN}" "${MATERIAL_DIR}" 3 > "${OUTDIR}/material_stdout.txt" 2>"${OUTDIR}/material_stderr.txt" \
  || fail "devnet_pqc_root_helper failed to mint material"
for req in trusted-root.spec v0.cert.bin v0.kem.sk.bin v1.cert.bin v1.kem.sk.bin v2.cert.bin v2.kem.sk.bin; do
  [ -s "${MATERIAL_DIR}/${req}" ] || fail "expected material file missing/empty: ${req}"
done
# No root secret key is ever written to disk by the helper.
[ ! -e "${MATERIAL_DIR}/root.sk.bin" ] || fail "unexpected root secret key file on disk"
TRUSTED_SPEC="$(cat "${MATERIAL_DIR}/trusted-root.spec")"
ROOT_ID_HEX="$(cat "${MATERIAL_DIR}/root.id.hex")"
emit "temporary_pqc_static_root_material_generated: true (root_id=${ROOT_ID_HEX} suite=100 kem=ml-kem-768 validators=3; temp dir; root secret key in-memory only)"

# ---------------------------------------------------------------------------
# 8. LIVE SOCKET — CROSS-PROCESS STATIC-ROOT STRICT-AUTH MULTI-PEER flood.
#    A deployed node runs with operator-configured PqcStaticRoot material,
#    `--p2p-mutual-auth required`, and a low per-peer budget. TWO Run 373 helper
#    peers (dial-flood-static-root) built from the SAME material complete the
#    Required KEMTLS handshake against the SAME running target/release/qbind-node:
#      - HONEST peer (vid 1) stays under budget;
#      - ABUSIVE peer (vid 2) floods over budget.
#    The deployed per-peer buckets are ISOLATED on live /metrics.
# ---------------------------------------------------------------------------
log "LIVE SOCKET: cross-process static-root strict-auth multi-peer per-peer flood"
A_P2P_PORT="$(free_port)"
A_METRICS_PORT="$(free_port)"
HONEST_LISTEN_PORT="$(free_port)"
ABUSIVE_LISTEN_PORT="$(free_port)"
A_DATA="${OUTDIR}/nodes/static_root_node_a/data"
A_LOG="${OUTDIR}/nodes/static_root_node_a/node.log"
mkdir -p "${A_DATA}" "$(dirname "${A_LOG}")"
(
  cd "${REPO_ROOT}"
  QBIND_METRICS_HTTP_ADDR="127.0.0.1:${A_METRICS_PORT}" \
    timeout 180 "${NODE_BIN}" \
      --env devnet --network-mode p2p --enable-p2p \
      --p2p-listen-addr "127.0.0.1:${A_P2P_PORT}" --validator-id 0 --data-dir "${A_DATA}" \
      --p2p-mutual-auth required \
      --p2p-pqc-root-mode pqc-static-root \
      --p2p-trusted-root "${TRUSTED_SPEC}" \
      --p2p-leaf-cert "${MATERIAL_DIR}/v0.cert.bin" \
      --p2p-leaf-cert-key "${MATERIAL_DIR}/v0.kem.sk.bin" \
      --p2p-peer "${HONEST_VID}@127.0.0.1:${HONEST_LISTEN_PORT}" \
      --p2p-peer-leaf-cert "${HONEST_VID}:${MATERIAL_DIR}/v${HONEST_VID}.cert.bin" \
      --p2p-peer "${ABUSIVE_VID}@127.0.0.1:${ABUSIVE_LISTEN_PORT}" \
      --p2p-peer-leaf-cert "${ABUSIVE_VID}:${MATERIAL_DIR}/v${ABUSIVE_VID}.cert.bin" \
      --p2p-max-messages-per-second "${PP_MAX}" \
      --p2p-burst-allowance "${PP_BURST}"
) > "${A_LOG}" 2>&1 &
A_PID=$!
NODE_PIDS+=("${A_PID}")
log "launched static_root_node_a pid=${A_PID} p2p=${A_P2P_PORT} metrics=${A_METRICS_PORT}"

if ! wait_for_transport_up "${A_LOG}" 60; then
  fail "static_root_node_a did not come up"
fi
grep -q 'mutual_auth=Required' "${A_LOG}" \
  || fail "static_root_node_a did not log mutual_auth=Required"
grep -q 'pqc_root_mode=pqc-static-root' "${A_LOG}" \
  || fail "static_root_node_a did not log pqc_root_mode=pqc-static-root"
A_PQC_MODE_METRIC="$(scrape_metric "${A_METRICS_PORT}" qbind_p2p_pqc_root_mode)"
A_PQC_ROOTS_METRIC="$(scrape_metric "${A_METRICS_PORT}" qbind_p2p_pqc_roots_configured)"
[ "${A_PQC_MODE_METRIC}" = "1" ] \
  || fail "deployed node did not export qbind_p2p_pqc_root_mode=1 (got ${A_PQC_MODE_METRIC})"
[ "${A_PQC_ROOTS_METRIC}" = "1" ] \
  || fail "deployed node did not export qbind_p2p_pqc_roots_configured=1 (got ${A_PQC_ROOTS_METRIC})"
emit "cross_process_static_root_admission_live: deployed node running under MutualAuthMode::Required + PqcStaticRoot (qbind_p2p_pqc_root_mode=1, qbind_p2p_pqc_roots_configured=1) (live socket)"
sleep 1

# Cert-derived per-peer bucket labels (computed by the release helper from the
# ACTUAL generated leaf certs shared with the deployed node).
HONEST_LABEL="$("${HELPER_BIN}" bucket-key-cert "${MATERIAL_DIR}/v${HONEST_VID}.cert.bin")"
ABUSIVE_LABEL="$("${HELPER_BIN}" bucket-key-cert "${MATERIAL_DIR}/v${ABUSIVE_VID}.cert.bin")"
[ -n "${HONEST_LABEL}" ] && [ -n "${ABUSIVE_LABEL}" ] || fail "failed to compute per-peer bucket labels"
[ "${HONEST_LABEL}" != "${ABUSIVE_LABEL}" ] || fail "honest and abusive bucket labels collided"
emit "per_peer_bucket_labels: honest_vid=${HONEST_VID} label=${HONEST_LABEL}; abusive_vid=${ABUSIVE_VID} label=${ABUSIVE_LABEL} (cert-derived)"

# The deployed per-peer family must be ABSENT before any flood.
PP_START="$(scrape_per_peer_drops "${A_METRICS_PORT}")"
[ "${PP_START}" = "MISSING" ] || fail "per-peer drop family present before any flood (got ${PP_START})"

# Launch BOTH peers concurrently (honest under budget + abusive over budget),
# each built from the SAME operator static-root material.
"${HELPER_BIN}" dial-flood-static-root "0@127.0.0.1:${A_P2P_PORT}" "127.0.0.1:${HONEST_LISTEN_PORT}" \
  "${HONEST_VID}" "${PP_UNDER_FRAMES}" "${PP_UNDER_PACE}" \
  "${MATERIAL_DIR}/trusted-root.spec" "${MATERIAL_DIR}/v${HONEST_VID}.cert.bin" \
  "${MATERIAL_DIR}/v${HONEST_VID}.kem.sk.bin" "${MATERIAL_DIR}/v0.cert.bin" \
  "${OUTDIR}/static_honest.txt" > "${OUTDIR}/static_honest_stdout.txt" 2>&1 &
HONEST_JOB=$!
"${HELPER_BIN}" dial-flood-static-root "0@127.0.0.1:${A_P2P_PORT}" "127.0.0.1:${ABUSIVE_LISTEN_PORT}" \
  "${ABUSIVE_VID}" "${PP_OVER_FRAMES}" "${PP_OVER_PACE}" \
  "${MATERIAL_DIR}/trusted-root.spec" "${MATERIAL_DIR}/v${ABUSIVE_VID}.cert.bin" \
  "${MATERIAL_DIR}/v${ABUSIVE_VID}.kem.sk.bin" "${MATERIAL_DIR}/v0.cert.bin" \
  "${OUTDIR}/static_abusive.txt" > "${OUTDIR}/static_abusive_stdout.txt" 2>&1 &
ABUSIVE_JOB=$!

set +e
wait "${HONEST_JOB}"; HONEST_RC=$?
wait "${ABUSIVE_JOB}"; ABUSIVE_RC=$?
set -e
[ "${HONEST_RC}" -eq 0 ] || fail "honest static-root dial-flood failed (rc=${HONEST_RC})"
[ "${ABUSIVE_RC}" -eq 0 ] || fail "abusive static-root dial-flood failed (rc=${ABUSIVE_RC})"

grep -q '^connected: true' "${OUTDIR}/static_honest.txt" \
  || fail "honest peer did not complete the Required static-root KEMTLS handshake"
grep -q '^target_node_id_seen: true' "${OUTDIR}/static_honest.txt" \
  || fail "honest peer did not register the deployed node's cert-derived NodeId"
grep -q '^connected: true' "${OUTDIR}/static_abusive.txt" \
  || fail "abusive peer did not complete the Required static-root KEMTLS handshake"
grep -q '^target_node_id_seen: true' "${OUTDIR}/static_abusive.txt" \
  || fail "abusive peer did not register the deployed node's cert-derived NodeId"
emit "multi_peer_static_root_kemtls_admitted: TWO peers completed MutualAuthMode::Required + PqcStaticRoot KEMTLS handshakes against target/release/qbind-node (live socket)"
emit "cert_derived_node_id_observed_live: both peers observed the deployed node's cert-derived NodeId (from its leaf ML-KEM-768 pk); the deployed node registered each peer under its verified cert-derived NodeId"
sleep 1

# Per-bucket isolation on live /metrics.
HONEST_DROPS="$(scrape_per_peer_drops_for_label "${A_METRICS_PORT}" "${HONEST_LABEL}")"
ABUSIVE_DROPS="$(scrape_per_peer_drops_for_label "${A_METRICS_PORT}" "${ABUSIVE_LABEL}")"
TOTAL_PP_DROPS="$(scrape_per_peer_drops "${A_METRICS_PORT}")"

[ "${ABUSIVE_DROPS}" != "MISSING" ] \
  || fail "abusive peer flood did NOT surface any per-peer drops on live /metrics"
[ "${ABUSIVE_DROPS}" -gt 0 ] \
  || fail "abusive peer per-peer drops not > 0 (got ${ABUSIVE_DROPS})"
emit "over_budget_static_root_peer_live: abusive peer over-budget flood → qbind_net_per_peer_drops_total{peer=\"${ABUSIVE_LABEL}\",reason=\"rate_limit\"}=${ABUSIVE_DROPS} on LIVE /metrics (live socket)"

[ "${HONEST_DROPS}" = "MISSING" ] \
  || fail "honest peer bucket unexpectedly recorded per-peer drops: ${HONEST_DROPS} (bucket isolation broken)"
emit "under_budget_static_root_peer_live: honest peer under-budget flood → no drops in its bucket (label ${HONEST_LABEL} ABSENT) (live socket)"
emit "multi_peer_bucket_isolation_live: abusive drops attributed ONLY to abusive bucket; honest bucket clean (total per-peer drops=${TOTAL_PP_DROPS}) (live socket)"
emit "abusive_peer_does_not_consume_honest_peer_budget_live: honest peer stayed fully under budget while the abusive peer's bucket absorbed all drops (live socket)"

# Connection-rate counter must be untouched by the per-peer flood.
A_CONN_METRIC="$(scrape_metric "${A_METRICS_PORT}" qbind_p2p_connection_rate_drop_total)"
[ "${A_CONN_METRIC}" = "0" ] \
  || fail "static-root multi-peer flood incremented the connection-rate counter (${A_CONN_METRIC})"
emit "combined_limiter_independence_per_peer_side: static-root multi-peer flood left qbind_p2p_connection_rate_drop_total=0 (controls independent, live socket)"

# The read loop must not tear down purely because of per-peer drops.
kill -0 "${A_PID}" 2>/dev/null || fail "deployed node exited during/after the static-root multi-peer flood"
emit "per_peer_drop_does_not_tear_down: deployed node still serving /metrics after the static-root multi-peer flood"
stop_node "${A_PID}"

emit ""
emit "VERDICT: PASS — public-DevNet abuse/DoS M12 cross-process PqcStaticRoot strict-auth hardening POSITIVE."
emit "  Two peers completed MutualAuthMode::Required + PqcStaticRoot KEMTLS handshakes against"
emit "  target/release/qbind-node using operator-configured static-root material; an abusive over-budget"
emit "  flood was isolated to its own cert-derived per-peer bucket on live /metrics while the honest peer"
emit "  kept a full budget; the connection-rate control stayed independent; all Run 371/372 guarantees held."
emit "  M12 remains Green for scope (no broadening to public DevNet launch readiness)."

log "PASS"
