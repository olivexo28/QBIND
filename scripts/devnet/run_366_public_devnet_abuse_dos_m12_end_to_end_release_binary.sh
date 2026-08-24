#!/usr/bin/env bash
# Run 366: release-binary END-TO-END evidence harness for the public DevNet
# abuse/DoS M12 controls — the runtime-owned connection-rate limiter (Run 362)
# AND the per-peer message-rate override threaded through the DEPLOYED
# `P2pNodeBuilder` path (Run 365) — proven together on the real
# `target/release/qbind-node` plus a release-built helper.
#
# This harness:
#   * builds (or reuses) `target/release/qbind-node` and the Run 366 helper
#     example, capturing SHA-256s, the toolchain, and Build IDs;
#   * runs the Run 366 release-built helper, which links the real
#     Run 361/362/363/365 runtime symbols and proves, in release mode: default
#     config preserves old behavior (connection limiter disabled; per-peer
#     defaults 1000/100; drop metric zero); an enabled connection-rate limiter
#     accepts under-budget and refuses over-budget inbound connections while
#     incrementing `qbind_p2p_connection_rate_drop_total`; a custom per-peer
#     message-rate override reaches the DEPLOYED builder peer-manager limiter
#     construction path (`build_deployed_peer_manager`) and allows under-budget /
#     drops over-budget messages; the two limiters are independent; invalid
#     configs fail closed; MainNet is refused;
#   * exercises the production binary CLI surface: `--help` succeeds and does NOT
#     surface the hidden abuse/DoS flags; an invented abuse/DoS flag is rejected
#     by clap; the real hidden flags parse;
#   * launches a bounded, timeout-supervised real `qbind-node` on an explicit
#     temporary data-dir with the hidden abuse/DoS flags and records the
#     deployed-path liveness observed. On DevNet the node runs in LocalMesh mode
#     (`enable_p2p` is ignored), so the P2P accept/message path is NOT driven
#     over a live socket in this environment; this blocker is recorded honestly
#     and keeps M12 Yellow/Partial (see the evidence doc).
#
# Run 366 does NOT open a default-open public port, launch a public DevNet,
# deploy a seed / bootnode / faucet / RPC / explorer / status page, change any
# wire format, weaken peer admission, or mutate trust/validator/epoch state.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run366-public-devnet-abuse-dos-m12-end-to-end-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run366] %s\n' "$*"; }
fail() { printf '[run366] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Build (idempotent) the release binary + helper.
# ---------------------------------------------------------------------------
log "building release binary + helper"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release >/dev/null 2>&1 ) \
  || fail "cargo build -p qbind-node --release failed"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release \
    --example run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example run_366 helper (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 366 release-binary end-to-end evidence ==="
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
# 2. Run the release-built helper (real Run 361/362/363/365 runtime symbols;
#    per-peer scenarios drive the DEPLOYED P2pNodeBuilder path).
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

# The abuse/DoS flags are hidden/devnet-only: they MUST NOT appear in --help.
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

# An invented abuse/DoS flag MUST be rejected by clap (unknown argument).
set +e
"${NODE_BIN}" --p2p-connection-rate-bogus 1 --version > "${OUTDIR}/invented_flag.txt" 2>&1
INVENTED_RC=$?
set -e
[ "${INVENTED_RC}" -ne 0 ] \
  || fail "invented flag --p2p-connection-rate-bogus was NOT rejected"
emit "invented_flag_rejected: true (rc=${INVENTED_RC})"

# The real hidden flags parse (clap accepts them). Use --version to short-circuit
# before any node startup so this is a fast parse-only check.
set +e
"${NODE_BIN}" --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms 1000 \
  --p2p-connection-rate-max 20 \
  --p2p-max-messages-per-second 750 \
  --p2p-burst-allowance 60 --version > "${OUTDIR}/real_flags_parse.txt" 2>&1
REAL_RC=$?
set -e
[ "${REAL_RC}" -eq 0 ] \
  || fail "real hidden flags did not parse (rc=${REAL_RC}); see real_flags_parse.txt"
emit "real_hidden_flags_parse: true (rc=${REAL_RC})"

# ---------------------------------------------------------------------------
# 4. Bounded, timeout-supervised real node launch (deployed-path liveness).
#    We launch a real target/release/qbind-node on an explicit temporary
#    data-dir with the hidden abuse/DoS flags. On DevNet the node runs in
#    LocalMesh mode (enable_p2p ignored), so it enters the consensus loop and
#    the P2P accept/message path is NOT driven over a live socket here. We
#    record this honestly: the real binary accepts and starts with the hidden
#    flags (proving they parse and are wired into startup), but the live
#    inbound/message path is not exercised on a running node in this
#    environment, which is why M12 stays Yellow/Partial.
# ---------------------------------------------------------------------------
log "bounded real-node launch (deployed-path liveness probe)"
NODE_DATA="${OUTDIR}/node_data"
NODE_LOG="${OUTDIR}/node_launch.log"
mkdir -p "${NODE_DATA}"
set +e
timeout 20 "${NODE_BIN}" \
  --env devnet \
  --data-dir "${NODE_DATA}" \
  --enable-p2p \
  --p2p-connection-rate-limit-enabled \
  --p2p-connection-rate-window-ms 1000 \
  --p2p-connection-rate-max 20 \
  --p2p-max-messages-per-second 750 \
  --p2p-burst-allowance 60 > "${NODE_LOG}" 2>&1
NODE_RC=$?
set -e
# rc=124 → timeout reaped a running node (expected: consensus loop blocks).
if [ "${NODE_RC}" -eq 124 ] && grep -q 'Consensus loop running' "${NODE_LOG}"; then
  emit "node_launch: started + reaped by timeout (rc=124); real binary accepted hidden abuse/DoS flags"
elif [ "${NODE_RC}" -eq 0 ]; then
  emit "node_launch: exited cleanly (rc=0) with hidden abuse/DoS flags"
else
  emit "node_launch: rc=${NODE_RC} (see node_launch.log)"
fi
if grep -q 'network_mode=local-mesh' "${NODE_LOG}"; then
  emit "node_launch_p2p_path: NOT driven — DevNet LocalMesh ignores --enable-p2p (documented blocker; M12 stays Yellow/Partial)"
else
  emit "node_launch_p2p_path: see node_launch.log"
fi

# Semantic fail-closed (invalid config / MainNet refusal) is proven by the
# release-built helper, which links and calls the *exact* production validation
# function `CliArgs::abuse_dos_runtime_config()` (helper scenarios 05 + 06).
#
# It is NOT re-run here as a full production-binary launch on purpose: on every
# invocation reachable in this environment the `qbind-node` binary enters its
# blocking LocalMesh consensus loop BEFORE the abuse/DoS config validation
# branch in `main.rs` (the validation lives on the P2P-builder path, which is
# not reached before the consensus loop blocks on these DevNet invocations), so
# a full-node run would hang rather than exit. The helper exercises the same
# validation code path deterministically and without launching a node. This is
# an honest limitation of the reachable production invocations, not a skipped
# check — see docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md.
emit "invalid_config_fail_closed: proven via release helper (scenario 05; production validation fn CliArgs::abuse_dos_runtime_config)"
emit "mainnet_abuse_dos_refused: proven via release helper (scenario 06; production validation fn CliArgs::abuse_dos_runtime_config)"

emit "verdict: PARTIAL-POSITIVE (deployed-builder path release-binary proven; live socket path not driven under LocalMesh; M12 stays Yellow/Partial)"
log "DONE — see ${SUMMARY}"