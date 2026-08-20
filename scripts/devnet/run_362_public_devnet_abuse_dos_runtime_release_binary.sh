#!/usr/bin/env bash
# Run 362: release-binary evidence harness for the public DevNet abuse/DoS
# runtime wiring landed in Run 362.
#
# Run 362 wires the Run 361 `AbuseDosConfig` / `ConnectionRateLimiter` model
# into the live `p2p_tcp` accept path behind a runtime-owned, default-off
# handle, adds the `qbind_p2p_connection_rate_drop_total` metric, and exposes a
# hidden/devnet-only `--p2p-connection-rate-limit-*` CLI flag family.
#
# This harness:
#   * builds (or reuses) `target/release/qbind-node` and the Run 362 helper
#     example, capturing SHA-256s, the toolchain, and Build IDs;
#   * runs the Run 362 release-built helper, which links the real Run 361/362
#     runtime symbols and proves: default config preserves old behavior; an
#     enabled DevNet limiter accepts under-budget and refuses over-budget
#     inbound connections; the drop metric increments on refusal and is
#     registered exactly once with no endpoint labels; invalid configs fail
#     closed; MainNet is refused;
#   * exercises the production binary CLI surface: `--help` succeeds and does
#     NOT surface the hidden abuse/DoS flags (they are hidden/devnet-only);
#     no unintended public `--p2p-connection-rate*` flag is listed; an invented
#     abuse/DoS flag is rejected by clap; the real hidden flags parse.
#
# Run 362 does NOT open a public port, launch a public DevNet, deploy a seed /
# bootnode / faucet / RPC / explorer / status page, change any wire format,
# weaken peer admission, or mutate trust/validator/epoch state.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run362-public-devnet-abuse-dos-runtime-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_362_public_devnet_abuse_dos_runtime_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run362] %s\n' "$*"; }
fail() { printf '[run362] FAIL: %s\n' "$*" >&2; exit 1; }
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
    --example run_362_public_devnet_abuse_dos_runtime_release_binary_helper >/dev/null 2>&1 ) \
  || fail "cargo build --example run_362 helper (release) failed"

[ -x "${NODE_BIN}" ]   || fail "release node binary missing: ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "release helper binary missing: ${HELPER_BIN}"

emit "=== Run 362 release-binary evidence ==="
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
# 2. Run the release-built helper (real Run 361/362 runtime symbols).
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
emit "help_hidden_flags_absent: true (all Run 362 abuse/DoS flags are hidden)"

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
  --p2p-connection-rate-max 20 --version > "${OUTDIR}/real_flags_parse.txt" 2>&1
REAL_RC=$?
set -e
[ "${REAL_RC}" -eq 0 ] \
  || fail "real hidden flags did not parse (rc=${REAL_RC}); see real_flags_parse.txt"
emit "real_hidden_flags_parse: true (rc=${REAL_RC})"

emit "verdict: PASS"
log "PASS — see ${SUMMARY}"
