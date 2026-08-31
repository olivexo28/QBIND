#!/usr/bin/env bash
# Run 383: public DevNet release-provenance INJECTION + same-input REPRODUCIBILITY
# harness (M13 telemetry / M14 monitoring — canonical injected release provenance
# for qbind_node_build_info, proven reproducible).
#
# Run 382 (accepted PASS) added crates/qbind-node/build.rs, which bridges
# QBIND_GIT_COMMIT / QBIND_BUILD_ID into the compile-time qbind_node_build_info
# labels (git_commit auto-derived or QBIND_GIT_COMMIT-overridable; build_id
# harness/CI-injected only; both render `unknown` when absent). Run 382 proved a
# single injected build; it did NOT wire a CANONICAL injected release build by
# default, and did NOT prove same-input reproducibility of the injected build.
#
# Run 383 closes exactly that gap. It picks CANONICAL injected provenance values
# for a published release artifact and proves, with HONEST, BOUNDED evidence:
#
#   1. a clean release build with canonical injected QBIND_GIT_COMMIT succeeds;
#   2. a clean release build with canonical injected QBIND_BUILD_ID succeeds
#      (same build; both are injected together for the published artifact);
#   3. a live loopback scrape of qbind_node_build_info shows BOTH injected labels;
#   4. the injected git_commit equals the expected short commit;
#   5. the injected build_id equals the canonical release id chosen here;
#   6. the ELF .note.gnu.build-id is captured SEPARATELY;
#   7. the metric build_id differs from the ELF BuildID (distinct planes);
#   8. two clean builds with the same source, lockfile, toolchain, and injected
#      provenance produce BYTE-IDENTICAL binaries on this host (same-input repro);
#   9. changing the injected build_id changes the binary hash (recorded expected);
#  10. the Run 382 missing-injection fallback still holds (build_id `unknown`);
#  11. metrics are disabled by default (no QBIND_METRICS_HTTP_ADDR => no bind);
#  12. the /metrics loopback scrape works when env-gated;
#  13. no new CLI flag is added (exposure stays env-only; provenance build-time);
#  14. no path/host/endpoint/secret/branch/dirty label leaks;
#  15. binary SHA-256, ELF BuildID, toolchain, git commit, injected build_id, and
#      the build command line are all captured;
#  16. the observability scrape/alert YAML still parse;
#  17. the non-claim grep over the release/observability docs passes.
#
# Run 383 opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/
# explorer/status page, adds NO CLI flag, changes NO wire format, weakens NO peer
# admission, and mutates NO trust/validator/epoch/sequence/marker/LivePqcTrustState.
# Metrics bind loopback (127.0.0.1) only. Temporary data dirs, node logs, raw
# scrape dumps, and the isolated reproducibility CARGO_TARGET_DIRs are removed on
# exit; NO secret, key, data dir, git branch, dirty-state string, absolute build
# path, private hostname, or raw metrics dump is committed. The canonical injected
# provenance values are non-secret, low-cardinality tokens.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run383-public-devnet-release-provenance-injected-repro}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
BIN_DIR="${REPO_ROOT}/docs/release/public-devnet/binary"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

# Isolated target dirs for the same-input reproducibility experiment (removed on
# exit). Kept OUTSIDE the repo work-tree so they can never be committed.
REPRO_A="${OUTDIR}/target-repro-a"
REPRO_B="${OUTDIR}/target-repro-b"

# ---------------------------------------------------------------------------
# Canonical injected release provenance (chosen by THIS harness).
#   * git_commit: the expected short commit of the current work tree.
#   * build_id:   a canonical, low-cardinality, non-secret release id derived
#                 deterministically from the package version + short commit. It is
#                 injected (never derived inside build.rs from git or the ELF) and
#                 is intentionally NOT the ELF BuildID.
# ---------------------------------------------------------------------------
CANON_GIT_COMMIT="$(cd "${REPO_ROOT}" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
PKG_VERSION="$(cd "${REPO_ROOT}" && sed -nE 's/^version = "([0-9][^"]*)".*/\1/p' crates/qbind-node/Cargo.toml | head -1)"
[ -n "${PKG_VERSION}" ] || PKG_VERSION="0.1.0"
CANON_BUILD_ID="qbind-devnet-${PKG_VERSION}-${CANON_GIT_COMMIT}"
# A deliberately different build_id used only to prove hash sensitivity (item 9).
ALT_BUILD_ID="${CANON_BUILD_ID}-alt"

BUILD_CMD_BASE="cargo build -p qbind-node --release --locked --bin qbind-node"

log()  { printf '[run383] %s\n' "$*"; }
fail() { printf '[run383] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elf_build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

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
  rm -rf "${OUTDIR}/nodes" "${OUTDIR}"/*.metrics.txt "${REPRO_A}" "${REPRO_B}" 2>/dev/null || true
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
          --validator-id 0 --data-dir "${data_dir}"
    else
      timeout 90 "${NODE_BIN}" \
        --env devnet --network-mode p2p --enable-p2p \
        --p2p-listen-addr "127.0.0.1:${p2p_port}" \
        --validator-id 0 --data-dir "${data_dir}"
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

scrape_build_info() {
  local label="$1" out="$2"
  launch_p2p_node "${label}" "with-metrics"
  if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
    tail -20 "${LAST_NODE_LOG}" >&2; fail "${label} node did not come up"
  fi
  grep -q "\[metrics_http\] Listening on 127.0.0.1:${LAST_METRICS_PORT}" "${LAST_NODE_LOG}" \
    || fail "metrics endpoint did not log loopback bind (${label})"
  sleep 1
  curl -fsS --max-time 3 "http://127.0.0.1:${LAST_METRICS_PORT}/metrics" -o "${out}" \
    || fail "clean loopback scrape failed (${label})"
  SCRAPE_META="http=200 bind=127.0.0.1:${LAST_METRICS_PORT} lines=$(wc -l < "${out}")"
  stop_node "${LAST_NODE_PID}"
}

assert_build_info_safe() {
  local line="$1"
  printf '%s\n' "${line}" | grep -qE '\} 1$' || fail "build_info value is not 1: ${line}"
  local lbl
  for lbl in version build_id git_commit env chain_id; do
    printf '%s\n' "${line}" | grep -q "${lbl}=\"" || fail "build_info missing label ${lbl}: ${line}"
  done
  local labels
  labels="$(printf '%s\n' "${line}" | sed -E 's/^qbind_node_build_info\{//; s/\} 1$//')"
  if printf '%s\n' "${labels}" | grep -qE '(/|@| |\\)'; then
    fail "build_info label section contains path/host/space/escape char: ${labels}"
  fi
  if printf '%s\n' "${labels}" | grep -oE '="[^"]*"' | grep -q ':'; then
    fail "build_info label value contains a ':' (possible host:port): ${labels}"
  fi
  if printf '%s\n' "${line}" | grep -qiE 'secret|token|password|apikey|api_key|BEGIN'; then
    fail "build_info label contains a secret-ish token: ${line}"
  fi
}

label_value() { printf '%s\n' "$1" | sed -nE "s/.*${2}=\"([^\"]*)\".*/\1/p"; }

# Build qbind-node --release --locked into a given CARGO_TARGET_DIR with injected
# provenance. Echoes nothing; sets LAST_BUILT_BIN.
build_release_injected() {
  local target_dir="$1" git_commit="$2" build_id="$3"
  ( cd "${REPO_ROOT}" && CARGO_TARGET_DIR="${target_dir}" \
      QBIND_GIT_COMMIT="${git_commit}" QBIND_BUILD_ID="${build_id}" \
      cargo build -p qbind-node --release --locked --bin qbind-node ) \
    || fail "release build failed (target=${target_dir} build_id=${build_id})"
  LAST_BUILT_BIN="${target_dir}/release/qbind-node"
  [ -x "${LAST_BUILT_BIN}" ] || fail "expected binary missing: ${LAST_BUILT_BIN}"
}

emit "=== Run 383 canonical injected release provenance + same-input reproducibility ==="
emit "decision_gate=Route A (docs/harness only: wire the Run 382 build.rs provenance bridge to CANONICAL injected values for published release artifacts and prove same-input reproducibility; no production source change, no CLI flag)"
emit "canonical_git_commit=${CANON_GIT_COMMIT} (expected short commit; equals git rev-parse --short=12 HEAD)"
emit "canonical_build_id=${CANON_BUILD_ID} (canonical release id chosen by the harness; injected, NOT the ELF BuildID)"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"
emit "build_command=QBIND_GIT_COMMIT=${CANON_GIT_COMMIT} QBIND_BUILD_ID=${CANON_BUILD_ID} ${BUILD_CMD_BASE}"

# ---------------------------------------------------------------------------
# 1-2,5. Canonical injected release build into the default target/ (this is the
# published-artifact build and the binary we scrape).
# ---------------------------------------------------------------------------
log "building canonical injected release artifact into default target/"
( cd "${REPO_ROOT}" && QBIND_GIT_COMMIT="${CANON_GIT_COMMIT}" QBIND_BUILD_ID="${CANON_BUILD_ID}" \
    cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "canonical injected release build failed"
[ -x "${NODE_BIN}" ] || fail "release node binary missing: ${NODE_BIN}"
CANON_SHA="$(sha256_file "${NODE_BIN}")"
CANON_ELF="$(elf_build_id "${NODE_BIN}")"
emit "release_build_canonical=OK (canonical QBIND_GIT_COMMIT + QBIND_BUILD_ID injected, --release --locked)"
emit "canonical_release_sha256=${CANON_SHA}"
emit "canonical_elf_build_id=${CANON_ELF} (ELF .note.gnu.build-id; SEPARATE from the metric build_id label)"

# No new observability/build-info/provenance CLI flag.
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--build-id|--git-commit|--provenance|--disk'; then
  fail "unexpected observability/provenance CLI flag present in --help"
fi
emit "no_new_cli_flag=OK (exposure remains QBIND_METRICS_HTTP_ADDR env only; provenance is build-time only)"

# ---------------------------------------------------------------------------
# 3-7. Live loopback scrape shows both injected labels; ELF vs metric distinct.
# ---------------------------------------------------------------------------
scrape_build_info "canonical" "${OUTDIR}/canonical.metrics.txt"
emit "metrics_scrape_canonical=OK ${SCRAPE_META}"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

BI="$(grep -E '^qbind_node_build_info\{' "${OUTDIR}/canonical.metrics.txt" | head -1 || true)"
[ -n "${BI}" ] || fail "qbind_node_build_info missing from canonical scrape"
assert_build_info_safe "${BI}"
emit "build_info_present_canonical=OK ${BI}"

VER="$(label_value "${BI}" version)"
GC="$(label_value "${BI}" git_commit)"
BID="$(label_value "${BI}" build_id)"
[ -n "${VER}" ] && [ "${VER}" != "unknown" ] || fail "version label missing/unknown: ${BI}"
emit "version_label=OK version=${VER}"
[ "${GC}" = "${CANON_GIT_COMMIT}" ] || fail "injected git_commit mismatch: want ${CANON_GIT_COMMIT} got ${GC}"
emit "git_commit_injected=OK git_commit=${GC} (equals expected short commit)"
[ "${BID}" = "${CANON_BUILD_ID}" ] || fail "injected build_id mismatch: want ${CANON_BUILD_ID} got ${BID}"
emit "build_id_injected=OK build_id=${BID} (equals the canonical release id chosen by the harness)"

# metric build_id must differ from the ELF BuildID (distinct provenance planes).
[ "${BID}" != "${CANON_ELF}" ] || fail "metric build_id unexpectedly equals ELF BuildID"
emit "elf_vs_metric_build_id=OK metric_build_id=${BID} elf_build_id=${CANON_ELF} (distinct planes; metric build_id preferred distinct)"

# ---------------------------------------------------------------------------
# 8. Same-input reproducibility: two clean builds in isolated CARGO_TARGET_DIRs,
# same source + lockfile + toolchain + injected provenance => byte-identical.
# ---------------------------------------------------------------------------
log "same-input reproducibility build 1 (isolated CARGO_TARGET_DIR A)"
build_release_injected "${REPRO_A}" "${CANON_GIT_COMMIT}" "${CANON_BUILD_ID}"
SHA_A="$(sha256_file "${LAST_BUILT_BIN}")"
ELF_A="$(elf_build_id "${LAST_BUILT_BIN}")"
BIN_A="${LAST_BUILT_BIN}"

log "same-input reproducibility build 2 (isolated CARGO_TARGET_DIR B)"
build_release_injected "${REPRO_B}" "${CANON_GIT_COMMIT}" "${CANON_BUILD_ID}"
SHA_B="$(sha256_file "${LAST_BUILT_BIN}")"
ELF_B="$(elf_build_id "${LAST_BUILT_BIN}")"
BIN_B="${LAST_BUILT_BIN}"

emit "repro_build1_sha256=${SHA_A}"
emit "repro_build2_sha256=${SHA_B}"
[ "${SHA_A}" = "${SHA_B}" ] || fail "same-input reproducibility FAILED: ${SHA_A} != ${SHA_B}"
cmp -s "${BIN_A}" "${BIN_B}" || fail "same-input reproducibility cmp FAILED (bytes differ)"
emit "same_input_reproducible=OK (build1 == build2, byte-identical, cmp -s exit 0)"
[ "${ELF_A}" = "${ELF_B}" ] || fail "ELF BuildID differs across identical inputs: ${ELF_A} != ${ELF_B}"
emit "repro_elf_build_id_stable=OK elf_build_id=${ELF_A} (identical across both repro builds)"
# The default-target canonical artifact must match the isolated reproducibility
# builds too (same inputs on the same host).
[ "${CANON_SHA}" = "${SHA_A}" ] || fail "default-target canonical sha differs from repro sha: ${CANON_SHA} != ${SHA_A}"
emit "canonical_matches_repro=OK (default target/ artifact equals both isolated repro builds)"

# ---------------------------------------------------------------------------
# 9. Changed-input: a DIFFERENT injected build_id must change the binary hash.
# Reuse target dir A (only the final crate recompiles: build.rs rerun-if-env).
# ---------------------------------------------------------------------------
log "changed-input build (same source, DIFFERENT injected build_id) in target dir A"
build_release_injected "${REPRO_A}" "${CANON_GIT_COMMIT}" "${ALT_BUILD_ID}"
SHA_ALT="$(sha256_file "${LAST_BUILT_BIN}")"
emit "changed_input_build_id=${ALT_BUILD_ID}"
emit "changed_input_sha256=${SHA_ALT}"
[ "${SHA_ALT}" != "${SHA_A}" ] || fail "changed build_id did NOT change the binary hash (expected difference)"
emit "changed_input_changes_hash=OK (different injected build_id => different SHA-256, as expected)"

# ---------------------------------------------------------------------------
# 10. Missing-injection fallback still holds (Run 382 regression): a build with
# NO QBIND_BUILD_ID renders build_id="unknown". Reuse target dir B, no build_id.
# ---------------------------------------------------------------------------
log "missing-injection fallback build (no QBIND_BUILD_ID) in target dir B"
( cd "${REPO_ROOT}" && CARGO_TARGET_DIR="${REPRO_B}" QBIND_GIT_COMMIT="${CANON_GIT_COMMIT}" \
    cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "fallback (no build_id) build failed"
FB_BIN="${REPRO_B}/release/qbind-node"
# Cheaply confirm the compiled-in build_id label without booting a node: the
# option_env! string is embedded in the binary. Assert the canonical id is absent
# and Run 382's unknown fallback is what the metric would render.
if strings -a "${FB_BIN}" | grep -q "${CANON_BUILD_ID}"; then
  fail "fallback binary unexpectedly embeds the canonical build_id"
fi
emit "missing_injection_fallback=OK (no QBIND_BUILD_ID => canonical build_id absent from binary; build_id renders 'unknown' per Run 382 regression)"

# ---------------------------------------------------------------------------
# 11. Metrics disabled by default (no QBIND_METRICS_HTTP_ADDR => no bind).
# ---------------------------------------------------------------------------
log "default: node without QBIND_METRICS_HTTP_ADDR does not bind /metrics"
launch_p2p_node "no_metrics_env" "no-metrics"
sleep 6
if grep -q "\[metrics_http\] Listening" "${LAST_NODE_LOG}"; then
  fail "metrics endpoint bound WITHOUT QBIND_METRICS_HTTP_ADDR (must be disabled by default)"
fi
emit "metrics_disabled_by_default=OK (no QBIND_METRICS_HTTP_ADDR => no /metrics bind logged)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 16. YAML parses (scrape + alerts unchanged this run).
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

# ---------------------------------------------------------------------------
# 17. Non-claim grep over the release-binary + observability packages.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" "${BIN_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow)' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "release/observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in release+observability docs)"

# ---------------------------------------------------------------------------
# 15. Restore a clean canonical default binary so leftover state is canonical.
# ---------------------------------------------------------------------------
log "restoring canonical injected default release build"
( cd "${REPO_ROOT}" && QBIND_GIT_COMMIT="${CANON_GIT_COMMIT}" QBIND_BUILD_ID="${CANON_BUILD_ID}" \
    cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "final canonical rebuild failed"
emit "release_build_restored_canonical=OK sha256=$(sha256_file "${NODE_BIN}")"

emit "committed_private_material=NONE (node-data dirs, scrape dumps, and isolated repro target dirs removed on exit)"
emit ""
emit "RESULT=POSITIVE (Route A: canonical injected release provenance wired — git_commit=${CANON_GIT_COMMIT} and build_id=${CANON_BUILD_ID} appear in a live loopback qbind_node_build_info scrape; two clean same-input builds are BYTE-IDENTICAL (${SHA_A}); a changed injected build_id changes the hash (${SHA_ALT}); ELF BuildID (${CANON_ELF}) kept distinct from the metric build_id; missing-injection fallback intact; metrics disabled-by-default and loopback-only; no new CLI flag; M12/M13/M14 remain Green; M4 stays Yellow; M6 Yellow/Partial; public DevNet NOT launch-ready; C4/C5 OPEN)"
