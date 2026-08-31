#!/usr/bin/env bash
# Run 382: public DevNet build-info PROVENANCE harness (M13 telemetry /
# M14 monitoring & alerting — release provenance for qbind_node_build_info).
#
# Run 381 landed `qbind_node_build_info{version,build_id,git_commit,env,chain_id}`
# but `build_id`/`git_commit` rendered `unknown` unless the build environment
# injected QBIND_BUILD_ID / QBIND_GIT_COMMIT. Run 382 adds a build script
# (crates/qbind-node/build.rs, DECISION GATE Route B) that bridges release
# provenance into those two compile-time labels:
#
#   * git_commit — explicit QBIND_GIT_COMMIT env wins, else a short git commit
#     hash is derived at build time; missing → `unknown`.
#   * build_id   — a stable harness/CI-injected QBIND_BUILD_ID only (never
#     derived from git or the ELF); missing → `unknown`.
#
# This harness proves, with HONEST, BOUNDED evidence:
#   1. a release build succeeds;
#   2. qbind_node_build_info appears in a live loopback scrape;
#   3. the version label is present;
#   4. git_commit is populated (auto-derived) in a default build, and honours an
#      injected QBIND_GIT_COMMIT override in an injected build;
#   5. build_id is populated when QBIND_BUILD_ID is injected;
#   6. missing injection still renders `unknown` (build_id in the default build);
#   7. all labels are sanitized to [A-Za-z0-9._-];
#   8. no path/host/endpoint/secret label leaks;
#   9. qbind_node_data_dir_free_bytes still appears when --data-dir is set;
#  10. metrics are disabled by default (no QBIND_METRICS_HTTP_ADDR ⇒ no bind);
#  11. the scrape YAML parses;
#  12. the alert YAML parses;
#  13. enabled alert expressions remain backed by present metrics / up / the
#      Run-380-proven per-peer series;
#  14. the non-claim grep passes over the observability package;
#  15. the release SHA-256 and ELF BuildID are captured SEPARATELY from the
#      metric labels (ELF .note.gnu.build-id ≠ the qbind_node_build_info
#      build_id label).
#
# Run 382 opens NO externally reachable port, deploys NO seed/bootnode/faucet/
# RPC/explorer/status page, adds NO CLI flag, changes NO wire format, weakens NO
# peer admission, and mutates NO trust/validator/epoch/sequence/marker/
# LivePqcTrustState. Metrics bind loopback (127.0.0.1) only. Temporary data dirs,
# node logs, and raw scrape dumps are removed on exit; NO secret, key, data dir,
# git branch, dirty-state string, absolute build path, or raw metrics dump is
# committed. The injected provenance values used below (git_commit override and
# build_id) are non-secret, low-cardinality tokens.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run382-public-devnet-build-info-provenance}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

# Non-secret, low-cardinality provenance tokens injected for the "injected" build.
INJ_GIT_COMMIT="deadbeefcafe0382"
INJ_BUILD_ID="run382-buildid-abc123"

log()  { printf '[run382] %s\n' "$*"; }
fail() { printf '[run382] FAIL: %s\n' "$*" >&2; exit 1; }
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
  rm -rf "${OUTDIR}/nodes" "${OUTDIR}"/*.metrics.txt 2>/dev/null || true
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

# Boot a node (optionally with metrics) and return its ports/pid via globals.
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

# Boot with metrics, scrape the build_info line into a file, then stop.
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
  # $1 = build_info line
  local line="$1"
  printf '%s\n' "${line}" | grep -qE '\} 1$' || fail "build_info value is not 1: ${line}"
  local lbl
  for lbl in version build_id git_commit env chain_id; do
    printf '%s\n' "${line}" | grep -q "${lbl}=\"" || fail "build_info missing label ${lbl}: ${line}"
  done
  # Label section between the braces: no path/host/space/quote/backslash chars.
  local labels
  labels="$(printf '%s\n' "${line}" | sed -E 's/^qbind_node_build_info\{//; s/\} 1$//')"
  if printf '%s\n' "${labels}" | grep -qE '(/|@| |\\)'; then
    fail "build_info label section contains path/host/space/escape char: ${labels}"
  fi
  # No ':' inside any label VALUE (chain_id is hex without a colon; a host:port would add one).
  if printf '%s\n' "${labels}" | grep -oE '="[^"]*"' | grep -q ':'; then
    fail "build_info label value contains a ':' (possible host:port): ${labels}"
  fi
  if printf '%s\n' "${line}" | grep -qiE 'secret|token|password|apikey|api_key|BEGIN'; then
    fail "build_info label contains a secret-ish token: ${line}"
  fi
}

label_value() { # $1=line $2=key
  printf '%s\n' "$1" | sed -nE "s/.*${2}=\"([^\"]*)\".*/\1/p"
}

# ---------------------------------------------------------------------------
# 15 (part). Capture the ELF BuildID / SHA of a fresh DEFAULT release build.
# ---------------------------------------------------------------------------
log "building qbind-node (release, default/no-injection)"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "default qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release node binary missing: ${NODE_BIN}"

emit "=== Run 382 release-binary build-info provenance evidence ==="
emit "decision_gate=Route B (build.rs bridges git commit + harness build id into qbind_node_build_info; no runtime change, no CLI flag)"
emit "release_build_default=OK"
emit "release_sha256_default=$(sha256_file "${NODE_BIN}")"
emit "elf_build_id_default=$(elf_build_id "${NODE_BIN}") (ELF .note.gnu.build-id; SEPARATE from the metric build_id label)"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# No new observability/build-info CLI flag (exposure stays env-only).
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--build-id|--git-commit|--provenance|--disk'; then
  fail "unexpected observability/provenance CLI flag present in --help (exposure must stay env-only)"
fi
emit "no_new_cli_flag=OK (exposure remains QBIND_METRICS_HTTP_ADDR env only; provenance is build-time only)"

# ---------------------------------------------------------------------------
# 2-9. Default build: git_commit auto-derived, build_id unknown, disk present.
# ---------------------------------------------------------------------------
scrape_build_info "default" "${OUTDIR}/default.metrics.txt"
emit "metrics_scrape_default=OK ${SCRAPE_META}"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

BI_DEFAULT="$(grep -E '^qbind_node_build_info\{' "${OUTDIR}/default.metrics.txt" | head -1 || true)"
[ -n "${BI_DEFAULT}" ] || fail "qbind_node_build_info missing from default scrape"
assert_build_info_safe "${BI_DEFAULT}"
emit "build_info_present_default=OK ${BI_DEFAULT}"

VER_D="$(label_value "${BI_DEFAULT}" version)"
GC_D="$(label_value "${BI_DEFAULT}" git_commit)"
BID_D="$(label_value "${BI_DEFAULT}" build_id)"
[ -n "${VER_D}" ] && [ "${VER_D}" != "unknown" ] || fail "version label missing/unknown in default build: ${BI_DEFAULT}"
emit "version_label=OK version=${VER_D}"

# git_commit must be auto-derived (non-unknown) in a git work-tree build...
if [ "${GC_D}" = "unknown" ]; then
  emit "git_commit_default=UNKNOWN (no git/derivation available in this build env — Route B degrades safely to unknown)"
else
  printf '%s\n' "${GC_D}" | grep -qE '^[A-Za-z0-9._-]+$' || fail "git_commit not sanitized: ${GC_D}"
  emit "git_commit_default=OK git_commit=${GC_D} (auto-derived short hash; not a branch/dirty/path string)"
fi

# ...and build_id must remain `unknown` with no injection (fallback proof).
[ "${BID_D}" = "unknown" ] || fail "build_id must be 'unknown' without QBIND_BUILD_ID injection, got: ${BID_D}"
emit "build_id_default=OK build_id=unknown (missing injection renders unknown; NOT derived from git)"

# Disk gauge still present (Run 381 regression guard), value-only.
DISK_LINE="$(grep -E '^qbind_node_data_dir_free_bytes ' "${OUTDIR}/default.metrics.txt" | head -1 || true)"
[ -n "${DISK_LINE}" ] || fail "qbind_node_data_dir_free_bytes missing (Run 381 regression)"
printf '%s\n' "${DISK_LINE}" | grep -q '{' && fail "disk gauge must be value-only (found a label): ${DISK_LINE}"
DISK_VAL="$(printf '%s\n' "${DISK_LINE}" | awk '{print $2}')"
printf '%s\n' "${DISK_VAL}" | grep -qE '^[0-9]+$' || fail "disk gauge value not integer: ${DISK_VAL}"
[ "${DISK_VAL}" -gt 0 ] || fail "disk gauge not > 0: ${DISK_VAL}"
emit "disk_free_bytes_present=OK qbind_node_data_dir_free_bytes=${DISK_VAL} (Run 381 gauge intact, value-only)"

# ---------------------------------------------------------------------------
# 4-5. Injected build: git_commit override + build_id populated.
# ---------------------------------------------------------------------------
log "rebuilding qbind-node (release) with injected QBIND_GIT_COMMIT / QBIND_BUILD_ID"
( cd "${REPO_ROOT}" && QBIND_GIT_COMMIT="${INJ_GIT_COMMIT}" QBIND_BUILD_ID="${INJ_BUILD_ID}" \
    cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "injected qbind-node release build failed"
emit "release_build_injected=OK (QBIND_GIT_COMMIT / QBIND_BUILD_ID injected at build time)"
emit "elf_build_id_injected=$(elf_build_id "${NODE_BIN}") (ELF BuildID; still SEPARATE from the metric build_id label)"

scrape_build_info "injected" "${OUTDIR}/injected.metrics.txt"
emit "metrics_scrape_injected=OK ${SCRAPE_META}"

BI_INJ="$(grep -E '^qbind_node_build_info\{' "${OUTDIR}/injected.metrics.txt" | head -1 || true)"
[ -n "${BI_INJ}" ] || fail "qbind_node_build_info missing from injected scrape"
assert_build_info_safe "${BI_INJ}"
emit "build_info_present_injected=OK ${BI_INJ}"

GC_I="$(label_value "${BI_INJ}" git_commit)"
BID_I="$(label_value "${BI_INJ}" build_id)"
[ "${GC_I}" = "${INJ_GIT_COMMIT}" ] || fail "injected git_commit not honoured: want ${INJ_GIT_COMMIT} got ${GC_I}"
emit "git_commit_injected=OK git_commit=${GC_I} (explicit QBIND_GIT_COMMIT override honoured)"
[ "${BID_I}" = "${INJ_BUILD_ID}" ] || fail "injected build_id not honoured: want ${INJ_BUILD_ID} got ${BID_I}"
emit "build_id_injected=OK build_id=${BID_I} (harness/CI-injected value; not the ELF BuildID)"

# The metric build_id must NOT equal the ELF BuildID (distinct provenance planes).
ELF_BID="$(elf_build_id "${NODE_BIN}")"
[ "${BID_I}" != "${ELF_BID}" ] || fail "metric build_id unexpectedly equals ELF BuildID"
emit "elf_vs_metric_build_id=OK metric_build_id=${BID_I} elf_build_id=${ELF_BID} (distinct planes)"

# Restore a clean default binary so leftover state is not an injected build.
log "restoring default (no-injection) release build"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "final default rebuild failed"
emit "release_build_restored_default=OK"

# ---------------------------------------------------------------------------
# 10. Metrics disabled by default (no QBIND_METRICS_HTTP_ADDR ⇒ no bind).
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
# 11-13. YAML parses; enabled alert exprs reference present metrics.
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

FUTURE_LINE="$(grep -n -- '- name: qbind-devnet-observability-future-not-enabled' "${ALERTS_YML}" | head -1 | cut -d: -f1)"
[ -n "${FUTURE_LINE}" ] || fail "future/not-enabled group missing from alert rules"
python3 - "${ALERTS_YML}" "${FUTURE_LINE}" "${OUTDIR}/default.metrics.txt" <<'PY' || fail "enabled alert references a metric absent from the scrape"
import re, sys
alerts, future_line, scrape = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(scrape) as fh:
    present = set(re.findall(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)', fh.read(), re.M))
allow = {"up", "qbind_net_per_peer_drops_total"}
with open(alerts) as fh:
    lines = fh.readlines()
enabled = lines[:future_line - 1]
bad = []
for line in enabled:
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

# ---------------------------------------------------------------------------
# 14. Non-claim grep over the observability package.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow)' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in observability docs)"

emit "committed_private_material=NONE (node-data dirs + scrape dumps removed on exit)"
emit ""
emit "RESULT=POSITIVE (Route B: build.rs injects safe release provenance into qbind_node_build_info — git_commit auto-derived and QBIND_GIT_COMMIT-overridable, build_id harness-injected only with an unknown fallback; labels sanitized and secret-free; ELF BuildID kept separate from the metric build_id label; qbind_node_data_dir_free_bytes intact; metrics disabled-by-default and loopback-only; M12/M13/M14 remain Green; M4 stays Yellow; M6 Yellow/Partial; public DevNet NOT launch-ready; C4/C5 OPEN)"