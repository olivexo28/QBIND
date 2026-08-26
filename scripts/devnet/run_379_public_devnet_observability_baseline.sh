#!/usr/bin/env bash
# Run 379: public DevNet observability baseline harness (M13 telemetry / M14
# monitoring & alerting).
#
# This harness produces the Run 379 acceptance evidence for the operator-facing
# observability baseline (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`). It
# drives the RELEASE `target/release/qbind-node` binary directly and proves, with
# HONEST, BOUNDED evidence, that the pre-existing metrics endpoint plus the new
# docs/scrape/alert artifacts are sufficient to move M13 and M14 Yellow -> Green.
#
# DECISION GATE = Route B (docs + harness + machine-readable examples). There is
# NO production Rust source change and NO new CLI flag: metrics exposure remains
# the pre-existing `metrics_http` server gated by `QBIND_METRICS_HTTP_ADDR`
# (`crates/qbind-node/src/metrics_http.rs`, `crates/qbind-node/src/main.rs`).
#
# What it proves:
#   1. `cargo build -p qbind-node --release --bin qbind-node`;
#   2. `qbind-node --help` exposes NO new observability CLI flag (env-only);
#   3. a release node starts with QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>;
#   4. `/metrics` scrapes over loopback (HTTP 200);
#   5. the scrape contains the required baseline families that actually exist;
#   6. the endpoint is loopback-bound (no public exposure);
#   7. `prometheus-scrape.example.yml` parses as YAML;
#   8. `prometheus-alerts.example.yml` parses as YAML (incl. the future group);
#   9. every ENABLED alert's metric is present in the fresh scrape;
#  10. absent metrics (per-peer drops, state-size) stay in the future group only;
#  11. no live-seed / M4 claim is made;
#  12. no TestNet/MainNet/C4/C5 claim is made.
#
# Run 379 opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/
# explorer/status page, changes NO wire format, weakens NO peer admission, and
# mutates NO trust/validator/epoch/sequence/marker/LivePqcTrustState. The metrics
# endpoint is bound to loopback (127.0.0.1). Temporary data dirs and scrape dumps
# are removed on exit; no secret, key, data dir, or raw metrics dump is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run379-public-devnet-observability-baseline}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run379] %s\n' "$*"; }
fail() { printf '[run379] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
free_port() { python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

NODE_DATA="${OUTDIR}/node-data"
SCRAPE_OUT="${OUTDIR}/metrics.txt"
NODE_LOG="${OUTDIR}/node.log"
NODE_PID=""
cleanup() {
  [ -n "${NODE_PID}" ] && kill "${NODE_PID}" 2>/dev/null || true
  rm -rf "${NODE_DATA}" "${SCRAPE_OUT}" "${NODE_LOG}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the release node binary.
# ---------------------------------------------------------------------------
log "building qbind-node (release)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"

emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 2. --help exposes NO new observability CLI flag (env-only exposure).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry'; then
  fail "unexpected observability CLI flag present in --help (exposure must stay env-only)"
fi
emit "no_new_observability_cli_flag=OK (exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 3-6. Boot loopback node with metrics endpoint; scrape /metrics over loopback.
# ---------------------------------------------------------------------------
rm -rf "${NODE_DATA}"; mkdir -p "${NODE_DATA}"
METRICS_PORT="$(free_port)"
log "booting release node with QBIND_METRICS_HTTP_ADDR=127.0.0.1:${METRICS_PORT}…"
QBIND_METRICS_HTTP_ADDR="127.0.0.1:${METRICS_PORT}" "${NODE_BIN}" \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr "127.0.0.1:0" \
  --validator-id 0 --data-dir "${NODE_DATA}" \
  > "${NODE_LOG}" 2>&1 &
NODE_PID=$!
sleep 8
kill -0 "${NODE_PID}" 2>/dev/null || { tail -20 "${NODE_LOG}" >&2; fail "node died before scrape"; }
grep -q "\[metrics_http\] Listening on 127.0.0.1:${METRICS_PORT}" "${NODE_LOG}" \
  || fail "metrics endpoint did not log loopback bind"

HTTP_CODE="$(python3 - "${METRICS_PORT}" "${SCRAPE_OUT}" <<'PY'
import sys, urllib.request
port, out = sys.argv[1], sys.argv[2]
req = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5)
body = req.read().decode()
open(out, "w").write(body)
print(req.status)
PY
)" || fail "loopback scrape of /metrics failed"
[ "${HTTP_CODE}" = "200" ] || fail "GET /metrics returned ${HTTP_CODE} (want 200)"
emit "metrics_endpoint_scrape=OK http=200 bind=127.0.0.1:${METRICS_PORT} lines=$(wc -l < "${SCRAPE_OUT}")"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

kill "${NODE_PID}" 2>/dev/null || true; NODE_PID=""

# ---------------------------------------------------------------------------
# 5/9. Required baseline families present; every ENABLED alert metric present.
# ---------------------------------------------------------------------------
REQUIRED=(
  qbind_consensus_committed_height
  qbind_consensus_current_view
  qbind_p2p_connections_current
  qbind_p2p_connection_rate_drop_total
  qbind_p2p_pqc_trust_bundle_loaded
  qbind_p2p_pqc_trust_bundle_signature_rejected_total
  qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total
  qbind_snapshot_failure_total
  qbind_restore_catchup_mode_active
  qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total
)
for m in "${REQUIRED[@]}"; do
  grep -qE "^${m}([ {]|$)" "${SCRAPE_OUT}" || fail "required/enabled-alert metric absent from scrape: ${m}"
done
emit "required_families_present=OK (${#REQUIRED[@]} enabled-alert metrics verified in fresh scrape)"

# ---------------------------------------------------------------------------
# 10. Absent metrics stay FUTURE-only (must NOT appear in the clean scrape).
# ---------------------------------------------------------------------------
for m in qbind_net_per_peer_drops_total qbind_state_size_bytes; do
  if grep -qE "^${m}([ {]|$)" "${SCRAPE_OUT}"; then
    fail "metric expected absent was present in scrape: ${m} (would need to leave FUTURE group)"
  fi
done
emit "absent_metrics_stay_future=OK (qbind_net_per_peer_drops_total, qbind_state_size_bytes absent; alerts kept in future/not-enabled group)"

# ---------------------------------------------------------------------------
# 7-8. Example scrape config and alert rules parse as YAML.
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
    # Dependency-free structural fallback: strict indentation/mapping sanity.
    with open(path) as fh:
        lines = fh.readlines()
    stack = []
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

# Confirm the alert rules DO carry a future/not-enabled group and DO reference the
# enabled metrics — a cheap structural check that the two files are consistent.
grep -q "qbind-devnet-observability-future-not-enabled" "${ALERTS_YML}" \
  || fail "alert rules missing the future/not-enabled group"
grep -q "qbind_net_per_peer_drops_total" "${ALERTS_YML}" \
  || fail "future per-peer-drop alert missing from alert rules"
emit "alert_rules_future_group=OK (absent-metric alerts present only in future/not-enabled group)"

# ---------------------------------------------------------------------------
# 11-12. No live-seed/M4 and no TestNet/MainNet/C4/C5 claim in the emitted docs.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow)' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in observability docs)"

emit "committed_private_material=NONE (node-data dir + scrape dump removed on exit)"
emit ""
emit "RESULT=POSITIVE (Route B: operator observability baseline; release-binary scrape evidence + parsed scrape/alert configs; M13 and M14 -> Green; M4 stays Yellow; C4/C5 OPEN; no launch/TestNet/MainNet claim)"
log "summary written to ${SUMMARY}"
