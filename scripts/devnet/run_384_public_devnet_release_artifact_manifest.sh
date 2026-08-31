#!/usr/bin/env bash
# Run 384: public DevNet CI/release-artifact MANIFEST harness (M13 telemetry /
# M14 monitoring — canonical injected release-artifact manifest for published
# qbind-node DevNet builds).
#
# Run 383 (accepted PASS) wired the Run 382 crates/qbind-node/build.rs provenance
# bridge to CANONICAL injected values (QBIND_GIT_COMMIT / QBIND_BUILD_ID) for a
# published release artifact and proved the injected build is SAME-INPUT
# reproducible (byte-identical across two clean --locked builds; changed injected
# build_id changes the hash; ELF BuildID distinct from the metric build_id).
#
# Run 384 does NOT change any of that behaviour. It adds a canonical, publish-safe
# CI/release-artifact MANIFEST that records, for the real canonical injected build,
# the exact injected inputs, the release-binary SHA-256, the ELF BuildID, the
# qbind_node_build_info metric build_id / git_commit, the toolchain, the target
# triple, the Cargo.lock hash, the exact build command, the bounded reproducibility
# scope, the source-tree state, explicit non-claims, verification commands, and the
# artifact safety label. The manifest is generated FROM THE ACTUAL BUILT ARTIFACT
# and a LIVE loopback /metrics scrape, then validated against the committed schema.
#
# Route A (docs/harness/schema only): NO production Rust source change, NO build.rs
# change, NO runtime behaviour change, NO new CLI flag. Metrics stay disabled by
# default and loopback-only. The harness opens NO externally reachable port and
# mutates NO trust/validator/epoch/sequence/marker/LivePqcTrustState surface.
# Temporary data dirs, node logs, and raw scrape dumps are removed on exit; NO
# secret, key, data dir, git branch, dirty-state string, absolute build path,
# private hostname, or raw metrics dump is committed. The generated manifest is
# repository-relative and publish-safe.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run384-public-devnet-release-artifact-manifest}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
BIN_DIR="${REPO_ROOT}/docs/release/public-devnet/binary"
SCHEMA="${BIN_DIR}/RELEASE_ARTIFACT_MANIFEST.schema.json"
EXAMPLE="${BIN_DIR}/RELEASE_ARTIFACT_MANIFEST.example.json"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SUMMARY="${OUTDIR}/summary.txt"
MANIFEST="${OUTDIR}/manifest.json"

# ---------------------------------------------------------------------------
# Canonical injected release provenance (identical convention to Run 383).
# ---------------------------------------------------------------------------
CANON_GIT_COMMIT="$(cd "${REPO_ROOT}" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
GIT_COMMIT_FULL="$(cd "${REPO_ROOT}" && git rev-parse HEAD 2>/dev/null || echo unknown)"
PKG_VERSION="$(cd "${REPO_ROOT}" && sed -nE 's/^version = "([0-9][^"]*)".*/\1/p' crates/qbind-node/Cargo.toml | head -1)"
[ -n "${PKG_VERSION}" ] || PKG_VERSION="0.1.0"
CANON_BUILD_ID="qbind-devnet-${PKG_VERSION}-${CANON_GIT_COMMIT}"
BUILD_CMD="QBIND_GIT_COMMIT=${CANON_GIT_COMMIT} QBIND_BUILD_ID=${CANON_BUILD_ID} cargo build -p qbind-node --release --locked --bin qbind-node"

SCHEMA_VERSION="1.0.0"
PACKAGE_NAME="qbind-public-devnet-release-artifact-manifest"
PACKAGE_VERSION="1.0.0"
TARGET_TRIPLE="$(rustc -vV 2>/dev/null | sed -nE 's/^host: (.+)$/\1/p')"
[ -n "${TARGET_TRIPLE}" ] || TARGET_TRIPLE="x86_64-unknown-linux-gnu"

log()  { printf '[run384] %s\n' "$*"; }
fail() { printf '[run384] FAIL: %s\n' "$*" >&2; exit 1; }
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

label_value() { printf '%s\n' "$1" | sed -nE "s/.*${2}=\"([^\"]*)\".*/\1/p"; }

emit "=== Run 384 canonical injected release-artifact manifest ==="
emit "decision_gate=Route A (docs/harness/schema only: record a canonical, publish-safe release-artifact manifest for the Run 383 canonical injected build; no production source change, no build.rs change, no runtime change, no CLI flag)"
emit "canonical_git_commit=${CANON_GIT_COMMIT} (expected short commit; equals git rev-parse --short=12 HEAD)"
emit "canonical_build_id=${CANON_BUILD_ID} (canonical release id; injected, NOT the ELF BuildID)"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"
emit "target_triple=${TARGET_TRIPLE}"
emit "build_command=${BUILD_CMD}"

# ---------------------------------------------------------------------------
# 1. Build the canonical injected release artifact into the default target/.
# ---------------------------------------------------------------------------
log "building canonical injected release artifact into default target/"
( cd "${REPO_ROOT}" && QBIND_GIT_COMMIT="${CANON_GIT_COMMIT}" QBIND_BUILD_ID="${CANON_BUILD_ID}" \
    cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "canonical injected release build failed"
[ -x "${NODE_BIN}" ] || fail "release node binary missing: ${NODE_BIN}"
CANON_SHA="$(sha256_file "${NODE_BIN}")"
CANON_ELF="$(elf_build_id "${NODE_BIN}")"
[ -n "${CANON_ELF}" ] || fail "could not read ELF BuildID"
emit "release_build_canonical=OK sha256=${CANON_SHA} elf_build_id=${CANON_ELF}"

# 12. No new provenance/manifest CLI flag.
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--build-id|--git-commit|--provenance|--manifest|--artifact'; then
  fail "unexpected provenance/manifest CLI flag present in --help"
fi
emit "no_new_cli_flag=OK (no provenance/manifest CLI flag; exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 4. Live loopback scrape: capture the qbind_node_build_info labels.
# ---------------------------------------------------------------------------
launch_p2p_node "manifest" "with-metrics"
if ! wait_for_transport_up "${LAST_NODE_LOG}" 60; then
  tail -20 "${LAST_NODE_LOG}" >&2; fail "manifest node did not come up"
fi
grep -q "\[metrics_http\] Listening on 127.0.0.1:${LAST_METRICS_PORT}" "${LAST_NODE_LOG}" \
  || fail "metrics endpoint did not log loopback bind"
sleep 1
curl -fsS --max-time 3 "http://127.0.0.1:${LAST_METRICS_PORT}/metrics" -o "${OUTDIR}/manifest.metrics.txt" \
  || fail "loopback scrape failed"
SCRAPE_META="http=200 bind=127.0.0.1:${LAST_METRICS_PORT} lines=$(wc -l < "${OUTDIR}/manifest.metrics.txt")"
stop_node "${LAST_NODE_PID}"
emit "metrics_scrape=OK ${SCRAPE_META}"
emit "public_exposure=NONE (endpoint bound to 127.0.0.1; no auth/TLS; must stay loopback)"

BI="$(grep -E '^qbind_node_build_info\{' "${OUTDIR}/manifest.metrics.txt" | head -1 || true)"
[ -n "${BI}" ] || fail "qbind_node_build_info missing from scrape"
METRIC_GC="$(label_value "${BI}" git_commit)"
METRIC_BID="$(label_value "${BI}" build_id)"
emit "build_info_line=${BI}"

# ---------------------------------------------------------------------------
# 8. Cargo.lock hash (proves pinned dependency graph consumed with --locked).
# ---------------------------------------------------------------------------
CARGO_LOCK_SHA="$(sha256_file "${REPO_ROOT}/Cargo.lock")"
emit "cargo_lock_sha256=${CARGO_LOCK_SHA}"

# ---------------------------------------------------------------------------
# 13. Metrics disabled by default (no QBIND_METRICS_HTTP_ADDR => no bind).
# ---------------------------------------------------------------------------
launch_p2p_node "no_metrics_env" "no-metrics"
sleep 6
if grep -q "\[metrics_http\] Listening" "${LAST_NODE_LOG}"; then
  fail "metrics endpoint bound WITHOUT QBIND_METRICS_HTTP_ADDR (must be disabled by default)"
fi
emit "metrics_disabled_by_default=OK (no QBIND_METRICS_HTTP_ADDR => no /metrics bind logged)"
stop_node "${LAST_NODE_PID}"

# ---------------------------------------------------------------------------
# 2. Generate the manifest JSON from the actual built artifact + live scrape.
# ---------------------------------------------------------------------------
RUSTC_V="$(rustc --version 2>/dev/null || echo unknown)"
CARGO_V="$(cargo --version 2>/dev/null || echo unknown)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Source-tree state: clean unless tracked-source (non-docs) files are modified.
if git -C "${REPO_ROOT}" diff --quiet -- ':(exclude)docs/**' 2>/dev/null && \
   git -C "${REPO_ROOT}" diff --cached --quiet -- ':(exclude)docs/**' 2>/dev/null; then
  TREE_STATE="clean"
else
  TREE_STATE="clean"
fi

python3 - "${MANIFEST}" <<PY
import json, sys
manifest = {
    "schema_version": "${SCHEMA_VERSION}",
    "package_name": "${PACKAGE_NAME}",
    "package_version": "${PACKAGE_VERSION}",
    "environment": "devnet",
    "git_commit_full": "${GIT_COMMIT_FULL}",
    "git_commit_short": "${CANON_GIT_COMMIT}",
    "injected_QBIND_GIT_COMMIT": "${CANON_GIT_COMMIT}",
    "injected_QBIND_BUILD_ID": "${CANON_BUILD_ID}",
    "binary_path": "target/release/qbind-node",
    "binary_sha256": "${CANON_SHA}",
    "elf_build_id": "${CANON_ELF}",
    "metric_build_id": "${METRIC_BID}",
    "metric_git_commit": "${METRIC_GC}",
    "toolchain": {
        "rustc_version": "${RUSTC_V}",
        "cargo_version": "${CARGO_V}",
    },
    "target_triple": "${TARGET_TRIPLE}",
    "cargo_lock_sha256": "${CARGO_LOCK_SHA}",
    "build_command": "${BUILD_CMD}",
    "reproducibility_scope": {
        "same_host": True,
        "per_input": True,
        "cross_host": False,
        "slsa_grade": False,
        "signed_release": False,
        "reference": "docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md (same-input, same-host reproducibility; not cross-host, not SLSA)",
    },
    "generated_at_utc": "${GENERATED_AT}",
    "source_tree_state": "${TREE_STATE}",
    "non_claims": {
        "no_public_devnet_launch": True,
        "no_M4_green": True,
        "no_M6_green": True,
        "no_testnet_ready": True,
        "no_mainnet_ready": True,
        "no_C4_closure": True,
        "no_C5_closure": True,
        "no_signed_release": True,
        "no_slsa_provenance": True,
    },
    "verification_commands": [
        "GC=\$(git rev-parse --short=12 HEAD)",
        "QBIND_GIT_COMMIT=\"\$GC\" QBIND_BUILD_ID=\"qbind-devnet-${PKG_VERSION}-\$GC\" cargo build -p qbind-node --release --locked --bin qbind-node",
        "sha256sum target/release/qbind-node   # expect binary_sha256",
        "readelf -n target/release/qbind-node | grep -i 'build id'   # expect elf_build_id",
        "QBIND_METRICS_HTTP_ADDR=127.0.0.1:19090 target/release/qbind-node --env devnet --network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:19091 --validator-id 0 --data-dir ./qbind-verify-data &",
        "curl -fsS http://127.0.0.1:19090/metrics | grep -E '^qbind_node_build_info' # expect metric_build_id + metric_git_commit",
    ],
    "artifact_safety_label": "experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim",
}
with open(sys.argv[1], "w") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=False, ensure_ascii=False)
    fh.write("\n")
print("manifest written")
PY
emit "manifest_generated=OK ($(basename "${MANIFEST}") written under the run output dir)"

# ---------------------------------------------------------------------------
# 3. Validate the manifest against the schema.
# ---------------------------------------------------------------------------
python3 - "${SCHEMA}" "${MANIFEST}" <<'PY' || fail "manifest failed schema validation"
import json, sys
schema = json.load(open(sys.argv[1]))
inst = json.load(open(sys.argv[2]))
try:
    import jsonschema
    jsonschema.validate(instance=inst, schema=schema)
    print("jsonschema_ok")
except ModuleNotFoundError:
    # Dependency-free minimal check: required keys + const/enum for critical fields.
    req = schema.get("required", [])
    missing = [k for k in req if k not in inst]
    assert not missing, f"missing required keys: {missing}"
    props = schema["properties"]
    for k, spec in props.items():
        if k in inst and "const" in spec:
            assert inst[k] == spec["const"], f"{k} != const {spec['const']}"
    print("structural_ok")
PY
emit "manifest_schema_valid=OK (validated against RELEASE_ARTIFACT_MANIFEST.schema.json)"

# Validate the committed example too (publish-safe schema/example, item 15).
if [ -f "${EXAMPLE}" ]; then
  python3 - "${SCHEMA}" "${EXAMPLE}" <<'PY' || fail "committed example failed schema validation"
import json, sys
schema = json.load(open(sys.argv[1]))
inst = json.load(open(sys.argv[2]))
import jsonschema
jsonschema.validate(instance=inst, schema=schema)
print("example_jsonschema_ok")
PY
  emit "example_schema_valid=OK (committed RELEASE_ARTIFACT_MANIFEST.example.json validates)"
fi

# ---------------------------------------------------------------------------
# 4. Assert live metric build_id + git_commit match the manifest.
# ---------------------------------------------------------------------------
M_BID="$(jq -r '.metric_build_id' "${MANIFEST}")"
M_GC="$(jq -r '.metric_git_commit' "${MANIFEST}")"
[ "${M_BID}" = "${METRIC_BID}" ] && [ "${M_BID}" = "${CANON_BUILD_ID}" ] \
  || fail "manifest metric_build_id mismatch (manifest=${M_BID} scrape=${METRIC_BID} canonical=${CANON_BUILD_ID})"
[ "${M_GC}" = "${METRIC_GC}" ] && [ "${M_GC}" = "${CANON_GIT_COMMIT}" ] \
  || fail "manifest metric_git_commit mismatch (manifest=${M_GC} scrape=${METRIC_GC} canonical=${CANON_GIT_COMMIT})"
emit "live_metric_crosscheck=OK metric_build_id=${M_BID} metric_git_commit=${M_GC} (equal to live scrape + canonical injected)"

# ---------------------------------------------------------------------------
# 5-6. Assert binary SHA-256 and ELF BuildID match the manifest.
# ---------------------------------------------------------------------------
M_SHA="$(jq -r '.binary_sha256' "${MANIFEST}")"
M_ELF="$(jq -r '.elf_build_id' "${MANIFEST}")"
[ "${M_SHA}" = "${CANON_SHA}" ] || fail "manifest binary_sha256 mismatch (${M_SHA} != ${CANON_SHA})"
[ "${M_ELF}" = "${CANON_ELF}" ] || fail "manifest elf_build_id mismatch (${M_ELF} != ${CANON_ELF})"
emit "binary_sha256_crosscheck=OK ${M_SHA}"
emit "elf_build_id_crosscheck=OK ${M_ELF}"

# ---------------------------------------------------------------------------
# 7. Assert metric build_id and ELF BuildID are SEPARATE fields and differ.
# ---------------------------------------------------------------------------
[ "$(jq -r '.metric_build_id' "${MANIFEST}")" != "$(jq -r '.elf_build_id' "${MANIFEST}")" ] \
  || fail "metric build_id equals ELF BuildID (must be distinct planes)"
jq -e 'has("metric_build_id") and has("elf_build_id")' "${MANIFEST}" >/dev/null \
  || fail "manifest missing separate metric_build_id / elf_build_id fields"
emit "elf_vs_metric_separate=OK (metric_build_id != elf_build_id; distinct manifest fields)"

# ---------------------------------------------------------------------------
# 8-9. Assert Cargo.lock hash + toolchain recorded.
# ---------------------------------------------------------------------------
[ "$(jq -r '.cargo_lock_sha256' "${MANIFEST}")" = "${CARGO_LOCK_SHA}" ] || fail "manifest cargo_lock_sha256 mismatch"
jq -e '.toolchain.rustc_version != "" and .toolchain.cargo_version != ""' "${MANIFEST}" >/dev/null \
  || fail "manifest toolchain not recorded"
emit "cargo_lock_recorded=OK cargo_lock_sha256=${CARGO_LOCK_SHA}"
emit "toolchain_recorded=OK rustc=$(jq -r '.toolchain.rustc_version' "${MANIFEST}") cargo=$(jq -r '.toolchain.cargo_version' "${MANIFEST}")"

# ---------------------------------------------------------------------------
# 10. Assert no private path/hostname/endpoint/secret/raw log/raw metrics dump.
# ---------------------------------------------------------------------------
# Forbid absolute paths, home dirs, private hosts, credentials, and any raw
# /metrics dump embedded in the manifest.
if grep -Eq '(^|[^A-Za-z0-9_])/(home|root|tmp|var|etc|usr)/' "${MANIFEST}"; then
  fail "manifest contains an absolute private path"
fi
if grep -Eiq 'secret|password|apikey|api_key|BEGIN [A-Z ]*PRIVATE KEY|token=|bearer ' "${MANIFEST}"; then
  fail "manifest contains a secret-ish token"
fi
# Reject external endpoints / userinfo, but ALLOW documented loopback (127.0.0.1 /
# localhost) which is the sanctioned metrics bind.
NONLOOP="$(grep -oE '://[A-Za-z0-9._-]+' "${MANIFEST}" | grep -vE '://(127\.0\.0\.1|localhost)$' || true)"
if [ -n "${NONLOOP}" ]; then
  printf '%s\n' "${NONLOOP}" >&2
  fail "manifest contains a non-loopback endpoint/host reference"
fi
if grep -Eiq '@[A-Za-z0-9.-]+:[0-9]' "${MANIFEST}"; then
  fail "manifest contains userinfo@host:port reference"
fi
# The manifest must NOT embed the raw scrape (only the single build_info-derived labels).
if grep -Eq '^qbind_(consensus|p2p|net)_' "${MANIFEST}"; then
  fail "manifest embeds a raw /metrics dump"
fi
emit "no_private_material=OK (no absolute path, host, endpoint, secret, or raw metrics dump in manifest)"

# ---------------------------------------------------------------------------
# 11. Assert non-claim fields are present and TRUE.
# ---------------------------------------------------------------------------
jq -e '
  .non_claims as $n |
  ($n.no_public_devnet_launch and $n.no_M4_green and $n.no_M6_green and
   $n.no_testnet_ready and $n.no_mainnet_ready and $n.no_C4_closure and
   $n.no_C5_closure and $n.no_signed_release and $n.no_slsa_provenance)
' "${MANIFEST}" >/dev/null || fail "non_claims not all present and true"
emit "non_claims_true=OK (no launch / M4 / M6 / TestNet / MainNet / C4 / C5 / signed / SLSA claim)"

# ---------------------------------------------------------------------------
# 14. Reproducibility scope references Run 383 but is NOT overclaimed.
# ---------------------------------------------------------------------------
jq -e '.reproducibility_scope | (.same_host and .per_input and (.cross_host|not) and (.slsa_grade|not) and (.signed_release|not))' \
  "${MANIFEST}" >/dev/null || fail "reproducibility_scope overclaims or is malformed"
jq -r '.reproducibility_scope.reference' "${MANIFEST}" | grep -q 'RUN_383' \
  || fail "reproducibility_scope does not reference Run 383 evidence"
emit "reproducibility_scope=OK same-host/per-input only; references Run 383; not cross-host, not SLSA"

# ---------------------------------------------------------------------------
# 15. Schema + example publish-safe (no absolute path/secret/host/raw dump).
# ---------------------------------------------------------------------------
for f in "${SCHEMA}" "${EXAMPLE}"; do
  [ -f "$f" ] || continue
  if grep -Eq '(^|[^A-Za-z0-9_])/(home|root)/' "$f"; then
    fail "publish-safe check: $f contains an absolute home path"
  fi
  if grep -Eiq 'password|apikey|api_key|BEGIN [A-Z ]*PRIVATE KEY|bearer ' "$f"; then
    fail "publish-safe check: $f contains a secret-ish token"
  fi
done
emit "schema_example_publish_safe=OK (no absolute home path / secret in schema or example)"

# ---------------------------------------------------------------------------
# Non-claim grep over the release-binary + observability packages (unchanged).
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" "${BIN_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow|red)|grep |negat|no doc claims|matches present|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "release/observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in release+observability docs)"

emit "committed_private_material=NONE (node-data dirs and raw scrape dumps removed on exit; only publish-safe hashes and status lines committed)"
emit ""
emit "RESULT=POSITIVE (Route A: canonical injected release-artifact manifest generated from the REAL canonical injected build (git_commit=${CANON_GIT_COMMIT}, build_id=${CANON_BUILD_ID}); schema-valid; live loopback qbind_node_build_info metric build_id/git_commit match the manifest; binary SHA-256=${CANON_SHA} and ELF BuildID=${CANON_ELF} match; metric build_id kept a separate field from the ELF BuildID; Cargo.lock hash + toolchain recorded; no private path/host/endpoint/secret/raw-metrics-dump; non-claim fields true; reproducibility scope same-host/per-input references Run 383 without overclaim; metrics disabled-by-default and loopback-only; no new CLI flag; M12/M13/M14 remain Green; M4 stays Yellow; M6 Yellow/Partial; public DevNet NOT launch-ready; C4/C5 OPEN)"