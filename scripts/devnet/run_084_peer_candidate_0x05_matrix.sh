#!/usr/bin/env bash
#
# Run 084: repeatable release-binary N=2 DevNet harness for the
# peer-candidate 0x05 matrix originally captured by Run 081.
#
# Scope: evidence orchestration only. The harness builds existing release
# binaries, mints DevNet signed trust material, wraps the signed baseline
# bundle as peer-candidate fixtures, runs two qbind-node release processes
# over loopback, scrapes /metrics, captures stderr, and asserts the
# validation-only invariants. It does not add protocol features, propagation,
# peer-driven live apply, activation_epoch, KMS/HSM, signing-key ratification,
# fast-sync restore, or consensus/KEMTLS redesign.
#
# Usage:
#   scripts/devnet/run_084_peer_candidate_0x05_matrix.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run084-peer-candidate-0x05-matrix

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run084-peer-candidate-0x05-matrix}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN084_NODE_TIMEOUT:-45s}"
P2P_BASE="${QBIND_RUN084_P2P_BASE:-19840}"
METRICS_BASE="${QBIND_RUN084_METRICS_BASE:-9380}"

NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
TRUST_HELPER="${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper"
ROOT_HELPER="${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper"
SIGNER_HELPER="${REPO_ROOT}/target/release/examples/devnet_consensus_signer_keystore_helper"

PIDS=()

log() {
  printf '[run084] %s\n' "$*"
}

fail() {
  printf '[run084] FAIL: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

build_id() {
  readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'
}

metric_value() {
  local file="$1"
  local name="$2"
  awk -v n="${name}" '$1 == n {print $2; found=1; exit} END {if (!found) print "0"}' "${file}"
}

assert_metric_eq() {
  local file="$1"
  local name="$2"
  local expected="$3"
  local actual
  actual="$(metric_value "${file}" "${name}")"
  if [ "${actual}" != "${expected}" ]; then
    fail "metric ${name} in ${file} expected ${expected}, got ${actual}"
  fi
}

assert_metric_ge() {
  local file="$1"
  local name="$2"
  local floor="$3"
  local actual
  actual="$(metric_value "${file}" "${name}")"
  if [ "${actual}" -lt "${floor}" ]; then
    fail "metric ${name} in ${file} expected >= ${floor}, got ${actual}"
  fi
}

assert_zero_family() {
  local file="$1"
  shift
  local metric
  for metric in "$@"; do
    assert_metric_eq "${file}" "${metric}" "0"
  done
}

fetch_metrics() {
  local port="$1"
  local out="$2"
  curl -fsS --max-time 2 "http://127.0.0.1:${port}/metrics" > "${out}"
}

wait_for_metrics() {
  local port="$1"
  local out="$2"
  local i
  for ((i = 1; i <= 60; i++)); do
    if fetch_metrics "${port}" "${out}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  fail "metrics endpoint 127.0.0.1:${port} did not become available"
}

wait_for_metric_eq() {
  local port="$1"
  local out="$2"
  local name="$3"
  local expected="$4"
  local i actual
  for ((i = 1; i <= 80; i++)); do
    if fetch_metrics "${port}" "${out}" 2>/dev/null; then
      actual="$(metric_value "${out}" "${name}")"
      if [ "${actual}" = "${expected}" ]; then
        return 0
      fi
    fi
    sleep 0.5
  done
  actual="$(metric_value "${out}" "${name}" 2>/dev/null || echo 0)"
  fail "metric ${name} on port ${port} did not reach ${expected}; last=${actual}"
}

wait_for_log() {
  local file="$1"
  local pattern="$2"
  local i
  for ((i = 1; i <= 80; i++)); do
    if [ -f "${file}" ] && grep -qE "${pattern}" "${file}"; then
      return 0
    fi
    sleep 0.5
  done
  fail "log ${file} did not contain pattern: ${pattern}"
}

common_args() {
  local vid="$1"
  local listen_port="$2"
  local peer_vid="$3"
  local peer_port="$4"
  local data_dir="$5"
  printf '%s\n' \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr "127.0.0.1:${listen_port}" \
    --p2p-peer "${peer_vid}@127.0.0.1:${peer_port}" \
    --validator-id "${vid}" \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "${OUTDIR}/material/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "$(cat "${OUTDIR}/material/signing-key.spec")" \
    --p2p-leaf-cert "${OUTDIR}/material/v${vid}.cert.bin" \
    --p2p-leaf-cert-key "${OUTDIR}/material/v${vid}.kem.sk.bin" \
    --p2p-peer-leaf-cert "${peer_vid}:${OUTDIR}/material/v${peer_vid}.cert.bin" \
    --signer-keystore-path "${OUTDIR}/signers/v${vid}" \
    --validator-consensus-key "0:100:$(cat "${OUTDIR}/signers/v0/validator-0.pk.hex")" \
    --validator-consensus-key "1:100:$(cat "${OUTDIR}/signers/v1/validator-1.pk.hex")" \
    --data-dir "${data_dir}"
}

start_node() {
  local label="$1"
  local vid="$2"
  local listen_port="$3"
  local peer_vid="$4"
  local peer_port="$5"
  local metrics_port="$6"
  local data_dir="$7"
  shift 7
  mkdir -p "${data_dir}"
  local stdout="${OUTDIR}/logs/${label}.stdout.log"
  local stderr="${OUTDIR}/logs/${label}.stderr.log"
  local -a args=()
  mapfile -t args < <(common_args "${vid}" "${listen_port}" "${peer_vid}" "${peer_port}" "${data_dir}")
  (
    cd "${REPO_ROOT}"
    QBIND_METRICS_HTTP_ADDR="127.0.0.1:${metrics_port}" \
      timeout "${NODE_TIMEOUT}" "${NODE_BIN}" "${args[@]}" "$@"
  ) >"${stdout}" 2>"${stderr}" &
  LAST_PID=$!
  PIDS+=("${LAST_PID}")
  log "started ${label} pid=${LAST_PID} p2p=${listen_port} metrics=${metrics_port}"
}

stop_pid() {
  local pid="$1"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

assert_common_invariants() {
  local metrics_file="$1"
  local log_file="$2"
  assert_metric_ge "${metrics_file}" "qbind_p2p_pqc_cert_verify_accepted_total" "1"
  assert_metric_eq "${metrics_file}" "qbind_p2p_pqc_cert_verify_rejected_total" "0"
  assert_zero_family "${metrics_file}" \
    qbind_p2p_trust_bundle_live_reload_trigger_total \
    qbind_p2p_trust_bundle_live_reload_apply_success_total \
    qbind_p2p_trust_bundle_live_reload_apply_failure_total \
    qbind_p2p_trust_bundle_live_reload_already_in_progress_total \
    qbind_p2p_trust_bundle_live_reload_sessions_evicted_total \
    qbind_p2p_session_eviction_attempt_total \
    qbind_p2p_session_eviction_success_total \
    qbind_p2p_session_eviction_failure_total \
    qbind_p2p_session_eviction_sessions_evicted_total
  if grep -E -- '--p2p-trusted-root.*fallback|fallback.*--p2p-trusted-root' "${log_file}" >/dev/null; then
    fail "unexpected --p2p-trusted-root fallback evidence in ${log_file}"
  fi
  if grep -E 'DummySig|DummyKem|DummyAead|dummy_kem_registered=true|dummy_aead_registered=true' "${log_file}" >/dev/null; then
    fail "unexpected active Dummy* evidence in ${log_file}"
  fi
  wait_for_log "${log_file}" 'P2P transport up'
}

write_envelopes() {
  command -v python3 >/dev/null || fail "python3 not found"
  python3 - "$OUTDIR" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
bundle_path = out / "material" / "trust-bundle.json"
seq_path = out / "data" / "v1" / "pqc_trust_bundle_sequence.json"
bundle_bytes = bundle_path.read_bytes()
bundle = json.loads(bundle_bytes)
seq = json.loads(seq_path.read_text())
prefix = seq["bundle_fingerprint"][:8]
base = {
    "envelope_version": 1,
    "domain_tag": "qbind-peer-trust-bundle-candidate-v0",
    "peer_id": "run084-valid",
    "environment": "devnet",
    "chain_id_hex": seq["chain_id"],
    "declared_sequence": bundle["sequence"],
    "declared_fingerprint_prefix": prefix,
    "declared_length": len(bundle_bytes),
    "bundle_bytes": bundle_bytes.hex(),
}
env_dir = out / "envelopes"
env_dir.mkdir(parents=True, exist_ok=True)
(env_dir / "candidate_valid.json").write_text(json.dumps(base, indent=2, sort_keys=True) + "\n")
wrong = dict(base)
wrong["peer_id"] = "run084-invalid-wrong-chain"
wrong["chain_id_hex"] = "0000000000000000"
(env_dir / "candidate_invalid_wrong_chain.json").write_text(json.dumps(wrong, indent=2, sort_keys=True) + "\n")
dup = dict(base)
dup["peer_id"] = "run084-duplicate"
(env_dir / "candidate_duplicate.json").write_text(json.dumps(dup, indent=2, sort_keys=True) + "\n")
PY
}

run_baseline() {
  local sc="baseline"
  local p0=$((P2P_BASE + 0))
  local p1=$((P2P_BASE + 1))
  local m0=$((METRICS_BASE + 0))
  local m1=$((METRICS_BASE + 1))
  start_node "${sc}_v1" 1 "${p1}" 0 "${p0}" "${m1}" "${OUTDIR}/data/v1"
  local pid1="${LAST_PID}"
  sleep 1
  start_node "${sc}_v0" 0 "${p0}" 1 "${p1}" "${m0}" "${OUTDIR}/data/v0"
  local pid0="${LAST_PID}"
  wait_for_log "${OUTDIR}/logs/${sc}_v0.stderr.log" 'P2P transport up'
  wait_for_log "${OUTDIR}/logs/${sc}_v1.stderr.log" 'P2P transport up'
  wait_for_metrics "${m0}" "${OUTDIR}/metrics/${sc}_v0.metrics"
  wait_for_metrics "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v0.metrics" "${OUTDIR}/logs/${sc}_v0.stderr.log"
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v1.metrics" "${OUTDIR}/logs/${sc}_v1.stderr.log"
  test -f "${OUTDIR}/data/v1/pqc_trust_bundle_sequence.json" || fail "baseline did not create receiver sequence file"
  stop_pid "${pid0}"
  stop_pid "${pid1}"
}

run_single_send_scenario() {
  local sc="$1"
  local envelope="$2"
  local receiver_validation="$3"
  local expected_receiver_metric="$4"
  local expected_receiver_value="$5"
  local idx="$6"
  local p0=$((P2P_BASE + idx * 10))
  local p1=$((P2P_BASE + idx * 10 + 1))
  local m0=$((METRICS_BASE + idx * 10))
  local m1=$((METRICS_BASE + idx * 10 + 1))
  local seq_file="${OUTDIR}/data/v1/pqc_trust_bundle_sequence.json"
  local before after
  before="$(sha256_file "${seq_file}")"
  printf '%s  %s\n' "${before}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.before.sha256"

  local -a receiver_flags=()
  if [ "${receiver_validation}" = "enabled" ]; then
    receiver_flags=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  fi
  start_node "${sc}_v1" 1 "${p1}" 0 "${p0}" "${m1}" "${OUTDIR}/data/v1" "${receiver_flags[@]}"
  local pid1="${LAST_PID}"
  sleep 1
  start_node "${sc}_v0" 0 "${p0}" 1 "${p1}" "${m0}" "${OUTDIR}/data/v0" \
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled \
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}" \
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  local pid0="${LAST_PID}"

  wait_for_metric_eq "${m0}" "${OUTDIR}/metrics/${sc}_v0.metrics" \
    qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_eq "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics" \
    "${expected_receiver_metric}" "${expected_receiver_value}"
  fetch_metrics "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v0.metrics" "${OUTDIR}/logs/${sc}_v0.stderr.log"
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v1.metrics" "${OUTDIR}/logs/${sc}_v1.stderr.log"
  after="$(sha256_file "${seq_file}")"
  printf '%s  %s\n' "${after}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.after.sha256"
  [ "${before}" = "${after}" ] || fail "${sc} changed receiver sequence file"
  stop_pid "${pid0}"
  stop_pid "${pid1}"
}

run_duplicate_scenario() {
  local sc="duplicate"
  local idx=4
  local envelope="${OUTDIR}/envelopes/candidate_duplicate.json"
  local p0=$((P2P_BASE + idx * 10))
  local p1=$((P2P_BASE + idx * 10 + 1))
  local m0=$((METRICS_BASE + idx * 10))
  local m1=$((METRICS_BASE + idx * 10 + 1))
  local seq_file="${OUTDIR}/data/v1/pqc_trust_bundle_sequence.json"
  local before after
  before="$(sha256_file "${seq_file}")"
  printf '%s  %s\n' "${before}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.before.sha256"

  start_node "${sc}_v1" 1 "${p1}" 0 "${p0}" "${m1}" "${OUTDIR}/data/v1" \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
  local pid1="${LAST_PID}"
  sleep 1
  start_node "${sc}_v0a" 0 "${p0}" 1 "${p1}" "${m0}" "${OUTDIR}/data/v0" \
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled \
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}" \
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  local pid0a="${LAST_PID}"
  wait_for_metric_eq "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics" \
    qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  stop_pid "${pid0a}"
  sleep 1
  start_node "${sc}_v0b" 0 "$((p0 + 2))" 1 "${p1}" "$((m0 + 2))" "${OUTDIR}/data/v0" \
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled \
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}" \
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  local pid0b="${LAST_PID}"
  wait_for_metric_eq "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics" \
    qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1
  fetch_metrics "${m1}" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v1.metrics" "${OUTDIR}/logs/${sc}_v1.stderr.log"
  after="$(sha256_file "${seq_file}")"
  printf '%s  %s\n' "${after}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.after.sha256"
  [ "${before}" = "${after}" ] || fail "${sc} changed receiver sequence file"
  stop_pid "${pid0b}"
  stop_pid "${pid1}"
}

summarize() {
  {
    echo "Run 084 peer-candidate 0x05 matrix"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
    echo
    echo "release artifacts:"
    for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}"; do
      echo "  ${bin}"
      echo "    sha256: $(sha256_file "${bin}")"
      echo "    build_id: $(build_id "${bin}")"
    done
    echo
    echo "scenario status: pass"
    echo "  baseline N=2 startup: pass"
    echo "  valid 0x05 send/validate: pass"
    echo "  receiver-disabled cheap-ignore: pass"
    echo "  invalid wrong-chain reject: pass"
    echo "  duplicate suppression: pass"
  } > "${OUTDIR}/summary.txt"
  grep -hE '\[Run040\]|\[binary\] Run 033' "${OUTDIR}"/logs/*.stderr.log \
    > "${OUTDIR}/run033_run040_lines.txt" || true
  grep -hE 'Run 078: peer-candidate wire frame observed|Run 079: installing live peer-candidate wire|Run 080: peer-candidate wire publish attempt complete' \
    "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/peer_candidate_lines.txt" || true
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "${OUTDIR}"
  mkdir -p "${OUTDIR}/material" "${OUTDIR}/logs" "${OUTDIR}/metrics" "${OUTDIR}/sequence"

  cd "${REPO_ROOT}"
  log "building release qbind-node and helper binaries"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
  cargo build --release -p qbind-node --example devnet_pqc_root_helper
  cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper

  log "recording sha256 and ELF BuildID"
  for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}"; do
    test -x "${bin}" || fail "missing executable ${bin}"
    printf '%s  %s\n' "$(sha256_file "${bin}")" "${bin}" >> "${OUTDIR}/artifact_sha256.txt"
    printf '%s  %s\n' "$(build_id "${bin}")" "${bin}" >> "${OUTDIR}/artifact_build_id.txt"
  done

  log "minting signed N=2 DevNet trust-bundle material"
  "${TRUST_HELPER}" "${OUTDIR}/material" 2 signed-devnet 1 \
    > "${OUTDIR}/material/helper.stdout.log" \
    2> "${OUTDIR}/material/helper.stderr.log"

  log "minting DevNet consensus signer keystores for Run 033 no-DummySig proof"
  mkdir -p "${OUTDIR}/signers"
  "${SIGNER_HELPER}" "${OUTDIR}/signers" 2 \
    > "${OUTDIR}/signers/helper.stdout.log" \
    2> "${OUTDIR}/signers/helper.stderr.log"

  log "running baseline N=2 startup"
  run_baseline

  log "generating valid, invalid/wrong-chain, and duplicate candidate envelopes"
  write_envelopes

  log "running valid 0x05 send/validate scenario"
  run_single_send_scenario "valid" "${OUTDIR}/envelopes/candidate_valid.json" enabled \
    qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1 1
  assert_metric_eq "${OUTDIR}/metrics/valid_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/valid_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0

  log "running receiver-disabled cheap-ignore scenario"
  run_single_send_scenario "receiver_disabled" "${OUTDIR}/envelopes/candidate_valid.json" disabled \
    qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0 2
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 0

  log "running invalid wrong-chain reject scenario"
  run_single_send_scenario "invalid_wrong_chain" "${OUTDIR}/envelopes/candidate_invalid_wrong_chain.json" enabled \
    qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1 3
  assert_metric_eq "${OUTDIR}/metrics/invalid_wrong_chain_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/invalid_wrong_chain_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0

  log "running duplicate suppression scenario"
  run_duplicate_scenario

  log "capturing summary evidence"
  summarize
  log "PASS: Run 084 matrix artifacts captured under ${OUTDIR}"
}

main "$@"