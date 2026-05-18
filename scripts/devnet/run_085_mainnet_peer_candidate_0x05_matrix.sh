#!/usr/bin/env bash
#
# Run 085: repeatable release-binary N=4 MainNet harness for the
# peer-candidate 0x05 validation-only matrix proven at N=2 by Run 084.
#
# Scope: evidence orchestration only. The harness builds existing release
# binaries, mints signed MainNet trust material, wraps the signed baseline
# bundle as peer-candidate fixtures, runs four qbind-node release processes
# over loopback, scrapes /metrics, captures stderr/stdout, and asserts the
# validation-only invariants. It does not add protocol features, propagation,
# peer-driven live apply, activation_epoch, KMS/HSM, signing-key ratification,
# fast-sync restore, or consensus/KEMTLS redesign.
#
# Usage:
#   scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run085-mainnet-peer-candidate-0x05-matrix

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run085-mainnet-peer-candidate-0x05-matrix}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN085_NODE_TIMEOUT:-60s}"
P2P_BASE="${QBIND_RUN085_P2P_BASE:-19850}"
METRICS_BASE="${QBIND_RUN085_METRICS_BASE:-9390}"
ARCHIVE_DIR="${QBIND_RUN085_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_085_mainnet_peer_candidate_0x05_matrix}"

NODE_BIN="${QBIND_RUN085_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"
TRUST_HELPER="${QBIND_RUN085_TRUST_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper}"
ROOT_HELPER="${QBIND_RUN085_ROOT_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper}"
SIGNER_HELPER="${QBIND_RUN085_SIGNER_HELPER:-${REPO_ROOT}/target/release/examples/devnet_consensus_signer_keystore_helper}"

PIDS=()
SCENARIO_PIDS=()
START_EXTRA_V0=()
START_EXTRA_V1=()
START_EXTRA_V2=()
START_EXTRA_V3=()

log() { printf '[run085] %s\n' "$*"; }
fail() { printf '[run085] FAIL: %s\n' "$*" >&2; exit 1; }

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

sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

metric_value() {
  local file="$1" name="$2"
  awk -v n="${name}" '$1 == n {print $2; found=1; exit} END {if (!found) print "0"}' "${file}"
}

assert_metric_eq() {
  local file="$1" name="$2" expected="$3" actual
  actual="$(metric_value "${file}" "${name}")"
  [ "${actual}" = "${expected}" ] || fail "metric ${name} in ${file} expected ${expected}, got ${actual}"
}

assert_metric_ge() {
  local file="$1" name="$2" floor="$3" actual
  actual="$(metric_value "${file}" "${name}")"
  [ "${actual}" -ge "${floor}" ] || fail "metric ${name} in ${file} expected >= ${floor}, got ${actual}"
}

assert_zero_family() {
  local file="$1" metric
  shift
  for metric in "$@"; do
    assert_metric_eq "${file}" "${metric}" "0"
  done
}

fetch_metrics() {
  local port="$1" out="$2"
  curl -fsS --max-time 2 "http://127.0.0.1:${port}/metrics" > "${out}"
}

wait_for_metrics() {
  local port="$1" out="$2" i
  for ((i = 1; i <= 80; i++)); do
    fetch_metrics "${port}" "${out}" 2>/dev/null && return 0
    sleep 0.5
  done
  fail "metrics endpoint 127.0.0.1:${port} did not become available"
}

wait_for_metric_eq() {
  local port="$1" out="$2" name="$3" expected="$4" i actual
  for ((i = 1; i <= 100; i++)); do
    if fetch_metrics "${port}" "${out}" 2>/dev/null; then
      actual="$(metric_value "${out}" "${name}")"
      [ "${actual}" = "${expected}" ] && return 0
    fi
    sleep 0.5
  done
  actual="$(metric_value "${out}" "${name}" 2>/dev/null || echo 0)"
  fail "metric ${name} on port ${port} did not reach ${expected}; last=${actual}"
}

wait_for_metric_ge() {
  local port="$1" out="$2" name="$3" floor="$4" i actual
  for ((i = 1; i <= 100; i++)); do
    if fetch_metrics "${port}" "${out}" 2>/dev/null; then
      actual="$(metric_value "${out}" "${name}")"
      [ "${actual}" -ge "${floor}" ] && return 0
    fi
    sleep 0.5
  done
  actual="$(metric_value "${out}" "${name}" 2>/dev/null || echo 0)"
  fail "metric ${name} on port ${port} did not reach >= ${floor}; last=${actual}"
}

wait_for_log() {
  local file="$1" pattern="$2" i
  for ((i = 1; i <= 100; i++)); do
    [ -f "${file}" ] && grep -qE "${pattern}" "${file}" && return 0
    sleep 0.5
  done
  fail "log ${file} did not contain pattern: ${pattern}"
}

p2p_port() { echo $((P2P_BASE + $1 * 10 + $2)); }
metrics_port() { echo $((METRICS_BASE + $1 * 10 + $2)); }

consensus_key_args() {
  local vid
  for vid in 0 1 2 3; do
    printf '%s\n' --validator-consensus-key "${vid}:100:$(cat "${OUTDIR}/signers/v${vid}/validator-${vid}.pk.hex")"
  done
}

peer_args() {
  local self="$1" idx="$2" peer
  for peer in 0 1 2 3; do
    if [ "${peer}" != "${self}" ]; then
      printf '%s\n' --p2p-peer "${peer}@127.0.0.1:$(p2p_port "${idx}" "${peer}")"
      printf '%s\n' --p2p-peer-leaf-cert "${peer}:${OUTDIR}/material/v${peer}.cert.bin"
    fi
  done
}

common_args() {
  local vid="$1" listen_port="$2" idx="$3" data_dir="$4"
  printf '%s\n' \
    --env mainnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr "127.0.0.1:${listen_port}" \
    --validator-id "${vid}" \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "${OUTDIR}/material/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "$(cat "${OUTDIR}/material/signing-key.spec")" \
    --p2p-leaf-cert "${OUTDIR}/material/v${vid}.cert.bin" \
    --p2p-leaf-cert-key "${OUTDIR}/material/v${vid}.kem.sk.bin" \
    --signer-keystore-path "${OUTDIR}/signers/v${vid}" \
    --data-dir "${data_dir}"
  peer_args "${vid}" "${idx}"
  consensus_key_args
}

start_node() {
  local label="$1" vid="$2" idx="$3" listen_port="$4" metrics_port="$5" data_dir="$6"
  shift 6
  mkdir -p "${data_dir}"
  local stdout="${OUTDIR}/logs/${label}.stdout.log"
  local stderr="${OUTDIR}/logs/${label}.stderr.log"
  local -a args=()
  mapfile -t args < <(common_args "${vid}" "${listen_port}" "${idx}" "${data_dir}")
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

stop_all_scenario_pids() {
  local pid
  for pid in "$@"; do stop_pid "${pid}"; done
}

assert_common_invariants() {
  local metrics_file="$1" log_file="$2"
  assert_metric_ge "${metrics_file}" qbind_p2p_pqc_cert_verify_accepted_total 1
  assert_metric_eq "${metrics_file}" qbind_p2p_pqc_cert_verify_rejected_total 0
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

assert_no_rebroadcast() {
  local sc="$1" sender="$2" vid file
  for vid in 0 1 2 3; do
    file="${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    if [ "${vid}" != "${sender}" ]; then
      assert_metric_eq "${file}" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 0
      assert_metric_eq "${file}" qbind_p2p_pqc_trust_bundle_peer_candidate_send_failure_total 0
      assert_metric_eq "${file}" qbind_p2p_pqc_trust_bundle_peer_candidate_send_no_peer_total 0
      assert_metric_eq "${file}" qbind_p2p_pqc_trust_bundle_peer_candidate_send_oversize_total 0
    fi
  done
}

snapshot_sequence_hashes() {
  local sc="$1" phase="$2" vid seq_file hash
  for vid in 0 1 2 3; do
    seq_file="${OUTDIR}/data/v${vid}/pqc_trust_bundle_sequence.json"
    test -f "${seq_file}" || fail "missing sequence file ${seq_file}"
    hash="$(sha256_file "${seq_file}")"
    printf '%s  %s\n' "${hash}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.v${vid}.${phase}.sha256"
  done
}

assert_sequence_hashes_unchanged() {
  local sc="$1" vid before after
  for vid in 0 1 2 3; do
    before="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.before.sha256")"
    after="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.after.sha256")"
    [ "${before}" = "${after}" ] || fail "${sc} changed v${vid} sequence file"
  done
}

wait_for_cluster_metrics() {
  local sc="$1" idx="$2" vid
  for vid in 0 1 2 3; do
    wait_for_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
  done
}

start_cluster() {
  local sc="$1" idx="$2"
  local -a pids=()
  start_node "${sc}_v3" 3 "${idx}" "$(p2p_port "${idx}" 3)" "$(metrics_port "${idx}" 3)" "${OUTDIR}/data/v3" "${START_EXTRA_V3[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v2" 2 "${idx}" "$(p2p_port "${idx}" 2)" "$(metrics_port "${idx}" 2)" "${OUTDIR}/data/v2" "${START_EXTRA_V2[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v1" 1 "${idx}" "$(p2p_port "${idx}" 1)" "$(metrics_port "${idx}" 1)" "${OUTDIR}/data/v1" "${START_EXTRA_V1[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v0" 0 "${idx}" "$(p2p_port "${idx}" 0)" "$(metrics_port "${idx}" 0)" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"; pids+=("${LAST_PID}")
  SCENARIO_PIDS=("${pids[@]}")
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
    "peer_id": "run085-valid",
    "environment": "mainnet",
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
wrong["peer_id"] = "run085-invalid-wrong-chain"
wrong["chain_id_hex"] = "0000000000000000"
(env_dir / "candidate_invalid_wrong_chain.json").write_text(json.dumps(wrong, indent=2, sort_keys=True) + "\n")
dup = dict(base)
dup["peer_id"] = "run085-duplicate"
(env_dir / "candidate_duplicate.json").write_text(json.dumps(dup, indent=2, sort_keys=True) + "\n")
PY
}

run_baseline() {
  local sc="baseline" idx=0 vid
  START_EXTRA_V0=(); START_EXTRA_V1=(); START_EXTRA_V2=(); START_EXTRA_V3=()
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  for vid in 0 1 2 3; do
    wait_for_metric_ge "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_cert_verify_accepted_total 1
  done
  for vid in 0 1 2 3; do
    wait_for_metric_ge "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_consensus_committed_height 1
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
    test -f "${OUTDIR}/data/v${vid}/pqc_trust_bundle_sequence.json" || fail "baseline did not create v${vid} sequence file"
  done
  snapshot_sequence_hashes "baseline" "after"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

run_single_send_scenario() {
  local sc="$1" envelope="$2" receiver_validation="$3" expected_receiver_metric="$4" expected_receiver_value="$5" idx="$6" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(--p2p-trust-bundle-peer-candidate-wire-publish-enabled --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}" --p2p-trust-bundle-peer-candidate-wire-publish-once)
  START_EXTRA_V1=(); START_EXTRA_V2=(); START_EXTRA_V3=()
  if [ "${receiver_validation}" = "enabled" ]; then
    START_EXTRA_V1=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  fi
  start_cluster "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" "${expected_receiver_metric}" "${expected_receiver_value}"
  for vid in 0 1 2 3; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  assert_no_rebroadcast "${sc}" 0
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

run_duplicate_scenario() {
  local sc="duplicate" idx=4 envelope="${OUTDIR}/envelopes/candidate_duplicate.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(--p2p-trust-bundle-peer-candidate-wire-publish-enabled --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}" --p2p-trust-bundle-peer-candidate-wire-publish-once)
  START_EXTRA_V1=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  START_EXTRA_V2=(); START_EXTRA_V3=()
  start_cluster "${sc}" "${idx}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  stop_pid "${SCENARIO_PIDS[3]}"
  sleep 1
  start_node "${sc}_v0_second" 0 "${idx}" "$(( $(p2p_port "${idx}" 0) + 4 ))" "$(( $(metrics_port "${idx}" 0) + 4 ))" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"
  local second_sender_pid="${LAST_PID}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1
  fetch_metrics "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1
  for vid in 1 2 3; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  fetch_metrics "$(( $(metrics_port "${idx}" 0) + 4 ))" "${OUTDIR}/metrics/${sc}_v0.metrics"
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v0.metrics" "${OUTDIR}/logs/${sc}_v0_second.stderr.log"
  assert_no_rebroadcast "${sc}" 0
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_pid "${second_sender_pid}"
  stop_all_scenario_pids "${SCENARIO_PIDS[0]}" "${SCENARIO_PIDS[1]}" "${SCENARIO_PIDS[2]}"
}

summarize() {
  {
    echo "Run 085 MainNet peer-candidate 0x05 matrix"
    echo "outdir: ${OUTDIR}"
    echo "archive_dir: ${ARCHIVE_DIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
    echo "chain_id: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["chain_id"])' "${OUTDIR}/data/v1/pqc_trust_bundle_sequence.json")"
    echo
    echo "release artifacts:"
    for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}"; do
      echo "  ${bin}"
      echo "    sha256: $(sha256_file "${bin}")"
      echo "    build_id: $(build_id "${bin}")"
    done
    echo
    echo "scenario status: pass"
    echo "  baseline N=4 MainNet startup: pass"
    echo "  valid 0x05 send/validate: pass"
    echo "  receiver-disabled cheap-ignore: pass"
    echo "  invalid wrong-chain reject: pass"
    echo "  duplicate suppression: pass"
  } > "${OUTDIR}/summary.txt"
  grep -hE '\[Run040\]|\[binary\] Run 033|SuiteAwareValidatorKeyProvider built honestly' "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/run033_run040_lines.txt" || true
  grep -hE 'Run 078: peer-candidate wire frame observed|Run 079: installing live peer-candidate wire|Run 080: peer-candidate wire publish attempt complete|validation-only|not-applied|disabled' "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/peer_candidate_lines.txt" || true
}

archive_artifacts() {
  rm -rf "${ARCHIVE_DIR}"
  mkdir -p "${ARCHIVE_DIR}/logs"
  cp "${OUTDIR}/summary.txt" "${ARCHIVE_DIR}/summary.txt"
  cp "${OUTDIR}/artifact_sha256.txt" "${ARCHIVE_DIR}/artifact_sha256.txt"
  cp "${OUTDIR}/artifact_build_id.txt" "${ARCHIVE_DIR}/artifact_build_id.txt"
  cp "${OUTDIR}/run033_run040_lines.txt" "${ARCHIVE_DIR}/run033_run040_lines.txt"
  cp "${OUTDIR}/peer_candidate_lines.txt" "${ARCHIVE_DIR}/peer_candidate_lines.txt"
  cp -R "${OUTDIR}/metrics" "${ARCHIVE_DIR}/metrics"
  cp -R "${OUTDIR}/sequence" "${ARCHIVE_DIR}/sequence"
  cp -R "${OUTDIR}/envelopes" "${ARCHIVE_DIR}/envelopes"
  cp "${OUTDIR}"/logs/*.stderr.log "${ARCHIVE_DIR}/logs/"
  cp "${OUTDIR}"/logs/*.stdout.log "${ARCHIVE_DIR}/logs/"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "${OUTDIR}"
  mkdir -p "${OUTDIR}/material" "${OUTDIR}/logs" "${OUTDIR}/metrics" "${OUTDIR}/sequence"

  cd "${REPO_ROOT}"
  log "building release qbind-node and helper binaries"
  [ -x "${NODE_BIN}" ] || cargo build --release -p qbind-node --bin qbind-node
  [ -x "${TRUST_HELPER}" ] || cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
  [ -x "${ROOT_HELPER}" ] || cargo build --release -p qbind-node --example devnet_pqc_root_helper
  [ -x "${SIGNER_HELPER}" ] || cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper

  log "recording sha256 and ELF BuildID"
  for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}"; do
    test -x "${bin}" || fail "missing executable ${bin}"
    printf '%s  %s\n' "$(sha256_file "${bin}")" "${bin}" >> "${OUTDIR}/artifact_sha256.txt"
    printf '%s  %s\n' "$(build_id "${bin}")" "${bin}" >> "${OUTDIR}/artifact_build_id.txt"
  done

  log "minting signed N=4 MainNet trust-bundle material"
  "${TRUST_HELPER}" "${OUTDIR}/material" 4 signed-mainnet 1 > "${OUTDIR}/material/helper.stdout.log" 2> "${OUTDIR}/material/helper.stderr.log"

  log "minting consensus signer keystores for Run 033 no-DummySig proof"
  mkdir -p "${OUTDIR}/signers"
  "${SIGNER_HELPER}" "${OUTDIR}/signers" 4 > "${OUTDIR}/signers/helper.stdout.log" 2> "${OUTDIR}/signers/helper.stderr.log"

  log "running baseline N=4 MainNet startup"
  run_baseline

  log "generating valid, invalid/wrong-chain, and duplicate candidate envelopes"
  write_envelopes

  log "running valid 0x05 send/validate scenario"
  run_single_send_scenario "valid" "${OUTDIR}/envelopes/candidate_valid.json" enabled qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1 1
  assert_metric_eq "${OUTDIR}/metrics/valid_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/valid_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0

  log "running receiver-disabled cheap-ignore scenario"
  run_single_send_scenario "receiver_disabled" "${OUTDIR}/envelopes/candidate_valid.json" disabled qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0 2
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  assert_metric_eq "${OUTDIR}/metrics/receiver_disabled_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 0

  log "running invalid wrong-chain reject scenario"
  run_single_send_scenario "invalid_wrong_chain" "${OUTDIR}/envelopes/candidate_invalid_wrong_chain.json" enabled qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1 3
  assert_metric_eq "${OUTDIR}/metrics/invalid_wrong_chain_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/invalid_wrong_chain_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0

  log "running duplicate suppression scenario"
  run_duplicate_scenario

  log "capturing summary evidence"
  summarize
  archive_artifacts
  log "PASS: Run 085 matrix artifacts captured under ${OUTDIR} and ${ARCHIVE_DIR}"
}

main "$@"