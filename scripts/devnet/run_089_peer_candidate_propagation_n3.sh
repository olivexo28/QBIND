#!/usr/bin/env bash
#
# Run 089: repeatable release-binary N=3 DevNet harness that proves the
# Run 088 validation-before-rebroadcast propagation prototype for
# peer-candidate `0x05` frames on real release `qbind-node` processes.
#
# Scope: evidence orchestration only. The harness builds existing
# release binaries, mints signed DevNet trust material, wraps the signed
# baseline bundle as peer-candidate fixtures, runs three qbind-node
# release processes over loopback, enables propagation on V1, scrapes
# /metrics, captures stdout/stderr, captures Run033/Run040 lines, hashes
# sequence files before/after, and asserts:
#
#   - V0 sends a valid 0x05 peer-candidate frame to V1,
#   - V1 validates and rebroadcasts to V2 only (source exclusion),
#   - V2 validates (validated_total = 1 on V2),
#   - invalid wrong-chain candidates do NOT rebroadcast,
#   - duplicate candidates do NOT rebroadcast repeatedly,
#   - source peer (V0) NEVER receives its own candidate back,
#   - no apply / no sequence burn / no session eviction / no LivePqcTrustState
#     mutation on any node,
#   - no --p2p-trusted-root fallback and no active Dummy crypto.
#
# It does not add protocol features, peer-driven live apply,
# activation_epoch, KMS/HSM, signing-key ratification, fast-sync restore,
# or consensus/KEMTLS redesign. It preserves Run 087 safety gates and
# the Run 088 propagation semantics (disabled by default, hidden flag,
# validation-before-rebroadcast, source-peer exclusion, bounded queue/
# rate/target/seen-cache).
#
# Usage:
#   scripts/devnet/run_089_peer_candidate_propagation_n3.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run089-peer-candidate-propagation-n3

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run089-peer-candidate-propagation-n3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN089_NODE_TIMEOUT:-60s}"
P2P_BASE="${QBIND_RUN089_P2P_BASE:-19890}"
METRICS_BASE="${QBIND_RUN089_METRICS_BASE:-9395}"
ARCHIVE_DIR="${QBIND_RUN089_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_089_peer_candidate_propagation_n3}"

NODE_BIN="${QBIND_RUN089_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"
TRUST_HELPER="${QBIND_RUN089_TRUST_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper}"
ROOT_HELPER="${QBIND_RUN089_ROOT_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper}"
SIGNER_HELPER="${QBIND_RUN089_SIGNER_HELPER:-${REPO_ROOT}/target/release/examples/devnet_consensus_signer_keystore_helper}"

PIDS=()
SCENARIO_PIDS=()
START_EXTRA_V0=()
START_EXTRA_V1=()
START_EXTRA_V2=()

log() { printf '[run089] %s\n' "$*"; }
fail() { printf '[run089] FAIL: %s\n' "$*" >&2; exit 1; }

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
  for ((i = 1; i <= 120; i++)); do
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
  for ((i = 1; i <= 120; i++)); do
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
  for ((i = 1; i <= 120; i++)); do
    [ -f "${file}" ] && grep -qE "${pattern}" "${file}" && return 0
    sleep 0.5
  done
  fail "log ${file} did not contain pattern: ${pattern}"
}

# Disjoint port slots per scenario (idx) and per validator (vid).
# idx 0..9 supported; vid 0..2.
p2p_port() { echo $((P2P_BASE + $1 * 10 + $2)); }
metrics_port() { echo $((METRICS_BASE + $1 * 10 + $2)); }

consensus_key_args() {
  local vid
  for vid in 0 1 2; do
    printf '%s\n' --validator-consensus-key "${vid}:100:$(cat "${OUTDIR}/signers/v${vid}/validator-${vid}.pk.hex")"
  done
}

peer_args() {
  local self="$1" idx="$2" peer
  for peer in 0 1 2; do
    if [ "${peer}" != "${self}" ]; then
      printf '%s\n' --p2p-peer "${peer}@127.0.0.1:$(p2p_port "${idx}" "${peer}")"
      printf '%s\n' --p2p-peer-leaf-cert "${peer}:${OUTDIR}/material/v${peer}.cert.bin"
    fi
  done
}

common_args() {
  local vid="$1" listen_port="$2" idx="$3" data_dir="$4"
  printf '%s\n' \
    --env devnet \
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
  # Invariants shared by every scenario/node: a working PQC mutual-auth
  # transport (Run 040 real crypto, no active Dummy*), no live reload
  # apply, no session eviction, no --p2p-trusted-root fallback.
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
  # Run 088: never expose an applied counter family on peer-candidate path.
  if grep -E 'qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total' "${metrics_file}" >/dev/null; then
    fail "unexpected peer_candidate_applied_total metric in ${metrics_file}"
  fi
  wait_for_log "${log_file}" 'P2P transport up'
}

snapshot_sequence_hashes() {
  local sc="$1" phase="$2" vid seq_file hash
  for vid in 0 1 2; do
    seq_file="${OUTDIR}/data/v${vid}/pqc_trust_bundle_sequence.json"
    test -f "${seq_file}" || fail "missing sequence file ${seq_file}"
    hash="$(sha256_file "${seq_file}")"
    printf '%s  %s\n' "${hash}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.v${vid}.${phase}.sha256"
  done
}

assert_sequence_hashes_unchanged() {
  local sc="$1" vid before after
  for vid in 0 1 2; do
    before="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.before.sha256")"
    after="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.after.sha256")"
    [ "${before}" = "${after}" ] || fail "${sc} changed v${vid} sequence file (before=${before} after=${after})"
  done
}

wait_for_cluster_metrics() {
  local sc="$1" idx="$2" vid
  for vid in 0 1 2; do
    wait_for_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
  done
}

start_cluster() {
  local sc="$1" idx="$2"
  local -a pids=()
  # Start V2 and V1 first so V0's publish-once has connected receivers ready.
  start_node "${sc}_v2" 2 "${idx}" "$(p2p_port "${idx}" 2)" "$(metrics_port "${idx}" 2)" "${OUTDIR}/data/v2" "${START_EXTRA_V2[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v1" 1 "${idx}" "$(p2p_port "${idx}" 1)" "$(metrics_port "${idx}" 1)" "${OUTDIR}/data/v1" "${START_EXTRA_V1[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v0" 0 "${idx}" "$(p2p_port "${idx}" 0)" "$(metrics_port "${idx}" 0)" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"; pids+=("${LAST_PID}")
  SCENARIO_PIDS=("${pids[@]}")
}

# Generate a valid signed-devnet peer-candidate envelope JSON (matches the
# Run 080 `PeerCandidateWirePublishConfig::envelope_path` format) plus an
# invalid-wrong-chain variant and a duplicate variant. The valid envelope
# wraps the *same* signed baseline bundle the cluster is loaded with, so
# the receiver's Run 069 loader chain validates honestly without any
# fallback path and without mutating sequence/state.
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
    "peer_id": "run089-valid",
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
wrong["peer_id"] = "run089-invalid-wrong-chain"
wrong["chain_id_hex"] = "0000000000000000"
(env_dir / "candidate_invalid_wrong_chain.json").write_text(json.dumps(wrong, indent=2, sort_keys=True) + "\n")
dup = dict(base)
dup["peer_id"] = "run089-duplicate"
(env_dir / "candidate_duplicate.json").write_text(json.dumps(dup, indent=2, sort_keys=True) + "\n")
PY
}

run_baseline() {
  local sc="baseline" idx=0 vid
  START_EXTRA_V0=(); START_EXTRA_V1=(); START_EXTRA_V2=()
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  for vid in 0 1 2; do
    wait_for_metric_ge "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_cert_verify_accepted_total 1
  done
  for vid in 0 1 2; do
    wait_for_metric_ge "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_consensus_committed_height 1
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
    test -f "${OUTDIR}/data/v${vid}/pqc_trust_bundle_sequence.json" || fail "baseline did not create v${vid} sequence file"
    # No peer-candidate traffic on any node before any scenario runs.
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 0
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  done
  snapshot_sequence_hashes "baseline" "after"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Primary objective scenario: V0 publish-once → V1 validate+propagate →
# V2 validate; assert V0 NEVER receives the candidate back from V1.
run_valid_propagation() {
  local sc="valid" idx=1 envelope="${OUTDIR}/envelopes/candidate_valid.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  START_EXTRA_V1=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-propagation-enabled
  )
  START_EXTRA_V2=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  # V0 publishes exactly one valid 0x05 frame to its connected peers.
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  # V1 receives and validates the frame.
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  # V1 then rebroadcasts to V2 (validation-before-propagation).
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  # V2 receives and validates the propagated frame.
  wait_for_metric_eq "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1

  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done

  # V1 invariants for valid path. V1 is the propagation hub: it
  # receives V0's directly-broadcast publish-once frame, validates it,
  # and rebroadcasts to its only non-source peer (V2).
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_duplicate_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_rate_limited_total 0

  # V2 invariants — V2 receives the validated 0x05 frame at least once
  # (the Run 080 publish broadcasts to all V0-connected peers, so V2
  # may also receive directly from V0 in addition to the V1 propagation;
  # in that case the receiver-side LRU deduplicates the second copy,
  # but the propagation evidence already passed above with
  # `propagation_sent_total == 1` on V1, which is V2 by construction
  # since V2 is V1's only non-source peer). V2 must validate at least
  # once, never reject, and never itself propagate (V2's propagation
  # flag is disabled).
  local v2_received v2_duplicate
  v2_received="$(metric_value "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total)"
  [ "${v2_received}" -ge 1 ] || fail "V2 received_total expected >= 1, got ${v2_received}"
  [ "${v2_received}" -le 2 ] || fail "V2 received_total expected <= 2 (direct + propagation), got ${v2_received}"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  v2_duplicate="$(metric_value "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total)"
  [ "${v2_duplicate}" -eq $((v2_received - 1)) ] || fail "V2 duplicate_total expected $((v2_received - 1)) (received - validated), got ${v2_duplicate}"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0

  # V0 invariants — source peer NEVER receives its own candidate back
  # from V1 (source exclusion). V0 itself never propagates anything
  # (propagation disabled). V0's publish broadcast counts at least 1
  # successfully enqueued send.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1

  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Negative scenario: invalid (wrong-chain) candidate must be rejected on
# V1 and must NOT be rebroadcast to V2; V0 source still never receives
# an echo.
run_invalid_wrong_chain() {
  local sc="invalid_wrong_chain" idx=2 envelope="${OUTDIR}/envelopes/candidate_invalid_wrong_chain.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  START_EXTRA_V1=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-propagation-enabled
  )
  START_EXTRA_V2=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  # Give V1 time to (not) propagate.
  sleep 3
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # V1: received, rejected, NOT validated, NOT propagated. V1 must record
  # propagation_suppressed_invalid=1 (the propagation gate fires on the
  # validator rejection).
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total 1
  # V2: may receive the invalid frame DIRECTLY from V0 (publish-once
  # broadcasts to all V0-connected peers), but V2 must NEVER receive an
  # invalid candidate VIA V1 propagation (V1 rejects then suppresses).
  # Therefore V2.received_total is at most 1 (the direct V0 copy), and
  # V2 must reject it: validated_total stays 0 and rejected_total
  # matches received_total. V2 must never propagate anything itself.
  local v2_received_inv
  v2_received_inv="$(metric_value "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total)"
  [ "${v2_received_inv}" -le 1 ] || fail "V2 received invalid > 1 means V1 propagated invalid; got ${v2_received_inv}"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" "qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total" "${v2_received_inv}"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  # V0: source still receives no echo.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Duplicate suppression scenario: V0 publishes once, V1 validates +
# propagates. A second V0 process publishes the SAME envelope; V1
# receives it again, the local seen-cache fires, and V1 does NOT
# rebroadcast a second time. V0 still never receives an echo from V1.
run_duplicate_scenario() {
  local sc="duplicate" idx=3 envelope="${OUTDIR}/envelopes/candidate_duplicate.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  START_EXTRA_V1=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-propagation-enabled
  )
  START_EXTRA_V2=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  # Bring V0 down and restart it on a different port slot to re-publish
  # the same envelope. V1 must duplicate-suppress it.
  stop_pid "${SCENARIO_PIDS[2]}"
  sleep 1
  local v0_second_p2p=$(( $(p2p_port "${idx}" 0) + 4 ))
  local v0_second_metrics=$(( $(metrics_port "${idx}" 0) + 4 ))
  start_node "${sc}_v0_second" 0 "${idx}" "${v0_second_p2p}" "${v0_second_metrics}" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"
  local second_sender_pid="${LAST_PID}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  # Allow a couple of seconds for any (would-be) propagation to settle;
  # then assert duplicate suppression fired and propagation count stayed
  # at exactly 1.
  sleep 3
  fetch_metrics "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  # V2: at least one validated, no rebroadcast loop. The exact received
  # count depends on race between V0 direct send vs V1 propagation, plus
  # the second V0 process's direct send; in all cases V2 must validate
  # at most once (LRU dedup), and never propagate. V1 must not have
  # rebroadcast a second time.
  fetch_metrics "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics"
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  # V0 second process: source still receives no echo.
  fetch_metrics "${v0_second_metrics}" "${OUTDIR}/metrics/${sc}_v0_second.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0_second.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
  for vid in 1 2; do
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  assert_common_invariants "${OUTDIR}/metrics/${sc}_v0_second.metrics" "${OUTDIR}/logs/${sc}_v0_second.stderr.log"
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_pid "${second_sender_pid}"
  stop_all_scenario_pids "${SCENARIO_PIDS[0]}" "${SCENARIO_PIDS[1]}"
}

# Source-exclusion stand-alone scenario: re-runs the valid path and
# additionally asserts that V0's `received_total` stays at 0 and that no
# propagation occurs on V0 (V0 propagation disabled), proving V1 excludes
# the source from the rebroadcast target set even after multiple seconds
# of settle time.
run_source_exclusion_scenario() {
  local sc="source_exclusion" idx=4 envelope="${OUTDIR}/envelopes/candidate_valid.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  START_EXTRA_V1=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-propagation-enabled
  )
  START_EXTRA_V2=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  # Settle window: even with several seconds, V0 must never receive its
  # own candidate back; no loop may form.
  sleep 5
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # Hard source-exclusion + no-loop assertions.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  # V1 propagated exactly once (no loop echo from V2).
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 1
  # V2 never propagates and never echoes anything back.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

summarize() {
  {
    echo "Run 089 N=3 DevNet peer-candidate propagation harness"
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
    echo "  baseline N=3 DevNet startup: pass"
    echo "  valid V0 -> V1 -> V2 propagation (source-exclusion enforced): pass"
    echo "  invalid wrong-chain non-propagation: pass"
    echo "  duplicate suppression (no repeated rebroadcast): pass"
    echo "  source-exclusion settle-window (no loop): pass"
  } > "${OUTDIR}/summary.txt"
  grep -hE '\[Run040\]|\[binary\] Run 033|SuiteAwareValidatorKeyProvider built honestly' "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/run033_run040_lines.txt" || true
  grep -hE 'Run 078: peer-candidate wire frame observed|Run 079: installing live peer-candidate wire|Run 080: peer-candidate wire publish attempt complete|Run 088:|propagation_enabled|validation-only|not-applied|disabled' "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/peer_candidate_lines.txt" || true
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
  log "building release qbind-node and helper binaries (skipped if prebuilt)"
  [ -x "${NODE_BIN}" ]    || cargo build --release -p qbind-node --bin qbind-node
  [ -x "${TRUST_HELPER}" ] || cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
  [ -x "${ROOT_HELPER}" ]  || cargo build --release -p qbind-node --example devnet_pqc_root_helper
  [ -x "${SIGNER_HELPER}" ] || cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper

  log "recording sha256 and ELF BuildID"
  for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}"; do
    test -x "${bin}" || fail "missing executable ${bin}"
    printf '%s  %s\n' "$(sha256_file "${bin}")" "${bin}" >> "${OUTDIR}/artifact_sha256.txt"
    printf '%s  %s\n' "$(build_id "${bin}")" "${bin}" >> "${OUTDIR}/artifact_build_id.txt"
  done

  log "minting signed N=3 DevNet trust-bundle material"
  "${TRUST_HELPER}" "${OUTDIR}/material" 3 signed-devnet 1 \
    > "${OUTDIR}/material/helper.stdout.log" \
    2> "${OUTDIR}/material/helper.stderr.log"

  log "minting DevNet consensus signer keystores (Run 033 active=true, no DummySig)"
  mkdir -p "${OUTDIR}/signers"
  "${SIGNER_HELPER}" "${OUTDIR}/signers" 3 \
    > "${OUTDIR}/signers/helper.stdout.log" \
    2> "${OUTDIR}/signers/helper.stderr.log"

  log "running baseline N=3 DevNet startup"
  run_baseline

  log "generating valid, invalid/wrong-chain, and duplicate candidate envelopes"
  write_envelopes

  log "running valid V0 -> V1 -> V2 propagation scenario"
  run_valid_propagation

  log "running invalid wrong-chain non-propagation scenario"
  run_invalid_wrong_chain

  log "running duplicate suppression scenario"
  run_duplicate_scenario

  log "running source-exclusion settle scenario"
  run_source_exclusion_scenario

  log "capturing summary and archiving artifacts"
  summarize
  archive_artifacts
  log "PASS: Run 089 N=3 propagation evidence captured under ${OUTDIR} and ${ARCHIVE_DIR}"
}

main "$@"
