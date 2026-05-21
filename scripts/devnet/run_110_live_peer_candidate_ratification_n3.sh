#!/usr/bin/env bash
#
# Run 110: release-binary N=3 DevNet harness that proves the Run 109 live
# inbound `0x05` peer-candidate wire ratification gate on real release
# `qbind-node` processes.
#
# Scope: evidence orchestration only. This harness reuses the Run 089
# DevNet mutual-auth N=3 transport topology and overlays Run 100 / 101 /
# 103 / 104 / 105 / 106 / 107 / 109 genesis-authority + ratification
# fixtures via `run_110_live_ratification_fixture_helper`. It enables the
# Run 088 propagation path on V1 (the relay), enables Run 109 ratification
# on V1 and V2, and proves the following invariants on release binaries:
#
#   Scenario `valid_ratified`:
#     - V0 sends 0x05 candidate wrapping the cluster's R1-signed baseline
#       bundle (the ratified key);
#     - V1 receives, ratification-validates, validates the inner bundle,
#       and rebroadcasts to V2 (source-peer V0 excluded);
#     - V2 receives and validates;
#     - V0 NEVER receives its own candidate back (source-peer exclusion).
#
#   Scenario `missing_ratification`:
#     - V0 sends 0x05 candidate wrapping a U1-signed alternate bundle
#       (U1 is a freshly-minted signing key NOT covered by V1's
#       ratification sidecar; V1 accepts U1 via
#       `--p2p-trust-bundle-signing-key` so the inner Run 050 / 076
#       signature check succeeds and the Run 109 ratification gate is
#       reached);
#     - V1 receives, the Run 109 ratification gate rejects with
#       `RatificationRefused(Missing)`, propagation is suppressed
#       (`propagation_suppressed_invalid_total >= 1`,
#       `propagation_sent_total == 0`);
#     - V2 does NOT receive the candidate via V1 propagation (it may
#       receive directly from V0's broadcast and then ALSO reject).
#
#   Scenario `bad_ratification_startup_refuse`:
#     - V1 is started with the tampered `ratification.bad-signature.json`
#       sidecar; the Run 105 startup preflight gate refuses to install
#       the live dispatcher and the binary exits non-zero;
#     - V1 NEVER reaches `P2P transport up`; defense-in-depth proof that
#       bad-signature ratification cannot reach the live wire path.
#
#   Scenario `duplicate_unratified_no_promotion`:
#     - V0 publishes the unratified envelope twice (publish-once + a
#       second V0 process); V1 ratification-rejects both; the seen-cache
#       does NOT convert a rejection into an acceptance;
#     - `propagation_sent_total` on V1 stays at 0 across both arrivals.
#
#   Scenario `devnet_no_opt_in_legacy`:
#     - V1 and V2 are started WITHOUT
#       `--p2p-trust-bundle-ratification-enforcement-enabled` and
#       WITHOUT `--p2p-trust-bundle-ratification`; the Run 106
#       `devnet-no-operator-opt-in` skip branch fires and the live
#       dispatcher uses the pre-Run-109 unguarded path; V0 publishes the
#       ratified envelope and V1 / V2 validate exactly as in the
#       unguarded Run 089 case.
#
# Across every scenario the harness asserts the non-mutation invariants
# enumerated by Run 087 / 088 / 089 / 105 / 107 / 109:
#
#   - `pqc_trust_bundle_sequence.json` is byte-identical on every node
#     before and after the scenario;
#   - no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
#     metric family appears (Run 088 contract);
#   - all `live_reload_apply_*` and `session_eviction_*` counters stay
#     at 0;
#   - no `--p2p-trusted-root` fallback log line fires;
#   - no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true`
#     log line fires.
#
# Run 110 does NOT introduce: peer-driven live apply, reload-apply
# enforcement, SIGHUP enforcement, signing-key rotation/revocation,
# authority anti-rollback persistence, KMS/HSM, governance, validator
# rotation, wire-format changes, fallback authorities, fallback signing
# keys, or static production source-code anchors. It does NOT claim full
# C4 closure or C5 closure.
#
# Usage:
#   scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run110-live-peer-candidate-ratification-n3
#
# Tunables (env):
#   QBIND_RUN110_NODE_TIMEOUT=60s
#   QBIND_RUN110_P2P_BASE=19000
#   QBIND_RUN110_METRICS_BASE=9500

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run110-live-peer-candidate-ratification-n3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN110_NODE_TIMEOUT:-60s}"
P2P_BASE="${QBIND_RUN110_P2P_BASE:-19000}"
METRICS_BASE="${QBIND_RUN110_METRICS_BASE:-9500}"
ARCHIVE_DIR="${QBIND_RUN110_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_110_live_peer_candidate_ratification_n3}"

NODE_BIN="${QBIND_RUN110_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"
TRUST_HELPER="${QBIND_RUN110_TRUST_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper}"
ROOT_HELPER="${QBIND_RUN110_ROOT_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper}"
SIGNER_HELPER="${QBIND_RUN110_SIGNER_HELPER:-${REPO_ROOT}/target/release/examples/devnet_consensus_signer_keystore_helper}"
RAT_HELPER="${QBIND_RUN110_RAT_HELPER:-${REPO_ROOT}/target/release/examples/run_110_live_ratification_fixture_helper}"

PIDS=()
SCENARIO_PIDS=()
START_EXTRA_V0=()
START_EXTRA_V1=()
START_EXTRA_V2=()
EXTRA_SIGNING_KEYS=()

log() { printf '[run110] %s\n' "$*"; }
fail() { printf '[run110] FAIL: %s\n' "$*" >&2; exit 1; }

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

# Base args every node needs. The cluster's baseline trust-bundle is
# signed by R1 (the ratified key); we additionally accept the U1
# (unratified) key on every node so the U1-signed alternate bundle's
# Run 050 / 076 signature check succeeds and the candidate reaches the
# Run 109 ratification gate. The Run 109 gate is the one that distinguishes
# ratified from unratified — exercising it on the live wire is the whole
# point of Run 110.
common_args() {
  local vid="$1" listen_port="$2" idx="$3" data_dir="$4" extra_key
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
  for extra_key in "${EXTRA_SIGNING_KEYS[@]:-}"; do
    [ -n "${extra_key}" ] && printf '%s\n' --p2p-trust-bundle-signing-key "${extra_key}"
  done
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
  start_node "${sc}_v2" 2 "${idx}" "$(p2p_port "${idx}" 2)" "$(metrics_port "${idx}" 2)" "${OUTDIR}/data/v2" "${START_EXTRA_V2[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v1" 1 "${idx}" "$(p2p_port "${idx}" 1)" "$(metrics_port "${idx}" 1)" "${OUTDIR}/data/v1" "${START_EXTRA_V1[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v0" 0 "${idx}" "$(p2p_port "${idx}" 0)" "$(metrics_port "${idx}" 0)" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"; pids+=("${LAST_PID}")
  SCENARIO_PIDS=("${pids[@]}")
}

# Args common to every Run 110 ratification-aware node (V1 + V2 in the
# enforced-policy scenarios). V0 — the sender — does not need them: V0
# never receives 0x05 frames for ratification, and the Run 106 DevNet
# gate decision is local-per-node.
ratification_args_valid() {
  printf '%s\n' \
    --genesis-path "${OUTDIR}/fixtures/genesis.json" \
    --expect-genesis-hash "$(cat "${OUTDIR}/fixtures/expected-genesis-hash.txt")" \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "${OUTDIR}/fixtures/ratification.valid.json"
}

ratification_args_bad() {
  printf '%s\n' \
    --genesis-path "${OUTDIR}/fixtures/genesis.json" \
    --expect-genesis-hash "$(cat "${OUTDIR}/fixtures/expected-genesis-hash.txt")" \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "${OUTDIR}/fixtures/ratification.bad-signature.json"
}

# Scenario A — Cluster baseline with ratification enforcement enabled on
# V1+V2; proves the ratified cluster boots, mutual auth succeeds, and no
# peer-candidate traffic flows yet.
run_baseline_ratification() {
  local sc="baseline_ratification" idx=0 vid
  START_EXTRA_V0=()
  mapfile -t START_EXTRA_V1 < <(ratification_args_valid)
  mapfile -t START_EXTRA_V2 < <(ratification_args_valid)
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  for vid in 0 1 2; do
    wait_for_metric_ge "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_cert_verify_accepted_total 1
  done
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
    test -f "${OUTDIR}/data/v${vid}/pqc_trust_bundle_sequence.json" || fail "baseline did not create v${vid} sequence file"
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
    assert_metric_eq "${OUTDIR}/metrics/${sc}_v${vid}.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 0
  done
  # V1 and V2 must log the Run 109 INVOKED gate marker; V0 does not
  # because V0 has no live ratification dispatcher installed.
  for vid in 1 2; do
    grep -qE 'ratification gate INVOKED|live peer-candidate.*ratification.*INVOKED|policy=devnet-operator-opt-in' \
      "${OUTDIR}/logs/${sc}_v${vid}.stderr.log" || \
      fail "${sc}: V${vid} did not log the Run 109 ratification INVOKED marker"
  done
  snapshot_sequence_hashes "${sc}" "after"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Scenario 1 — Valid ratified candidate validates AND propagates.
run_valid_ratified() {
  local sc="valid_ratified" idx=1 envelope="${OUTDIR}/fixtures/envelope.ratified.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  mapfile -t START_EXTRA_V1 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
    --p2p-trust-bundle-peer-candidate-propagation-enabled)
  mapfile -t START_EXTRA_V2 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1

  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done

  # V1 invariants: ratification PASS → validated → propagate to V2 (V0
  # excluded as source peer).
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total 0

  # V2 invariants: validates the propagated frame; never propagates itself.
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0

  # V0 source exclusion + settle window.
  sleep 3
  fetch_metrics "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0

  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Scenario 2 — Missing-ratification candidate rejects and does NOT propagate.
run_missing_ratification() {
  local sc="missing_ratification" idx=2 envelope="${OUTDIR}/fixtures/envelope.unratified.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  mapfile -t START_EXTRA_V1 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
    --p2p-trust-bundle-peer-candidate-propagation-enabled)
  mapfile -t START_EXTRA_V2 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  # Settle so any (would-be) propagation completes.
  sleep 3
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # V1: ratification REJECT → propagation suppressed.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total 1
  grep -qE 'RatificationRefused|ratification.*reject|Missing' "${OUTDIR}/logs/${sc}_v1.stderr.log" || \
    fail "${sc}: V1 did not log a ratification-refusal marker"
  # V2 must NOT receive via V1 propagation. Direct-broadcast from V0 may
  # still hit V2; V2 must reject identically.
  local v2_received
  v2_received="$(metric_value "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total)"
  [ "${v2_received}" -le 1 ] || fail "V2 received unratified > 1 means V1 propagated unratified; got ${v2_received}"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  # V0 source still receives no echo.
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

# Scenario 3 — Bad-signature ratification refuses at startup (Run 105
# preflight, defense-in-depth: bad-signature ratification objects cannot
# reach the live wire path because the binary refuses to install the
# live dispatcher).
run_bad_ratification_startup_refuse() {
  local sc="bad_ratification_startup_refuse"
  local stdout="${OUTDIR}/logs/${sc}_v1.stdout.log"
  local stderr="${OUTDIR}/logs/${sc}_v1.stderr.log"
  local data_dir="${OUTDIR}/data/${sc}_v1"
  mkdir -p "${data_dir}"
  # V1 only — we just need to prove the binary exits non-zero with a
  # typed refusal log line. We do not need V0/V2 for this proof.
  local -a args=()
  mapfile -t args < <(common_args 1 "$(p2p_port 7 1)" 7 "${data_dir}")
  set +e
  (
    cd "${REPO_ROOT}"
    QBIND_METRICS_HTTP_ADDR="127.0.0.1:$(metrics_port 7 1)" \
      timeout 30s "${NODE_BIN}" "${args[@]}" \
        --genesis-path "${OUTDIR}/fixtures/genesis.json" \
        --expect-genesis-hash "$(cat "${OUTDIR}/fixtures/expected-genesis-hash.txt")" \
        --p2p-trust-bundle-ratification-enforcement-enabled \
        --p2p-trust-bundle-ratification "${OUTDIR}/fixtures/ratification.bad-signature.json"
  ) >"${stdout}" 2>"${stderr}"
  local rc=$?
  set -e
  [ "${rc}" != "0" ] || fail "${sc}: V1 with bad-signature ratification unexpectedly exited 0"
  grep -qE 'RatificationRefused|BadSignature|bad signature|ratification.*reject|run-105.*refused|run-109.*FATAL' "${stderr}" || \
    fail "${sc}: V1 did not log a bad-signature refusal marker"
  if grep -qE 'P2P transport up' "${stderr}"; then
    fail "${sc}: V1 reached 'P2P transport up' with a bad-signature ratification (should have refused)"
  fi
  if find "${data_dir}" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "${sc}: sequence file created under ${data_dir} despite startup refuse"
  fi
  printf '%s\n' "${rc}" > "${OUTDIR}/logs/${sc}_v1.exit_code"
}

# Scenario 4 — Duplicate unratified candidate: seen-cache does NOT
# convert rejection into acceptance. Two consecutive arrivals of the
# same unratified envelope still ratification-reject; no propagation
# sent.
run_duplicate_unratified_no_promotion() {
  local sc="duplicate_unratified_no_promotion" idx=4 envelope="${OUTDIR}/fixtures/envelope.unratified.json" vid
  snapshot_sequence_hashes "${sc}" "before"
  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  mapfile -t START_EXTRA_V1 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
    --p2p-trust-bundle-peer-candidate-propagation-enabled)
  mapfile -t START_EXTRA_V2 < <(ratification_args_valid; printf '%s\n' \
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_metric_eq "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  # Bring V0 down, then restart on a different port slot and republish.
  stop_pid "${SCENARIO_PIDS[2]}"
  sleep 1
  local v0_second_p2p=$(( $(p2p_port "${idx}" 0) + 5 ))
  local v0_second_metrics=$(( $(metrics_port "${idx}" 0) + 5 ))
  start_node "${sc}_v0_second" 0 "${idx}" "${v0_second_p2p}" "${v0_second_metrics}" "${OUTDIR}/data/v0" "${START_EXTRA_V0[@]}"
  local second_sender_pid="${LAST_PID}"
  wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  sleep 3
  fetch_metrics "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics"
  assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  # The second arrival is either re-rejected outright OR duplicate-
  # suppressed; in BOTH cases V1 must not have propagated and must not
  # have flipped any prior rejection into acceptance. Sum of duplicate
  # + rejected covers the second arrival.
  local v1_rejected v1_duplicate
  v1_rejected="$(metric_value "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total)"
  v1_duplicate="$(metric_value "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total)"
  [ "$(( v1_rejected + v1_duplicate ))" -ge 2 ] || fail "${sc}: V1 rejected+duplicate < received; possible promotion"
  fetch_metrics "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics"
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
  for vid in 1 2; do
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_pid "${second_sender_pid}"
  stop_all_scenario_pids "${SCENARIO_PIDS[0]}" "${SCENARIO_PIDS[1]}"
}

# Scenario 5 — DevNet no-opt-in legacy path is preserved (no
# ratification flags). Mirrors Run 089's valid path.
run_devnet_no_opt_in_legacy() {
  local sc="devnet_no_opt_in_legacy" idx=5 envelope="${OUTDIR}/fixtures/envelope.ratified.json" vid
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
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # V1 should log the DevNet skip marker since no ratification flag is set.
  grep -qE 'ratification gate SKIPPED|devnet-no-operator-opt-in|policy=devnet-no-operator-opt-in' \
    "${OUTDIR}/logs/${sc}_v1.stderr.log" || \
    fail "${sc}: V1 did not log a DevNet no-opt-in skip marker"
  snapshot_sequence_hashes "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
}

summarize() {
  {
    echo "Run 110 N=3 DevNet live peer-candidate ratification harness"
    echo "outdir: ${OUTDIR}"
    echo "archive_dir: ${ARCHIVE_DIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo
    echo "release artifacts:"
    for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}" "${RAT_HELPER}"; do
      echo "  ${bin}"
      echo "    sha256: $(sha256_file "${bin}")"
      echo "    build_id: $(build_id "${bin}")"
    done
    echo
    echo "fixture summary:"
    if [ -f "${OUTDIR}/fixtures/summary.json" ]; then
      sed 's/^/  /' "${OUTDIR}/fixtures/summary.json"
    fi
    echo
    echo "scenario status: pass"
    echo "  baseline_ratification (N=3 DevNet startup with Run 109 gate INVOKED on V1+V2): pass"
    echo "  valid_ratified (V0 -> V1 ratification PASS -> V1 propagate -> V2 validate; V0 source excluded): pass"
    echo "  missing_ratification (U1-signed candidate -> V1 RatificationRefused(Missing) -> propagation_suppressed_invalid; V2 no propagated receipt): pass"
    echo "  bad_ratification_startup_refuse (V1 with tampered sidecar refuses Run 105 preflight, never reaches transport up): pass"
    echo "  duplicate_unratified_no_promotion (seen-cache does NOT promote rejection to acceptance): pass"
    echo "  devnet_no_opt_in_legacy (no ratification flags -> Run 109 gate SKIPPED, Run 089 behavior preserved): pass"
  } > "${OUTDIR}/summary.txt"
  grep -hE 'ratification gate (INVOKED|SKIPPED)|RatificationRefused|policy=(mainnet|testnet|devnet)-(default-strict|no-operator-opt-in|operator-opt-in)|run-109|run-105' \
    "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/ratification_lines.txt" || true
  grep -hE '\[Run040\]|\[binary\] Run 033|SuiteAwareValidatorKeyProvider built honestly' \
    "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/run033_run040_lines.txt" || true
}

archive_artifacts() {
  rm -rf "${ARCHIVE_DIR}"
  mkdir -p "${ARCHIVE_DIR}/logs"
  cp "${OUTDIR}/summary.txt" "${ARCHIVE_DIR}/summary.txt"
  [ -f "${OUTDIR}/artifact_sha256.txt" ]   && cp "${OUTDIR}/artifact_sha256.txt"   "${ARCHIVE_DIR}/artifact_sha256.txt"
  [ -f "${OUTDIR}/artifact_build_id.txt" ] && cp "${OUTDIR}/artifact_build_id.txt" "${ARCHIVE_DIR}/artifact_build_id.txt"
  [ -f "${OUTDIR}/ratification_lines.txt" ] && cp "${OUTDIR}/ratification_lines.txt" "${ARCHIVE_DIR}/ratification_lines.txt"
  [ -f "${OUTDIR}/run033_run040_lines.txt" ] && cp "${OUTDIR}/run033_run040_lines.txt" "${ARCHIVE_DIR}/run033_run040_lines.txt"
  cp -R "${OUTDIR}/metrics"   "${ARCHIVE_DIR}/metrics"   2>/dev/null || true
  cp -R "${OUTDIR}/sequence"  "${ARCHIVE_DIR}/sequence"  2>/dev/null || true
  cp -R "${OUTDIR}/fixtures"  "${ARCHIVE_DIR}/fixtures"  2>/dev/null || true
  cp "${OUTDIR}"/logs/*.stderr.log "${ARCHIVE_DIR}/logs/" 2>/dev/null || true
  cp "${OUTDIR}"/logs/*.stdout.log "${ARCHIVE_DIR}/logs/" 2>/dev/null || true
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "${OUTDIR}"
  mkdir -p "${OUTDIR}/material" "${OUTDIR}/logs" "${OUTDIR}/metrics" "${OUTDIR}/sequence" "${OUTDIR}/fixtures"

  cd "${REPO_ROOT}"
  log "building release qbind-node + helper binaries (skipped if prebuilt)"
  [ -x "${NODE_BIN}" ]      || cargo build --release -p qbind-node --bin qbind-node
  [ -x "${TRUST_HELPER}" ]  || cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
  [ -x "${ROOT_HELPER}" ]   || cargo build --release -p qbind-node --example devnet_pqc_root_helper
  [ -x "${SIGNER_HELPER}" ] || cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
  [ -x "${RAT_HELPER}" ]    || cargo build --release -p qbind-node --example run_110_live_ratification_fixture_helper

  log "recording sha256 and ELF BuildID"
  for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}" "${RAT_HELPER}"; do
    test -x "${bin}" || fail "missing executable ${bin}"
    printf '%s  %s\n' "$(sha256_file "${bin}")" "${bin}" >> "${OUTDIR}/artifact_sha256.txt"
    printf '%s  %s\n' "$(build_id "${bin}")"   "${bin}" >> "${OUTDIR}/artifact_build_id.txt"
  done

  log "minting signed N=3 DevNet trust-bundle material (R1-signed baseline)"
  "${TRUST_HELPER}" "${OUTDIR}/material" 3 signed-devnet 1 \
    > "${OUTDIR}/material/helper.stdout.log" \
    2> "${OUTDIR}/material/helper.stderr.log"

  log "minting DevNet consensus signer keystores (Run 033 active=true, no DummySig)"
  mkdir -p "${OUTDIR}/signers"
  "${SIGNER_HELPER}" "${OUTDIR}/signers" 3 \
    > "${OUTDIR}/signers/helper.stdout.log" \
    2> "${OUTDIR}/signers/helper.stderr.log"

  log "overlaying Run 110 genesis-authority + ratification fixtures (R1 ratified, U1 unratified)"
  "${RAT_HELPER}" "${OUTDIR}/material" "${OUTDIR}/fixtures" \
    > "${OUTDIR}/fixtures/helper.stdout.log" \
    2> "${OUTDIR}/fixtures/helper.stderr.log"

  # V1 (and V2 in symmetric scenarios) must also accept the U1
  # (unratified) signing key so the U1-signed alternate bundle's
  # signature check passes locally and the candidate actually reaches
  # the Run 109 ratification gate; otherwise the rejection would happen
  # at the inner Run 050 / 076 signature layer and would NOT exercise
  # the Run 109 surface this run is supposed to evidence.
  EXTRA_SIGNING_KEYS=(
    "$(cat "${OUTDIR}/fixtures/signing-key.unratified.spec")"
  )

  log "running baseline_ratification scenario"
  run_baseline_ratification
  log "running valid_ratified scenario"
  run_valid_ratified
  log "running missing_ratification scenario"
  run_missing_ratification
  log "running bad_ratification_startup_refuse scenario"
  run_bad_ratification_startup_refuse
  log "running duplicate_unratified_no_promotion scenario"
  run_duplicate_unratified_no_promotion
  log "running devnet_no_opt_in_legacy scenario"
  EXTRA_SIGNING_KEYS=()
  run_devnet_no_opt_in_legacy

  log "capturing summary and archiving artifacts"
  summarize
  archive_artifacts
  log "PASS: Run 110 live ratification evidence captured under ${OUTDIR} and ${ARCHIVE_DIR}"
}

main "$@"
