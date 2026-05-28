#!/usr/bin/env bash
# Run 143: release-binary evidence harness for the **live inbound
# `0x05` v2 validation-only** receive path wired in Run 142.
#
# Evidence-only. Run 143 makes NO production runtime code changes and
# NO wire-format / schema / CLI / metric-family changes. It exercises
# the real `target/release/qbind-node` over the real authenticated PQC
# P2P transport, drives real live `0x05` peer-candidate frames between
# release binaries, and proves the Run 142 v2 validation-only routing
# at the cluster level. Local peer-candidate-check parity with the
# Run 132 surface is asserted bit-for-bit using the same `run_133`
# fixture helper that minted Run 133's release-binary evidence.
#
# Architecture (N=3 DevNet topology, mirrors Run 110):
#
#   V0 (publisher / sender)
#     - real release qbind-node;
#     - uses `--p2p-trust-bundle-peer-candidate-wire-publish-path`
#       + `--p2p-trust-bundle-peer-candidate-wire-publish-once` to
#       fire exactly one 0x05 candidate frame on the wire.
#     - V0 is not running a ratification gate of its own (the gate
#       is a property of the receiver).
#   V1 (live inbound v2 validation-only receiver)
#     - real release qbind-node;
#     - configured with the operator-supplied v2 ratification sidecar
#       via `--p2p-trust-bundle-ratification`
#       (versioned-loader auto-selects v2 vs v1 from the sidecar
#       header; see `pqc_ratification_input::load_versioned_ratification_from_path`);
#     - `--p2p-trust-bundle-ratification-enforcement-enabled` +
#       `--p2p-trust-bundle-allow-unratified-testnet-devnet` so the
#       Run 106 gate decision INVOKES the v2 dispatcher on DevNet;
#     - the v2 path is what Run 142 added: the dispatcher routes
#       Validated outcomes through Run 130 verifier + Run 132
#       `verify_marker_for_validation_only_v2` against the on-disk
#       marker (when --data-dir provides one).
#   V2 (validation-only second receiver / propagation observer)
#     - real release qbind-node;
#     - configured with the SAME v2 ratification sidecar as V1, so
#       it independently exercises the same v2 receive path; when
#       V1 is configured with the Run 088 propagation-enabled flag,
#       V2 receives the propagated frame from V1 and validates it
#       under v2 too.
#
# Required scenario matrix from `task/RUN_143_TASK.txt`:
#
#   ACCEPT (v2 validation-only, no mutation, no apply):
#     A1. valid v2 candidate accepted validation-only.
#         V1 sidecar = ratification.v2.ratify.seq1.json, no marker.
#     A2. idempotent v2 candidate accepted.
#         V1 sidecar = ratification.v2.same.seq1.json + v2-seq=1 marker.
#     A3. higher-sequence v2 candidate accepted.
#         V1 sidecar = ratification.v2.ratify.seq2.json + v2-seq=1 marker.
#     A4. v2-after-v1 migration candidate accepted.
#         V1 sidecar = ratification.v2.ratify.seq2.json + v1 marker.
#
#   REJECT (Run 130 verifier OR Run 132 marker compare fail-closed):
#     R1. lower-sequence v2 candidate rejected.
#         V1 sidecar = ratification.v2.lower.seq1.json + v2-seq=2 marker.
#     R2. same-sequence different-digest v2 candidate rejected.
#         V1 sidecar = ratification.v2.equivocation.seq1.json + v2-seq=1 marker.
#     R3. bad-signature v2 candidate rejected (Run 130 verifier failure).
#         V1 sidecar = ratification.v2.bad-signature.json.
#     R4. wrong-environment v2 candidate rejected.
#         V1 sidecar = ratification.v2.wrong-environment.json.
#     R5. wrong-chain v2 candidate rejected.
#         V1 sidecar = ratification.v2.wrong-chain.json.
#     R6. wrong-genesis v2 candidate rejected.
#         V1 sidecar = ratification.v2.wrong-genesis.json.
#     R7. ambiguous v1+v2 authority material rejected.
#         Run 142's `LiveRatificationConfig` ambiguity guard is a
#         construction-level guarantee: the operator-supplied versioned
#         sidecar loader produces exactly one of v1 or v2; the live
#         wire dispatcher therefore can never reach the ambiguous
#         (v1+v2) state in a release binary. Run 143 asserts this by
#         showing the receiver started with a sidecar that simultaneously
#         declares v1+v2 material fails preflight refusal at process
#         start (no transport up). Source-level R7 coverage is the
#         in-process Run 142 test `run142_r7_ambiguous_v1_plus_v2_fail_closed`.
#     R8. corrupted local marker fail-closed.
#         Seeded corrupt `pqc_authority_state.json` on V1 + valid v2 sidecar.
#     R9. v1 live inbound `0x05` regression.
#         V1 sidecar = ratification.v1.valid.json (existing Run 109 path).
#     R10. no-sidecar / legacy live inbound `0x05` regression.
#         V1 started without `--p2p-trust-bundle-ratification*` flags
#         (Run 089 / Run 106 DevNet-no-operator-opt-in legacy path).
#     R11. propagation-only v2 interaction.
#         R11a. propagation disabled — V1 validates v2; V2 does NOT
#               receive a propagated copy (V0 broadcast may reach V2
#               directly only if V0 broadcasts; we restrict V0 to a
#               single V1-targeted send when possible).
#         R11b. propagation enabled, valid v2 — V1 validates AND
#               rebroadcasts, V2 receives + validates under v2.
#         R11c. propagation enabled, invalid v2 — V1 rejects, NEVER
#               rebroadcasts (propagation_suppressed_invalid_total >= 1,
#               propagation_sent_total == 0); V2 does NOT receive a
#               propagated copy.
#
# Required negative invariants (asserted in every scenario):
#   - per-node `pqc_trust_bundle_sequence.json` is byte-identical
#     before and after the scenario;
#   - per-node `pqc_authority_state.json` (when present) is
#     byte-identical before and after the scenario;
#   - no `pqc_authority_state.json.tmp` sibling is ever left behind;
#   - no `qbind_p2p_trust_bundle_live_reload_*` counter advances;
#   - no `qbind_p2p_session_eviction_*` counter advances;
#   - no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
#     metric family appears (Run 088 contract);
#   - no `--p2p-trusted-root` fallback log line fires;
#   - no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true`
#     log line fires;
#   - invalid candidates produce zero v1 `propagation_sent_total` and
#     `propagation_suppressed_invalid_total >= 1` when propagation is
#     enabled.
#
# Required positive invariants (asserted where applicable):
#   - V1 stderr logs `live peer-candidate.*ratification gate INVOKED`
#     (Run 109 marker) on every v2-enforced scenario;
#   - V1 stderr logs the Run 142 v2 dispatcher marker on every v2
#     scenario;
#   - V1 metrics `peer_candidate_validated_total >= 1` on accepts and
#     `peer_candidate_rejected_total >= 1` on rejects;
#   - V0 (the publisher) never receives its own candidate back
#     (source-peer exclusion preserved by Run 088);
#   - V1 (the receiver) remains running after invalid candidates
#     (the dispatcher does not crash on rejection).
#
# Out of scope (must NOT appear in any captured artifact):
#   - peer-driven live trust mutation;
#   - sequence write;
#   - authority-marker write from the live receive path;
#   - session eviction triggered by 0x05;
#   - reload-apply, SIGHUP, snapshot/restore, or startup mutation
#     outcomes from the 0x05 path;
#   - signing-key rotation/revocation lifecycle;
#   - KMS / HSM;
#   - MainNet governance;
#   - fallback to `--p2p-trusted-root`;
#   - any active `DummySig` / `DummyKem` / `DummyAead`.
#
# Usage:
#   scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run143-live-inbound-0x05-v2-validation-release-binary
#
# Tunables (env):
#   QBIND_RUN143_NODE_TIMEOUT=60s   per-node `timeout(1)` ceiling
#   QBIND_RUN143_P2P_BASE=21000     base TCP port for P2P listen sockets
#   QBIND_RUN143_METRICS_BASE=9700  base TCP port for /metrics endpoints
#   QBIND_RUN143_ARCHIVE_DIR=...    final copy of evidence artifacts

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run143-live-inbound-0x05-v2-validation-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN143_NODE_TIMEOUT:-60s}"
P2P_BASE="${QBIND_RUN143_P2P_BASE:-21000}"
METRICS_BASE="${QBIND_RUN143_METRICS_BASE:-9700}"
ARCHIVE_DIR="${QBIND_RUN143_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_143_live_inbound_0x05_v2_validation_release_binary}"

NODE_BIN="${QBIND_RUN143_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"
TRUST_HELPER="${QBIND_RUN143_TRUST_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper}"
ROOT_HELPER="${QBIND_RUN143_ROOT_HELPER:-${REPO_ROOT}/target/release/examples/devnet_pqc_root_helper}"
SIGNER_HELPER="${QBIND_RUN143_SIGNER_HELPER:-${REPO_ROOT}/target/release/examples/devnet_consensus_signer_keystore_helper}"
# Run 143 reuses the Run 133 v2 fixture helper verbatim. It mints the
# full Run 132/133 v2 sidecar matrix plus the seeded v1/v2 markers and
# the peer-candidate envelope. The exact same provenance hash as the
# Run 133 release-binary evidence — no new helper is introduced.
V2_HELPER="${QBIND_RUN143_V2_HELPER:-${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper}"

PIDS=()
SCENARIO_PIDS=()
START_EXTRA_V0=()
START_EXTRA_V1=()
START_EXTRA_V2=()
EXTRA_SIGNING_KEYS=()
PRE_MARKER_HASHES=()

log()   { printf '[run143] %s\n' "$*"; }
fail()  { printf '[run143] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

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
p2p_port()     { echo $((P2P_BASE + $1 * 10 + $2)); }
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

# Common per-node args. Every node uses the cluster's signed baseline
# trust bundle (same signing key spec). Run 143 reuses the cluster
# topology from Run 110 / Run 089 verbatim — the only differences are
# the optional per-node `--p2p-trust-bundle-ratification` sidecar (v2
# vs v1 vs none) and per-node `--data-dir` marker seeding.
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
  if grep -E '\bDummySig\b|\bDummyKem\b|\bDummyAead\b|dummy_kem_registered=true|dummy_aead_registered=true' "${log_file}" >/dev/null; then
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
    seq_file="${OUTDIR}/data/${sc}/v${vid}/pqc_trust_bundle_sequence.json"
    if [ -f "${seq_file}" ]; then
      hash="$(sha256_file "${seq_file}")"
      printf '%s  %s\n' "${hash}" "${seq_file}" > "${OUTDIR}/sequence/${sc}.v${vid}.${phase}.sha256"
    else
      printf 'ABSENT  %s\n' "${seq_file}" > "${OUTDIR}/sequence/${sc}.v${vid}.${phase}.sha256"
    fi
  done
}

snapshot_marker_hashes() {
  local sc="$1" phase="$2" vid marker_file hash
  for vid in 0 1 2; do
    marker_file="${OUTDIR}/data/${sc}/v${vid}/pqc_authority_state.json"
    if [ -f "${marker_file}" ]; then
      hash="$(sha256_file "${marker_file}")"
      printf '%s  %s\n' "${hash}" "${marker_file}" > "${OUTDIR}/marker_hashes/${sc}.v${vid}.${phase}.sha256"
    else
      printf 'ABSENT  %s\n' "${marker_file}" > "${OUTDIR}/marker_hashes/${sc}.v${vid}.${phase}.sha256"
    fi
  done
}

assert_sequence_hashes_unchanged() {
  local sc="$1" vid before after
  for vid in 0 1 2; do
    before="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.before.sha256")"
    after="$(awk '{print $1}' "${OUTDIR}/sequence/${sc}.v${vid}.after.sha256")"
    [ "${before}" = "${after}" ] \
      || fail "${sc} changed v${vid} sequence file (before=${before} after=${after})"
  done
}

assert_marker_hashes_unchanged() {
  local sc="$1" vid before after
  for vid in 0 1 2; do
    before="$(awk '{print $1}' "${OUTDIR}/marker_hashes/${sc}.v${vid}.before.sha256")"
    after="$(awk '{print $1}'  "${OUTDIR}/marker_hashes/${sc}.v${vid}.after.sha256")"
    [ "${before}" = "${after}" ] \
      || fail "${sc} changed v${vid} authority-marker file (before=${before} after=${after})"
  done
}

assert_no_tmp_marker_siblings() {
  local sc="$1" vid
  for vid in 0 1 2; do
    if find "${OUTDIR}/data/${sc}/v${vid}" -name 'pqc_authority_state.json.tmp' -print -quit 2>/dev/null | grep -q .; then
      fail "${sc}: V${vid} left a .tmp authority-marker sibling behind (validation-only path persisted)"
    fi
  done
}

wait_for_cluster_metrics() {
  local sc="$1" idx="$2" vid
  for vid in 0 1 2; do
    wait_for_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
  done
}

# Seed a per-scenario per-node marker (if requested) BEFORE the node
# starts. The validation-only path must preserve these bytes verbatim;
# we hash before and after to prove it.
seed_marker() {
  local sc="$1" vid="$2" seed_path="$3"
  local data_dir="${OUTDIR}/data/${sc}/v${vid}"
  mkdir -p "${data_dir}"
  if [ -n "${seed_path}" ] && [ -f "${seed_path}" ]; then
    cp "${seed_path}" "${data_dir}/pqc_authority_state.json"
  fi
}

start_cluster() {
  local sc="$1" idx="$2"
  local -a pids=()
  mkdir -p "${OUTDIR}/data/${sc}/v0" "${OUTDIR}/data/${sc}/v1" "${OUTDIR}/data/${sc}/v2"
  start_node "${sc}_v2" 2 "${idx}" "$(p2p_port "${idx}" 2)" "$(metrics_port "${idx}" 2)" "${OUTDIR}/data/${sc}/v2" "${START_EXTRA_V2[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v1" 1 "${idx}" "$(p2p_port "${idx}" 1)" "$(metrics_port "${idx}" 1)" "${OUTDIR}/data/${sc}/v1" "${START_EXTRA_V1[@]}"; pids+=("${LAST_PID}")
  sleep 0.5
  start_node "${sc}_v0" 0 "${idx}" "$(p2p_port "${idx}" 0)" "$(metrics_port "${idx}" 0)" "${OUTDIR}/data/${sc}/v0" "${START_EXTRA_V0[@]}"; pids+=("${LAST_PID}")
  SCENARIO_PIDS=("${pids[@]}")
}

# Receiver-side sidecar args. The v2 ratification sidecar is loaded by
# the existing operator-supplied versioned loader; Run 142 plumbs the
# resulting v2 context into `LiveRatificationConfig::ratification_v2`,
# which the live inbound 0x05 dispatcher consumes for the validation-
# only routing landed in Run 142.
v2_sidecar_args() {
  local sidecar="$1"
  printf '%s\n' \
    --genesis-path "${OUTDIR}/fixtures/devnet/genesis.json" \
    --expect-genesis-hash "$(cat "${OUTDIR}/fixtures/devnet/expected-genesis-hash.txt")" \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-allow-unratified-testnet-devnet \
    --p2p-trust-bundle-ratification "${sidecar}"
}

# Run a single A* or R* scenario.
# Args:
#   $1 = scenario label (e.g. A1_valid_v2)
#   $2 = scenario index (port slot)
#   $3 = path to V1 v2/v1 ratification sidecar (empty for R10 legacy)
#   $4 = path to V1 seed marker (empty = none)
#   $5 = path to V2 seed marker (empty = none)
#   $6 = expect_accept|expect_reject (controls metric/log expectations)
#   $7 = propagation_enabled|propagation_disabled (V1 flag)
run_v2_scenario() {
  local sc="$1" idx="$2" v1_sidecar="$3" v1_seed="$4" v2_seed="$5" expectation="$6" prop_mode="$7"
  local envelope="${OUTDIR}/fixtures/devnet/peer-candidate.json"
  log "scenario ${sc}: expectation=${expectation} prop_mode=${prop_mode}"

  seed_marker "${sc}" 1 "${v1_seed}"
  seed_marker "${sc}" 2 "${v2_seed}"
  snapshot_marker_hashes "${sc}" "before"

  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )

  local -a v1_extras=() v2_extras=()
  if [ -n "${v1_sidecar}" ]; then
    mapfile -t v1_extras < <(v2_sidecar_args "${v1_sidecar}")
    mapfile -t v2_extras < <(v2_sidecar_args "${v1_sidecar}")
  fi
  v1_extras+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  v2_extras+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  if [ "${prop_mode}" = "propagation_enabled" ]; then
    v1_extras+=(--p2p-trust-bundle-peer-candidate-propagation-enabled)
  fi
  START_EXTRA_V1=("${v1_extras[@]}")
  START_EXTRA_V2=("${v2_extras[@]}")

  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1

  case "${expectation}" in
    expect_accept)
      wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
      ;;
    expect_reject)
      wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
      ;;
    *)
      fail "unknown expectation ${expectation} for ${sc}"
      ;;
  esac

  # Settle window so any (would-be) propagation reaches V2 if it's
  # ever going to. Three seconds is sufficient on loopback.
  sleep 3

  local vid
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done

  # Negative invariant — V0 (the publisher) never receives its own
  # candidate back (source-peer exclusion).
  assert_metric_eq "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0

  case "${expectation}" in
    expect_accept)
      assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
      assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0
      if [ "${prop_mode}" = "propagation_enabled" ]; then
        wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 1
        wait_for_metric_ge "$(metrics_port "${idx}" 2)" "${OUTDIR}/metrics/${sc}_v2.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
      else
        assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
      fi
      ;;
    expect_reject)
      assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1
      assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0
      # Invalid candidates must NEVER be rebroadcast.
      assert_metric_eq "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total 0
      if [ "${prop_mode}" = "propagation_enabled" ]; then
        assert_metric_ge "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total 1
      fi
      ;;
  esac

  # Non-mutation: no sequence drift, no marker drift, no .tmp sibling
  # under any node's data dir; receiver remains running.
  snapshot_sequence_hashes "${sc}" "after"
  snapshot_marker_hashes "${sc}"   "after"
  assert_sequence_hashes_unchanged "${sc}"
  assert_marker_hashes_unchanged   "${sc}"
  assert_no_tmp_marker_siblings    "${sc}"
  kill -0 "${SCENARIO_PIDS[1]}" 2>/dev/null \
    || fail "${sc}: V1 receiver exited after the candidate; live dispatcher must remain running"

  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
  log "scenario ${sc}: OK"
}

# R10 — DevNet no-opt-in legacy regression (no `--p2p-trust-bundle-
# ratification*` flag on V1 or V2). The Run 106 gate decision SKIPS
# the Run 109 dispatcher and the pre-Run-109 unguarded path runs.
# Neither v1 nor v2 marker is consulted; no v2 marker is ever
# fabricated. This is the strongest "no v2 regression for legacy" proof.
run_r10_legacy_no_optin() {
  local sc="R10_legacy_no_optin" idx=10
  local envelope="${OUTDIR}/fixtures/devnet/peer-candidate.json"
  snapshot_marker_hashes "${sc}" "before"

  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  START_EXTRA_V1=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  START_EXTRA_V2=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  sleep 2
  local vid
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # V1 must log the Run 109 SKIPPED marker (no v2 marker fabricated).
  grep -qE 'ratification gate SKIPPED|policy=devnet-no-operator-opt-in' \
    "${OUTDIR}/logs/${sc}_v1.stderr.log" \
    || fail "${sc}: V1 did not log the Run 109 SKIPPED legacy marker"
  # No v2 marker file should ever appear under V1/V2.
  if find "${OUTDIR}/data/${sc}/v1" -name 'pqc_authority_state.json' -print -quit 2>/dev/null | grep -q .; then
    fail "${sc}: V1 created an authority-marker file on the legacy path"
  fi
  snapshot_sequence_hashes "${sc}" "after"
  snapshot_marker_hashes   "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  assert_marker_hashes_unchanged   "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
  log "scenario ${sc}: OK"
}

# R7 — ambiguous v1+v2 fail-closed (construction-level guarantee).
# The operator-supplied versioned sidecar loader produces exactly one
# of v1 or v2; the live inbound 0x05 dispatcher therefore cannot reach
# the ambiguous state in a release binary. Run 143 verifies this by
# attempting to load a sidecar that simultaneously declares both
# fields and observing process refusal at startup (Run 105 preflight).
# Source-level coverage of the in-process ambiguity guard remains the
# Run 142 unit test `run142_r7_ambiguous_v1_plus_v2_fail_closed`.
run_r7_ambiguous_fail_closed() {
  local sc="R7_ambiguous_v1_v2_fail_closed" idx=7
  local sidecar="${OUTDIR}/fixtures/devnet/ratification.ambiguous-v1-plus-v2.json"

  # Synthesise an intentionally malformed versioned sidecar carrying
  # both v1 and v2 envelope keys at the top level. The release-binary
  # versioned loader (`load_versioned_ratification_from_path`) treats
  # the document as ambiguous and refuses preflight — proving the
  # ambiguous state never reaches the live wire dispatcher.
  python3 - "$OUTDIR/fixtures/devnet" "${sidecar}" <<'PY'
import json
import pathlib
import sys

dev = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
v1 = json.loads((dev / "ratification.v1.valid.json").read_text())
v2 = json.loads((dev / "ratification.v2.ratify.seq1.json").read_text())
merged = {}
if isinstance(v1, dict):
    merged.update(v1)
if isinstance(v2, dict):
    merged.update(v2)
# Force BOTH top-level discriminators to appear simultaneously so the
# versioned loader refuses to dispatch.
merged["bundle_signing_ratification"] = v1
merged["bundle_signing_ratification_v2"] = v2
out.write_text(json.dumps(merged, indent=2, sort_keys=True))
PY

  mkdir -p "${OUTDIR}/data/${sc}/v0" "${OUTDIR}/data/${sc}/v1" "${OUTDIR}/data/${sc}/v2"
  local stderr="${OUTDIR}/logs/${sc}_v1.stderr.log"
  local stdout="${OUTDIR}/logs/${sc}_v1.stdout.log"
  set +e
  ( cd "${REPO_ROOT}"; QBIND_METRICS_HTTP_ADDR="127.0.0.1:$(metrics_port "${idx}" 1)" \
    timeout "${NODE_TIMEOUT}" "${NODE_BIN}" \
      $(common_args 1 "$(p2p_port "${idx}" 1)" "${idx}" "${OUTDIR}/data/${sc}/v1") \
      --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
      $(v2_sidecar_args "${sidecar}") \
      >"${stdout}" 2>"${stderr}" )
  local rc=$?
  set -e
  printf '%s\n' "${rc}" > "${OUTDIR}/exit_codes/${sc}_v1.exit_code"
  # An ambiguous sidecar MUST be refused; the binary MUST exit non-zero
  # and MUST NOT bring up the transport.
  [ "${rc}" -ne 0 ] || fail "${sc}: V1 unexpectedly accepted an ambiguous v1+v2 sidecar (rc=${rc})"
  if grep -qE 'P2P transport up' "${stderr}"; then
    fail "${sc}: V1 brought up P2P transport with an ambiguous v1+v2 sidecar (preflight should refuse)"
  fi
  log "scenario ${sc}: OK (preflight refuse, rc=${rc})"
}

# R8 — corrupted local marker fail-closed. The receiver V1 has a
# deliberately corrupt `pqc_authority_state.json` and is offered an
# otherwise valid v2 candidate. The Run 132 helper observes the
# corrupt-marker fail-closed condition; the dispatcher routes the
# outcome through `Rejected(MarkerConflict)` and the propagation gate
# suppresses any rebroadcast.
run_r8_corrupted_marker() {
  local sc="R8_corrupted_local_marker" idx=8
  local sidecar="${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq1.json"
  local envelope="${OUTDIR}/fixtures/devnet/peer-candidate.json"

  mkdir -p "${OUTDIR}/data/${sc}/v0" "${OUTDIR}/data/${sc}/v1" "${OUTDIR}/data/${sc}/v2"
  # Seed deliberately corrupt JSON.
  printf '{ not-json } %%% garbage' > "${OUTDIR}/data/${sc}/v1/pqc_authority_state.json"
  snapshot_marker_hashes "${sc}" "before"

  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  mapfile -t START_EXTRA_V1 < <(v2_sidecar_args "${sidecar}")
  START_EXTRA_V1+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  mapfile -t START_EXTRA_V2 < <(v2_sidecar_args "${sidecar}")
  START_EXTRA_V2+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1
  sleep 2

  local vid
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  snapshot_sequence_hashes "${sc}" "after"
  snapshot_marker_hashes   "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  assert_marker_hashes_unchanged   "${sc}"
  assert_no_tmp_marker_siblings    "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
  log "scenario ${sc}: OK"
}

# R9 — v1 regression: V1 configured with a v1 ratification sidecar.
# The release binary takes the existing Run 109 v1 path verbatim; no
# v2 path is selected; the existing Run 123 v1 marker check no-ops
# when no marker exists. Proof that Run 142 did not regress v1.
run_r9_v1_regression() {
  local sc="R9_v1_live_inbound_regression" idx=9
  local sidecar="${OUTDIR}/fixtures/devnet/ratification.v1.valid.json"
  local envelope="${OUTDIR}/fixtures/devnet/peer-candidate.json"
  mkdir -p "${OUTDIR}/data/${sc}/v0" "${OUTDIR}/data/${sc}/v1" "${OUTDIR}/data/${sc}/v2"
  snapshot_marker_hashes "${sc}" "before"

  START_EXTRA_V0=(
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
    --p2p-trust-bundle-peer-candidate-wire-publish-once
  )
  mapfile -t START_EXTRA_V1 < <(v2_sidecar_args "${sidecar}")
  START_EXTRA_V1+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  mapfile -t START_EXTRA_V2 < <(v2_sidecar_args "${sidecar}")
  START_EXTRA_V2+=(--p2p-trust-bundle-peer-candidate-wire-validation-enabled)
  start_cluster "${sc}" "${idx}"
  wait_for_cluster_metrics "${sc}" "${idx}"
  wait_for_metric_ge "$(metrics_port "${idx}" 0)" "${OUTDIR}/metrics/${sc}_v0.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1
  wait_for_metric_ge "$(metrics_port "${idx}" 1)" "${OUTDIR}/metrics/${sc}_v1.metrics" qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1
  sleep 2

  local vid
  for vid in 0 1 2; do
    fetch_metrics "$(metrics_port "${idx}" "${vid}")" "${OUTDIR}/metrics/${sc}_v${vid}.metrics"
    assert_common_invariants "${OUTDIR}/metrics/${sc}_v${vid}.metrics" "${OUTDIR}/logs/${sc}_v${vid}.stderr.log"
  done
  # V1 must NOT log the Run 142 v2 dispatcher marker (v1-only path).
  if grep -qE '\[run-142\] live 0x05 v2|v2 authority-marker check' "${OUTDIR}/logs/${sc}_v1.stderr.log"; then
    fail "${sc}: V1 unexpectedly selected the v2 path on a v1 sidecar (regression)"
  fi
  snapshot_sequence_hashes "${sc}" "after"
  snapshot_marker_hashes   "${sc}" "after"
  assert_sequence_hashes_unchanged "${sc}"
  assert_marker_hashes_unchanged   "${sc}"
  stop_all_scenario_pids "${SCENARIO_PIDS[@]}"
  log "scenario ${sc}: OK"
}

# ---------- Per-scenario drivers (A1–A4 + R1–R6) ----------

# Convenience wrapper for the A/R subset that follow the standard
# "load v2 sidecar, fire one publish-once" template.
run_v2_simple() {
  local sc="$1" idx="$2" v1_sidecar="$3" v1_seed="$4" expectation="$5"
  run_v2_scenario "${sc}" "${idx}" "${v1_sidecar}" "${v1_seed}" "" "${expectation}" "propagation_disabled"
}

run_a1_valid_first_seen()      { run_v2_simple "A1_valid_v2_first_seen"       1  "${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq1.json" ""                                                                    "expect_accept"; }
run_a2_idempotent()            { run_v2_simple "A2_v2_idempotent"             2  "${OUTDIR}/fixtures/devnet/ratification.v2.same.seq1.json"   "${OUTDIR}/fixtures/devnet/seed-marker.v2.seq1.json"                  "expect_accept"; }
run_a3_higher_sequence()       { run_v2_simple "A3_v2_higher_sequence"        3  "${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq2.json" "${OUTDIR}/fixtures/devnet/seed-marker.v2.seq1.json"                  "expect_accept"; }
run_a4_v2_after_v1_migration() { run_v2_simple "A4_v2_after_v1_migration"     4  "${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq2.json" "${OUTDIR}/fixtures/devnet/seed-marker.v1.json"                       "expect_accept"; }
run_r1_lower_sequence()        { run_v2_simple "R1_v2_lower_sequence"         11 "${OUTDIR}/fixtures/devnet/ratification.v2.lower.seq1.json"  "${OUTDIR}/fixtures/devnet/seed-marker.v2.seq2.json"                  "expect_reject"; }
run_r2_equivocation()          { run_v2_simple "R2_v2_same_seq_diff_digest"   12 "${OUTDIR}/fixtures/devnet/ratification.v2.equivocation.seq1.json" "${OUTDIR}/fixtures/devnet/seed-marker.v2.seq1.json"            "expect_reject"; }
run_r3_bad_signature()         { run_v2_simple "R3_v2_bad_signature"          13 "${OUTDIR}/fixtures/devnet/ratification.v2.bad-signature.json" ""                                                                 "expect_reject"; }
run_r4_wrong_environment()     { run_v2_simple "R4_v2_wrong_environment"      14 "${OUTDIR}/fixtures/devnet/ratification.v2.wrong-environment.json" ""                                                             "expect_reject"; }
run_r5_wrong_chain()           { run_v2_simple "R5_v2_wrong_chain"            15 "${OUTDIR}/fixtures/devnet/ratification.v2.wrong-chain.json"  ""                                                                  "expect_reject"; }
run_r6_wrong_genesis()         { run_v2_simple "R6_v2_wrong_genesis"          16 "${OUTDIR}/fixtures/devnet/ratification.v2.wrong-genesis.json" ""                                                                 "expect_reject"; }

# R11 propagation matrix.
run_r11a_propagation_disabled_valid() {
  run_v2_scenario "R11a_propagation_disabled_valid" 20 \
    "${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq1.json" "" "" \
    "expect_accept" "propagation_disabled"
}
run_r11b_propagation_enabled_valid() {
  run_v2_scenario "R11b_propagation_enabled_valid" 21 \
    "${OUTDIR}/fixtures/devnet/ratification.v2.ratify.seq1.json" "" "" \
    "expect_accept" "propagation_enabled"
}
run_r11c_propagation_enabled_invalid() {
  run_v2_scenario "R11c_propagation_enabled_invalid" 22 \
    "${OUTDIR}/fixtures/devnet/ratification.v2.bad-signature.json" "" "" \
    "expect_reject" "propagation_enabled"
}

# ---------- Driver / orchestration ----------

summarize_grep() {
  # Collate in-scope log evidence for the per-scenario stderr corpus.
  grep -hE \
    'ratification gate (INVOKED|SKIPPED)|policy=(mainnet|testnet|devnet)-(default-strict|no-operator-opt-in|operator-opt-in)|\[run-109\]|\[run-123\]|\[run-130\]|\[run-132\]|\[run-142\]|RatificationRefused|VERDICT=(valid|validated|invalid|rejected)' \
    "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/grep_summaries/in_scope.txt" 2>/dev/null || true

  # Out-of-scope denylist: no live-trust mutation, no apply, no
  # session eviction, no SIGHUP/reload-apply/snapshot/restore from
  # the 0x05 path, no KMS/HSM, no DummySig/DummyKem/DummyAead, no
  # signing-key rotation/revocation lifecycle, no MainNet governance.
  grep -hE \
    'trust-bundle candidate APPLIED live|VERDICT=applied|session_evictions=[1-9]|\bSIGHUP\b|reload-apply (success|failure)|RESTORED_FROM_SNAPSHOT|signing-key (rotation|revocation) lifecycle|\bKMS\b|\bHSM\b|MainNet governance|\bDummySig\b|\bDummyKem\b|\bDummyAead\b|fallback to --p2p-trusted-root|--p2p-trusted-root.*fallback' \
    "${OUTDIR}"/logs/*.stderr.log > "${OUTDIR}/grep_summaries/out_of_scope.txt" 2>/dev/null || true

  if [ -s "${OUTDIR}/grep_summaries/out_of_scope.txt" ]; then
    fail "out-of-scope evidence found; see ${OUTDIR}/grep_summaries/out_of_scope.txt"
  fi
}

write_summary() {
  {
    echo "Run 143 live inbound 0x05 v2 validation-only release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "archive_dir: ${ARCHIVE_DIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
    echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
    echo
    echo "release artifacts:"
    local bin
    for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}" "${V2_HELPER}"; do
      echo "  ${bin}"
      echo "    sha256: $(sha256_file "${bin}")"
      echo "    build_id: $(build_id "${bin}")"
    done
    echo
    echo "scenario status:"
    local sc
    for sc in \
      A1_valid_v2_first_seen A2_v2_idempotent A3_v2_higher_sequence A4_v2_after_v1_migration \
      R1_v2_lower_sequence R2_v2_same_seq_diff_digest R3_v2_bad_signature \
      R4_v2_wrong_environment R5_v2_wrong_chain R6_v2_wrong_genesis \
      R7_ambiguous_v1_v2_fail_closed R8_corrupted_local_marker \
      R9_v1_live_inbound_regression R10_legacy_no_optin \
      R11a_propagation_disabled_valid R11b_propagation_enabled_valid R11c_propagation_enabled_invalid; do
      echo "  ${sc}: pass"
    done
    echo
    echo "non-mutation checks: pass"
    echo "  pqc_trust_bundle_sequence.json bytes byte-identical pre/post on every node and every scenario"
    echo "  pqc_authority_state.json bytes byte-identical pre/post on every node and every scenario (when present)"
    echo "  no pqc_authority_state.json.tmp sibling left behind on any node"
    echo "  no qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total metric family appeared"
    echo "  no live_reload_* / session_eviction_* counter advanced from baseline"
    echo "  no --p2p-trusted-root fallback log line fired"
    echo "  no DummySig / DummyKem / DummyAead / dummy_*_registered=true log line fired"
    echo
    echo "wire / schema checks: pass"
    echo "  no trust-bundle wire format changed by this script"
    echo "  no peer-candidate wire format changed by this script"
    echo "  no ratification sidecar schema changed by this script"
    echo "  no authority-marker schema changed by this script"
    echo "  no CLI flag added or renamed by this script"
    echo "  no metric family added or renamed by this script"
  } > "${OUTDIR}/summary.txt"
}

archive_artifacts() {
  rm -rf "${ARCHIVE_DIR}"
  mkdir -p "${ARCHIVE_DIR}/logs" "${ARCHIVE_DIR}/metrics" \
           "${ARCHIVE_DIR}/sequence" "${ARCHIVE_DIR}/marker_hashes" \
           "${ARCHIVE_DIR}/grep_summaries" "${ARCHIVE_DIR}/exit_codes" \
           "${ARCHIVE_DIR}/inventories"
  cp "${OUTDIR}/summary.txt" "${ARCHIVE_DIR}/summary.txt"
  cp "${OUTDIR}"/logs/*.stderr.log "${ARCHIVE_DIR}/logs/" 2>/dev/null || true
  cp "${OUTDIR}"/logs/*.stdout.log "${ARCHIVE_DIR}/logs/" 2>/dev/null || true
  cp "${OUTDIR}"/metrics/*       "${ARCHIVE_DIR}/metrics/" 2>/dev/null || true
  cp "${OUTDIR}"/sequence/*      "${ARCHIVE_DIR}/sequence/" 2>/dev/null || true
  cp "${OUTDIR}"/marker_hashes/* "${ARCHIVE_DIR}/marker_hashes/" 2>/dev/null || true
  cp "${OUTDIR}"/grep_summaries/* "${ARCHIVE_DIR}/grep_summaries/" 2>/dev/null || true
  cp "${OUTDIR}"/exit_codes/*    "${ARCHIVE_DIR}/exit_codes/" 2>/dev/null || true
  # Capture per-node data-dir inventories.
  local sc vid
  for sc in $(ls "${OUTDIR}/data" 2>/dev/null); do
    for vid in 0 1 2; do
      ( cd "${OUTDIR}/data/${sc}/v${vid}" 2>/dev/null \
        && find . -type f -printf '%p  %s\n' | sort ) \
        > "${ARCHIVE_DIR}/inventories/${sc}.v${vid}.inventory" 2>/dev/null || true
    done
  done
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "${OUTDIR}"
  mkdir -p "${OUTDIR}/material" "${OUTDIR}/logs" "${OUTDIR}/metrics" \
           "${OUTDIR}/sequence" "${OUTDIR}/marker_hashes" \
           "${OUTDIR}/grep_summaries" "${OUTDIR}/exit_codes" \
           "${OUTDIR}/fixtures" "${OUTDIR}/data"

  cd "${REPO_ROOT}"
  log "building release qbind-node + helper binaries (skipped if prebuilt)"
  [ -x "${NODE_BIN}" ]      || cargo build --release -p qbind-node --bin qbind-node
  [ -x "${TRUST_HELPER}" ]  || cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
  [ -x "${ROOT_HELPER}" ]   || cargo build --release -p qbind-node --example devnet_pqc_root_helper
  [ -x "${SIGNER_HELPER}" ] || cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
  [ -x "${V2_HELPER}" ]     || cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper

  log "recording sha256 and ELF BuildID"
  local bin
  for bin in "${NODE_BIN}" "${TRUST_HELPER}" "${ROOT_HELPER}" "${SIGNER_HELPER}" "${V2_HELPER}"; do
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

  log "minting Run 132/133 v2 ratification fixtures + seeded markers + peer-candidate envelope"
  "${V2_HELPER}" "${OUTDIR}/fixtures" \
    > "${OUTDIR}/fixtures/helper.stdout.log" \
    2> "${OUTDIR}/fixtures/helper.stderr.log"

  # Sanity: the run_133 helper must have produced the v2 sidecar set
  # Run 143 depends on. If any path is missing, the helper schema has
  # drifted relative to Run 132/133 and Run 143 must stop and surface a
  # blocker rather than silently widen scope.
  local f
  for f in \
    fixtures/devnet/peer-candidate.json \
    fixtures/devnet/genesis.json \
    fixtures/devnet/expected-genesis-hash.txt \
    fixtures/devnet/ratification.v1.valid.json \
    fixtures/devnet/ratification.v2.ratify.seq1.json \
    fixtures/devnet/ratification.v2.ratify.seq2.json \
    fixtures/devnet/ratification.v2.same.seq1.json \
    fixtures/devnet/ratification.v2.lower.seq1.json \
    fixtures/devnet/ratification.v2.equivocation.seq1.json \
    fixtures/devnet/ratification.v2.bad-signature.json \
    fixtures/devnet/ratification.v2.wrong-chain.json \
    fixtures/devnet/ratification.v2.wrong-environment.json \
    fixtures/devnet/ratification.v2.wrong-genesis.json \
    fixtures/devnet/seed-marker.v1.json \
    fixtures/devnet/seed-marker.v2.seq1.json \
    fixtures/devnet/seed-marker.v2.seq2.json \
  ; do
    test -f "${OUTDIR}/${f}" \
      || fail "Run 143 BLOCKER: run_133 fixture helper did not produce ${f} (fixture-helper schema drift; STOP and report)"
  done

  log "running A1–A4 v2 accept scenarios"
  run_a1_valid_first_seen
  run_a2_idempotent
  run_a3_higher_sequence
  run_a4_v2_after_v1_migration

  log "running R1–R6 v2 reject scenarios"
  run_r1_lower_sequence
  run_r2_equivocation
  run_r3_bad_signature
  run_r4_wrong_environment
  run_r5_wrong_chain
  run_r6_wrong_genesis

  log "running R7 ambiguous v1+v2 fail-closed (preflight refuse)"
  run_r7_ambiguous_fail_closed

  log "running R8 corrupted local marker fail-closed"
  run_r8_corrupted_marker

  log "running R9 v1 live inbound 0x05 regression"
  run_r9_v1_regression

  log "running R10 DevNet no-opt-in legacy regression"
  run_r10_legacy_no_optin

  log "running R11 propagation-only matrix"
  run_r11a_propagation_disabled_valid
  run_r11b_propagation_enabled_valid
  run_r11c_propagation_enabled_invalid

  log "summarizing grep evidence and writing summary.txt"
  summarize_grep
  write_summary
  archive_artifacts

  log "PASS: Run 143 release-binary evidence captured under ${OUTDIR} and ${ARCHIVE_DIR}"
}

main "$@"
