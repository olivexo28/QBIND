#!/usr/bin/env bash
# Run 133 — release-binary evidence matrix for the v2 (ratification-v2)
# validation-only authority-marker check on the reload-check and
# peer-candidate-check binary surfaces (Run 132 wiring; no production
# mutating surface is touched).
#
# Evidence-only. This harness does NOT change production runtime code and
# does NOT touch any wire format. It exercises BOTH the v1 sidecar
# fall-through path (regression: Run 123) and the v2 sidecar dispatch
# (Run 132) against ephemeral DevNet fixtures minted by
# `run_133_v2_validation_only_fixture_helper`.
#
# Scenario matrix (DevNet, reload-check unless otherwise noted):
#   v1 regression:
#     1.  v1 valid sidecar, no marker → Run 123 first-seen pass, VERDICT=valid
#   v2 acceptance:
#     2.  v2 ratify@seq=1, no marker → no-persisted-marker-yet
#     3.  v2 ratify@seq=1, v2-seq=1 marker (same digest) → v2 idempotent
#     4.  v2 ratify@seq=2, v2-seq=1 marker → v2 higher-sequence upgrade
#     5.  v2 rotate@seq=2, v2-seq=1 marker → v2 higher-sequence upgrade (rotate)
#     6.  v2 revoke@seq=2, v2-seq=1 marker → v2 higher-sequence upgrade (revoke)
#     7.  v2 ratify@seq=2, v1 marker → v2-after-v1 migration candidate
#   v2 rejection:
#     8.  v2 same-sequence different-digest → equivocation refused
#     9.  v2 lower sequence (seq=1 vs marker seq=2) → lower-sequence refused
#     10. v2 ratify@seq=0 → malformed seq=0 refused
#     11. v2 tampered signature → V2 verifier failure
#     12. v2 wrong chain → V2 verifier failure
#     13. v2 wrong environment → V2 verifier failure
#     14. v2 wrong genesis → V2 verifier failure
#   peer-candidate-check spot-check:
#     15. v2 ratify@seq=1, no marker → Run 132 v2 peer-candidate-check pass
#     16. v2 bad-signature → Run 132 v2 peer-candidate-check rejection
#
# No SIGHUP, no peer-driven live apply, no signing-key rotation against
# live runtime trust state, no anti-rollback persistence write, no KMS/HSM,
# no governance, no trust-bundle wire format change, no peer-candidate
# wire format change. Every scenario data-dir is asserted to contain NO
# `pqc_authority_state.json.tmp` post-write artifact and NO sequence file.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run133-v2-validation-only-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run133] %s\n' "$*"; }
fail() { printf '[run133] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

assert_grep() {
  local file="$1" pattern="$2"
  grep -qE -- "$pattern" "$file" || fail "${file} missing pattern: ${pattern}"
}

assert_not_grep() {
  local file="$1" pattern="$2"
  if grep -qE -- "$pattern" "$file"; then
    fail "${file} unexpectedly matched pattern: ${pattern}"
  fi
}

# A validation-only run MUST NOT:
#   * leave a sequence persistence file under the scenario data dir,
#   * advance the on-disk authority marker (we compare the original
#     bytes of the seeded marker, if any, to the post-run bytes),
#   * leave behind a .tmp marker sibling,
#   * emit any apply / propagate / session-eviction / KMS / SIGHUP marker
#     in stderr.
assert_no_mutation() {
  local data_dir="$1" stderr="$2" pre_marker="$3"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a validation-only path)"
  fi
  if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
    local post="${data_dir}/pqc_authority_state.json"
    if [ -f "$post" ]; then
      cmp -s "$pre_marker" "$post" || fail "authority marker bytes changed under ${data_dir} (validation-only path persisted)"
    fi
  else
    # No pre-seeded marker: validation-only paths must NOT create one.
    if [ -f "${data_dir}/pqc_authority_state.json" ]; then
      fail "authority marker was created under ${data_dir} (validation-only path persisted)"
    fi
  fi
  assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_not_grep "$stderr" 'VERDICT=applied'
  assert_not_grep "$stderr" 'session_evictions=[1-9]'
  assert_not_grep "$stderr" 'SIGHUP'
  assert_not_grep "$stderr" 'KMS|HSM'
}

run_case() {
  local name="$1" expected_rc="$2" pre_marker="$3"
  shift 3
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local rcfile="${OUTDIR}/logs/${name}.exit_code"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"
  if [ -n "$pre_marker" ]; then
    cp "$pre_marker" "${data_dir}/pqc_authority_state.json"
  fi

  set +e
  "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"
  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc}; stderr=${stderr}"
  assert_no_mutation "$data_dir" "$stderr" "$pre_marker"
  printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and Run 133 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 133 v2 validation-only release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo
    echo "scenario status:"
  } > "$SUMMARY"

  log "generating ephemeral fixtures"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    >"$OUTDIR/logs/fixture_helper.stdout.log" \
    2>"$OUTDIR/logs/fixture_helper.stderr.log"

  local DEV="$OUTDIR/fixtures/devnet"
  local dev_hash dev_key
  dev_hash="$(cat "$DEV/expected-genesis-hash.txt")"
  dev_key="$(cat "$DEV/signing-key.ratified.spec")"

  # Common flag block for reload-check: DevNet, enforcement-enabled with the
  # allow-unratified escape so a pure-v2 sidecar (which carries no v1 fields)
  # passes the v1 enforcer and reaches the Run 132 dispatch.
  devnet_reload_common=(
    --env devnet
    --genesis-path "$DEV/genesis.json"
    --expect-genesis-hash "$dev_hash"
    --p2p-trust-bundle "$DEV/baseline-bundle.json"
    --p2p-trust-bundle-signing-key "$dev_key"
    --p2p-trust-bundle-reload-check "$DEV/candidate-bundle.json"
    --p2p-trust-bundle-ratification-enforcement-enabled
    --p2p-trust-bundle-allow-unratified-testnet-devnet
  )

  devnet_peer_common=(
    --env devnet
    --genesis-path "$DEV/genesis.json"
    --expect-genesis-hash "$dev_hash"
    --p2p-trust-bundle-signing-key "$dev_key"
    --p2p-trust-bundle-peer-candidate-validation-enabled
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.json"
    --p2p-trust-bundle-ratification-enforcement-enabled
    --p2p-trust-bundle-allow-unratified-testnet-devnet
  )

  ##########################################################################
  # Scenario 1 — v1 regression: v1 valid sidecar, no marker → first-seen pass
  ##########################################################################
  log "Scenario 1: v1 valid sidecar, no marker (Run 123 first-seen pass)"
  run_case scenario_01_v1_first_seen 0 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v1.valid.json"
  assert_grep "$OUTDIR/logs/scenario_01_v1_first_seen.stderr.log" '\[run-123\] reload-check authority-marker check passed'
  assert_grep "$OUTDIR/logs/scenario_01_v1_first_seen.stderr.log" 'VERDICT=valid'

  ##########################################################################
  # v2 acceptance scenarios
  ##########################################################################
  log "Scenario 2: v2 ratify@seq=1, no marker (no-persisted-marker-yet)"
  run_case scenario_02_v2_first_seen 0 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_02_v2_first_seen.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: no-persisted-marker-yet'
  assert_grep "$OUTDIR/logs/scenario_02_v2_first_seen.stderr.log" 'VERDICT=valid'

  log "Scenario 3: v2 same-sequence same-digest, v2-seq=1 marker (idempotent)"
  run_case scenario_03_v2_idempotent 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.same.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_03_v2_idempotent.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: v2 idempotent'
  assert_grep "$OUTDIR/logs/scenario_03_v2_idempotent.stderr.log" 'VERDICT=valid'

  log "Scenario 4: v2 ratify@seq=2 over v2-seq=1 marker (upgrade-compatible)"
  run_case scenario_04_v2_upgrade_ratify 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_04_v2_upgrade_ratify.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2'
  assert_grep "$OUTDIR/logs/scenario_04_v2_upgrade_ratify.stderr.log" 'VERDICT=valid'

  log "Scenario 5: v2 rotate@seq=2 over v2-seq=1 marker (rotate upgrade)"
  run_case scenario_05_v2_upgrade_rotate 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.rotate.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_05_v2_upgrade_rotate.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2'
  assert_grep "$OUTDIR/logs/scenario_05_v2_upgrade_rotate.stderr.log" 'VERDICT=valid'

  log "Scenario 6: v2 revoke@seq=2 over v2-seq=1 marker (revoke upgrade)"
  run_case scenario_06_v2_upgrade_revoke 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.revoke.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_06_v2_upgrade_revoke.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2'
  assert_grep "$OUTDIR/logs/scenario_06_v2_upgrade_revoke.stderr.log" 'VERDICT=valid'

  log "Scenario 7: v2 ratify@seq=2 over v1 marker (v2-after-v1 migration candidate)"
  run_case scenario_07_v2_after_v1_migration 0 "$DEV/seed-marker.v1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_07_v2_after_v1_migration.stderr.log" '\[run-132\] reload-check v2 authority-marker check passed: v2-after-v1 migration candidate'
  assert_grep "$OUTDIR/logs/scenario_07_v2_after_v1_migration.stderr.log" 'VERDICT=valid'

  ##########################################################################
  # v2 rejection scenarios
  ##########################################################################
  log "Scenario 8: v2 same-sequence different-digest (equivocation refused)"
  run_case scenario_08_v2_equivocation 1 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.equivocation.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_08_v2_equivocation.stderr.log" 'Run 132: v2 same-sequence different-digest refused'
  assert_grep "$OUTDIR/logs/scenario_08_v2_equivocation.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 9: v2 lower sequence (seq=1 vs marker seq=2)"
  run_case scenario_09_v2_lower_sequence 1 "$DEV/seed-marker.v2.seq2.json" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.lower.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_09_v2_lower_sequence.stderr.log" 'Run 132: v2 lower sequence refused'
  assert_grep "$OUTDIR/logs/scenario_09_v2_lower_sequence.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 10: v2 ratify@seq=0 (malformed; verifier refusal)"
  run_case scenario_10_v2_sequence_zero 1 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.sequence-zero.json"
  assert_grep "$OUTDIR/logs/scenario_10_v2_sequence_zero.stderr.log" 'authority_domain_sequence=0 is invalid'
  assert_grep "$OUTDIR/logs/scenario_10_v2_sequence_zero.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 11: v2 tampered signature (verifier refusal)"
  run_case scenario_11_v2_bad_signature 1 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/scenario_11_v2_bad_signature.stderr.log" 'signature failed ML-DSA-44 PQC verification'
  assert_grep "$OUTDIR/logs/scenario_11_v2_bad_signature.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 12: v2 wrong chain (verifier refusal)"
  run_case scenario_12_v2_wrong_chain 1 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-chain.json"
  assert_grep "$OUTDIR/logs/scenario_12_v2_wrong_chain.stderr.log" 'chain_id mismatch'
  assert_grep "$OUTDIR/logs/scenario_12_v2_wrong_chain.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 13: v2 wrong environment (verifier refusal)"
  run_case scenario_13_v2_wrong_environment 1 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-environment.json"
  assert_grep "$OUTDIR/logs/scenario_13_v2_wrong_environment.stderr.log" 'environment mismatch'
  assert_grep "$OUTDIR/logs/scenario_13_v2_wrong_environment.stderr.log" 'Run 132: VERDICT=invalid'

  log "Scenario 14: v2 wrong genesis (verifier refusal)"
  run_case scenario_14_v2_wrong_genesis 1 "" \
    "${devnet_reload_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-genesis.json"
  assert_grep "$OUTDIR/logs/scenario_14_v2_wrong_genesis.stderr.log" 'genesis_hash does not match runtime canonical genesis hash'
  assert_grep "$OUTDIR/logs/scenario_14_v2_wrong_genesis.stderr.log" 'Run 132: VERDICT=invalid'

  ##########################################################################
  # Peer-candidate-check spot-check
  ##########################################################################
  log "Scenario 15: peer-candidate-check v2 ratify@seq=1, no marker (pass)"
  run_case scenario_15_peer_check_v2_pass 0 "" \
    "${devnet_peer_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_15_peer_check_v2_pass.stderr.log" '\[run-132\] peer-candidate-check v2 authority-marker check passed'
  assert_grep "$OUTDIR/logs/scenario_15_peer_check_v2_pass.stderr.log" 'VERDICT=validated'

  log "Scenario 16: peer-candidate-check v2 bad-signature (refused)"
  run_case scenario_16_peer_check_v2_bad 1 "" \
    "${devnet_peer_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/scenario_16_peer_check_v2_bad.stderr.log" 'signature failed ML-DSA-44 PQC verification'
  assert_grep "$OUTDIR/logs/scenario_16_peer_check_v2_bad.stderr.log" 'Run 132: VERDICT=invalid'

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json files were created under scenario data dirs"
    echo "  no pqc_authority_state.json was advanced or rewritten under any scenario data dir"
    echo "  no pqc_authority_state.json.tmp sibling was left behind under any scenario data dir"
    echo "  no apply / propagate / session-eviction / SIGHUP / KMS markers were observed"
    echo "wire format checks: source-only, no trust-bundle, peer-candidate, or ratification wire format changed by this script"
  } >> "$SUMMARY"
  log "PASS: Run 133 evidence captured under ${OUTDIR}"
}

main "$@"
