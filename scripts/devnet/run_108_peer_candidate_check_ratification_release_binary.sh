#!/usr/bin/env bash
# Run 108: release-binary evidence matrix for local peer-candidate-check
# bundle-signing-key ratification enforcement. Evidence-only; no live wire,
# propagation, reload-apply, SIGHUP, or peer-driven apply behavior is changed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run108-peer-candidate-check-ratification-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_108_peer_candidate_ratification_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run108] %s\n' "$*"; }
fail() { printf '[run108] FAIL: %s\n' "$*" >&2; exit 1; }
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

assert_no_node_startup() {
  local stderr="$1"
  assert_not_grep "$stderr" 'P2P transport up|metrics HTTP|consensus|Starting QBIND|peer-candidate wire publish|propagation|session eviction|reload-apply|SIGHUP|LivePqcTrustState|apply success'
}

assert_no_sequence_write() {
  local data_dir="$1"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir}"
  fi
}

run_case() {
  local name="$1" expected_rc="$2"
  shift 2
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local rcfile="${OUTDIR}/logs/${name}.exit_code"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"

  set +e
  "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"
  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc}; stderr=${stderr}"
  assert_no_sequence_write "$data_dir"
  assert_no_node_startup "$stderr"
  printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and Run 108 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_108_peer_candidate_ratification_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 108 peer-candidate-check ratification release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo
    echo "scenario status:"
  } > "$SUMMARY"

  log "generating ephemeral fixtures"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" >"$OUTDIR/logs/fixture_helper.stdout.log" 2>"$OUTDIR/logs/fixture_helper.stderr.log"

  local main_hash dev_hash main_key dev_key main_rat dev_rat main_bad dev_bad main_env main_unrat dev_env dev_unrat
  main_hash="$(cat "$OUTDIR/fixtures/mainnet/expected-genesis-hash.txt")"
  dev_hash="$(cat "$OUTDIR/fixtures/devnet/expected-genesis-hash.txt")"
  main_key="$(cat "$OUTDIR/fixtures/mainnet/signing-key.ratified.spec")"
  dev_key="$(cat "$OUTDIR/fixtures/devnet/signing-key.ratified.spec")"
  main_rat="$OUTDIR/fixtures/mainnet/ratification.valid.json"
  dev_rat="$OUTDIR/fixtures/devnet/ratification.valid.json"
  main_bad="$OUTDIR/fixtures/mainnet/ratification.bad-signature.json"
  dev_bad="$OUTDIR/fixtures/devnet/ratification.bad-signature.json"
  main_env="$OUTDIR/fixtures/mainnet/peer-candidate.ratified.json"
  main_unrat="$OUTDIR/fixtures/mainnet/peer-candidate.unratified.json"
  dev_env="$OUTDIR/fixtures/devnet/peer-candidate.ratified.json"
  dev_unrat="$OUTDIR/fixtures/devnet/peer-candidate.unratified.json"

  log "Scenario 1: MainNet valid ratification passes"
  run_case scenario_1_mainnet_valid 0 \
    --env mainnet \
    --genesis-path "$OUTDIR/fixtures/mainnet/genesis.json" \
    --expect-genesis-hash "$main_hash" \
    --p2p-trust-bundle-signing-key "$main_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$main_env" \
    --p2p-trust-bundle-ratification "$main_rat"
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" '\[run-102\] OK: canonical Run 101 genesis verification passed'
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" '\[run-107\] peer-candidate-check ratification gate INVOKED.*mainnet-default-strict'
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" 'VERDICT=validated'

  log "Scenario 2: MainNet missing ratification rejects"
  run_case scenario_2_mainnet_missing 1 \
    --env mainnet \
    --genesis-path "$OUTDIR/fixtures/mainnet/genesis.json" \
    --expect-genesis-hash "$main_hash" \
    --p2p-trust-bundle-signing-key "$main_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$main_env"
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" '\[run-107\] peer-candidate-check ratification gate INVOKED.*mainnet-default-strict'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" 'RatificationRefused\(Missing|missing ratification|Missing'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" 'VERDICT=rejected'

  log "Scenario 3: MainNet bad ratification rejects"
  run_case scenario_3_mainnet_bad_signature 1 \
    --env mainnet \
    --genesis-path "$OUTDIR/fixtures/mainnet/genesis.json" \
    --expect-genesis-hash "$main_hash" \
    --p2p-trust-bundle-signing-key "$main_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$main_env" \
    --p2p-trust-bundle-ratification "$main_bad"
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" 'BadSignature|bad signature|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" 'VERDICT=rejected'

  log "Scenario 4: DevNet without opt-in preserves legacy unratified local-check behavior"
  run_case scenario_4_devnet_no_opt_in_legacy 0 \
    --env devnet \
    --genesis-path "$OUTDIR/fixtures/devnet/genesis.json" \
    --expect-genesis-hash "$dev_hash" \
    --p2p-trust-bundle-signing-key "$(cat "$OUTDIR/fixtures/devnet/signing-key.unratified.spec")" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$dev_unrat"
  assert_grep "$OUTDIR/logs/scenario_4_devnet_no_opt_in_legacy.stderr.log" '\[run-107\] peer-candidate-check ratification gate SKIPPED.*devnet-no-operator-opt-in'
  assert_grep "$OUTDIR/logs/scenario_4_devnet_no_opt_in_legacy.stderr.log" 'VERDICT=validated'

  log "Scenario 5a: DevNet opt-in valid ratification passes"
  run_case scenario_5a_devnet_opt_in_valid 0 \
    --env devnet \
    --genesis-path "$OUTDIR/fixtures/devnet/genesis.json" \
    --expect-genesis-hash "$dev_hash" \
    --p2p-trust-bundle-signing-key "$dev_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$dev_env" \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$dev_rat"
  assert_grep "$OUTDIR/logs/scenario_5a_devnet_opt_in_valid.stderr.log" '\[run-107\] peer-candidate-check ratification gate INVOKED.*devnet-operator-opt-in'
  assert_grep "$OUTDIR/logs/scenario_5a_devnet_opt_in_valid.stderr.log" 'VERDICT=validated'

  log "Scenario 5b: DevNet opt-in missing ratification rejects"
  run_case scenario_5b_devnet_opt_in_missing 1 \
    --env devnet \
    --genesis-path "$OUTDIR/fixtures/devnet/genesis.json" \
    --expect-genesis-hash "$dev_hash" \
    --p2p-trust-bundle-signing-key "$dev_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$dev_env" \
    --p2p-trust-bundle-ratification-enforcement-enabled
  assert_grep "$OUTDIR/logs/scenario_5b_devnet_opt_in_missing.stderr.log" 'Missing|missing ratification|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_5b_devnet_opt_in_missing.stderr.log" 'VERDICT=rejected'

  log "Scenario 5c: DevNet opt-in bad ratification rejects"
  run_case scenario_5c_devnet_opt_in_bad_signature 1 \
    --env devnet \
    --genesis-path "$OUTDIR/fixtures/devnet/genesis.json" \
    --expect-genesis-hash "$dev_hash" \
    --p2p-trust-bundle-signing-key "$dev_key" \
    --p2p-trust-bundle-peer-candidate-validation-enabled \
    --p2p-trust-bundle-peer-candidate-check "$dev_env" \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$dev_bad"
  assert_grep "$OUTDIR/logs/scenario_5c_devnet_opt_in_bad_signature.stderr.log" 'BadSignature|bad signature|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_5c_devnet_opt_in_bad_signature.stderr.log" 'VERDICT=rejected'

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json files were created under scenario data dirs"
    echo "  no node startup/P2P/propagation/session-eviction/reload-apply markers were observed"
    echo "wire format checks: source-only, no trust-bundle or peer-candidate structs changed by this script"
  } >> "$SUMMARY"
  log "PASS: Run 108 evidence captured under ${OUTDIR}"
}

main "$@"
