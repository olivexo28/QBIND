#!/usr/bin/env bash
# Run 113: release-binary evidence matrix for process-start reload-apply
# bundle-signing-key ratification enforcement (Run 112 wiring).
#
# Evidence-only. Run 113 prefers NO production runtime code changes. This
# harness exercises the reload-apply branch of `target/release/qbind-node`
# against ephemeral DevNet/MainNet trust-bundle + ratification fixtures
# minted by `run_113_reload_apply_ratification_fixture_helper`.
#
# Scenarios proved:
#   1. MainNet  valid    ratification → reload-apply succeeds, Run 070/073
#                                       ordering preserved.
#   2. MainNet  missing  ratification → refused before any mutation.
#   3. MainNet  bad      ratification (sig flip)         → refused before mutation.
#   4. MainNet  wrong    chain in ratification           → refused before mutation.
#   5. MainNet  wrong    environment in ratification     → refused before mutation.
#   6. MainNet  unknown  authority root in ratification  → refused before mutation.
#   7. DevNet   without  opt-in (legacy unratified)      → applies (gate SKIPPED).
#   8. DevNet   opt-in   valid ratification              → reload-apply succeeds.
#   9. DevNet   opt-in   missing ratification            → refused before mutation.
#
# No SIGHUP, no peer-driven live apply, no signing-key rotation/revocation,
# no authority anti-rollback persistence, no KMS/HSM, no governance, no
# trust-bundle wire format change, no peer-candidate wire format change.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run113-reload-apply-ratification-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_113_reload_apply_ratification_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run113] %s\n' "$*"; }
fail() { printf '[run113] FAIL: %s\n' "$*" >&2; exit 1; }
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

# A reload-apply REJECTION before mutation must satisfy all of:
#   * no sequence-persistence file written under the scenario data dir;
#   * no Run 070 canonical APPLIED log line;
#   * no Run 073 VERDICT=applied marker;
#   * no session-eviction marker.
assert_no_mutation() {
  local data_dir="$1" stderr="$2"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a refusal path)"
  fi
  assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_not_grep "$stderr" 'VERDICT=applied'
  assert_not_grep "$stderr" 'session_evictions=[1-9]'
}

# A reload-apply SUCCESS must show the Run 070 canonical applied log line
# AND the Run 073 VERDICT=applied marker. The two together prove the
# `validate → snapshot → swap → evict_sessions → commit_sequence` order
# survived: the canonical line is emitted only by `AppliedCandidate::
# applied_log_line`, which `apply_post_validation` only returns after
# the full four-step pipeline completes (see Run 112 / Run 070 docs).
assert_apply_ordering() {
  local stderr="$1"
  assert_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_grep "$stderr" 'sequence_commit=ok'
  assert_grep "$stderr" 'VERDICT=applied'
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
  printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and Run 113 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_113_reload_apply_ratification_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 113 reload-apply ratification release-binary evidence"
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

  local main_hash dev_hash main_key dev_key dev_unrat_key
  main_hash="$(cat "$OUTDIR/fixtures/mainnet/expected-genesis-hash.txt")"
  dev_hash="$(cat "$OUTDIR/fixtures/devnet/expected-genesis-hash.txt")"
  main_key="$(cat "$OUTDIR/fixtures/mainnet/signing-key.ratified.spec")"
  dev_key="$(cat "$OUTDIR/fixtures/devnet/signing-key.ratified.spec")"
  dev_unrat_key="$(cat "$OUTDIR/fixtures/devnet/signing-key.unratified.spec")"

  local main_baseline="$OUTDIR/fixtures/mainnet/baseline-bundle.json"
  local main_cand="$OUTDIR/fixtures/mainnet/candidate-bundle.ratified.json"
  local main_rat_valid="$OUTDIR/fixtures/mainnet/ratification.valid.json"
  local main_rat_bad="$OUTDIR/fixtures/mainnet/ratification.bad-signature.json"
  local main_rat_wchain="$OUTDIR/fixtures/mainnet/ratification.wrong-chain.json"
  local main_rat_wenv="$OUTDIR/fixtures/mainnet/ratification.wrong-environment.json"
  local main_rat_unk="$OUTDIR/fixtures/mainnet/ratification.unknown-authority.json"

  local dev_baseline="$OUTDIR/fixtures/devnet/baseline-bundle.json"
  local dev_cand="$OUTDIR/fixtures/devnet/candidate-bundle.ratified.json"
  local dev_cand_unrat="$OUTDIR/fixtures/devnet/candidate-bundle.unratified.json"
  local dev_rat_valid="$OUTDIR/fixtures/devnet/ratification.valid.json"

  # Common MainNet flag block: signed-bundle baseline, ratified signing key,
  # genesis-pinned, reload-apply armed.
  mainnet_args() {
    printf -- '--env mainnet --genesis-path %s --expect-genesis-hash %s ' \
      "$OUTDIR/fixtures/mainnet/genesis.json" "$main_hash"
    printf -- '--p2p-trust-bundle %s --p2p-trust-bundle-signing-key %s ' \
      "$main_baseline" "$main_key"
    printf -- '--p2p-trust-bundle-reload-apply-enabled --p2p-trust-bundle-reload-apply-path %s ' \
      "$main_cand"
  }

  devnet_args() {
    printf -- '--env devnet --genesis-path %s --expect-genesis-hash %s ' \
      "$OUTDIR/fixtures/devnet/genesis.json" "$dev_hash"
    printf -- '--p2p-trust-bundle %s ' "$dev_baseline"
    printf -- '--p2p-trust-bundle-reload-apply-enabled --p2p-trust-bundle-reload-apply-path %s ' \
      "$2"
    printf -- '--p2p-trust-bundle-signing-key %s ' "$1"
  }

  log "Scenario 1: MainNet valid ratification → reload-apply succeeds"
  # shellcheck disable=SC2046
  run_case scenario_1_mainnet_valid 0 \
    $(mainnet_args) \
    --p2p-trust-bundle-ratification "$main_rat_valid"
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" '\[run-102\] OK: canonical Run 101 genesis verification passed'
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" '\[run-112\] reload-apply ratification gate INVOKED.*Mainnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log"

  log "Scenario 2: MainNet missing ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_2_mainnet_missing 1 \
    $(mainnet_args)
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" '\[run-112\] reload-apply ratification gate INVOKED.*Mainnet'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" 'ratification missing|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_2_mainnet_missing" "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log"

  log "Scenario 3: MainNet bad-signature ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_3_mainnet_bad_signature 1 \
    $(mainnet_args) \
    --p2p-trust-bundle-ratification "$main_rat_bad"
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" 'signature failed PQC verification|BadSignature|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_3_mainnet_bad_signature" "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log"

  log "Scenario 4: MainNet wrong-chain ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_4_mainnet_wrong_chain 1 \
    $(mainnet_args) \
    --p2p-trust-bundle-ratification "$main_rat_wchain"
  assert_grep "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log" 'chain_id mismatch|ChainMismatch|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_4_mainnet_wrong_chain" "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log"

  log "Scenario 5: MainNet wrong-environment ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_5_mainnet_wrong_env 1 \
    $(mainnet_args) \
    --p2p-trust-bundle-ratification "$main_rat_wenv"
  assert_grep "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log" 'environment mismatch|EnvironmentMismatch|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_5_mainnet_wrong_env" "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log"

  log "Scenario 6: MainNet unknown-authority ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_6_mainnet_unknown_authority 1 \
    $(mainnet_args) \
    --p2p-trust-bundle-ratification "$main_rat_unk"
  assert_grep "$OUTDIR/logs/scenario_6_mainnet_unknown_authority.stderr.log" 'not present in genesis bundle_signing_authority_roots|UnknownAuthority|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_6_mainnet_unknown_authority.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_6_mainnet_unknown_authority" "$OUTDIR/logs/scenario_6_mainnet_unknown_authority.stderr.log"

  log "Scenario 7: DevNet without opt-in (legacy unratified) → applies"
  # Legacy DevNet ergonomics: candidate signed by an unratified signing key,
  # no ratification sidecar, no `--p2p-trust-bundle-ratification-enforcement-enabled`.
  # Baseline must be signed by the same unratified key so the Run 073 adapter
  # can seed the live trust handle.
  # We override the baseline to be the unratified-signed candidate-sequence-2
  # bundle's sibling — easier: regenerate via fixture helper would create new
  # material. Instead, use the ratified baseline + supply BOTH signing keys,
  # so the unratified candidate is accepted but baseline stays valid.
  # shellcheck disable=SC2046
  run_case scenario_7_devnet_legacy_no_opt_in 0 \
    $(devnet_args "$dev_key" "$dev_cand_unrat") \
    --p2p-trust-bundle-signing-key "$dev_unrat_key"
  assert_grep "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log" '\[run-112\] reload-apply ratification gate SKIPPED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log"

  log "Scenario 8: DevNet opt-in valid ratification → reload-apply succeeds"
  # shellcheck disable=SC2046
  run_case scenario_8_devnet_opt_in_valid 0 \
    $(devnet_args "$dev_key" "$dev_cand") \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$dev_rat_valid"
  assert_grep "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log" '\[run-112\] reload-apply ratification gate INVOKED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log"

  log "Scenario 9: DevNet opt-in missing ratification → refused before mutation"
  # shellcheck disable=SC2046
  run_case scenario_9_devnet_opt_in_missing 1 \
    $(devnet_args "$dev_key" "$dev_cand") \
    --p2p-trust-bundle-ratification-enforcement-enabled
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" '\[run-112\] reload-apply ratification gate INVOKED.*Devnet'
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" 'ratification missing|RatificationRefused'
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" 'VERDICT=invalid'
  assert_no_mutation "$OUTDIR/data/scenario_9_devnet_opt_in_missing" "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log"

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json was created under any refusal scenario data dir"
    echo "  no Run 070 APPLIED log line, no Run 073 VERDICT=applied, and no"
    echo "  session_evictions>=1 marker was emitted on any refusal scenario."
    echo "apply-ordering checks: pass"
    echo "  Run 070 canonical applied_log_line + 'sequence_commit=ok' + Run 073"
    echo "  VERDICT=applied present together on every accepted scenario."
    echo "wire-format checks: source-only, no trust-bundle or ratification structs"
    echo "  changed by this evidence harness."
    echo "scope-non-goal checks: SIGHUP live reload, peer-driven live apply,"
    echo "  signing-key rotation/revocation, authority anti-rollback persistence,"
    echo "  KMS/HSM, governance, validator-set rotation: NOT touched."
  } >> "$SUMMARY"
  log "PASS: Run 113 evidence captured under ${OUTDIR}"
}

main "$@"
