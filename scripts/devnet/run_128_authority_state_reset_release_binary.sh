#!/usr/bin/env bash
# Run 128: release-binary evidence harness for Run 127 authority-state-reset CLI.
# Evidence-only. Prefers NO production runtime code changes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${1:-${REPO_ROOT}/docs/devnet/run_128_authority_state_reset_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_113_reload_apply_ratification_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run128] %s\n' "$*"; }
fail() { printf '[run128] FAIL: %s\n' "$*" >&2; exit 1; }
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

marker_sha_or_none() {
  local marker_path="$1"
  if [ -f "$marker_path" ]; then
    sha256_file "$marker_path"
  else
    echo '<none>'
  fi
}

assert_no_normal_startup_markers() {
  local stderr="$1"
  assert_not_grep "$stderr" 'P2P transport up|metrics HTTP|consensus|Starting QBIND|peer-candidate wire publish|propagation|session eviction|reload-apply|SIGHUP|LivePqcTrustState|trust-bundle candidate APPLIED live|\\[restore\\]'
}

assert_audit_common() {
  local audit_path="$1" expected_env="$2" expected_result="$3" expected_reason_regex="$4"
  python3 - "$audit_path" "$expected_env" "$expected_result" "$expected_reason_regex" <<'PY'
import json, re, sys
path, expected_env, expected_result, expected_reason_regex = sys.argv[1:5]
with open(path, 'r', encoding='utf-8') as f:
    d = json.load(f)
assert d.get('record_version') == 1, d
assert d.get('action') == 'authority_state_reset', d
assert d.get('environment') == expected_env, d
assert d.get('result') == expected_result, d
if expected_result == 'success':
    assert d.get('refusal_reason_if_any') is None, d
    assert d.get('refusal_detail_if_any') is None, d
else:
    reason = d.get('refusal_reason_if_any')
    assert isinstance(reason, str) and reason, d
    assert re.search(expected_reason_regex, reason), (reason, expected_reason_regex)
    assert isinstance(d.get('refusal_detail_if_any'), str) and d.get('refusal_detail_if_any'), d
raw = json.dumps(d, sort_keys=True).lower()
for banned in ('private_key', 'secret_key', 'ml_dsa44_secret', 'operator_note": "'):
    assert banned not in raw, banned
PY
}

assert_success_audit_and_marker() {
  local marker_path="$1" audit_path="$2"
  python3 - "$marker_path" "$audit_path" <<'PY'
import json, re, sys
marker_path, audit_path = sys.argv[1:3]
with open(marker_path, 'r', encoding='utf-8') as f:
    marker = json.load(f)
with open(audit_path, 'r', encoding='utf-8') as f:
    audit = json.load(f)
assert isinstance(audit.get('chain_id'), str) and re.fullmatch(r'[0-9a-f]{16}', audit['chain_id']), audit
assert isinstance(audit.get('genesis_hash'), str) and re.fullmatch(r'[0-9a-f]{64}', audit['genesis_hash']), audit
assert isinstance(audit.get('ratification_hash'), str) and re.fullmatch(r'[0-9a-f]{64}', audit['ratification_hash']), audit
assert isinstance(audit.get('trust_bundle_fingerprint'), str) and re.fullmatch(r'[0-9a-f]{64}', audit['trust_bundle_fingerprint']), audit
assert isinstance(audit.get('new_marker_hash'), str) and re.fullmatch(r'[0-9a-f]{64}', audit['new_marker_hash']), audit
assert isinstance(audit.get('new_marker_record'), dict), audit
assert marker == audit['new_marker_record'], (marker, audit['new_marker_record'])
PY
}

run_case() {
  local name="$1" expected_rc="$2" expected_stderr_pattern="$3" expected_refusal_reason_regex="$4" expected_env="$5" audit_policy="$6"
  shift 6

  local data_dir="${OUTDIR}/data/${name}"
  local logs_dir="${OUTDIR}/logs"
  local stdout="${logs_dir}/${name}.stdout.log"
  local stderr="${logs_dir}/${name}.stderr.log"
  local rcfile="${logs_dir}/${name}.exit_code"
  local marker_path="${data_dir}/pqc_authority_state.json"
  local audit_path="${OUTDIR}/audits/${name}.audit.json"
  mkdir -p "$data_dir"

  local marker_sha_before
  marker_sha_before="$(marker_sha_or_none "$marker_path")"

  if [ "$audit_policy" != "no-audit-flag" ]; then
    rm -f "$audit_path"
  fi

  set +e
  if [ "$audit_policy" = "no-audit-flag" ]; then
    "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  else
    "$NODE_BIN" "$@" --data-dir "$data_dir" --authority-state-reset-output-audit "$audit_path" >"$stdout" 2>"$stderr"
  fi
  local rc=$?
  set -e

  printf '%s\n' "$rc" > "$rcfile"

  local marker_sha_after
  marker_sha_after="$(marker_sha_or_none "$marker_path")"
  printf '%s\n' "$marker_sha_before" > "${logs_dir}/${name}.marker_sha_before"
  printf '%s\n' "$marker_sha_after" > "${logs_dir}/${name}.marker_sha_after"

  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc}; stderr=${stderr}"
  assert_grep "$stderr" "$expected_stderr_pattern"
  assert_no_normal_startup_markers "$stderr"

  if [ "$expected_rc" = "0" ]; then
    [ -f "$marker_path" ] || fail "${name} expected marker write at ${marker_path}"
    assert_audit_common "$audit_path" "$expected_env" success '^$'
    assert_success_audit_and_marker "$marker_path" "$audit_path"
  else
    [ "$marker_sha_before" = "$marker_sha_after" ] || fail "${name} marker changed on refusal (before=${marker_sha_before} after=${marker_sha_after})"
    if [ "$audit_policy" = "audit-required" ]; then
      [ -f "$audit_path" ] || fail "${name} expected refusal audit at ${audit_path}"
      assert_audit_common "$audit_path" "$expected_env" refused "$expected_refusal_reason_regex"
    else
      [ ! -e "$audit_path" ] || fail "${name} unexpectedly wrote audit when audit flag absent"
    fi
  fi

  printf '  %s: rc=%s marker_sha_before=%s marker_sha_after=%s audit=%s\n' \
    "$name" "$rc" "$marker_sha_before" "$marker_sha_after" "$audit_policy" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR/logs" "$OUTDIR/data" "$OUTDIR/fixtures" "$OUTDIR/audits"
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and fixture helper"
  cargo build --release -p qbind-node --bin qbind-node \
    > "$OUTDIR/logs/build.qbind-node.stdout.log" \
    2> "$OUTDIR/logs/build.qbind-node.stderr.log"
  cargo build --release -p qbind-node --example run_113_reload_apply_ratification_fixture_helper \
    > "$OUTDIR/logs/build.fixture-helper.stdout.log" \
    2> "$OUTDIR/logs/build.fixture-helper.stderr.log"

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 128 authority-state-reset release-binary evidence"
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

  log "generating fixtures"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    > "$OUTDIR/logs/fixture_helper.stdout.log" \
    2> "$OUTDIR/logs/fixture_helper.stderr.log"

  local DEV_GENESIS="$OUTDIR/fixtures/devnet/genesis.json"
  local DEV_HASH
  DEV_HASH="$(tr -d '\r\n' < "$OUTDIR/fixtures/devnet/expected-genesis-hash.txt")"
  local DEV_SIGNING_SPEC
  DEV_SIGNING_SPEC="$(tr -d '\r\n' < "$OUTDIR/fixtures/devnet/signing-key.ratified.spec")"
  local DEV_BUNDLE="$OUTDIR/fixtures/devnet/baseline-bundle.json"
  local DEV_RAT_VALID="$OUTDIR/fixtures/devnet/ratification.valid.json"
  local DEV_RAT_BAD="$OUTDIR/fixtures/devnet/ratification.bad-signature.json"
  local DEV_RAT_WRONG_CHAIN="$OUTDIR/fixtures/devnet/ratification.wrong-chain.json"
  local DEV_RAT_WRONG_ENV="$OUTDIR/fixtures/devnet/ratification.wrong-environment.json"

  local MAIN_GENESIS="$OUTDIR/fixtures/mainnet/genesis.json"
  local MAIN_HASH
  MAIN_HASH="$(tr -d '\r\n' < "$OUTDIR/fixtures/mainnet/expected-genesis-hash.txt")"
  local MAIN_SIGNING_SPEC
  MAIN_SIGNING_SPEC="$(tr -d '\r\n' < "$OUTDIR/fixtures/mainnet/signing-key.ratified.spec")"
  local MAIN_BUNDLE="$OUTDIR/fixtures/mainnet/baseline-bundle.json"
  local MAIN_RAT_VALID="$OUTDIR/fixtures/mainnet/ratification.valid.json"

  log "Scenario 1: DevNet success"
  run_case \
    scenario_1_devnet_success \
    0 \
    'authority-state-reset: SUCCESS' \
    '^$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_VALID" \
    --authority-state-reset-operator-note 'run128-scenario-1-devnet-success'

  log "Scenario 2: MainNet local reset refused"
  run_case \
    scenario_2_mainnet_local_refusal \
    1 \
    'MainNetLocalResetUnsupported' \
    '^MainNetLocalResetUnsupported$' \
    mainnet \
    audit-required \
    --authority-state-reset \
    --env mainnet \
    --genesis-path "$MAIN_GENESIS" \
    --expect-genesis-hash "$MAIN_HASH" \
    --p2p-trust-bundle "$MAIN_BUNDLE" \
    --p2p-trust-bundle-signing-key "$MAIN_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$MAIN_RAT_VALID" \
    --authority-state-reset-operator-note 'run128-scenario-2-mainnet-refusal'

  log "Scenario 3: Missing ratification refused"
  run_case \
    scenario_3_missing_ratification_refusal \
    1 \
    'MissingRatification' \
    '^MissingRatification$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --authority-state-reset-operator-note 'run128-scenario-3-missing-ratification'

  log "Scenario 4: Bad ratification refused"
  run_case \
    scenario_4_bad_ratification_refusal \
    1 \
    'RatificationEnforcementFailed|InvalidRatification' \
    '^(RatificationEnforcementFailed|InvalidRatification)$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_BAD" \
    --authority-state-reset-operator-note 'run128-scenario-4-bad-ratification'

  log "Scenario 5: Wrong expected genesis hash refused"
  run_case \
    scenario_5_wrong_expected_genesis_hash_refusal \
    1 \
    'GenesisHashMismatch' \
    '^GenesisHashMismatch$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_VALID" \
    --authority-state-reset-operator-note 'run128-scenario-5-wrong-genesis-hash'

  log "Scenario 6: Corrupt existing marker refused and unchanged"
  mkdir -p "$OUTDIR/data/scenario_6_corrupt_existing_marker_refusal"
  printf 'not-json-run128-corrupt-marker\n' > "$OUTDIR/data/scenario_6_corrupt_existing_marker_refusal/pqc_authority_state.json"
  run_case \
    scenario_6_corrupt_existing_marker_refusal \
    1 \
    'ExistingMarkerCorrupt' \
    '^ExistingMarkerCorrupt$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_VALID" \
    --authority-state-reset-operator-note 'run128-scenario-6-corrupt-existing-marker'

  log "Scenario 7: Missing audit output flag refused"
  run_case \
    scenario_7_missing_audit_output_path_refusal \
    1 \
    'AuditOutputMissing' \
    '^AuditOutputMissing$' \
    devnet \
    no-audit-flag \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_VALID" \
    --authority-state-reset-operator-note 'run128-scenario-7-missing-audit-flag'

  log "Scenario 8a: Wrong chain ratification refused"
  run_case \
    scenario_8a_wrong_chain_ratification_refusal \
    1 \
    'RatificationEnforcementFailed' \
    '^RatificationEnforcementFailed$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_WRONG_CHAIN" \
    --authority-state-reset-operator-note 'run128-scenario-8a-wrong-chain'

  log "Scenario 8b: Wrong environment ratification refused"
  run_case \
    scenario_8b_wrong_environment_ratification_refusal \
    1 \
    'RatificationEnforcementFailed' \
    '^RatificationEnforcementFailed$' \
    devnet \
    audit-required \
    --authority-state-reset \
    --env devnet \
    --genesis-path "$DEV_GENESIS" \
    --expect-genesis-hash "$DEV_HASH" \
    --p2p-trust-bundle "$DEV_BUNDLE" \
    --p2p-trust-bundle-signing-key "$DEV_SIGNING_SPEC" \
    --p2p-trust-bundle-ratification "$DEV_RAT_WRONG_ENV" \
    --authority-state-reset-operator-note 'run128-scenario-8b-wrong-environment'

  {
    echo
    echo 'assertions: pass'
    echo '  marker written only on success scenario'
    echo '  marker sha unchanged on every refusal scenario'
    echo '  no normal startup markers observed in any scenario'
    echo '  audit schema fields validated for success/refusal scenarios with audit path'
    echo '  no private key material observed in audit records'
    echo 'VERDICT: strongest-positive (release-binary harness scope)'
  } >> "$SUMMARY"

  log "PASS: Run 128 release-binary evidence captured under ${OUTDIR}"
}

main "$@"
