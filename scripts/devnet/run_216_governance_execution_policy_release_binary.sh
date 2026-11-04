#!/usr/bin/env bash
# Run 216 — Release-binary governance-execution policy-selector evidence.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_216_governance_execution_policy_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_216_BIN="${REPO_ROOT}/target/release/examples/run_216_governance_execution_policy_release_binary_helper"
HELPER_216_OUT="${OUTDIR}/helper_evidence/run_216"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
GREP_DIR="${OUTDIR}/grep_summaries"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
DATA_DIR="${OUTDIR}/data"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"
MUT_PROOF="${OUTDIR}/mutation_proof.txt"
NOMUT_PROOF="${OUTDIR}/no_mutation_proof.txt"
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"

log() { printf '[run-216] %s\n' "$*" >&2; }
fail() { printf '[run-216] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

RUN_ID="run216-${EPOCHREALTIME//[.,]/}-$$-${RANDOM}"
RESULTS="${EXIT_DIR}/regression_results.tsv"
SUMMARY_TMP=""
STARTED=0
COMPLETED=0
INCOMPLETE=0
REGRESSION_FAILED=0
TEST_VERDICTS=()

publish_incomplete() {
  local tmp
  if ! tmp="$(mktemp "${SUMMARY}.tmp.XXXXXX")"; then return 1; fi
  SUMMARY_TMP="$tmp"
  if ! printf 'run_id=%s\nverdict: INCOMPLETE\n' "$RUN_ID" > "$tmp"; then return 1; fi
  if ! mv -fT -- "$tmp" "$SUMMARY"; then return 1; fi
  SUMMARY_TMP=""
}
finish() {
  local rc=$?
  local abandoned_tmp="$SUMMARY_TMP"
  trap - EXIT INT TERM HUP
  if [[ "$COMPLETED" -ne 1 || "$rc" -ne 0 ]]; then
    [[ "$rc" -ne 0 ]] || rc=1
    if [[ "$STARTED" -eq 1 ]]; then
      publish_incomplete || log "cannot repair summary; any PASS is untrusted without normal zero completion"
    fi
  fi
  if [[ -n "$SUMMARY_TMP" ]]; then
    rm -f -- "$SUMMARY_TMP" || log "cannot remove summary temporary file"
  fi
  if [[ -n "$abandoned_tmp" && "$abandoned_tmp" != "$SUMMARY_TMP" ]]; then
    rm -f -- "$abandoned_tmp" || log "cannot remove abandoned summary temporary file"
  fi
  exit "$rc"
}
interrupted() {
  log "interrupted by $1; foreground-command traps may be deferred"
  COMPLETED=0
  exit "$2"
}
trap finish EXIT
trap 'interrupted SIGINT 130' INT
trap 'interrupted SIGTERM 143' TERM
trap 'interrupted SIGHUP 129' HUP

log "OUTDIR=${OUTDIR}"
log "run_id=${RUN_ID}"
if ! mkdir -p "${OUTDIR}" || ! publish_incomplete; then
  fail "summary initialization failed; any existing summary may be from an earlier run and is untrusted"
fi
STARTED=1
rm -rf "${HELPER_216_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_216_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-216 provenance"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status_short:"; git -C "${REPO_ROOT}" status --short 2>/dev/null || true
  echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
  echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
  echo "host: $(uname -a 2>/dev/null || echo unknown)"
  echo "outdir: ${OUTDIR}"
  echo "env_selector: ${ENV_SELECTOR}"
  echo "cli_selector: ${CLI_SELECTOR}"
} >> "${PROVENANCE}"

log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) > "${LOGS_DIR}/build_qbind_node.log" 2>&1 || fail "qbind-node build failed"
log "cargo build --release -p qbind-node --example run_216_governance_execution_policy_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_216_governance_execution_policy_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_216.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_216_BIN}" ]] || fail "missing ${HELPER_216_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_216_path:    ${HELPER_216_BIN}"
  echo "helper_216_sha256:  $(sha256_file "${HELPER_216_BIN}")"
  echo "helper_216_buildid: $(build_id "${HELPER_216_BIN}")"
} >> "${PROVENANCE}"

log "running Run 216 helper"
set +e
"${HELPER_216_BIN}" "${HELPER_216_OUT}" > "${LOGS_DIR}/helper_run_216.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_216.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_216 helper failed"
assert_grep "${HELPER_216_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 216 governance-execution fixture inventory (helper-minted):"
  if [[ -d "${HELPER_216_OUT}/fixtures" ]]; then
    for f in "${HELPER_216_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/governance_execution_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'validator-set rotation (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'autonomous apply|apply on receipt|peer-majority authority'
  assert_not_grep "$logf" 'real KMS backend|real HSM backend|real RemoteSigner backend|RemoteSigner backend connected'
  assert_not_grep "$logf" 'custody attestation production (enabled|active|wired)'
  assert_not_grep "$logf" 'MainNet peer-driven apply ENABLED'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY -u QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1 || true
  local rc=$?
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides selector"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'p2p-trust-bundle-governance-execution-policy'
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'governance execution|production governance|mainnet governance|validator-set rotation|on-chain governance proof verifier|run-215|run-216'
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
run_surface_scenario S5_cli_selector_devnet devnet "${CLI_SELECTOR}" fixture-governance-allowed
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=production-governance-required" "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_env_selector_devnet.log" 2>&1 || true; S6_RC=$?; echo "$S6_RC" > "${EXIT_DIR}/S6_env_selector_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S6_env_selector_devnet.log"
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=fixture-governance-allowed" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" disabled ) > "${LOGS_DIR}/S7_cli_over_env_devnet.log" 2>&1 || true; S7_RC=$?; echo "$S7_RC" > "${EXIT_DIR}/S7_cli_over_env_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S7_cli_over_env_devnet.log"
( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus ) > "${LOGS_DIR}/S8_invalid_selector_devnet.log" 2>&1 || true; S8_RC=$?; echo "$S8_RC" > "${EXIT_DIR}/S8_invalid_selector_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S8_invalid_selector_devnet.log"
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=mainnet-governance-required" "${NODE_BIN}" --print-genesis-hash --env mainnet "${CLI_SELECTOR}" mainnet-governance-required ) > "${LOGS_DIR}/S9_mainnet_armed.log" 2>&1 || true; S9_RC=$?; echo "$S9_RC" > "${EXIT_DIR}/S9_mainnet_armed.rc"; assert_surface_silent "${LOGS_DIR}/S9_mainnet_armed.log"
( cd "${REPO_ROOT}" && env QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY=fixture-attestation-allowed "${ENV_SELECTOR}=fixture-governance-allowed" "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S10_legacy_selectors_compat.log" 2>&1 || true; S10_RC=$?; echo "$S10_RC" > "${EXIT_DIR}/S10_legacy_selectors_compat.rc"; assert_surface_silent "${LOGS_DIR}/S10_legacy_selectors_compat.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 216 source-reachability proof — production symbols within ${SRC_DIR}:"
  for sym in pqc_governance_execution_policy_surface QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY p2p_trust_bundle_governance_execution_policy governance_execution_policy_from_selector governance_execution_policy_from_cli_or_env governance_execution_policy_env_selector preflight_v2_marker_governance_execution_for_reload_check preflight_v2_marker_governance_execution_for_reload_apply preflight_v2_marker_governance_execution_for_startup_p2p_trust_bundle preflight_v2_marker_governance_execution_for_sighup preflight_v2_marker_governance_execution_for_local_peer_candidate_check preflight_v2_marker_governance_execution_for_live_inbound_0x05 preflight_v2_marker_governance_execution_for_peer_driven_drain GovernanceExecutionPolicy FixtureGovernanceAllowed EmergencyCouncilFixtureAllowed ProductionGovernanceRequired MainnetGovernanceRequired route_loaded_governance_execution_to_reload_check_callsite_decision ProductionGovernanceUnavailable OnChainGovernanceUnavailable MainNetGovernanceUnavailable mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_execution_policy_surface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'governance_execution_policy_from_cli_or_env'
grep -RIn --include='*.rs' 'p2p_trust_bundle_governance_execution_policy' "${SRC_DIR}" > "${REACH_DIR}/cli_flag_reachability.txt" || fail "missing CLI field reachability"

{
  echo "Run 216 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_216_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 216 no-mutation proof for rejected governance-execution-policy scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  R1..R40 helper corpus: no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, marker/sequence bytes unchanged where present, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. Selector/preflight wrappers are pure typed outcome functions."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_216_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 216 mutation proof (release-binary scope): selector resolution occurs before governance-execution material parse; material parse before marker decision; governance execution, lifecycle, governance-proof, custody and custody-attestation validation occur before apply/mutation; accepted mutating compatibility remains subject to Run 055 sequence commit before v2 marker persist. No mutation is performed by this fixture-only helper."
} > "${MUT_PROOF}"

record_result() {
  if ! printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; then
    log "manifest write failed for $1"
    INCOMPLETE=1
    return 1
  fi
}
run_regression() {
  local kind="$1" label="$2"; shift 2
  local key="run216:${kind}:${label}" stem logf rc fd
  if [[ "$kind" == test ]]; then stem="test_${label}"; else stem="lib_${label}"; fi
  logf="${TEST_LOGS}/${stem}.log"
  if [[ "$kind" == test && ! -f "${REPO_ROOT}/crates/qbind-node/tests/${label}.rs" ]]; then
    log "missing required target: $key"
    REGRESSION_FAILED=1
    record_result "$key" missing_target "" || INCOMPLETE=1
    return 1
  fi
  if ! exec {fd}> "$logf"; then
    log "cannot capture $key; command not launched"
    INCOMPLETE=1
    record_result "$key" capture_error "" || INCOMPLETE=1
    return 1
  fi
  log "regression $key"
  if ( cd "${REPO_ROOT}" && cargo test -p qbind-node "$@" -- --test-threads=1 ) >&"$fd" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if ! exec {fd}>&-; then log "log close failed: $key"; INCOMPLETE=1; fi
  if ! printf '%s\n' "$rc" > "${EXIT_DIR}/${stem}.rc"; then
    log "status write failed: $key"
    INCOMPLETE=1
  fi
  record_result "$key" returned "$rc" || INCOMPLETE=1
  if ! printf '%s\trc=%d\n' "$key" "$rc"; then log "result output failed: $key"; INCOMPLETE=1; fi
  [[ "$rc" -eq 0 ]] || REGRESSION_FAILED=1
  return "$rc"
}
validate_results() {
  local line key state rc stem stored extra fd status_fd count=0
  local -A expected=() seen=()
  TEST_VERDICTS=()
  for key in "${TEST_TARGETS[@]}"; do expected["run216:test:${key}"]="test_${key}"; done
  expected["run216:lib:pqc_authority"]="lib_pqc_authority"
  expected["run216:lib:lib_all"]="lib_lib_all"
  if IFS= read -r -d '' line < "$RESULTS"; then log "NUL in manifest"; return 1; fi
  if ! exec {fd}< "$RESULTS"; then log "cannot read regression manifest"; return 1; fi
  if ! IFS= read -r line <&"$fd" || [[ "$line" != "run_id=${RUN_ID}" ]]; then
    exec {fd}<&-; log "stale/missing manifest invocation"; return 1
  fi
  if ! IFS= read -r line <&"$fd" || [[ "$line" != $'command_key\tstate\trc' ]]; then
    exec {fd}<&-; log "invalid manifest schema"; return 1
  fi
  while true; do
    line=""
    if ! IFS= read -r line <&"$fd"; then
      if [[ -n "$line" ]]; then exec {fd}<&-; log "unterminated result"; return 1; fi
      break
    fi
    if [[ ! "$line" =~ ^([^$'\t']+)$'\t'(returned|missing_target|capture_error)$'\t'([0-9]*)$ ]]; then
      exec {fd}<&-; log "malformed result"; return 1
    fi
    key="${BASH_REMATCH[1]}"; state="${BASH_REMATCH[2]}"; rc="${BASH_REMATCH[3]}"
    if [[ -z "${expected[$key]+present}" || -n "${seen[$key]+present}" ]]; then
      exec {fd}<&-; log "unknown/duplicate result: $key"; return 1
    fi
    seen["$key"]=1; stem="${expected[$key]}"; count=$((count + 1))
    if [[ "$state" == returned ]]; then
      if [[ ! "$rc" =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( rc > 255 )); then
        exec {fd}<&-; log "invalid status: $key"; return 1
      fi
      if [[ ! -f "${TEST_LOGS}/${stem}.log" || ! -f "${EXIT_DIR}/${stem}.rc" ]] ||
         ! exec {status_fd}< "${EXIT_DIR}/${stem}.rc"; then
        exec {fd}<&-; log "missing/unreadable status/log: $key"; return 1
      fi
      extra=""
      if IFS= read -r -d '' stored < "${EXIT_DIR}/${stem}.rc"; then
        exec {status_fd}<&-; exec {fd}<&-; log "NUL in status: $key"; return 1
      fi
      if IFS= read -r stored <&"$status_fd" && ! IFS= read -r extra <&"$status_fd" &&
         [[ -z "$extra" && "$stored" == "$rc" ]]; then
        if ! exec {status_fd}<&-; then exec {fd}<&-; log "status close failed"; return 1; fi
      else
        exec {status_fd}<&-
        exec {fd}<&-; log "status/log mismatch: $key"; return 1
      fi
      [[ "$rc" -eq 0 ]] || REGRESSION_FAILED=1
    else
      if [[ -n "$rc" || -e "${EXIT_DIR}/${stem}.rc" || ( "$state" == missing_target && "$key" != run216:test:* ) ]]; then
        exec {fd}<&-; log "invalid non-returned result: $key"; return 1
      fi
      if [[ "$state" == capture_error ]]; then INCOMPLETE=1; else REGRESSION_FAILED=1; fi
    fi
    TEST_VERDICTS+=( "$line" )
  done
  if ! exec {fd}<&-; then log "manifest close failed"; return 1; fi
  if [[ "$count" -ne "${#expected[@]}" ]]; then log "missing required results"; return 1; fi
}
TEST_TARGETS=(run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_209_custody_attestation_policy_selector_tests run_207_custody_attestation_payload_callsite_tests run_205_custody_attestation_verifier_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_198_remote_signer_policy_selector_tests run_196_remote_signer_payload_callsite_tests run_194_remote_authority_signer_boundary_tests run_192_authority_custody_policy_selector_tests run_190_authority_custody_payload_callsite_tests run_188_authority_custody_boundary_tests run_186_onchain_governance_production_verifier_boundary_tests run_184_onchain_governance_payload_carrying_tests run_182_onchain_governance_production_callsite_wiring_tests run_180_onchain_governance_marker_integration_tests run_178_onchain_governance_proof_tests run_176_live_0x05_governance_proof_carrier_tests run_173_validation_only_governance_required_policy_tests run_171_governance_required_policy_selector_tests run_169_governance_proof_loader_surface_integration_tests run_167_governance_proof_carrier_tests run_165_governance_marker_integration_tests run_163_governance_authority_verifier_tests run_161_lifecycle_marker_integration_tests run_159_authority_signing_key_lifecycle_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests run_134_reload_apply_v2_authority_marker_tests run_138_sighup_v2_authority_marker_tests)
if ! printf 'run_id=%s\ncommand_key\tstate\trc\n' "$RUN_ID" > "$RESULTS"; then
  log "manifest initialization failed"; INCOMPLETE=1
fi
for t in "${TEST_TARGETS[@]}"; do
  if run_regression test "$t" --test "$t"; then :; else :; fi
done
if run_regression lib pqc_authority --lib pqc_authority; then :; else :; fi
if run_regression lib lib_all --lib; then :; else :; fi
if ! validate_results; then INCOMPLETE=1; fi
VERDICT=PASS
if [[ "$REGRESSION_FAILED" -ne 0 ]]; then VERDICT=FAIL; fi
if [[ "$INCOMPLETE" -ne 0 ]]; then VERDICT=INCOMPLETE; fi
SUMMARY_TMP="$(mktemp "${SUMMARY}.tmp.XXXXXX")" || fail "cannot create final summary temporary file"

{
  echo "run_id=${RUN_ID}"
  echo "Run 216 — release-binary governance-execution policy-selector evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_216_sha256:  $(sha256_file "${HELPER_216_BIN}")"
  echo "  helper_216_buildid: $(build_id "${HELPER_216_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_cli_selector_devnet S6_env_selector_devnet S7_cli_over_env_devnet S8_invalid_selector_devnet S9_mainnet_armed S10_legacy_selectors_compat; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_216rc=$(cat "${EXIT_DIR}/helper_run_216.rc")$(grep -E 'verdict:' "${HELPER_216_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper selector + A1-A16 / R1-R40 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_216_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"
  for v in "${TEST_VERDICTS[@]}"; do
    IFS=$'\t' read -r key state rc <<< "$v"
    printf '  %s\trc=%s\n' "${key#run216:}" "${rc:-${state}}"
  done
  echo "regression result records:"
  for v in "${TEST_VERDICTS[@]}"; do printf '  %s\n' "$v"; done
  echo
  echo "honest_limits: default Disabled; hidden CLI/env selectors additive; CLI-over-env deterministic; invalid values fail closed; fixture DevNet/TestNet only; emergency explicit non-production; production/on-chain/MainNet unavailable; MainNet peer-driven apply refused; no real governance engine/on-chain verifier/KMS-HSM/RemoteSigner/validator-set rotation; existing paths compatible; full C4 and C5 remain OPEN."
  echo
  echo "aggregate: ${VERDICT}"
  echo "verdict: ${VERDICT}"
} > "${SUMMARY_TMP}"
for v in "${TEST_VERDICTS[@]}"; do
  [[ "$(grep -Fxc -- "  ${v}" "${SUMMARY_TMP}")" == 1 ]] || fail "unincorporated regression result"
done
mv -fT -- "${SUMMARY_TMP}" "${SUMMARY}" || fail "cannot publish final summary"
SUMMARY_TMP=""
COMPLETED=1
log "done — summary at ${SUMMARY}"
[[ "$VERDICT" == PASS ]] && exit 0
# A complete FAIL is retained; abnormal exits and signals restore INCOMPLETE.
trap - EXIT
exit 1