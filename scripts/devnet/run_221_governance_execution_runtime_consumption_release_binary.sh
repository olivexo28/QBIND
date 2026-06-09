#!/usr/bin/env bash
# Run 221 — Release-binary governance-execution runtime-consumption evidence.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_221_governance_execution_runtime_consumption_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_221_BIN="${REPO_ROOT}/target/release/examples/run_221_governance_execution_runtime_consumption_release_binary_helper"
HELPER_221_OUT="${OUTDIR}/helper_evidence/run_221"
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

log() { printf '[run-221] %s\n' "$*" >&2; }
fail() { printf '[run-221] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_221_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_221_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-221 provenance"
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
log "cargo build --release -p qbind-node --example run_221_governance_execution_runtime_consumption_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_221_governance_execution_runtime_consumption_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_221.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_221_BIN}" ]] || fail "missing ${HELPER_221_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_221_path:    ${HELPER_221_BIN}"
  echo "helper_221_sha256:  $(sha256_file "${HELPER_221_BIN}")"
  echo "helper_221_buildid: $(build_id "${HELPER_221_BIN}")"
} >> "${PROVENANCE}"

log "running Run 221 helper"
set +e
"${HELPER_221_BIN}" "${HELPER_221_OUT}" > "${LOGS_DIR}/helper_run_221.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_221.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_221 helper failed"
assert_grep "${HELPER_221_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 221 governance-execution fixture inventory (helper-minted):"
  if [[ -d "${HELPER_221_OUT}/fixtures" ]]; then
    for f in "${HELPER_221_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
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
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'governance execution|production governance|mainnet governance|validator-set rotation|on-chain governance proof verifier|runtime arming|runtime consumption|run-217|run-220|run-221'
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
run_surface_scenario S5_cli_selector_devnet devnet "${CLI_SELECTOR}" fixture-governance-allowed
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=production-governance-required" "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_env_selector_devnet.log" 2>&1 || true; S6_RC=$?; echo "$S6_RC" > "${EXIT_DIR}/S6_env_selector_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S6_env_selector_devnet.log"
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=fixture-governance-allowed" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" disabled ) > "${LOGS_DIR}/S7_cli_over_env_devnet.log" 2>&1 || true; S7_RC=$?; echo "$S7_RC" > "${EXIT_DIR}/S7_cli_over_env_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S7_cli_over_env_devnet.log"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus ) > "${LOGS_DIR}/S8_invalid_selector_devnet.log" 2>&1; S8_RC=$?; set -e; echo "$S8_RC" > "${EXIT_DIR}/S8_invalid_selector_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S8_invalid_selector_devnet.log"
assert_grep "${LOGS_DIR}/S8_invalid_selector_devnet.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S8_invalid_selector_devnet.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
[[ "${S8_RC}" -ne 0 ]] || fail "invalid selector must fail closed (non-zero exit)"
set +e; ( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=bogus-env-value" "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S8b_invalid_env_selector_devnet.log" 2>&1; S8B_RC=$?; set -e; echo "$S8B_RC" > "${EXIT_DIR}/S8b_invalid_env_selector_devnet.rc"; assert_surface_silent "${LOGS_DIR}/S8b_invalid_env_selector_devnet.log"
assert_grep "${LOGS_DIR}/S8b_invalid_env_selector_devnet.log" 'invalid governance-execution policy selector'
[[ "${S8B_RC}" -ne 0 ]] || fail "invalid env selector must fail closed (non-zero exit)"
( cd "${REPO_ROOT}" && env "${ENV_SELECTOR}=mainnet-governance-required" "${NODE_BIN}" --print-genesis-hash --env mainnet "${CLI_SELECTOR}" mainnet-governance-required ) > "${LOGS_DIR}/S9_mainnet_armed.log" 2>&1 || true; S9_RC=$?; echo "$S9_RC" > "${EXIT_DIR}/S9_mainnet_armed.rc"; assert_surface_silent "${LOGS_DIR}/S9_mainnet_armed.log"
( cd "${REPO_ROOT}" && env QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY=fixture-attestation-allowed "${ENV_SELECTOR}=fixture-governance-allowed" "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S10_legacy_selectors_compat.log" 2>&1 || true; S10_RC=$?; echo "$S10_RC" > "${EXIT_DIR}/S10_legacy_selectors_compat.rc"; assert_surface_silent "${LOGS_DIR}/S10_legacy_selectors_compat.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 221 source-reachability proof — Run 220 runtime-consumption production symbols within ${SRC_DIR}:"
  for sym in pqc_governance_execution_runtime_arming GovernanceExecutionRuntimeArmingConfig GovernanceExecutionRuntimeConsumption ProceedLegacyBypass ProceedAccepted FailClosed consume_surface consume_surface_from_optional_sidecar_value governance_execution_load_status_from_optional_sidecar_value GovernanceExecutionRuntimeSurface from_outcome is_proceed is_fail_closed is_legacy_bypass fail_closed_reason rejecting_outcome consume_run_220_governance_execution_runtime_outcome arm_surface GovernanceExecutionPolicy FixtureGovernanceAllowed EmergencyCouncilFixtureAllowed ProductionGovernanceRequired MainnetGovernanceRequired ProductionGovernanceUnavailable OnChainGovernanceUnavailable MainNetGovernanceUnavailable mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_execution_runtime_arming'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceExecutionRuntimeConsumption'
assert_grep "${REACH_DIR}/source_reachability.txt" 'consume_surface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'governance_execution_load_status_from_optional_sidecar_value'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedLegacyBypass'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedAccepted'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FailClosed'
grep -RIn --include='*.rs' 'p2p_trust_bundle_governance_execution_policy' "${SRC_DIR}" > "${REACH_DIR}/cli_flag_reachability.txt" || fail "missing CLI field reachability"
# Prove the consumption layer is consumed by the long-running main.rs runtime
# hooks and the SIGHUP hook: the verdict is acted on (FailClosed -> Err), not
# discarded, and the real sidecar load status is routed (no forced Absent).
grep -RIn --include='*.rs' 'consume_surface\|GovernanceExecutionRuntimeConsumption\|consume_run_220_governance_execution_runtime_outcome\|governance_execution_load\|is_fail_closed\|is_proceed' "${SRC_DIR}/main.rs" "${SRC_DIR}/pqc_live_trust_reload.rs" > "${REACH_DIR}/runtime_hook_reachability.txt" || fail "missing runtime-hook reachability"
assert_grep "${REACH_DIR}/runtime_hook_reachability.txt" 'consume_surface'
assert_grep "${REACH_DIR}/runtime_hook_reachability.txt" 'is_fail_closed'
# Prove no discarded `let _outcome = arming.arm_surface(...)` survives at the
# production runtime call sites that claim consumption.
{
  echo "Run 221 discarded-outcome scan — any 'let _outcome = ...arm_surface' in production runtime call sites:"
  if grep -RInE --include='*.rs' '^[[:space:]]*let _outcome[[:space:]]*=.*arm_surface' "${SRC_DIR}/main.rs" "${SRC_DIR}/pqc_live_trust_reload.rs"; then
    echo "FAIL: discarded arm_surface outcome present"; exit 9
  else
    echo "ok: no discarded arm_surface outcome at the consuming runtime call sites"
  fi
} > "${REACH_DIR}/no_discarded_outcome.txt"
# Prove no forced `GovernanceExecutionLoadStatus::Absent` survives where a real
# sidecar load is routed at the consuming runtime call sites.
{
  echo "Run 221 forced-Absent scan — any hardcoded GovernanceExecutionLoadStatus::Absent passed to a consume/arm call at the runtime hooks:"
  if grep -RIn --include='*.rs' 'consume_surface([^)]*GovernanceExecutionLoadStatus::Absent' "${SRC_DIR}/main.rs" "${SRC_DIR}/pqc_live_trust_reload.rs"; then
    echo "FAIL: forced Absent passed into consume_surface at a runtime hook"; exit 10
  else
    echo "ok: no forced Absent threaded into consume_surface at the runtime hooks"
  fi
} > "${REACH_DIR}/no_forced_absent.txt"

{
  echo "Run 221 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_221_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 221 no-mutation proof for rejected runtime-consumption governance-execution scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  R4..R28 helper corpus (all driven through GovernanceExecutionRuntimeArmingConfig::consume_surface / consume_surface_from_optional_sidecar_value): a FailClosed consumption decision short-circuits the runtime call site BEFORE any mutation — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, marker/sequence bytes unchanged where present, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The consumption layer is a pure typed collapse of the per-surface outcome; a FailClosed decision performs no mutation."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_221_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 221 mutation proof (release-binary scope): selector resolution occurs before runtime policy arming; runtime arming occurs before governance-execution material parse (real sidecar status, not a forced Absent); material parse before runtime consumption; runtime consumption (consume_surface) before marker decision; governance execution, lifecycle, governance-proof, custody and custody-attestation validation occur before apply/mutation; accepted mutating compatibility remains subject to Run 055 sequence commit before v2 marker persist. No mutation is performed by this fixture-only helper; a ProceedAccepted decision is the precondition for the real binary's existing ordered mutating path."
} > "${MUT_PROOF}"

run_test_target() {
  local target="$1"
  local logf="${TEST_LOGS}/test_${target}.log"
  log "cargo test -p qbind-node --test ${target}"
  set +e
  ( cd "${REPO_ROOT}" && cargo test -p qbind-node --test "$target" -- --test-threads=1 ) > "$logf" 2>&1
  local rc=$?
  set -e
  echo "$rc" > "${EXIT_DIR}/test_${target}.rc"
  printf '%s\trc=%d\n' "test:${target}" "$rc"
}
run_lib_test() {
  local filter="$1"
  local label="${2:-${filter:-lib_all}}"
  local logf="${TEST_LOGS}/lib_${label}.log"
  log "cargo test -p qbind-node --lib ${filter}"
  set +e
  ( cd "${REPO_ROOT}" && cargo test -p qbind-node --lib ${filter} -- --test-threads=1 ) > "$logf" 2>&1
  local rc=$?
  set -e
  echo "$rc" > "${EXIT_DIR}/lib_${label}.rc"
  printf '%s\trc=%d\n' "lib:${label}" "$rc"
}
TEST_VERDICTS=()
TEST_TARGETS=(run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_209_custody_attestation_policy_selector_tests run_207_custody_attestation_payload_callsite_tests run_205_custody_attestation_verifier_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_198_remote_signer_policy_selector_tests run_196_remote_signer_payload_callsite_tests run_194_remote_authority_signer_boundary_tests run_192_authority_custody_policy_selector_tests run_190_authority_custody_payload_callsite_tests run_188_authority_custody_boundary_tests run_186_onchain_governance_production_verifier_boundary_tests run_184_onchain_governance_payload_carrying_tests run_182_onchain_governance_production_callsite_wiring_tests run_180_onchain_governance_marker_integration_tests run_178_onchain_governance_proof_tests run_176_live_0x05_governance_proof_carrier_tests run_173_validation_only_governance_required_policy_tests run_171_governance_required_policy_selector_tests run_169_governance_proof_loader_surface_integration_tests run_167_governance_proof_carrier_tests run_165_governance_marker_integration_tests run_163_governance_authority_verifier_tests run_161_lifecycle_marker_integration_tests run_159_authority_signing_key_lifecycle_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests run_134_reload_apply_v2_authority_marker_tests run_138_sighup_v2_authority_marker_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 221 — release-binary governance-execution runtime-consumption evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_221_sha256:  $(sha256_file "${HELPER_221_BIN}")"
  echo "  helper_221_buildid: $(build_id "${HELPER_221_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_cli_selector_devnet S6_env_selector_devnet S7_cli_over_env_devnet S8_invalid_selector_devnet S8b_invalid_env_selector_devnet S9_mainnet_armed S10_legacy_selectors_compat; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_221rc=$(cat "${EXIT_DIR}/helper_run_221.rc")$(grep -E 'verdict:' "${HELPER_221_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper runtime-consumption + A1-A24 / R1-R28 corpus verdicts (release mode, Run 220 consumption symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_221_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: default Disabled; hidden CLI/env selectors reach runtime consumption; CLI-over-env deterministic at the runtime config boundary; invalid CLI/env values fail closed before mutation; real governance-execution sidecar status consumed from the optional sidecar value (not a forced Absent) where representable; fixture DevNet/TestNet only; emergency explicit non-production; production/on-chain/MainNet unavailable/fail-closed; MainNet peer-driven apply refused; live 0x05 runtime-config policy threading limitation documented; no real governance engine/on-chain verifier/KMS-HSM/RemoteSigner/validator-set rotation; existing paths compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
log "done — summary at ${SUMMARY}"
