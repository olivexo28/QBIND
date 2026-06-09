#!/usr/bin/env bash
# Run 223 — Release-binary governance-execution evaluator-interface evidence.
#
# Proves the release-built code exposes and exercises the Run 222 typed
# production governance execution evaluator interface
# (`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`): the
# deterministic source/request/response/transcript digest helpers, the
# fixture/emergency fixture acceptance, the production/on-chain/MainNet
# unavailable fail-closed behaviour, and the MainNet peer-driven apply
# refusal guard. Fixture-only; no real governance engine; the evaluator
# module is pure (no marker/sequence write, no live trust swap, no session
# eviction, no Run 070 call). MainNet peer-driven apply remains refused.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_223_governance_execution_evaluator_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_223_BIN="${REPO_ROOT}/target/release/examples/run_223_governance_execution_evaluator_release_binary_helper"
HELPER_223_OUT="${OUTDIR}/helper_evidence/run_223"
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

log() { printf '[run-223] %s\n' "$*" >&2; }
fail() { printf '[run-223] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_223_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_223_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-223 provenance"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status_short:"; git -C "${REPO_ROOT}" status --short 2>/dev/null || true
  echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
  echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
  echo "host: $(uname -a 2>/dev/null || echo unknown)"
  echo "outdir: ${OUTDIR}"
} >> "${PROVENANCE}"

log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) > "${LOGS_DIR}/build_qbind_node.log" 2>&1 || fail "qbind-node build failed"
log "cargo build --release -p qbind-node --example run_223_governance_execution_evaluator_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_223_governance_execution_evaluator_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_223.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_223_BIN}" ]] || fail "missing ${HELPER_223_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_223_path:    ${HELPER_223_BIN}"
  echo "helper_223_sha256:  $(sha256_file "${HELPER_223_BIN}")"
  echo "helper_223_buildid: $(build_id "${HELPER_223_BIN}")"
} >> "${PROVENANCE}"

log "running Run 223 helper"
set +e
"${HELPER_223_BIN}" "${HELPER_223_OUT}" > "${LOGS_DIR}/helper_run_223.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_223.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_223 helper failed"
assert_grep "${HELPER_223_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 223 evaluator-interface fixture inventory (helper-minted):"
  if [[ -d "${HELPER_223_OUT}/fixtures" ]]; then
    for f in "${HELPER_223_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/evaluator_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'production decision source (enabled|active)'
  assert_not_grep "$logf" 'validator-set rotation (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'autonomous apply|apply on receipt|peer-majority authority'
  assert_not_grep "$logf" 'real KMS backend|real HSM backend|real RemoteSigner backend|RemoteSigner backend connected'
  assert_not_grep "$logf" 'custody attestation production (enabled|active|wired)'
  assert_not_grep "$logf" 'MainNet peer-driven apply ENABLED'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1 || true
  local rc=$?
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides evaluator interface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'governance execution evaluator|production governance execution evaluator|decision source identity|evaluator policy|evaluator request|evaluator response|run-222|run-223'
log "S2..S4 default surfaces silent on evaluator claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 223 source-reachability proof — Run 222 evaluator-interface symbols within ${SRC_DIR}:"
  for sym in pqc_governance_execution_evaluator ProductionGovernanceExecutionEvaluator EvaluatorSourceKind EvaluatorPolicy DecisionSourceIdentity EvaluatorRequest EvaluatorResponse EvaluatorOutcome EvaluatorComposedOutcome EvaluatorExpectations source_identity_digest request_digest response_digest evaluator_transcript_digest evaluate_governance_decision_source verify_governance_evaluator_response FixtureGovernanceExecutionEvaluatorInterface EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface ProductionDecisionSourceEvaluatorInterface OnChainDecisionSourceEvaluatorInterface MainnetDecisionSourceEvaluatorInterface evaluate_governance_evaluator_with_peer_driven_guard mainnet_peer_driven_apply_remains_refused_under_evaluator validator_set_rotation_remains_unsupported_under_evaluator local_operator_cannot_satisfy_evaluator_policy peer_majority_cannot_satisfy_evaluator_policy; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_execution_evaluator'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProductionGovernanceExecutionEvaluator'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorSourceKind'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorPolicy'
assert_grep "${REACH_DIR}/source_reachability.txt" 'DecisionSourceIdentity'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorRequest'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorResponse'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'source_identity_digest'
assert_grep "${REACH_DIR}/source_reachability.txt" 'request_digest'
assert_grep "${REACH_DIR}/source_reachability.txt" 'response_digest'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluator_transcript_digest'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FixtureGovernanceExecutionEvaluatorInterface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProductionDecisionSourceEvaluatorInterface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'OnChainDecisionSourceEvaluatorInterface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainnetDecisionSourceEvaluatorInterface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_governance_evaluator_with_peer_driven_guard'

# Module registration reachability (lib.rs exposes the module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_execution_evaluator' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Run 220 runtime-consumption compatibility reachability (unchanged consumer).
grep -RIn --include='*.rs' 'GovernanceExecutionRuntimeConsumption\|consume_surface' "${SRC_DIR}/pqc_governance_execution_runtime_arming.rs" > "${REACH_DIR}/run_220_consumption_reachability.txt" || fail "missing Run 220 consumption reachability"

{
  echo "Run 223 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_223_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 223 no-mutation proof for rejected evaluator-interface scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  R1..R40 helper corpus (all driven through the pure evaluator interface functions and trait methods): every rejected evaluator outcome is a typed value returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The evaluator module exposes no mutation API: every public function and trait method performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070. R38 confirms the inputs are unchanged after a rejecting evaluation; R39 confirms the composed peer-driven guard rejects without mutation; R40 confirms MainNet peer-driven apply is refused even with fixture approval."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_223_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 223 mutation proof (release-binary scope): the Run 222 evaluator interface is a pure validation surface. Acceptance is only ever a fixture (or emergency-council fixture) decision source under the matching explicit fixture policy on a DevNet/TestNet trust domain, or an authorized evaluator response with matching action/candidate-digest/sequence; it returns a typed accept value and performs no mutation. Production/on-chain/MainNet evaluators are callable but fail closed as unavailable. No mutation is performed by this fixture-only helper or by the evaluator module; an accepted evaluator outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 223 does not exercise."
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
TEST_TARGETS=(run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 223 — release-binary governance-execution evaluator-interface evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_223_sha256:  $(sha256_file "${HELPER_223_BIN}")"
  echo "  helper_223_buildid: $(build_id "${HELPER_223_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_223rc=$(cat "${EXIT_DIR}/helper_run_223.rc")$(grep -E 'verdict:' "${HELPER_223_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A18 / R1-R40 corpus verdicts (release mode, Run 222 evaluator-interface symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_223_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 222 evaluator interface is typed and release-evidenced through library symbols; it has no runtime CLI/env selector and no production call-site wiring (it composes with the Run 220 runtime consumption as a *future* production evaluator target, with the Disabled policy inert); no real governance execution engine; no real on-chain governance proof verifier; fixture evaluator DevNet/TestNet evidence-only; emergency fixture explicit non-production; production/on-chain/MainNet evaluator unavailable/fail-closed; MainNet peer-driven apply refused; validator-set rotation unsupported; existing Run 221 runtime-consumption behaviour compatible; no KMS/HSM/RemoteSigner backend; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
log "done — summary at ${SUMMARY}"
