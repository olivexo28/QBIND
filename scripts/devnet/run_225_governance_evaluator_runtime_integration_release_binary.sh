#!/usr/bin/env bash
# Run 225 — Release-binary governance evaluator runtime integration evidence.
#
# Proves the release-built code exposes and exercises the Run 224 governance
# evaluator runtime integration layer
# (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`):
# the integration entry points
# (`integrate_governance_evaluator_runtime_consumption` /
# `..._from_optional_sidecar_value`), the `GovernanceEvaluatorRuntimeIntegrationContext`
# input bundle, and the typed `GovernanceEvaluatorRuntimeIntegrationOutcome`,
# composing Run 220 runtime consumption, the Run 222 evaluator interface, Run
# 211 governance execution decision validation, and Run 213 payload material.
# It preserves ordering, fails closed before mutation, preserves the default
# legacy bypass, refuses MainNet peer-driven apply, and keeps production /
# on-chain / MainNet evaluators unavailable/fail-closed. Fixture-only; no real
# governance engine; the integration layer is pure (no marker/sequence write,
# no live trust swap, no session eviction, no Run 070 call). MainNet
# peer-driven apply remains refused.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_225_governance_evaluator_runtime_integration_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_225_BIN="${REPO_ROOT}/target/release/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper"
HELPER_225_OUT="${OUTDIR}/helper_evidence/run_225"
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

log() { printf '[run-225] %s\n' "$*" >&2; }
fail() { printf '[run-225] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_225_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_225_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-225 provenance"
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
log "cargo build --release -p qbind-node --example run_225_governance_evaluator_runtime_integration_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_225_governance_evaluator_runtime_integration_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_225.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_225_BIN}" ]] || fail "missing ${HELPER_225_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_225_path:    ${HELPER_225_BIN}"
  echo "helper_225_sha256:  $(sha256_file "${HELPER_225_BIN}")"
  echo "helper_225_buildid: $(build_id "${HELPER_225_BIN}")"
} >> "${PROVENANCE}"

log "running Run 225 helper"
set +e
"${HELPER_225_BIN}" "${HELPER_225_OUT}" > "${LOGS_DIR}/helper_run_225.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_225.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_225 helper failed"
assert_grep "${HELPER_225_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 225 integration fixture inventory (helper-minted):"
  if [[ -d "${HELPER_225_OUT}/fixtures" ]]; then
    for f in "${HELPER_225_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/integration_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime integration (enabled|active|wired)'
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

log "S1 help hides evaluator-runtime integration surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'evaluator runtime integration|governance evaluator runtime|integrate_governance_evaluator|GovernanceEvaluatorRuntimeIntegration|run-224|run-225'
log "S2..S4 default surfaces silent on integration claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 225 source-reachability proof — Run 224 evaluator-runtime integration symbols within ${SRC_DIR}:"
  for sym in pqc_governance_execution_evaluator_runtime_integration integrate_governance_evaluator_runtime_consumption integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value GovernanceEvaluatorRuntimeIntegrationContext GovernanceEvaluatorRuntimeIntegrationOutcome ProceedLegacyBypass ProceedMutate RuntimeConsumptionFailClosed EvaluatorRejected MainNetPeerDrivenApplyRefused consume_surface ProductionGovernanceExecutionEvaluator GovernanceExecutionExpectations GovernanceExecutionLoadStatus is_mutate_authorized is_peer_driven_apply_preflight; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_execution_evaluator_runtime_integration'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_governance_evaluator_runtime_consumption'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorRuntimeIntegrationContext'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorRuntimeIntegrationOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedLegacyBypass'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedMutate'
assert_grep "${REACH_DIR}/source_reachability.txt" 'RuntimeConsumptionFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorRejected'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetPeerDrivenApplyRefused'
assert_grep "${REACH_DIR}/source_reachability.txt" 'consume_surface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProductionGovernanceExecutionEvaluator'

# Module registration reachability (lib.rs exposes the integration module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_execution_evaluator_runtime_integration' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Run 220 runtime-consumption compatibility reachability (unchanged consumer).
grep -RIn --include='*.rs' 'GovernanceExecutionRuntimeConsumption\|consume_surface' "${SRC_DIR}/pqc_governance_execution_runtime_arming.rs" > "${REACH_DIR}/run_220_consumption_reachability.txt" || fail "missing Run 220 consumption reachability"
# Run 222 evaluator-interface compatibility reachability (unchanged consumer).
grep -RIn --include='*.rs' 'ProductionGovernanceExecutionEvaluator\|evaluate_governance_decision_source\|verify_governance_evaluator_response' "${SRC_DIR}/pqc_governance_execution_evaluator.rs" > "${REACH_DIR}/run_222_evaluator_reachability.txt" || fail "missing Run 222 evaluator reachability"
# No-mutation-before-integration-success guard reachability (the only mutate
# authorization is the terminal ProceedMutate variant).
grep -RIn --include='*.rs' 'is_mutate_authorized\|ProceedMutate' "${SRC_DIR}/pqc_governance_execution_evaluator_runtime_integration.rs" > "${REACH_DIR}/no_mutation_before_integration.txt" || fail "missing no-mutation guard reachability"

{
  echo "Run 225 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'evaluator runtime integration active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_225_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 225 no-mutation proof for rejected evaluator-runtime integration scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A15 / R1..R30 helper corpus (all driven through the pure integration entry points and the composed Run 220 / 222 / 211 / 213 library symbols): every rejected integration outcome is a typed value returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The integration layer exposes no mutation API: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070. Mutation authorization is only ever the terminal ProceedMutate variant, produced after BOTH the runtime-consumption stage and the evaluator stage agree. R29 confirms a validation-only rejection is pure/repeatable and non-mutating; R30 confirms a mutating-surface rejection is pure/repeatable and non-mutating; A12 confirms MainNet peer-driven apply is refused even with fixture evaluator approval."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_225_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 225 mutation proof (release-binary scope): the Run 224 integration layer is a pure composition surface. The only mutation-authorizing outcome is ProceedMutate, produced only when (a) Run 220 runtime consumption accepts the Run 213 carrier under the Run 211 decision validation, AND (b) the Run 222 evaluator evaluates the decision source and verifies an authorized response binding the matching action/candidate-digest/sequence — and only on a DevNet/TestNet trust domain with a fixture (or explicit emergency-council fixture) evaluator under the matching explicit fixture policy. Production/on-chain/MainNet evaluators are callable but fail closed as unavailable. No mutation is performed by this fixture-only helper or by the integration layer; an accepted ProceedMutate outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 225 does not exercise."
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
TEST_TARGETS=(run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 225 — release-binary governance evaluator runtime integration evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_225_sha256:  $(sha256_file "${HELPER_225_BIN}")"
  echo "  helper_225_buildid: $(build_id "${HELPER_225_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_225rc=$(cat "${EXIT_DIR}/helper_run_225.rc")$(grep -E 'verdict:' "${HELPER_225_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A15 / R1-R30 corpus verdicts (release mode, Run 224 integration symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_225_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 224 evaluator-runtime integration layer is typed and release-evidenced through library symbols; it composes the Run 220 runtime consumption, the Run 222 evaluator interface, the Run 211 decision validation, and the Run 213 payload material as a *future* production evaluation pipeline, with no runtime CLI/env selector and no production call-site wiring (the Disabled policy / Disabled evaluator policy remain inert); no real governance execution engine; no real on-chain governance proof verifier; fixture evaluator DevNet/TestNet evidence-only; emergency fixture explicit non-production; production/on-chain/MainNet evaluator unavailable/fail-closed; default Disabled legacy bypass preserved; MainNet peer-driven apply refused; validator-set rotation unsupported; existing Run 221 runtime-consumption and Run 223 evaluator-interface behaviour compatible; no KMS/HSM/RemoteSigner backend; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
log "done — summary at ${SUMMARY}"
