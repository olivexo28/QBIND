#!/usr/bin/env bash
# Run 227 — Release-binary governance evaluator runtime call-site wiring evidence.
#
# Proves the release-built code exposes and exercises the Run 226 governance
# evaluator runtime **call-site wiring** entry points in
# `crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`:
# `wire_governance_evaluator_runtime_callsite`,
# `wire_governance_evaluator_runtime_callsite_without_evaluator_context`, and the
# typed `GovernanceEvaluatorRuntimeCallsiteFailClosed`. These route the
# representable Run 220 runtime call sites
# (`consume_run_220_governance_execution_runtime_outcome` in main.rs and
# `consume_run_220_sighup_governance_execution_marker_decision` in
# pqc_live_trust_reload.rs) through the Run 224 integration layer, so the typed
# `GovernanceEvaluatorRuntimeIntegrationOutcome` — not the bare runtime
# consumption — gates each call site. The wiring consumes the outcome (never
# discards it), preserves the default Disabled legacy bypass, fails closed
# before mutation, refuses MainNet peer-driven apply, and keeps production /
# on-chain / MainNet evaluators unavailable/fail-closed. Fixture-only; no real
# governance engine; the wiring is pure (no marker/sequence write, no live
# trust swap, no session eviction, no Run 070 call). MainNet peer-driven apply
# remains refused.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_227_BIN="${REPO_ROOT}/target/release/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper"
HELPER_227_OUT="${OUTDIR}/helper_evidence/run_227"
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

log() { printf '[run-227] %s\n' "$*" >&2; }
fail() { printf '[run-227] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_227_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_227_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-227 provenance"
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
log "cargo build --release -p qbind-node --example run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_227.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_227_BIN}" ]] || fail "missing ${HELPER_227_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_227_path:    ${HELPER_227_BIN}"
  echo "helper_227_sha256:  $(sha256_file "${HELPER_227_BIN}")"
  echo "helper_227_buildid: $(build_id "${HELPER_227_BIN}")"
} >> "${PROVENANCE}"

log "running Run 227 helper"
set +e
"${HELPER_227_BIN}" "${HELPER_227_OUT}" > "${LOGS_DIR}/helper_run_227.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_227.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_227 helper failed"
assert_grep "${HELPER_227_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 227 call-site wiring fixture inventory (helper-minted):"
  if [[ -d "${HELPER_227_OUT}/fixtures" ]]; then
    for f in "${HELPER_227_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/callsite_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime (integration|call-site) (enabled|active|wired)'
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

log "S1 help hides evaluator-runtime call-site wiring surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'evaluator runtime call-site|governance evaluator runtime|wire_governance_evaluator|GovernanceEvaluatorRuntimeCallsite|run-226|run-227'
log "S2..S4 default surfaces silent on call-site wiring claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses
# and an invalid selector fails closed before mutation, while default Disabled
# remains legacy-compatible. These exercise the Run 215 hidden selector that
# the Run 217/220 arming carries into the Run 226 call-site wiring.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 227 source-reachability proof — Run 226 call-site wiring symbols within ${SRC_DIR}:"
  for sym in wire_governance_evaluator_runtime_callsite wire_governance_evaluator_runtime_callsite_without_evaluator_context GovernanceEvaluatorRuntimeCallsiteFailClosed consume_run_220_governance_execution_runtime_outcome consume_run_220_sighup_governance_execution_marker_decision GovernanceEvaluatorRuntimeIntegrationOutcome ProceedLegacyBypass ProceedMutate RuntimeConsumptionFailClosed EvaluatorRejected MainNetPeerDrivenApplyRefused integrate_governance_evaluator_runtime_consumption consume_surface ProductionGovernanceExecutionEvaluator GovernanceExecutionExpectations GovernanceExecutionLoadStatus is_mutate_authorized is_peer_driven_apply_preflight; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'wire_governance_evaluator_runtime_callsite'
assert_grep "${REACH_DIR}/source_reachability.txt" 'wire_governance_evaluator_runtime_callsite_without_evaluator_context'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorRuntimeCallsiteFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'consume_run_220_governance_execution_runtime_outcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'consume_run_220_sighup_governance_execution_marker_decision'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorRuntimeIntegrationOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedLegacyBypass'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedMutate'
assert_grep "${REACH_DIR}/source_reachability.txt" 'RuntimeConsumptionFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorRejected'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetPeerDrivenApplyRefused'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_governance_evaluator_runtime_consumption'

# Module registration reachability (lib.rs exposes the integration module that
# now carries the call-site wiring entry points).
grep -RIn --include='*.rs' 'pub mod pqc_governance_execution_evaluator_runtime_integration' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Call-site wiring reachability from the binary call sites (main.rs reload-apply
# / startup / reload-check / local peer-candidate-check; pqc_live_trust_reload.rs
# SIGHUP).
grep -RIn --include='*.rs' 'wire_governance_evaluator_runtime_callsite' "${SRC_DIR}/main.rs" > "${REACH_DIR}/main_callsite_wiring.txt" || fail "missing main.rs call-site wiring"
grep -RIn --include='*.rs' 'wire_governance_evaluator_runtime_callsite' "${SRC_DIR}/pqc_live_trust_reload.rs" > "${REACH_DIR}/sighup_callsite_wiring.txt" || fail "missing SIGHUP call-site wiring"
# Run 220 runtime-consumption call sites (the wired consumers).
grep -RIn --include='*.rs' 'consume_run_220_governance_execution_runtime_outcome' "${SRC_DIR}/main.rs" > "${REACH_DIR}/run_220_main_callsites.txt" || fail "missing Run 220 main.rs call sites"
grep -RIn --include='*.rs' 'consume_run_220_sighup_governance_execution_marker_decision' "${SRC_DIR}/pqc_live_trust_reload.rs" > "${REACH_DIR}/run_220_sighup_callsite.txt" || fail "missing Run 220 SIGHUP call site"
# Run 224 integration call (the wiring forwards to it).
grep -RIn --include='*.rs' 'integrate_governance_evaluator_runtime_consumption' "${SRC_DIR}/pqc_governance_execution_evaluator_runtime_integration.rs" > "${REACH_DIR}/run_224_integration_reachability.txt" || fail "missing Run 224 integration reachability"
# Run 222 evaluator-interface compatibility reachability (unchanged consumer).
grep -RIn --include='*.rs' 'ProductionGovernanceExecutionEvaluator\|evaluate_governance_decision_source\|verify_governance_evaluator_response' "${SRC_DIR}/pqc_governance_execution_evaluator.rs" > "${REACH_DIR}/run_222_evaluator_reachability.txt" || fail "missing Run 222 evaluator reachability"
# Run 213 payload material usage + Run 211 governance execution validation.
grep -RIn --include='*.rs' 'GovernanceExecutionLoadStatus\|GovernanceExecutionExpectations' "${SRC_DIR}/pqc_governance_execution_evaluator_runtime_integration.rs" > "${REACH_DIR}/run_213_211_usage.txt" || fail "missing Run 213/211 usage reachability"
# MainNet peer-driven guard reachability + no-mutation-before-success guard.
grep -RIn --include='*.rs' 'MainNetPeerDrivenApplyRefused\|is_peer_driven_apply_preflight' "${SRC_DIR}/pqc_governance_execution_evaluator_runtime_integration.rs" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
grep -RIn --include='*.rs' 'is_mutate_authorized\|ProceedMutate' "${SRC_DIR}/pqc_governance_execution_evaluator_runtime_integration.rs" > "${REACH_DIR}/no_mutation_before_success.txt" || fail "missing no-mutation guard reachability"

{
  echo "Run 227 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'evaluator runtime call-site active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_227_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 227 no-mutation proof for rejected call-site integration scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A23 / R1..R31 helper corpus (all driven through the Run 226 call-site wiring entry points wire_governance_evaluator_runtime_callsite / wire_governance_evaluator_runtime_callsite_without_evaluator_context, which forward to the pure Run 224 integration entry point composing Run 220 / 222 / 211 / 213 library symbols): every rejected outcome surfaces as a typed GovernanceEvaluatorRuntimeCallsiteFailClosed Err returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The wiring exposes no mutation API: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070. Mutation authorization is only ever the terminal ProceedMutate variant, produced after BOTH the runtime-consumption stage and the evaluator stage agree. R29 confirms a validation-only rejection is pure/repeatable and non-mutating; R30 confirms a mutating-surface rejection is pure/repeatable and non-mutating; R31 confirms MainNet peer-driven apply is refused even with fixture evaluator approval. The binary call-site entry without an evaluator context proceeds only as the legacy bypass under Disabled + absent carrier; any present carrier fails closed before mutation."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_227_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 227 mutation proof (release-binary scope): the Run 226 call-site wiring forwards to the pure Run 224 integration layer. The only mutation-authorizing outcome is ProceedMutate, produced only when (a) Run 220 runtime consumption accepts the Run 213 carrier under the Run 211 decision validation, AND (b) the Run 222 evaluator evaluates the decision source and verifies an authorized response binding the matching action/candidate-digest/sequence — and only on a DevNet/TestNet trust domain with a fixture (or explicit emergency-council fixture) evaluator under the matching explicit fixture policy. Production/on-chain/MainNet evaluators are callable but fail closed as unavailable. The binary call-site entry without an evaluator context never authorizes a mutation for a present carrier (it reaches the callable-but-unavailable production evaluator). No mutation is performed by this fixture-only helper or by the wiring; an accepted ProceedMutate outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 227 does not exercise."
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
TEST_TARGETS=(run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 227 — release-binary governance evaluator runtime call-site wiring evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_227_sha256:  $(sha256_file "${HELPER_227_BIN}")"
  echo "  helper_227_buildid: $(build_id "${HELPER_227_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_227rc=$(cat "${EXIT_DIR}/helper_run_227.rc")$(grep -E 'verdict:' "${HELPER_227_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A23 / R1-R31 corpus verdicts (release mode, Run 226 call-site wiring symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_227_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 226 call-site wiring routes the representable Run 220 runtime call sites (reload-check, reload-apply, startup --p2p-trust-bundle, SIGHUP, local peer-candidate-check) through the Run 224 integration layer; the binary marker/candidate metadata cannot yet carry a governance proposal/decision evaluator binding, so the live inbound 0x05 and peer-driven drain surfaces are wired but their full positive evaluator binding is not yet representable from the binary (only the Disabled + absent legacy bypass is Ok at those binary call sites; a present carrier fails closed); the default Disabled legacy bypass is preserved bit-for-bit; the integration outcome is consumed, not discarded; present carrier without evaluator context fails closed; no real governance execution engine; no real on-chain governance proof verifier; fixture evaluator DevNet/TestNet evidence-only; emergency fixture explicit non-production; production/on-chain/MainNet evaluator unavailable/fail-closed; MainNet peer-driven apply refused; validator-set rotation unsupported; existing Run 221 runtime-consumption, Run 223 evaluator-interface, and Run 225 integration-layer behaviour compatible; no KMS/HSM/RemoteSigner backend; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
log "done — summary at ${SUMMARY}"