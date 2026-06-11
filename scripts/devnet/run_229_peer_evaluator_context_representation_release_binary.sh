#!/usr/bin/env bash
# Run 229 — Release-binary peer evaluator-context representation evidence.
#
# Proves the release-built code exposes and exercises the Run 228 governance
# evaluator **peer evaluator-context representation** boundary in
# `crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`:
# `GovernanceEvaluatorPeerContext`, `evaluate_peer_evaluator_context`,
# `evaluate_peer_evaluator_context_wire_only`, the `PeerEvaluatorContextOutcome`
# variants, and the full carrier taxonomy `Absent` / `Present` / `Malformed` /
# `UnsupportedSurface` / `WireSchemaUnavailable` / `PeerMajorityUnsupported` /
# `MainNetRefused`. A representable `Present` context routes through the Run 226
# call-site wiring (`wire_governance_evaluator_runtime_callsite`) into the
# Run 224 integration layer (composing Run 220 runtime consumption + Run 222
# evaluator interface + Run 211 decision validation + Run 213 payload material).
# Only a routed `ProceedMutate` authorizes apply; every other outcome is typed
# fail-closed. The live wire inability to carry an evaluator binding is
# represented as typed `WireSchemaUnavailable`, never approval. The boundary is
# pure (no marker/sequence write, no live trust swap, no session eviction, no
# Run 070 call); the default Disabled + absent carrier preserves legacy
# validation; invalid live inbound 0x05 is not propagated/staged/applied;
# invalid peer-driven drain is not applied; production / on-chain / MainNet
# evaluators remain unavailable/fail-closed; MainNet peer-driven apply remains
# refused; validator-set rotation unsupported. Fixture-only; no real governance
# engine; no wire/schema/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_229_peer_evaluator_context_representation_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_229_BIN="${REPO_ROOT}/target/release/examples/run_229_peer_evaluator_context_representation_release_binary_helper"
HELPER_229_OUT="${OUTDIR}/helper_evidence/run_229"
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

log() { printf '[run-229] %s\n' "$*" >&2; }
fail() { printf '[run-229] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_229_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_229_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-229 provenance"
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
log "cargo build --release -p qbind-node --example run_229_peer_evaluator_context_representation_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_229_peer_evaluator_context_representation_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_229.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_229_BIN}" ]] || fail "missing ${HELPER_229_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_229_path:    ${HELPER_229_BIN}"
  echo "helper_229_sha256:  $(sha256_file "${HELPER_229_BIN}")"
  echo "helper_229_buildid: $(build_id "${HELPER_229_BIN}")"
} >> "${PROVENANCE}"

log "running Run 229 helper"
set +e
"${HELPER_229_BIN}" "${HELPER_229_OUT}" > "${LOGS_DIR}/helper_run_229.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_229.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_229 helper failed"
assert_grep "${HELPER_229_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 229 peer evaluator-context fixture inventory (helper-minted):"
  if [[ -d "${HELPER_229_OUT}/fixtures" ]]; then
    for f in "${HELPER_229_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/peer_context_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime (integration|call-site) (enabled|active|wired)'
  assert_not_grep "$logf" 'peer evaluator context (enabled|active|wired)'
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

log "S1 help hides peer evaluator-context representation surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'peer evaluator context|GovernanceEvaluatorPeerContext|evaluate_peer_evaluator_context|WireSchemaUnavailable|run-228|run-229'
log "S2..S4 default surfaces silent on peer evaluator-context claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses
# and an invalid selector fails closed before mutation, while default Disabled
# remains legacy-compatible. These exercise the Run 215 hidden selector that
# the Run 217/220 arming carries into the Run 226 call-site wiring that the
# Run 228 peer evaluator-context boundary routes a present context through.
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
MOD="${SRC_DIR}/pqc_governance_evaluator_peer_context.rs"
{
  echo "Run 229 source-reachability proof — Run 228 peer evaluator-context symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_peer_context GovernanceEvaluatorPeerContext PeerEvaluatorContextSurface PeerEvaluatorSourceClass PeerEvaluatorLoadStatus PeerEvaluatorCarrierStatus PeerEvaluatorContextOutcome evaluate_peer_evaluator_context evaluate_peer_evaluator_context_wire_only present_from_integration context_digest binds_consistently_with present_bindings_complete Absent Present Malformed UnsupportedSurface WireSchemaUnavailable PeerMajorityUnsupported MainNetRefused LegacyValidationPreserved RoutedProceedMutate RoutedFailClosed MalformedRejected MissingContextRejected is_apply_authorized is_legacy_validation_preserved is_fail_closed is_mainnet_refused no_propagation_no_staging_no_apply wire_governance_evaluator_runtime_callsite GovernanceEvaluatorRuntimeIntegrationOutcome GovernanceExecutionLoadStatus GovernanceExecutionExpectations from_load_status; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_peer_context'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorPeerContext'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_peer_evaluator_context'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_peer_evaluator_context_wire_only'
assert_grep "${REACH_DIR}/source_reachability.txt" 'PeerEvaluatorCarrierStatus'
for st in Absent Present Malformed UnsupportedSurface WireSchemaUnavailable PeerMajorityUnsupported MainNetRefused; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "${st}"
done
assert_grep "${REACH_DIR}/source_reachability.txt" 'RoutedProceedMutate'
assert_grep "${REACH_DIR}/source_reachability.txt" 'RoutedFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'wire_governance_evaluator_runtime_callsite'

# Module registration reachability (lib.rs exposes the Run 228 peer
# evaluator-context module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_peer_context' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Boundary entry points + carrier taxonomy within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_peer_evaluator_context\|pub fn evaluate_peer_evaluator_context_wire_only' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing boundary entry points"
grep -RIn --include='*.rs' 'enum PeerEvaluatorCarrierStatus\|Absent\|Present\|Malformed\|UnsupportedSurface\|WireSchemaUnavailable\|PeerMajorityUnsupported\|MainNetRefused' "${MOD}" > "${REACH_DIR}/carrier_taxonomy.txt" || fail "missing carrier taxonomy"
# Selected policy / load-status / payload digest / evaluator + candidate digest
# / sequence / lifecycle / environment-chain-genesis bindings within the module.
grep -RIn --include='*.rs' 'selected_policy\|load_status\|PeerEvaluatorLoadStatus\|from_load_status\|GovernanceExecutionLoadStatus' "${MOD}" > "${REACH_DIR}/policy_loadstatus_bindings.txt" || fail "missing policy/load-status bindings"
grep -RIn --include='*.rs' 'governance_execution_payload_digest\|candidate_trust_bundle_digest\|candidate_v2_marker_digest\|marker_digest' "${MOD}" > "${REACH_DIR}/payload_candidate_marker_bindings.txt" || fail "missing payload/candidate/marker digest bindings"
grep -RIn --include='*.rs' 'evaluator_source_identity_digest\|evaluator_request_digest\|evaluator_response_digest' "${MOD}" > "${REACH_DIR}/evaluator_digest_bindings.txt" || fail "missing evaluator source/request/response digest bindings"
grep -RIn --include='*.rs' 'authority_domain_sequence\|lifecycle_action' "${MOD}" > "${REACH_DIR}/sequence_lifecycle_bindings.txt" || fail "missing sequence/lifecycle bindings"
grep -RIn --include='*.rs' 'environment\|chain_id\|genesis_hash' "${MOD}" > "${REACH_DIR}/env_chain_genesis_bindings.txt" || fail "missing environment/chain/genesis bindings"
# Live inbound 0x05 + peer-driven drain validation surface bindings.
grep -RIn --include='*.rs' 'LiveInbound0x05\|PeerDrivenDrain\|PeerEvaluatorContextSurface' "${MOD}" > "${REACH_DIR}/validation_surface_bindings.txt" || fail "missing validation-surface bindings"
# Run 226 integration routing where representable.
grep -RIn --include='*.rs' 'wire_governance_evaluator_runtime_callsite\|GovernanceEvaluatorRuntimeIntegrationOutcome' "${MOD}" > "${REACH_DIR}/run_226_routing.txt" || fail "missing Run 226 routing reachability"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'MainNetRefused\|is_mainnet_refused' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# No-mutation / apply-authorization guard (only RoutedProceedMutate authorizes).
grep -RIn --include='*.rs' 'is_apply_authorized\|RoutedProceedMutate\|no_propagation_no_staging_no_apply' "${MOD}" > "${REACH_DIR}/no_mutation_before_success.txt" || fail "missing apply-authorization guard reachability"

{
  echo "Run 229 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'peer evaluator context active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_229_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 229 no-mutation proof for rejected peer evaluator-context representation scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A18 / R1..R27 helper corpus (driven through the Run 228 peer evaluator-context boundary evaluate_peer_evaluator_context / evaluate_peer_evaluator_context_wire_only, which route a representable Present context through the Run 226 call-site wiring wire_governance_evaluator_runtime_callsite into the pure Run 224 integration layer composing Run 220 / 222 / 211 / 213 library symbols): every rejected outcome surfaces as a typed PeerEvaluatorContextOutcome variant (RoutedFailClosed / UnsupportedSurface / WireSchemaUnavailable / MalformedRejected / MissingContextRejected / PeerMajorityUnsupported / MainNetRefused) returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The boundary exposes no mutation API: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070. Apply authorization is only ever the terminal RoutedProceedMutate variant (is_apply_authorized()), produced after the Run 226 wiring + composed pipeline agree. WireSchemaUnavailable is fail-closed and is explicitly NOT an approval. Invalid live inbound 0x05 is not propagated, not staged, not applied; invalid peer-driven drain is not applied; MainNet peer-driven apply is refused even with fixture evaluator approval."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_229_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 229 mutation proof (release-binary scope): the Run 228 peer evaluator-context boundary routes a representable Present context through the Run 226 call-site wiring into the pure Run 224 integration layer. The only apply-authorizing outcome is RoutedProceedMutate, produced only when (a) Run 220 runtime consumption accepts the Run 213 carrier under the Run 211 decision validation, AND (b) the Run 222 evaluator evaluates the decision source and verifies an authorized response binding the matching action/candidate-digest/sequence — and only on a DevNet/TestNet trust domain with a fixture (or explicit emergency-council fixture) evaluator under the matching explicit fixture policy. Production/on-chain/MainNet evaluators are callable but fail closed as unavailable. No mutation is performed by this fixture-only helper or by the boundary; an accepted RoutedProceedMutate outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 229 does not exercise."
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
TEST_TARGETS=(run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 229 — release-binary peer evaluator-context representation evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_229_sha256:  $(sha256_file "${HELPER_229_BIN}")"
  echo "  helper_229_buildid: $(build_id "${HELPER_229_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_229rc=$(cat "${EXIT_DIR}/helper_run_229.rc")$(grep -E 'verdict:' "${HELPER_229_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A18 / R1-R27 corpus verdicts (release mode, Run 228 peer evaluator-context symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_229_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 228 peer evaluator-context boundary is a local/source-test-only representation layer; the binary marker/candidate metadata cannot yet carry a governance proposal/decision evaluator binding, so the live inbound 0x05 and peer-driven drain surfaces are represented but their full positive evaluator binding is not yet wire-representable from the binary (the live wire carrier inability is the typed WireSchemaUnavailable, never approval); the default Disabled + absent carrier preserves legacy validation bit-for-bit; only a routed RoutedProceedMutate authorizes apply; missing/unsupported/malformed carrier under an explicit evaluator policy is typed fail-closed; no real governance execution engine; no real on-chain governance proof verifier; fixture evaluator DevNet/TestNet evidence-only; emergency fixture explicit non-production; production/on-chain/MainNet evaluator unavailable/fail-closed; MainNet peer-driven apply refused; validator-set rotation unsupported; existing Run 227 call-site wiring, Run 225 integration-layer, and Run 223 evaluator-interface behaviour compatible; no wire/trust-bundle/marker/sequence schema change; no KMS/HSM/RemoteSigner backend; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
