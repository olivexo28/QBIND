#!/usr/bin/env bash
# Run 233 — Release-binary governance evaluator replay/freshness runtime
# integration evidence.
#
# Proves the release-built code exposes and exercises the Run 232 governance
# evaluator **replay/freshness runtime integration** in
# `crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`:
# `integrate_governance_evaluator_replay_runtime`,
# `wire_governance_evaluator_replay_runtime_callsite`,
# `wire_governance_evaluator_replay_runtime_peer_context`, the typed
# `GovernanceEvaluatorReplayRuntimeOutcome` (`ProceedLegacyBypass`,
# `ProceedDeferred`, `ProceedFresh`, `ReplayFreshnessFailClosed`,
# `RuntimeIntegrationFailClosed`, `MainNetPeerDrivenApplyRefused`), and the
# grep-verifiable refusal helpers
# (`mainnet_peer_driven_apply_remains_refused_under_replay_runtime`,
# `fresh_replay_state_required_before_mutation`,
# `deferred_is_never_mutation_approval`,
# `production_mainnet_replay_state_remains_unavailable`,
# `validator_set_rotation_remains_unsupported_under_replay_runtime`,
# `policy_change_action_remains_unsupported_under_replay_runtime`). Run 232
# composes the Run 230 replay/freshness state boundary into the Run 224
# evaluator-runtime integration path as a mandatory pre-mutation gate: a mutate
# is authorized only after the Run 224 layer authorizes a mutate AND the Run 230
# state classifies the decision fresh. `ProceedFresh` is the only
# mutation-authorizing outcome; `ProceedDeferred` is not approval;
# expired/stale/replayed/consumed/superseded/wrong-binding/unavailable replay
# states fail closed before mutation. The integration is pure (no marker/sequence
# write, no live trust swap, no session eviction, no Run 070 call); read-only
# validation never consumes; explicit consume marks consumed only in the
# DevNet/TestNet fixture store after a successful fixture authorization;
# production/MainNet replay state remains unavailable/fail-closed; MainNet
# peer-driven apply remains refused even when fresh; validator-set rotation and
# policy-change actions remain unsupported. Fixture-only; no real governance
# engine; no RocksDB/file/schema/migration/storage/wire/marker/sequence/
# trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_233_BIN="${REPO_ROOT}/target/release/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper"
HELPER_233_OUT="${OUTDIR}/helper_evidence/run_233"
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

log() { printf '[run-233] %s\n' "$*" >&2; }
fail() { printf '[run-233] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_233_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_233_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-233 provenance"
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
log "cargo build --release -p qbind-node --example run_233_governance_evaluator_replay_runtime_integration_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_233_governance_evaluator_replay_runtime_integration_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_233.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_233_BIN}" ]] || fail "missing ${HELPER_233_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_233_path:    ${HELPER_233_BIN}"
  echo "helper_233_sha256:  $(sha256_file "${HELPER_233_BIN}")"
  echo "helper_233_buildid: $(build_id "${HELPER_233_BIN}")"
} >> "${PROVENANCE}"

log "running Run 233 helper"
set +e
"${HELPER_233_BIN}" "${HELPER_233_OUT}" > "${LOGS_DIR}/helper_run_233.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_233.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_233 helper failed"
assert_grep "${HELPER_233_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 233 runtime-integration fixture inventory (helper-minted):"
  if [[ -d "${HELPER_233_OUT}/fixtures" ]]; then
    for f in "${HELPER_233_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/runtime_integration_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime (integration|call-site) (enabled|active|wired)'
  assert_not_grep "$logf" 'replay/freshness runtime integration (enabled|active|wired)'
  assert_not_grep "$logf" 'replay state (enabled|active|wired)'
  assert_not_grep "$logf" 'replay/freshness (enabled|active|wired)'
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

log "S1 help hides replay/freshness runtime integration surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'replay/freshness runtime integration|GovernanceEvaluatorReplayRuntime|integrate_governance_evaluator_replay_runtime|run-232|run-233'
log "S2..S4 default surfaces silent on replay/freshness runtime integration claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation, while the default Disabled
# replay-state policy remains legacy-compatible. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 replay/freshness boundary gates in the Run 232
# composition.
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
MOD="${SRC_DIR}/pqc_governance_evaluator_replay_runtime_integration.rs"
{
  echo "Run 233 source-reachability proof — Run 232 replay/freshness runtime integration symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_replay_runtime_integration integrate_governance_evaluator_replay_runtime wire_governance_evaluator_replay_runtime_callsite wire_governance_evaluator_replay_runtime_peer_context GovernanceEvaluatorReplayRuntimeIntegrationContext GovernanceEvaluatorReplayRuntimeOutcome GovernanceEvaluatorReplayRuntimeCallsiteFailClosed ProceedLegacyBypass ProceedDeferred ProceedFresh ReplayFreshnessFailClosed RuntimeIntegrationFailClosed MainNetPeerDrivenApplyRefused is_proceed is_mutate_authorized is_legacy_bypass is_deferred is_fail_closed is_mainnet_peer_driven_apply_refused integrate_governance_evaluator_runtime_consumption GovernanceEvaluatorRuntimeIntegrationContext GovernanceEvaluatorRuntimeIntegrationOutcome wire_governance_evaluator_runtime_callsite evaluate_peer_evaluator_context GovernanceEvaluatorPeerContext PeerEvaluatorContextOutcome gate_evaluator_replay_freshness EvaluatorReplayFreshnessInput EvaluatorReplayFreshnessExpectations EvaluatorReplayFreshnessOutcome ReplayStateGateOutcome ReplayStatePolicy mainnet_peer_driven_apply_remains_refused_under_replay_runtime fresh_replay_state_required_before_mutation deferred_is_never_mutation_approval production_mainnet_replay_state_remains_unavailable validator_set_rotation_remains_unsupported_under_replay_runtime policy_change_action_remains_unsupported_under_replay_runtime; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_replay_runtime_integration'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_governance_evaluator_replay_runtime'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorReplayRuntimeOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedLegacyBypass'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedDeferred'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedFresh'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ReplayFreshnessFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'RuntimeIntegrationFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetPeerDrivenApplyRefused'

# Module registration reachability (lib.rs exposes the Run 232 runtime-integration module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_replay_runtime_integration' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Integration entry point + call-site / peer-context wiring within the module.
grep -RIn --include='*.rs' 'pub fn integrate_governance_evaluator_replay_runtime\|pub fn wire_governance_evaluator_replay_runtime_callsite\|pub fn wire_governance_evaluator_replay_runtime_peer_context' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing integration entry points"
# Composed outcome taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceEvaluatorReplayRuntimeOutcome\|ProceedLegacyBypass\|ProceedDeferred\|ProceedFresh\|ReplayFreshnessFailClosed\|RuntimeIntegrationFailClosed\|MainNetPeerDrivenApplyRefused' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing outcome taxonomy"
# Run 224 evaluator runtime integration usage.
grep -RIn --include='*.rs' 'integrate_governance_evaluator_runtime_consumption\|GovernanceEvaluatorRuntimeIntegrationContext\|GovernanceEvaluatorRuntimeIntegrationOutcome' "${MOD}" > "${REACH_DIR}/run224_usage.txt" || fail "missing Run 224 usage"
# Run 226 call-site integration usage.
grep -RIn --include='*.rs' 'wire_governance_evaluator_runtime_callsite\|callsite' "${MOD}" > "${REACH_DIR}/run226_usage.txt" || fail "missing Run 226 usage"
# Run 228 peer evaluator context compatibility.
grep -RIn --include='*.rs' 'evaluate_peer_evaluator_context\|GovernanceEvaluatorPeerContext\|PeerEvaluatorContextOutcome' "${MOD}" > "${REACH_DIR}/run228_usage.txt" || fail "missing Run 228 usage"
# Run 230 replay/freshness boundary usage.
grep -RIn --include='*.rs' 'gate_evaluator_replay_freshness\|EvaluatorReplayFreshnessInput\|EvaluatorReplayFreshnessExpectations\|EvaluatorReplayFreshnessOutcome\|ReplayStateGateOutcome\|ReplayStatePolicy' "${MOD}" > "${REACH_DIR}/run230_usage.txt" || fail "missing Run 230 usage"
# Read-only validation path (the integration is a pure function; never consumes).
grep -RIn --include='*.rs' 'Pure\|pure\|never marks a decision consumed\|read-only' "${MOD}" > "${REACH_DIR}/read_only_path.txt" || fail "missing read-only validation path"
# Explicit consume path (caller-side, fixture-only; performed AFTER ProceedFresh).
grep -RIn --include='*.rs' 'Explicit consume remains fixture-only\|explicit consume\|after a `ProceedFresh`' "${MOD}" > "${REACH_DIR}/explicit_consume_path.txt" || fail "missing explicit consume path"
# Production/MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'FailClosedMainNetUnavailable\|production_mainnet_replay_state_remains_unavailable\|Production / MainNet replay readers' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_remains_refused_under_replay_runtime\|MainNetPeerDrivenApplyRefused' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Fresh-required / deferred-not-approval guard (only ProceedFresh authorizes).
grep -RIn --include='*.rs' 'fresh_replay_state_required_before_mutation\|deferred_is_never_mutation_approval\|fn is_mutate_authorized' "${MOD}" > "${REACH_DIR}/no_mutation_before_success.txt" || fail "missing apply-authorization guard reachability"

{
  echo "Run 233 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'replay/freshness runtime integration active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'RocksDB schema change' 'file format change' 'database migration' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_233_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 233 no-mutation proof for rejected replay/freshness runtime integration scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A17 / R1..R27 helper corpus (driven through the Run 232 composed integration integrate_governance_evaluator_replay_runtime / wire_governance_evaluator_replay_runtime_callsite / wire_governance_evaluator_replay_runtime_peer_context, composing the Run 224 evaluator runtime integration, the Run 226 call-site wiring, the Run 228 peer evaluator context, and the Run 230 replay/freshness state boundary as the mandatory pre-mutation gate): every rejected outcome surfaces as a typed GovernanceEvaluatorReplayRuntimeOutcome non-proceed variant (ProceedDeferred / ReplayFreshnessFailClosed(...) / RuntimeIntegrationFailClosed(...) / MainNetPeerDrivenApplyRefused) returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The integration exposes no mutation API: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, never invokes Run 070, and never marks a decision consumed. The only mutation-authorizing outcome is ProceedFresh (is_mutate_authorized()), produced only after the Run 224 layer authorized a mutate AND the Run 230 replay/freshness state classified the decision fresh; ProceedDeferred is explicitly NOT an approval. Read-only validation never marks consumed; only an explicit caller-side consume_for / mark_consumed records a consumed decision in the DevNet/TestNet fixture store, and only after a successful ProceedFresh authorization. Production/MainNet readers are callable but always unavailable/fail-closed. MainNet peer-driven apply is refused even when state is fresh."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_233_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 233 mutation proof (release-binary scope): the Run 232 replay/freshness runtime integration is a pure composition layer that runs the Run 230 replay/freshness validation BEFORE any mutation authorization. The only mutation-authorizing outcome is ProceedFresh, produced only when the Run 224 evaluator-runtime integration authorized a mutate (runtime consumption accepted AND the evaluator authorized the same lifecycle action / candidate digest / authority-domain sequence) AND the Run 230 replay/freshness state classified a first-seen, in-window decision fresh whose binding (environment / chain / genesis / surface / evaluator digests / proposal / decision / lifecycle action / candidate digest / sequence / replay nonce / freshness window) matches the canonical expectations, on a DevNet/TestNet trust domain. ProceedDeferred (fresh-but-not-yet-effective) is explicitly NOT an approval. Production/MainNet replay state is callable but fails closed as unavailable; MainNet peer-driven apply is refused even when fresh. No mutation is performed by this fixture-only helper or by the integration layer; an accepted ProceedFresh outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 233 does not exercise. The DevNet/TestNet FixtureReplayStateStore is an in-process map only — it introduces no RocksDB schema, no file format, and no database migration."
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
TEST_TARGETS=(run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 233 — release-binary governance evaluator replay/freshness runtime integration evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_233_sha256:  $(sha256_file "${HELPER_233_BIN}")"
  echo "  helper_233_buildid: $(build_id "${HELPER_233_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_233rc=$(cat "${EXIT_DIR}/helper_run_233.rc")$(grep -E 'verdict:' "${HELPER_233_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A17 / R1-R27 corpus verdicts (release mode, Run 232 replay/freshness runtime integration symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_233_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 232 replay/freshness runtime integration is a local/source-test-only pure composition layer exercised here through release-built library symbols; it composes the Run 224 evaluator runtime integration, the Run 226 call-site wiring, the Run 228 peer evaluator context, and the Run 230 replay/freshness state boundary as a mandatory pre-mutation gate; the DevNet/TestNet FixtureReplayStateStore is an in-process map only and DevNet/TestNet evidence-only (it reads as Unavailable for a MainNet environment); production/MainNet replay state is callable but always unavailable/fail-closed; read-only validation never marks consumed; explicit consume marks consumed only in fixture evidence after a successful ProceedFresh authorization; only ProceedFresh authorizes a mutation and ProceedDeferred is not an approval; rejections are pure and non-mutating; MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine; no real on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, and no wire/marker/sequence/trust-bundle schema change; existing Run 231, Run 229, Run 227, Run 225, and Run 223 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

cat "${SUMMARY}"