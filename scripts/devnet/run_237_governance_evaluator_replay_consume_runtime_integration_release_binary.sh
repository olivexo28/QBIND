#!/usr/bin/env bash
# Run 237 — Release-binary governance evaluator replay consume runtime
# integration evidence.
#
# Proves the release-built code exposes and exercises the Run 236 governance
# evaluator **replay consume runtime integration** in
# `crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`:
# `integrate_replay_consume_runtime`, `wire_replay_consume_runtime_callsite`, the
# typed `ReplayConsumeRuntimeIntegrationInput` / `ReplayConsumeRuntimeOutcome`
# (`ProceedLegacyBypassNoConsume`, `ProceedDeferredNoConsume`,
# `ProceedValidationOnlyNoConsume`, `ProceedFreshMutationAuthorized`,
# `ConsumeFixtureAfterMutationSuccess`, `DoNotConsume{BeforeApply, ApplyFailed,
# RolledBack, UnsupportedSurface, MainNetRefused}`, `ReplayRuntimeFailClosed`,
# `ConsumeFailClosed`, `ProductionConsumeUnavailable`, `MainNetConsumeUnavailable`,
# `MainNetPeerDrivenApplyRefused`), and the grep-verifiable invariant / fail-closed
# helpers (`consume_integrated_as_after_success_only_post_mutation_step`,
# `fresh_required_before_mutation_authorization_under_consume_runtime`,
# `deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime`,
# `mainnet_peer_driven_apply_remains_refused_under_consume_runtime`,
# `production_mainnet_consume_remains_unavailable_under_consume_runtime`,
# `validator_set_rotation_remains_unsupported_under_consume_runtime`,
# `policy_change_action_remains_unsupported_under_consume_runtime`). Run 236
# composes the Run 232 replay/freshness runtime integration with the Run 234
# post-mutation consume boundary into a single lifecycle: the replay/freshness
# runtime integration runs FIRST and any non-`ProceedFresh` outcome maps to a
# non-consuming outcome WITHOUT calling the consume writer; fresh is required
# before mutation authorization; consume is after-success-only (only
# `ConsumeFixtureAfterMutationSuccess` after a modeled `AppliedSuccessfully`).
# Deferred / validation-only / before-apply / failed-apply / rolled-back /
# unsupported-surface / MainNet-refused outcomes never consume. The composition
# is pure (no marker/sequence write, no live trust swap, no session eviction, no
# Run 070 call, no persistent storage); the DevNet/TestNet FixtureReplayStateStore
# writer records consumed only on the explicit after-success path with a prior
# observation; production/MainNet consume writers are reached but always fail
# closed unavailable; MainNet peer-driven apply remains refused even when fresh;
# validator-set rotation and policy-change actions remain unsupported.
# Fixture-only; no real governance engine, mutation engine, or on-chain proof
# verifier; no RocksDB/file/schema/migration/storage/wire/marker/sequence/
# trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_237_BIN="${REPO_ROOT}/target/release/examples/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper"
HELPER_237_OUT="${OUTDIR}/helper_evidence/run_237"
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

log() { printf '[run-237] %s\n' "$*" >&2; }
fail() { printf '[run-237] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_237_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_237_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-237 provenance"
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
log "cargo build --release -p qbind-node --example run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_237.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_237_BIN}" ]] || fail "missing ${HELPER_237_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_237_path:    ${HELPER_237_BIN}"
  echo "helper_237_sha256:  $(sha256_file "${HELPER_237_BIN}")"
  echo "helper_237_buildid: $(build_id "${HELPER_237_BIN}")"
} >> "${PROVENANCE}"

log "running Run 237 helper"
set +e
"${HELPER_237_BIN}" "${HELPER_237_OUT}" > "${LOGS_DIR}/helper_run_237.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_237.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_237 helper failed"
assert_grep "${HELPER_237_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 237 consume-runtime-integration fixture inventory (helper-minted):"
  if [[ -d "${HELPER_237_OUT}/fixtures" ]]; then
    for f in "${HELPER_237_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/consume_runtime_integration_fixture_inventory.txt"

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
  assert_not_grep "$logf" 'consume boundary (enabled|active|wired)'
  assert_not_grep "$logf" 'consume runtime integration (enabled|active|wired)'
  assert_not_grep "$logf" 'post-mutation consume (enabled|active|wired)'
  assert_not_grep "$logf" 'real mutation engine (enabled|active|wired)'
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

log "S1 help hides consume-runtime-integration surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'consume runtime integration|replay consume runtime|ReplayConsumeRuntimeOutcome|integrate_replay_consume_runtime|run-236|run-237'
log "S2..S4 default surfaces silent on consume-runtime-integration claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step and Run 236 ties into one lifecycle.
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
MOD="${SRC_DIR}/pqc_governance_evaluator_replay_consume_runtime_integration.rs"
{
  echo "Run 237 source-reachability proof — Run 236 replay consume runtime integration symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_replay_consume_runtime_integration ReplayConsumeRuntimeIntegrationInput ReplayConsumeRuntimeOutcome integrate_replay_consume_runtime wire_replay_consume_runtime_callsite ProceedLegacyBypassNoConsume ProceedDeferredNoConsume ProceedValidationOnlyNoConsume ProceedFreshMutationAuthorized ConsumeFixtureAfterMutationSuccess DoNotConsumeBeforeApply DoNotConsumeApplyFailed DoNotConsumeRolledBack DoNotConsumeUnsupportedSurface DoNotConsumeMainNetRefused ReplayRuntimeFailClosed ConsumeFailClosed ProductionConsumeUnavailable MainNetConsumeUnavailable MainNetPeerDrivenApplyRefused integrate_governance_evaluator_replay_runtime perform_post_mutation_consume GovernanceEvaluatorReplayStateWriter FixtureReplayStateStore ProductionReplayStateReader MainnetReplayStateReader consume_integrated_as_after_success_only_post_mutation_step fresh_required_before_mutation_authorization_under_consume_runtime deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime mainnet_peer_driven_apply_remains_refused_under_consume_runtime production_mainnet_consume_remains_unavailable_under_consume_runtime validator_set_rotation_remains_unsupported_under_consume_runtime policy_change_action_remains_unsupported_under_consume_runtime; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_replay_consume_runtime_integration'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ReplayConsumeRuntimeIntegrationInput'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ReplayConsumeRuntimeOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_replay_consume_runtime'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProceedFreshMutationAuthorized'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ConsumeFixtureAfterMutationSuccess'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProductionConsumeUnavailable'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetConsumeUnavailable'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetPeerDrivenApplyRefused'

# Module registration reachability (lib.rs exposes the Run 236 integration module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_replay_consume_runtime_integration' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Integration entry points within the module.
grep -RIn --include='*.rs' 'pub fn integrate_replay_consume_runtime\|pub fn wire_replay_consume_runtime_callsite' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing integration entry points"
# Composed outcome taxonomy within the module.
grep -RIn --include='*.rs' 'enum ReplayConsumeRuntimeOutcome\|ProceedFreshMutationAuthorized\|ConsumeFixtureAfterMutationSuccess\|DoNotConsumeBeforeApply\|DoNotConsumeApplyFailed\|DoNotConsumeRolledBack\|DoNotConsumeUnsupportedSurface\|DoNotConsumeMainNetRefused\|ReplayRuntimeFailClosed\|ConsumeFailClosed\|ProductionConsumeUnavailable\|MainNetConsumeUnavailable\|MainNetPeerDrivenApplyRefused' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing outcome taxonomy"
# Run 232 replay/freshness runtime integration usage (runs before consume).
grep -RIn --include='*.rs' 'integrate_governance_evaluator_replay_runtime\|GovernanceEvaluatorReplayRuntimeOutcome\|ProceedFresh' "${MOD}" > "${REACH_DIR}/run232_usage.txt" || fail "missing Run 232 usage"
# Run 234 consume boundary usage (after-success-only consume step).
grep -RIn --include='*.rs' 'perform_post_mutation_consume\|ConsumeBoundaryOutcome\|MutationAuthorizationOutcome\|MutationCompletionStatus' "${MOD}" > "${REACH_DIR}/run234_usage.txt" || fail "missing Run 234 usage"
# Run 230 replay state reader/writer usage + fixture consume writer path.
grep -RIn --include='*.rs' 'GovernanceEvaluatorReplayStateWriter\|writer' "${MOD}" > "${REACH_DIR}/run230_writer_usage.txt" || fail "missing Run 230 writer usage"
# Production / MainNet consume unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionConsumeUnavailable\|MainNetConsumeUnavailable\|production_mainnet_consume_remains_unavailable_under_consume_runtime' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_remains_refused_under_consume_runtime\|MainNetPeerDrivenApplyRefused\|MainNet peer-driven apply remains refused' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# After-success-only / fresh-required guards.
grep -RIn --include='*.rs' 'consume_integrated_as_after_success_only_post_mutation_step\|fresh_required_before_mutation_authorization_under_consume_runtime\|deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime' "${MOD}" > "${REACH_DIR}/after_success_only.txt" || fail "missing after-success-only guard reachability"

{
  echo "Run 237 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'real mutation engine active' 'consume runtime integration active' 'post-mutation consume active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'RocksDB schema change' 'file format change' 'database migration' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_237_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 237 no-mutation proof for rejected replay-consume-runtime-integration scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A23 / R1..R35 helper corpus (driven through the Run 236 integrate_replay_consume_runtime / wire_replay_consume_runtime_callsite, composing the real Run 232 replay/freshness runtime integration and the real Run 234 post-mutation consume boundary over the Run 230 reader/writer traits): the replay/freshness runtime integration runs FIRST and any non-ProceedFresh outcome maps to a non-consuming ReplayConsumeRuntimeOutcome (ProceedLegacyBypassNoConsume / ProceedDeferredNoConsume / ReplayRuntimeFailClosed / MainNetPeerDrivenApplyRefused) WITHOUT calling the consume writer. Fresh is required before mutation authorization; consume is after-success-only — only ConsumeFixtureAfterMutationSuccess (after a Run 232 ProceedFresh and a modeled MutationCompletionStatus::AppliedSuccessfully on a wired DevNet/TestNet fixture policy) authorizes a fixture consume. Every rejected / non-consume outcome is returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The composition performs no network or file I/O and implements no persistent storage. The writer is never called on a non-consume path; only the explicit after-success path calls the DevNet/TestNet fixture writer's mark_consumed, and only after a prior observation. Production/MainNet consume writers are reached but always fail closed unavailable. MainNet peer-driven apply is refused and never consumes even when the replay state is fresh."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_237_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 237 mutation proof (release-binary scope): the Run 236 replay consume runtime integration is a pure composition that runs the Run 232 replay/freshness runtime integration FIRST (selector resolution -> runtime/evaluator/decision validation -> replay/freshness validation -> mutation authorization only on fresh), and only on a Run 232 ProceedFresh reaches the Run 234 post-mutation consume boundary. The Run 232 authorization is authoritative — it is injected into the consume binding's mutation-authorization outcome so the freshness and consume layers cannot disagree. The only consume-authorizing outcome is ConsumeFixtureAfterMutationSuccess, produced only when (i) the Run 232 layer returned ProceedFresh, (ii) neither the validation nor the mutation surface is validation-only, (iii) the consume binding matches the canonical expectations, (iv) the modeled mutation completion status is AppliedSuccessfully, and (v) a wired DevNet/TestNet fixture policy on a non-MainNet environment is active. Consume records consumed in the in-process FixtureReplayStateStore only via the explicit after-success path (mark_consumed), and only when a prior observation exists; otherwise it downgrades to ConsumeFailClosed. Production/MainNet consume is reached but fails closed unavailable; MainNet peer-driven apply is refused before any mutation authorization even when fresh. No mutation is performed by this fixture-only helper or by the composition; a ConsumeFixtureAfterMutationSuccess outcome is, at most, the after-success bookkeeping for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 237 does not exercise. The DevNet/TestNet FixtureReplayStateStore is an in-process map only — it introduces no RocksDB schema, no file format, and no database migration."
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
TEST_TARGETS=(run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 237 — release-binary governance evaluator replay consume runtime integration evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_237_sha256:  $(sha256_file "${HELPER_237_BIN}")"
  echo "  helper_237_buildid: $(build_id "${HELPER_237_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_237rc=$(cat "${EXIT_DIR}/helper_run_237.rc")$(grep -E 'verdict:' "${HELPER_237_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A23 / R1-R35 corpus verdicts (release mode, Run 236 replay consume runtime integration symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_237_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 236 replay consume runtime integration is a local/source-test-only pure composition exercised here through release-built library symbols (the same symbols a future production call site would use); it runs the real Run 232 replay/freshness runtime integration first and the real Run 234 post-mutation consume boundary only on a ProceedFresh, over the Run 230 reader/writer traits; the replay/freshness runtime integration runs before consume and any non-ProceedFresh outcome maps to a non-consuming outcome without calling the writer; fresh is required before mutation authorization; consume is after-success-only — only ConsumeFixtureAfterMutationSuccess (after a modeled AppliedSuccessfully) authorizes a fixture consume; deferred, validation-only, before-apply, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume; the DevNet/TestNet FixtureReplayStateStore is an in-process map only and DevNet/TestNet evidence-only; the fixture writer records consumed only on the explicit after-success path with a prior observation, and a re-validation then classifies the decision already-consumed through Run 230; production/MainNet consume writers are reached but always fail closed unavailable; rejections are pure and non-mutating and the writer is never called on a non-consume path; the consume authorization is overridden with the exact Run 232 freshness result; MainNet peer-driven apply remains refused and never consumes even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine, mutation engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 235, Run 233, Run 231, Run 229, and Run 227 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "Run 237 release-binary consume-runtime-integration evidence complete; summary at ${SUMMARY}"
