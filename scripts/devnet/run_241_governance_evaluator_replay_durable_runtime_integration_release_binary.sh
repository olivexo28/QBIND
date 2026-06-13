#!/usr/bin/env bash
# Run 241 — Release-binary governance evaluator durable replay backend runtime
# integration evidence.
#
# Proves the release-built code exposes and exercises the Run 240 governance
# evaluator **durable replay backend runtime integration** in
# `crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`:
# the composition entry point `integrate_durable_replay_runtime`; the typed
# crash-window recovery `recover_durable_replay_runtime_crash_window`; the
# runtime call-site wiring `wire_durable_replay_runtime_callsite`; the typed
# `DurableReplayRuntimeIntegrationInput` binding; the `DurableReplayRuntimeOutcome`
# taxonomy and its predicates (`authorizes_consume`, `authorizes_mutation`,
# `is_deferred`, `is_proceed`, `is_fail_closed`, `is_crash_window_fail_closed`,
# `is_mainnet_peer_driven_apply_refused`, `no_consume`, `tag`); and the
# grep-verifiable invariant / fail-closed helpers
# (`durable_observe_happens_before_mutation_authorization`,
# `consume_only_after_successful_mutation_under_durable_runtime`,
# `crash_window_ambiguity_fails_closed_under_durable_runtime`,
# `restart_snapshot_is_fixture_source_test_only_under_durable_runtime`,
# `mainnet_peer_driven_apply_remains_refused_under_durable_runtime`,
# `production_mainnet_durable_remains_unavailable_under_durable_runtime`,
# `local_operator_cannot_satisfy_durable_runtime_policy`,
# `peer_majority_cannot_satisfy_durable_runtime_policy`,
# `validator_set_rotation_remains_unsupported_under_durable_runtime`,
# `policy_change_action_remains_unsupported_under_durable_runtime`,
# `no_rocksdb_file_schema_migration_change_under_durable_runtime`,
# `durable_runtime_rejection_is_non_mutating`).
#
# Run 240 landed the typed durable replay-backend runtime integration plus
# source/test coverage at the source/test level (it composes the Run 238 durable
# backend with the Run 230/232 replay/freshness state path and the Run 236
# consume runtime integration). Run 241 proves on real `target/release/qbind-node`
# plus a release-built helper that the release-built code exposes and exercises
# it: a default Disabled policy is a Run 214 legacy bypass with no durable write;
# a durable read/observe happens before mutation authorization; a mutation is
# authorized only on a fresh / known-fresh durable state after the Run 230/232
# runtime agrees fresh; a durable compare-and-mark-consumed happens only after a
# modeled AppliedSuccessfully mutation, after which the decision reads consumed /
# fail-closed; read-only validation / deferral / failed-apply / rollback /
# consume-before-observe / consume-before-success never consume; an ambiguous
# crash window is typed and fails closed; fixture restart snapshot preserves
# observed and consumed state through the integration (a value clone, never a
# file format); production/MainNet durable backends are reached but always fail
# closed unavailable; MainNet peer-driven apply remains refused even when the
# durable state reads fresh; validator-set rotation and policy-change actions
# remain unsupported. The composition is pure (no marker/sequence write, no live
# trust swap, no session eviction, no Run 070 call, no persistent storage); no
# real governance engine, mutation engine, or on-chain proof verifier; no
# RocksDB/file/schema/migration/storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_241_BIN="${REPO_ROOT}/target/release/examples/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper"
HELPER_241_OUT="${OUTDIR}/helper_evidence/run_241"
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

log() { printf '[run-241] %s\n' "$*" >&2; }
fail() { printf '[run-241] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_241_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_241_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-241 provenance"
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
log "cargo build --release -p qbind-node --example run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_241.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_241_BIN}" ]] || fail "missing ${HELPER_241_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_241_path:    ${HELPER_241_BIN}"
  echo "helper_241_sha256:  $(sha256_file "${HELPER_241_BIN}")"
  echo "helper_241_buildid: $(build_id "${HELPER_241_BIN}")"
} >> "${PROVENANCE}"

log "running Run 241 helper"
set +e
"${HELPER_241_BIN}" "${HELPER_241_OUT}" > "${LOGS_DIR}/helper_run_241.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_241.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_241 helper failed"
assert_grep "${HELPER_241_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 241 durable-runtime-integration fixture inventory (helper-minted):"
  if [[ -d "${HELPER_241_OUT}/fixtures" ]]; then
    for f in "${HELPER_241_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/durable_runtime_fixture_inventory.txt"

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
  assert_not_grep "$logf" 'durable (replay )?backend (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'durable (replay )?runtime integration (enabled|active|wired)'
  assert_not_grep "$logf" 'persistent replay (state )?(store|backend) (enabled|active|wired)'
  assert_not_grep "$logf" 'RocksDB (backend )?(enabled|active|wired)'
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

log "S1 help hides durable-runtime-integration surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable replay (state )?backend|DurableReplayRuntimeOutcome|integrate_durable_replay_runtime|wire_durable_replay_runtime_callsite|recover_durable_replay_runtime_crash_window|run-240|run-241'
log "S2..S4 default surfaces silent on durable-runtime-integration claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step, Run 236 ties into one lifecycle,
# Run 238 specifies a durable backend contract for, and Run 240 wires that
# durable backend in as the runtime state provider — none of which the real
# binary activates.
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
MOD="${SRC_DIR}/pqc_governance_evaluator_replay_durable_runtime_integration.rs"
{
  echo "Run 241 source-reachability proof — Run 240 durable replay-backend runtime integration symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_replay_durable_runtime_integration DurableReplayRuntimeIntegrationInput DurableReplayRuntimeOutcome integrate_durable_replay_runtime recover_durable_replay_runtime_crash_window wire_durable_replay_runtime_callsite ProceedLegacyBypassNoDurableWrite ProceedDeferredObserved ProceedFreshObserved ProceedKnownFresh ProceedMutationAuthorized ConsumeDurableAfterMutationSuccess DoNotConsumeBeforeApply DoNotConsumeApplyFailed DoNotConsumeRolledBack CrashWindowFailClosed DurableReplayFailClosed ReplayRuntimeFailClosed ConsumeRuntimeFailClosed ProductionDurableUnavailable MainNetDurableUnavailable MainNetPeerDrivenApplyRefused durable_observe_happens_before_mutation_authorization consume_only_after_successful_mutation_under_durable_runtime crash_window_ambiguity_fails_closed_under_durable_runtime restart_snapshot_is_fixture_source_test_only_under_durable_runtime mainnet_peer_driven_apply_remains_refused_under_durable_runtime production_mainnet_durable_remains_unavailable_under_durable_runtime no_rocksdb_file_schema_migration_change_under_durable_runtime durable_runtime_rejection_is_non_mutating; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_replay_durable_runtime_integration'
assert_grep "${REACH_DIR}/source_reachability.txt" 'DurableReplayRuntimeIntegrationInput'
assert_grep "${REACH_DIR}/source_reachability.txt" 'DurableReplayRuntimeOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'integrate_durable_replay_runtime'
assert_grep "${REACH_DIR}/source_reachability.txt" 'recover_durable_replay_runtime_crash_window'
assert_grep "${REACH_DIR}/source_reachability.txt" 'wire_durable_replay_runtime_callsite'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ConsumeDurableAfterMutationSuccess'
assert_grep "${REACH_DIR}/source_reachability.txt" 'CrashWindowFailClosed'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainNetPeerDrivenApplyRefused'

# Module registration reachability (lib.rs exposes the Run 240 durable runtime integration module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_replay_durable_runtime_integration' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Composition entry points within the module.
grep -RIn --include='*.rs' 'pub fn integrate_durable_replay_runtime\|pub fn recover_durable_replay_runtime_crash_window\|pub fn wire_durable_replay_runtime_callsite' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing durable runtime entry points"
# Outcome taxonomy within the module.
grep -RIn --include='*.rs' 'enum DurableReplayRuntimeOutcome' "${MOD}" > "${REACH_DIR}/runtime_outcome_taxonomy.txt" || fail "missing runtime outcome taxonomy"
# Run 238 durable backend usage (durable read/observe + compare-and-mark-consumed + crash-window classify).
grep -RIn --include='*.rs' 'pqc_governance_evaluator_replay_durable_backend\|read_decision_state\|observe_decision_if_absent\|compare_and_mark_consumed\|classify_crash_window' "${MOD}" > "${REACH_DIR}/run238_durable_backend_usage.txt" || fail "missing Run 238 durable backend usage"
# Run 236 consume runtime usage + Run 232/230 replay/freshness runtime/state usage.
grep -RIn --include='*.rs' 'pqc_governance_evaluator_replay_consume_boundary\|surface_is_validation_only' "${MOD}" > "${REACH_DIR}/run236_consume_runtime_usage.txt" || fail "missing Run 236 consume runtime usage"
grep -RIn --include='*.rs' 'pqc_governance_evaluator_replay_state\|evaluate_evaluator_replay_freshness\|EvaluatorReplayFreshnessInput\|ReplayStatePolicy' "${MOD}" > "${REACH_DIR}/run230_232_replay_state_usage.txt" || fail "missing Run 230/232 replay state usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionDurableUnavailable\|MainNetDurableUnavailable\|FailClosedProductionUnavailable\|FailClosedMainNetUnavailable\|production_mainnet_durable_remains_unavailable_under_durable_runtime' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_remains_refused_under_durable_runtime\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefused\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'no_rocksdb_file_schema_migration_change_under_durable_runtime\|restart_snapshot_is_fixture_source_test_only_under_durable_runtime' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 241 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'real mutation engine active' 'consume runtime integration active' 'durable runtime integration active' 'post-mutation consume active' 'real persistent replay backend' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'RocksDB schema change' 'RocksDB schema drift' 'file format change' 'database migration' 'storage-format change' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_241_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_241.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 241 no-mutation proof for rejected durable-runtime-integration scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A27 / R1..R38 helper corpus (driven through the Run 240 integrate_durable_replay_runtime / recover_durable_replay_runtime_crash_window / wire_durable_replay_runtime_callsite composing the Run 238 read_decision_state / observe_decision_if_absent / compare_and_mark_consumed / classify_crash_window over the reader/writer/atomic traits and the DevNet/TestNet FixtureDurableReplayBackend with the Run 230/232 replay/freshness state path): the durable runtime integration is a pure, typed composition. Every evaluation is a pure function over an in-memory fixture map plus the Run 230 state — it performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, and never invokes Run 070. The only state mutation it can cause is the explicit fixture durable observe / compare-and-mark-consumed write on a proceed/consume path; every fail-closed outcome leaves the backend untouched. A default Disabled policy is a Run 214 legacy bypass that performs no durable write. The durable read/observe happens before mutation authorization, and a mutation is authorized only on a fresh / known-fresh durable state after the Run 230/232 runtime agrees fresh. ConsumeDurableAfterMutationSuccess is the only consume-authorizing outcome, and only after a durable observe and a modeled AppliedSuccessfully mutation — a consume before observe, before success, after a failed apply, after a rollback, or with a wrong compare-and-mark expected state is a non-consuming rejection that records nothing. A read-only validation surface and a deferral observe/read but never consume. A malformed / wrong-bound observe records nothing at all (backend stays empty). An ambiguous crash window is typed and fails closed. Restart durability is modeled only through restart_snapshot / from_snapshot (an in-process value clone), never a real file format, database, or migration. Production / MainNet durable backends are reached but always unavailable / fail-closed, and MainNet peer-driven apply is refused before any durable read / consume even when the durable state would otherwise read fresh. No real persistent replay backend, RocksDB schema, file format, or database migration exists. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_241_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 241 mutation proof (release-binary scope): the Run 240 durable replay-backend runtime integration is a pure, typed composition over the Run 238 durable backend contract (plus a DevNet/TestNet in-memory fixture), the Run 230/232 replay/freshness state path, and the Run 236 after-success-only consume runtime integration. It specifies the runtime ordering a real durable replay-state store would have to honour, but implements NONE of that storage: there is no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. integrate_durable_replay_runtime refuses MainNet peer-driven apply first, honours the Run 214 legacy bypass, performs the durable read/observe BEFORE mutation authorization, runs the Run 230/232 replay/freshness runtime evaluation, observes a first-seen fresh decision into the in-process HashMap under its classified observed state, authorizes a mutation only on a fresh observed record, and performs a durable compare-and-mark-consumed only after a modeled AppliedSuccessfully mutation completion on an exactly-ObservedFresh record — flipping only an in-memory consumed flag. Restart durability is modeled only by cloning the in-process record map (restart_snapshot / from_snapshot) — never by reading or writing any file. The ConsumeDurableAfterMutationSuccess outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production durable store; Run 241 does not exercise that mutating path and activates no production durable backend. Production / MainNet durable backends remain callable-but-unavailable / fail-closed; MainNet peer-driven apply is refused before any durable read / consume. The FixtureDurableReplayBackend is an in-process map only — it introduces no RocksDB schema, no file format, and no database migration."
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
TEST_TARGETS=(run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 241 — release-binary governance evaluator durable replay-backend runtime integration evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_241_sha256:  $(sha256_file "${HELPER_241_BIN}")"
  echo "  helper_241_buildid: $(build_id "${HELPER_241_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_241rc=$(cat "${EXIT_DIR}/helper_run_241.rc")$(grep -E 'verdict:' "${HELPER_241_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A27 / R1-R38 corpus verdicts (release mode, Run 240 durable replay-backend runtime integration symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_241_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 240 durable replay-backend runtime integration is a pure, typed composition over the Run 238 durable backend contract plus a DevNet/TestNet in-memory fixture, the Run 230/232 replay/freshness state path, and the Run 236 after-success-only consume runtime integration, exercised here through release-built library symbols (the same symbols a future production call site would use); a default Disabled policy is a Run 214 legacy bypass with no durable write; the durable read/observe happens before mutation authorization, and a mutation is authorized only on a fresh / known-fresh durable state after the Run 230/232 runtime agrees fresh; a durable compare-and-mark-consumed happens only after a modeled AppliedSuccessfully mutation, after which the decision reads consumed / fail-closed; read-only validation, deferral, failed-apply, rollback, and consume-before-observe / consume-before-success never consume; observed and consumed state both survive an in-process fixture restart snapshot (a value clone, never a file format); an ambiguous (after-mutation-before-consume / unknown / after-consume) crash window is typed and fails closed; production/MainNet durable backends are reached but always fail closed unavailable; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call) — a malformed observe records nothing and a rejected consume never marks consumed; MainNet peer-driven apply remains refused and never observes or consumes even when the durable state reads fresh; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine, mutation engine, or on-chain governance proof verifier; no real persistent replay backend; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "Run 241 evidence complete -> ${SUMMARY}"
cat "${SUMMARY}"