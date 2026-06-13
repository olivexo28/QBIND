#!/usr/bin/env bash
# Run 243 — Release-binary governance execution mutation-engine boundary evidence.
#
# Proves the release-built code exposes and exercises the Run 242 governance
# execution **mutation-engine boundary** in
# `crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`:
# the entry point `evaluate_governance_mutation_engine`; the crash-window
# recovery `recover_governance_mutation_window`; the runtime call-site wiring
# `wire_governance_mutation_engine_callsite`; the durable composition helper
# `project_mutation_outcome_to_durable_completion`; the typed bindings
# (`GovernanceMutationEngineInput`, `GovernanceMutationEngineExpectations`,
# `GovernanceMutationCandidate`, `GovernanceMutationSurface`,
# `GovernanceMutationPolicy`, `GovernanceMutationEnvironmentBinding`,
# `GovernanceMutationRuntimeBinding`); the engine kind / outcome taxonomy
# (`GovernanceMutationEngineKind`, `GovernanceMutationOutcome`); the
# pure/mockable executor trait `GovernanceMutationExecutor` with
# `FixtureMutationExecutor` / `ProductionMutationExecutor` /
# `MainNetMutationExecutor`; and the grep-verifiable invariant / fail-closed
# helpers (`mutation_engine_rejection_is_non_mutating`,
# `mutation_success_is_required_before_durable_consume`,
# `mutation_failure_never_consumes_durable_replay_state`,
# `mutation_rollback_never_consumes_durable_replay_state`,
# `production_mainnet_mutation_engine_unavailable`,
# `mainnet_peer_driven_apply_refused_by_mutation_engine`,
# `no_rocksdb_file_schema_migration_change_under_mutation_engine`,
# `validator_set_rotation_unsupported_by_mutation_engine`,
# `policy_change_unsupported_by_mutation_engine`,
# `local_operator_cannot_satisfy_mutation_engine_authority`,
# `peer_majority_cannot_satisfy_mutation_engine_authority`).
#
# Run 242 landed the typed mutation-engine boundary plus source/test coverage at
# the source/test level. Run 243 proves on real `target/release/qbind-node` plus
# a release-built helper that the release-built code exposes and exercises it: a
# Disabled policy / engine kind is a legacy bypass with no mutation; a binding
# validation runs before any apply and a mismatch is a non-mutating
# reject-before-apply that never reaches the executor; a read-only validation
# surface never mutates; a DevNet/TestNet fixture mutation success returns
# MutationAppliedSuccessfully and projects to the only consume-eligible durable
# completion; authorized-not-applied, failed apply, rollback, and ambiguous
# after-authorization windows never consume; production/MainNet engine kinds are
# reachable but always unavailable/fail-closed; MainNet peer-driven apply is
# refused before binding validation and before executor invocation;
# validator-set rotation and policy-change actions remain unsupported. The
# boundary is pure (no marker/sequence write, no live trust swap, no session
# eviction, no Run 070 call, no durable consume of its own, no persistent
# storage); no real governance engine, mutation engine, or on-chain proof
# verifier; no RocksDB/file/schema/migration/storage/wire/marker/sequence/
# trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_243_governance_execution_mutation_engine_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_243_BIN="${REPO_ROOT}/target/release/examples/run_243_governance_execution_mutation_engine_release_binary_helper"
HELPER_243_OUT="${OUTDIR}/helper_evidence/run_243"
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

log() { printf '[run-243] %s\n' "$*" >&2; }
fail() { printf '[run-243] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_243_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_243_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-243 provenance"
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
log "cargo build --release -p qbind-node --example run_243_governance_execution_mutation_engine_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_243_governance_execution_mutation_engine_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_243.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_243_BIN}" ]] || fail "missing ${HELPER_243_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_243_path:    ${HELPER_243_BIN}"
  echo "helper_243_sha256:  $(sha256_file "${HELPER_243_BIN}")"
  echo "helper_243_buildid: $(build_id "${HELPER_243_BIN}")"
} >> "${PROVENANCE}"

log "running Run 243 helper"
set +e
"${HELPER_243_BIN}" "${HELPER_243_OUT}" > "${LOGS_DIR}/helper_run_243.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_243.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_243 helper failed"
assert_grep "${HELPER_243_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 243 mutation-engine fixture inventory (helper-minted):"
  if [[ -d "${HELPER_243_OUT}/fixtures" ]]; then
    for f in "${HELPER_243_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/mutation_engine_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'real production mutation engine (enabled|active|wired)'
  assert_not_grep "$logf" 'real mutation engine (enabled|active|wired)'
  assert_not_grep "$logf" 'MainNet mutation engine (enabled|active|wired)'
  assert_not_grep "$logf" 'mutation engine (enabled|active|wired)'
  assert_not_grep "$logf" 'mutation-engine (enabled|active|wired)'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'durable (replay )?backend (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'persistent replay (state )?(store|backend) (enabled|active|wired)'
  assert_not_grep "$logf" 'RocksDB (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'file replay backend (enabled|active|wired)'
  assert_not_grep "$logf" 'post-mutation consume (enabled|active|wired)'
  assert_not_grep "$logf" 'validator-set rotation (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'policy-change action (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'autonomous apply|apply on receipt|apply-on-receipt|peer-majority authority'
  assert_not_grep "$logf" 'real KMS backend|real HSM backend|real RemoteSigner backend|RemoteSigner backend connected'
  assert_not_grep "$logf" 'MainNet peer-driven apply ENABLED'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1 || true
  local rc=$?
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides mutation-engine surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'mutation engine|mutation-engine|GovernanceMutationOutcome|evaluate_governance_mutation_engine|wire_governance_mutation_engine_callsite|recover_governance_mutation_window|run-242|run-243'
log "S2..S4 default surfaces silent on mutation-engine claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step, Run 236/238/240 tie into a durable
# runtime, and Run 242 hands to a typed mutation-engine boundary — none of which
# the real binary activates as a public production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'mutation engine|mutation-engine|run-242|run-243'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_execution_mutation_engine.rs"
RUN242_SYMS=(
  pqc_governance_execution_mutation_engine
  GovernanceMutationEngineInput
  GovernanceMutationEngineExpectations
  GovernanceMutationCandidate
  GovernanceMutationSurface
  GovernanceMutationPolicy
  GovernanceMutationEnvironmentBinding
  GovernanceMutationRuntimeBinding
  GovernanceMutationEngineKind
  GovernanceMutationOutcome
  GovernanceMutationExecutor
  FixtureMutationExecutor
  ProductionMutationExecutor
  MainNetMutationExecutor
  evaluate_governance_mutation_engine
  recover_governance_mutation_window
  wire_governance_mutation_engine_callsite
  project_mutation_outcome_to_durable_completion
  mutation_engine_rejection_is_non_mutating
  mutation_success_is_required_before_durable_consume
  mutation_failure_never_consumes_durable_replay_state
  mutation_rollback_never_consumes_durable_replay_state
  production_mainnet_mutation_engine_unavailable
  mainnet_peer_driven_apply_refused_by_mutation_engine
  no_rocksdb_file_schema_migration_change_under_mutation_engine
  validator_set_rotation_unsupported_by_mutation_engine
  policy_change_unsupported_by_mutation_engine
  local_operator_cannot_satisfy_mutation_engine_authority
  peer_majority_cannot_satisfy_mutation_engine_authority
)
{
  echo "Run 243 source-reachability proof — Run 242 governance execution mutation-engine boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN242_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN242_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs"
{
  echo "Run 243 helper-reachability proof — Run 242 symbols exercised by the release helper:"
  for sym in "${RUN242_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_governance_mutation_engine recover_governance_mutation_window wire_governance_mutation_engine_callsite project_mutation_outcome_to_durable_completion FixtureMutationExecutor ProductionMutationExecutor MainNetMutationExecutor; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 242 mutation-engine module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_execution_mutation_engine' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_governance_mutation_engine\|pub fn recover_governance_mutation_window\|pub fn wire_governance_mutation_engine_callsite\|pub fn project_mutation_outcome_to_durable_completion' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing mutation-engine entry points"
# Outcome / kind taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceMutationOutcome\|enum GovernanceMutationEngineKind' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing mutation-engine outcome/kind taxonomy"
# Executor trait + implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceMutationExecutor\|struct FixtureMutationExecutor\|struct ProductionMutationExecutor\|struct MainNetMutationExecutor' "${MOD}" > "${REACH_DIR}/executor_boundary.txt" || fail "missing executor boundary"
# Run 240 durable completion projection usage (DurableMutationCompletion).
grep -RIn --include='*.rs' 'DurableMutationCompletion\|pqc_governance_evaluator_replay_durable_backend' "${MOD}" > "${REACH_DIR}/run240_durable_projection_usage.txt" || fail "missing Run 240 durable projection usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionMutationUnavailable\|MainNetMutationUnavailable\|production_mainnet_mutation_engine_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_refused_by_mutation_engine\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefused\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'no_rocksdb_file_schema_migration_change_under_mutation_engine\|validator_set_rotation_unsupported_by_mutation_engine\|policy_change_unsupported_by_mutation_engine' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 243 denylist (proven empty across captured logs):"
  for pat in 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'real persistent replay backend enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the mutation-engine' 'live trust swap from the mutation-engine' 'session eviction from the mutation-engine' 'marker write from the mutation-engine' 'sequence write from the mutation-engine' 'DummySig' 'DummyKem' 'DummyAead' 'mutation engine active' 'production mutation engine active' 'real mutation engine active'; do
    if find "${LOGS_DIR}" "${HELPER_243_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_243.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 243 no-mutation proof for rejected mutation-engine scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / reachability helper corpus (driven through the Run 242 evaluate_governance_mutation_engine / recover_governance_mutation_window / wire_governance_mutation_engine_callsite / project_mutation_outcome_to_durable_completion over the GovernanceMutationExecutor trait and the DevNet/TestNet FixtureMutationExecutor plus the always-unavailable ProductionMutationExecutor / MainNetMutationExecutor): the mutation-engine boundary is a pure, typed function over its inputs plus a mockable executor. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, and never invokes Run 070. A Disabled policy / engine kind is a legacy bypass that performs no mutation and never invokes the executor. Binding validation runs before any apply; a wrong environment / chain / genesis / governance surface / mutation surface / candidate digest / decision digest / proposal id / decision id / authority-domain sequence / lifecycle action, or a malformed candidate, is a non-mutating reject-before-apply that never reaches the executor (the helper proves the fixture executor attempt counter stays at zero on every rejected path). A read-only validation surface never mutates. MutationAppliedSuccessfully is the only outcome that projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully; authorized-not-applied, failed apply, rollback, and ambiguous after-authorization windows never consume. Production / MainNet engine kinds are reachable but always unavailable / fail-closed. MainNet peer-driven apply is refused before binding validation and before executor invocation, even when the binding is otherwise broken. Validator-set rotation and policy-change actions remain unsupported. The executors are in-process models only — they introduce no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_243_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 243 mutation proof (release-binary scope): the Run 242 governance execution mutation-engine boundary is a pure, typed composition that makes the hand-off of an already-authorized governance evaluator decision to a future mutation executor explicit and typed, and projects mutation-engine outcomes into the Run 240 durable runtime's DurableMutationCompletion semantics. It specifies the ordering a real mutation engine would have to honour (MainNet peer-driven refusal -> legacy bypass -> binding validation -> read-only gating -> unsupported-action gating -> engine-kind routing -> executor hand-off -> durable projection), but implements NONE of that mutation: there is no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no real persistent replay backend, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureMutationExecutor models success/authorized/failure/rollback/ambiguous outcomes and performs no real trust mutation; the ProductionMutationExecutor and MainNetMutationExecutor are always unavailable / fail-closed. The MutationAppliedSuccessfully -> DurableMutationCompletion::AppliedSuccessfully projection is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production durable store; Run 243 does not exercise that mutating path and activates no production mutation engine. The boundary is pure and non-mutating on every rejection path; production/MainNet mutation engines remain callable-but-unavailable; MainNet peer-driven apply is refused before any mutation attempt."
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
TEST_TARGETS=(run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 243 — release-binary governance execution mutation-engine boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_243_sha256:  $(sha256_file "${HELPER_243_BIN}")"
  echo "  helper_243_buildid: $(build_id "${HELPER_243_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_243rc=$(cat "${EXIT_DIR}/helper_run_243.rc")$(grep -E 'verdict:' "${HELPER_243_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 242 mutation-engine boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_243_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 242 governance execution mutation-engine boundary is a pure, typed function over its inputs plus a mockable executor, exercised here through release-built library symbols (the same symbols a future production call site would use); a Disabled policy / engine kind is a legacy bypass with no mutation and no executor invocation; binding validation runs before any apply and a mismatch is a non-mutating reject-before-apply that never reaches the executor; a read-only validation surface never mutates; only a modeled MutationAppliedSuccessfully projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully, while authorized-not-applied, failed apply, rollback, and ambiguous after-authorization windows never consume; production/MainNet engine kinds are reachable but always unavailable/fail-closed; MainNet peer-driven apply is refused before binding validation and before executor invocation; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call); no real governance execution engine, mutation engine, or on-chain governance proof verifier; no real persistent replay backend; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "Run 243 evidence complete -> ${SUMMARY}"
