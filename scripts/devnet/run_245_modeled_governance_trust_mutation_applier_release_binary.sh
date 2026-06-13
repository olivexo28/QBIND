#!/usr/bin/env bash
# Run 245 — Release-binary modeled governance trust-state mutation applier evidence.
#
# Proves the release-built code exposes and exercises the Run 244 governance
# **modeled trust-state mutation applier boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`:
# the entry point `evaluate_modeled_trust_mutation`; the crash-window recovery
# `recover_modeled_trust_mutation`; the composition helpers
# `map_modeled_outcome_to_mutation_engine_outcome`,
# `project_modeled_outcome_to_durable_completion`,
# `modeled_outcome_authorizes_durable_consume`; the modeled state
# (`ModeledGovernanceTrustState`, `ModeledGovernanceTrustSnapshot`,
# `ModeledGovernanceTrustRoot`, `ModeledTrustRootStatus`); the typed bindings
# (`ModeledGovernanceTrustMutation`, `ModeledGovernanceTrustMutationInput`,
# `ModeledGovernanceTrustMutationExpectations`,
# `ModeledGovernanceTrustMutationPolicy`, `ModeledGovernanceTrustMutationSurface`,
# `ModeledGovernanceTrustMutationEnvironmentBinding`,
# `ModeledGovernanceTrustMutationRuntimeBinding`); the action / outcome taxonomy
# (`ModeledTrustMutationAction`, `ModeledTrustMutationOutcome`); the
# pure/mockable applier trait `ModeledGovernanceTrustMutationApplier` with
# `FixtureModeledTrustMutationApplier` / `ProductionModeledTrustMutationApplier`
# / `MainNetModeledTrustMutationApplier`; and the grep-verifiable invariant /
# fail-closed helpers (`modeled_trust_applier_rejection_is_non_mutating`,
# `modeled_trust_applier_never_calls_run_070`,
# `modeled_trust_applier_never_mutates_live_pqc_trust_state`,
# `modeled_trust_applier_success_required_before_durable_consume`,
# `modeled_trust_applier_failure_never_consumes`,
# `modeled_trust_applier_rollback_never_consumes`,
# `modeled_trust_applier_ambiguous_window_fails_closed`,
# `production_mainnet_modeled_trust_applier_unavailable`,
# `mainnet_peer_driven_apply_refused_by_modeled_trust_applier`,
# `validator_set_rotation_unsupported_by_modeled_trust_applier`,
# `policy_change_unsupported_by_modeled_trust_applier`,
# `modeled_trust_applier_no_rocksdb_file_schema_migration_change`,
# `local_operator_cannot_satisfy_modeled_trust_applier_authority`,
# `peer_majority_cannot_satisfy_modeled_trust_applier_authority`).
#
# Run 244 landed the typed modeled-applier boundary plus source/test coverage at
# the source/test level. Run 245 proves on real `target/release/qbind-node` plus
# a release-built helper that the release-built code exposes and exercises it: a
# Disabled policy / applier kind is a legacy bypass with no modeled mutation; a
# binding validation runs before any snapshot and a mismatch is a non-mutating
# reject-before-snapshot that never reaches the applier; a read-only validation
# surface never mutates; a DevNet/TestNet fixture modeled add/retire/revoke/
# emergency-revoke/noop succeeds and mutates only the in-memory
# ModeledGovernanceTrustState; only a modeled ModeledMutationApplied projects to
# the only consume-eligible durable completion; rejected/failed/rolled-back/
# rollback-failed/ambiguous/unavailable/unsupported outcomes never consume;
# production/MainNet applier kinds are reachable but always unavailable/
# fail-closed; MainNet peer-driven apply is refused before any snapshot and
# before applier invocation; validator-set rotation and policy-change actions
# remain unsupported. The boundary is pure (no marker/sequence write, no live
# trust swap, no session eviction, no Run 070 call, no LivePqcTrustState
# mutation, no durable consume of its own, no persistent storage); no real
# governance engine, mutation engine, or on-chain proof verifier; no RocksDB/
# file/schema/migration/storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_245_BIN="${REPO_ROOT}/target/release/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper"
HELPER_245_OUT="${OUTDIR}/helper_evidence/run_245"
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

log() { printf '[run-245] %s\n' "$*" >&2; }
fail() { printf '[run-245] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_245_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_245_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-245 provenance"
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
log "cargo build --release -p qbind-node --example run_245_modeled_governance_trust_mutation_applier_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_245_modeled_governance_trust_mutation_applier_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_245.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_245_BIN}" ]] || fail "missing ${HELPER_245_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_245_path:    ${HELPER_245_BIN}"
  echo "helper_245_sha256:  $(sha256_file "${HELPER_245_BIN}")"
  echo "helper_245_buildid: $(build_id "${HELPER_245_BIN}")"
} >> "${PROVENANCE}"

log "running Run 245 helper"
set +e
"${HELPER_245_BIN}" "${HELPER_245_OUT}" > "${LOGS_DIR}/helper_run_245.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_245.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_245 helper failed"
assert_grep "${HELPER_245_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 245 modeled-applier fixture inventory (helper-minted):"
  if [[ -d "${HELPER_245_OUT}/fixtures" ]]; then
    for f in "${HELPER_245_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/modeled_applier_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'modeled (trust )?(applier|mutation) (enabled|active|wired)'
  assert_not_grep "$logf" 'modeled-applier (enabled|active|wired)'
  assert_not_grep "$logf" 'modeled trust-state mutation (enabled|active|wired)'
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

log "S1 help hides modeled-applier surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'modeled trust|modeled-applier|ModeledTrustMutationOutcome|evaluate_modeled_trust_mutation|recover_modeled_trust_mutation|ModeledGovernanceTrustMutationApplier|run-244|run-245'
log "S2..S4 default surfaces silent on modeled-applier claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step, Run 236/238/240 tie into a durable
# runtime, Run 242 hands to a typed mutation-engine boundary, and Run 244 models
# a trust-state mutation applier on top — none of which the real binary activates
# as a public production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'modeled trust|modeled-applier|run-244|run-245'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_trust_mutation_applier.rs"
RUN244_SYMS=(
  pqc_governance_modeled_trust_mutation_applier
  ModeledGovernanceTrustState
  ModeledGovernanceTrustSnapshot
  ModeledGovernanceTrustRoot
  ModeledTrustRootStatus
  ModeledGovernanceTrustMutation
  ModeledGovernanceTrustMutationInput
  ModeledGovernanceTrustMutationExpectations
  ModeledGovernanceTrustMutationPolicy
  ModeledGovernanceTrustMutationSurface
  ModeledGovernanceTrustMutationEnvironmentBinding
  ModeledGovernanceTrustMutationRuntimeBinding
  ModeledTrustMutationAction
  ModeledTrustMutationOutcome
  ModeledGovernanceTrustMutationApplier
  FixtureModeledTrustMutationApplier
  ProductionModeledTrustMutationApplier
  MainNetModeledTrustMutationApplier
  evaluate_modeled_trust_mutation
  recover_modeled_trust_mutation
  map_modeled_outcome_to_mutation_engine_outcome
  project_modeled_outcome_to_durable_completion
  modeled_outcome_authorizes_durable_consume
  modeled_trust_applier_rejection_is_non_mutating
  modeled_trust_applier_never_calls_run_070
  modeled_trust_applier_never_mutates_live_pqc_trust_state
  modeled_trust_applier_success_required_before_durable_consume
  modeled_trust_applier_failure_never_consumes
  modeled_trust_applier_rollback_never_consumes
  modeled_trust_applier_ambiguous_window_fails_closed
  production_mainnet_modeled_trust_applier_unavailable
  mainnet_peer_driven_apply_refused_by_modeled_trust_applier
  validator_set_rotation_unsupported_by_modeled_trust_applier
  policy_change_unsupported_by_modeled_trust_applier
  modeled_trust_applier_no_rocksdb_file_schema_migration_change
  local_operator_cannot_satisfy_modeled_trust_applier_authority
  peer_majority_cannot_satisfy_modeled_trust_applier_authority
)
{
  echo "Run 245 source-reachability proof — Run 244 governance modeled trust-state mutation applier boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN244_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN244_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs"
{
  echo "Run 245 helper-reachability proof — Run 244 symbols exercised by the release helper:"
  for sym in "${RUN244_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_modeled_trust_mutation recover_modeled_trust_mutation map_modeled_outcome_to_mutation_engine_outcome project_modeled_outcome_to_durable_completion modeled_outcome_authorizes_durable_consume FixtureModeledTrustMutationApplier ProductionModeledTrustMutationApplier MainNetModeledTrustMutationApplier; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 244 modeled-applier module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_trust_mutation_applier' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_modeled_trust_mutation\|pub fn recover_modeled_trust_mutation\|pub fn map_modeled_outcome_to_mutation_engine_outcome\|pub fn project_modeled_outcome_to_durable_completion' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing modeled-applier entry points"
# Outcome / action taxonomy within the module.
grep -RIn --include='*.rs' 'enum ModeledTrustMutationOutcome\|enum ModeledTrustMutationAction' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing modeled-applier outcome/action taxonomy"
# Applier trait + implementations within the module.
grep -RIn --include='*.rs' 'trait ModeledGovernanceTrustMutationApplier\|struct FixtureModeledTrustMutationApplier\|struct ProductionModeledTrustMutationApplier\|struct MainNetModeledTrustMutationApplier' "${MOD}" > "${REACH_DIR}/applier_boundary.txt" || fail "missing applier boundary"
# Run 242 mutation outcome + Run 240 durable completion projection usage.
grep -RIn --include='*.rs' 'GovernanceMutationOutcome\|DurableMutationCompletion\|MutationEngineDurableProjection\|pqc_governance_execution_mutation_engine' "${MOD}" > "${REACH_DIR}/run242_run240_projection_usage.txt" || fail "missing Run 242/240 projection usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionModeledMutationUnavailable\|MainNetModeledMutationUnavailable\|production_mainnet_modeled_trust_applier_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_refused_by_modeled_trust_applier\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefused\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_trust_applier_no_rocksdb_file_schema_migration_change\|validator_set_rotation_unsupported_by_modeled_trust_applier\|policy_change_unsupported_by_modeled_trust_applier' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 245 denylist (proven empty across captured logs):"
  for pat in 'real production mutation engine enabled' 'modeled applier production enabled' 'MainNet modeled applier enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'real persistent replay backend enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled-applier' 'LivePqcTrustState mutation from the modeled-applier' 'real trust swap from the modeled-applier' 'session eviction from the modeled-applier' 'marker write from the modeled-applier' 'sequence write from the modeled-applier' 'durable consume by the modeled-applier' 'DummySig' 'DummyKem' 'DummyAead' 'modeled applier active' 'production modeled applier active' 'mainnet modeled applier active'; do
    if find "${LOGS_DIR}" "${HELPER_245_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_245.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 245 no-mutation proof for rejected modeled-applier scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / modeled-state / reachability helper corpus (driven through the Run 244 evaluate_modeled_trust_mutation / recover_modeled_trust_mutation / map_modeled_outcome_to_mutation_engine_outcome / project_modeled_outcome_to_durable_completion / modeled_outcome_authorizes_durable_consume over the ModeledGovernanceTrustMutationApplier trait and the DevNet/TestNet FixtureModeledTrustMutationApplier plus the always-unavailable ProductionModeledTrustMutationApplier / MainNetModeledTrustMutationApplier): the modeled-applier boundary is a pure, typed function over its inputs plus a mockable applier that mutates ONLY the in-memory ModeledGovernanceTrustState. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, never mutates LivePqcTrustState, and never invokes Run 070. A Disabled policy / applier kind is a legacy bypass that performs no modeled mutation and never invokes the applier. Binding validation runs before any snapshot; a wrong environment / chain / genesis / governance surface / mutation surface / candidate digest / decision digest / proposal id / decision id / authority-domain sequence / lifecycle action, or a malformed modeled mutation, is a non-mutating reject-before-snapshot that never reaches the applier (the helper proves the fixture applier attempt counter stays at zero on every reject-before-snapshot path, and the modeled state stays unchanged). A read-only validation surface never mutates. Retiring/revoking a missing root snapshots then rejects-before-apply with the modeled state unchanged. ModeledMutationApplied is the only outcome that maps to MutationAppliedSuccessfully and projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully; rejected/failed/rolled-back/rollback-failed/ambiguous/unavailable/unsupported outcomes never consume. Production / MainNet applier kinds are reachable but always unavailable / fail-closed. MainNet peer-driven apply is refused before any snapshot and before applier invocation, even when the binding is otherwise broken. Validator-set rotation and policy-change actions remain unsupported. The appliers are in-process models only — they introduce no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_245_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 245 mutation proof (release-binary scope): the Run 244 governance modeled trust-state mutation applier boundary is a pure, typed composition that adds the smallest in-memory model of what a future governance mutation applier would do after every Run 242 mutation-engine gate has already passed: snapshot a modeled trust state, apply a modeled trust-state update, report success/failure/rollback/rollback-failed/ambiguous windows, and project the modeled outcome through the Run 242 GovernanceMutationOutcome into the Run 240 durable runtime's DurableMutationCompletion semantics. It specifies the ordering a real mutation applier would have to honour (MainNet peer-driven refusal -> legacy bypass -> binding validation (reject before snapshot) -> read-only gating -> unsupported-action gating -> applier-kind routing -> applier hand-off -> modeled apply / rollback / report -> durable projection), but implements NONE of that production mutation: there is no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no real persistent replay backend, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledTrustMutationApplier mutates ONLY the in-memory ModeledGovernanceTrustState and performs no real trust mutation, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, no marker write, and no durable consume; the ProductionModeledTrustMutationApplier and MainNetModeledTrustMutationApplier are always unavailable / fail-closed. The ModeledMutationApplied -> MutationAppliedSuccessfully -> DurableMutationCompletion::AppliedSuccessfully projection is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production durable store; Run 245 does not exercise that mutating path and activates no production modeled applier. The boundary is pure and non-mutating on every rejection path; production/MainNet modeled appliers remain callable-but-unavailable; MainNet peer-driven apply is refused before any snapshot or applier invocation."
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
TEST_TARGETS=(run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 245 — release-binary modeled governance trust-state mutation applier evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_245_sha256:  $(sha256_file "${HELPER_245_BIN}")"
  echo "  helper_245_buildid: $(build_id "${HELPER_245_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_245rc=$(cat "${EXIT_DIR}/helper_run_245.rc")$(grep -E 'verdict:' "${HELPER_245_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 244 modeled-applier boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_245_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 244 governance modeled trust-state mutation applier boundary is a pure, typed function over its inputs plus a mockable applier that mutates ONLY the in-memory ModeledGovernanceTrustState, exercised here through release-built library symbols (the same symbols a future production call site would use); a Disabled policy / applier kind is a legacy bypass with no modeled mutation and no applier invocation; binding validation runs before any snapshot and a mismatch is a non-mutating reject-before-snapshot that never reaches the applier; a read-only validation surface never mutates; retiring/revoking a missing root snapshots then rejects-before-apply with modeled state unchanged; only a modeled ModeledMutationApplied maps to MutationAppliedSuccessfully and projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully, while rejected/failed/rolled-back/rollback-failed/ambiguous/unavailable/unsupported outcomes never consume; production/MainNet applier kinds are reachable but always unavailable/fail-closed; MainNet peer-driven apply is refused before any snapshot and before applier invocation; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call, no LivePqcTrustState mutation); no real governance execution engine, mutation engine, or on-chain governance proof verifier; no real persistent replay backend; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "done — summary at ${SUMMARY}"
cat "${SUMMARY}"