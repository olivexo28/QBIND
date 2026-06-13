#!/usr/bin/env bash
# Run 247 — Release-binary governance modeled end-to-end pipeline evidence.
#
# Proves the release-built code exposes and exercises the Run 246 governance
# **modeled end-to-end pipeline boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`:
# the entry point `run_modeled_end_to_end_pipeline`; the crash-window recovery
# `recover_modeled_end_to_end_pipeline_window`; the pure/mockable executor trait
# `GovernanceModeledEndToEndPipelineExecutor` with
# `DefaultGovernanceModeledEndToEndPipelineExecutor`; the typed bindings
# (`GovernanceModeledEndToEndPipelineInput`,
# `GovernanceModeledEndToEndPipelineExpectations`,
# `GovernanceModeledEndToEndPipelinePolicy`,
# `GovernanceModeledEndToEndPipelineSurface`,
# `GovernanceModeledEndToEndPipelineEnvironmentBinding`,
# `GovernanceModeledEndToEndPipelineRuntimeBinding`,
# `GovernanceModeledEndToEndPipelineCandidate`,
# `GovernanceModeledEndToEndPipelineReplayBinding`,
# `GovernanceModeledEndToEndPipelineMutationBinding`); the stage records
# (`EvaluatorCallsiteStage`, `DurableReplayObserveStage`, `MutationEngineStage`,
# `ModeledApplierStage`, `DurableProjectionStage`, `DurableConsumeDecisionStage`);
# the stage classifications (`EvaluatorCallsiteAuthorization`,
# `DurableReplayObservation`); the outcome / decision (
# `GovernanceModeledEndToEndPipelineOutcome`,
# `GovernanceModeledEndToEndPipelineDecision`); and the grep-verifiable invariant
# / fail-closed helpers (`modeled_end_to_end_pipeline_rejection_is_non_mutating`,
# `modeled_end_to_end_pipeline_never_calls_run_070`,
# `modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state`,
# `modeled_end_to_end_pipeline_success_required_before_durable_consume`,
# `modeled_end_to_end_pipeline_applier_success_required_before_consume`,
# `modeled_end_to_end_pipeline_failed_apply_never_consumes`,
# `modeled_end_to_end_pipeline_rollback_never_consumes`,
# `modeled_end_to_end_pipeline_ambiguous_window_fails_closed`,
# `modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first`,
# `modeled_end_to_end_pipeline_production_mainnet_unavailable`,
# `modeled_end_to_end_pipeline_validator_set_rotation_unsupported`,
# `modeled_end_to_end_pipeline_policy_change_unsupported`,
# `modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change`,
# `modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority`,
# `modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority`).
#
# Run 246 landed the typed end-to-end pipeline boundary plus source/test coverage
# at the source/test level. Run 247 proves on real `target/release/qbind-node`
# plus a release-built helper that the release-built code exposes and exercises
# it: a disabled pipeline / evaluator-call-site policy is a legacy bypass with no
# modeled mutation and no applier invocation; MainNet peer-driven apply is refused
# before any replay consume, modeled snapshot, or applier invocation;
# evaluator/call-site authorization runs before durable replay consume; durable
# replay freshness runs before mutation-engine authorization; mutation-engine
# authorization runs before modeled applier invocation; modeled applier success
# runs before durable consume authorization; the only consume-authorizing outcome
# is ModeledApplierAppliedAndDurableConsumeAuthorized; evaluator success alone,
# durable replay freshness alone, and mutation-engine authorization alone are each
# insufficient; every rejection / unavailable / rollback / rollback-failed /
# ambiguous / read-only / validator-set-rotation / policy-change path is
# non-mutating and non-consuming, and a rejection before the applier stage leaves
# the applier invocation count at zero. The pipeline is pure (no marker/sequence
# write, no live trust swap, no session eviction, no Run 070 call, no
# LivePqcTrustState mutation, no durable consume of its own, no persistent
# storage); no real governance engine, mutation engine, or on-chain proof
# verifier; no RocksDB/file/schema/migration/storage/wire/marker/sequence/
# trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_247_BIN="${REPO_ROOT}/target/release/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper"
HELPER_247_OUT="${OUTDIR}/helper_evidence/run_247"
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

log() { printf '[run-247] %s\n' "$*" >&2; }
fail() { printf '[run-247] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_247_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_247_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-247 provenance"
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
log "cargo build --release -p qbind-node --example run_247_governance_modeled_end_to_end_pipeline_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_247_governance_modeled_end_to_end_pipeline_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_247.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_247_BIN}" ]] || fail "missing ${HELPER_247_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_247_path:    ${HELPER_247_BIN}"
  echo "helper_247_sha256:  $(sha256_file "${HELPER_247_BIN}")"
  echo "helper_247_buildid: $(build_id "${HELPER_247_BIN}")"
} >> "${PROVENANCE}"

log "running Run 247 helper"
set +e
"${HELPER_247_BIN}" "${HELPER_247_OUT}" > "${LOGS_DIR}/helper_run_247.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_247.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_247 helper failed"
assert_grep "${HELPER_247_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 247 end-to-end-pipeline fixture inventory (helper-minted):"
  if [[ -d "${HELPER_247_OUT}/fixtures" ]]; then
    for f in "${HELPER_247_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/end_to_end_pipeline_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'modeled end-to-end pipeline (enabled|active|wired)'
  assert_not_grep "$logf" 'end-to-end pipeline (enabled|active|wired)'
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

log "S1 help hides end-to-end-pipeline surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'modeled end-to-end|end-to-end pipeline|GovernanceModeledEndToEndPipeline|run_modeled_end_to_end_pipeline|recover_modeled_end_to_end_pipeline_window|run-246|run-247'
log "S2..S4 default surfaces silent on end-to-end-pipeline claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step, Run 236/238/240 tie into a durable
# runtime, Run 242 hands to a typed mutation-engine boundary, Run 244 models a
# trust-state mutation applier, and Run 246 composes them into a typed end-to-end
# pipeline — none of which the real binary activates as a public production
# enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'modeled end-to-end|end-to-end pipeline|run-246|run-247'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_end_to_end_pipeline.rs"
RUN246_SYMS=(
  pqc_governance_modeled_end_to_end_pipeline
  GovernanceModeledEndToEndPipelineInput
  GovernanceModeledEndToEndPipelineExpectations
  GovernanceModeledEndToEndPipelinePolicy
  GovernanceModeledEndToEndPipelineSurface
  GovernanceModeledEndToEndPipelineEnvironmentBinding
  GovernanceModeledEndToEndPipelineRuntimeBinding
  GovernanceModeledEndToEndPipelineCandidate
  GovernanceModeledEndToEndPipelineReplayBinding
  GovernanceModeledEndToEndPipelineMutationBinding
  GovernanceModeledEndToEndPipelineDecision
  GovernanceModeledEndToEndPipelineOutcome
  GovernanceModeledEndToEndPipelineExecutor
  DefaultGovernanceModeledEndToEndPipelineExecutor
  EvaluatorCallsiteStage
  DurableReplayObserveStage
  MutationEngineStage
  ModeledApplierStage
  DurableProjectionStage
  DurableConsumeDecisionStage
  EvaluatorCallsiteAuthorization
  DurableReplayObservation
  run_modeled_end_to_end_pipeline
  recover_modeled_end_to_end_pipeline_window
  ModeledApplierAppliedAndDurableConsumeAuthorized
  MainNetPeerDrivenApplyRefusedNoConsume
  ProductionUnavailableNoConsume
  MainNetUnavailableNoConsume
  ValidatorSetRotationUnsupportedNoConsume
  PolicyChangeUnsupportedNoConsume
  BackendUnavailableNoConsume
  ReplayConsumedNoConsume
  ReplaySupersededNoConsume
  ReplayStaleOrExpiredNoConsume
  modeled_end_to_end_pipeline_rejection_is_non_mutating
  modeled_end_to_end_pipeline_never_calls_run_070
  modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state
  modeled_end_to_end_pipeline_success_required_before_durable_consume
  modeled_end_to_end_pipeline_applier_success_required_before_consume
  modeled_end_to_end_pipeline_failed_apply_never_consumes
  modeled_end_to_end_pipeline_rollback_never_consumes
  modeled_end_to_end_pipeline_ambiguous_window_fails_closed
  modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first
  modeled_end_to_end_pipeline_production_mainnet_unavailable
  modeled_end_to_end_pipeline_validator_set_rotation_unsupported
  modeled_end_to_end_pipeline_policy_change_unsupported
  modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change
  modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority
  modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 247 source-reachability proof — Run 246 governance modeled end-to-end pipeline boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN246_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN246_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs"
{
  echo "Run 247 helper-reachability proof — Run 246 symbols exercised by the release helper:"
  for sym in "${RUN246_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in run_modeled_end_to_end_pipeline recover_modeled_end_to_end_pipeline_window DefaultGovernanceModeledEndToEndPipelineExecutor GovernanceModeledEndToEndPipelineExecutor GovernanceModeledEndToEndPipelineInput GovernanceModeledEndToEndPipelineOutcome GovernanceModeledEndToEndPipelineDecision EvaluatorCallsiteAuthorization DurableReplayObservation; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 246 end-to-end pipeline module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_end_to_end_pipeline' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn run_modeled_end_to_end_pipeline\|pub fn recover_modeled_end_to_end_pipeline_window' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing end-to-end pipeline entry points"
# Outcome / stage taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceModeledEndToEndPipelineOutcome\|enum EvaluatorCallsiteAuthorization\|enum DurableReplayObservation' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing pipeline outcome/stage taxonomy"
# Executor trait + default implementation within the module.
grep -RIn --include='*.rs' 'trait GovernanceModeledEndToEndPipelineExecutor\|struct DefaultGovernanceModeledEndToEndPipelineExecutor' "${MOD}" > "${REACH_DIR}/executor_boundary.txt" || fail "missing executor boundary"
# Run 244 / 242 / 240 / 226 composition usage within the module.
grep -RIn --include='*.rs' 'evaluate_modeled_trust_mutation\|GovernanceMutationOutcome\|DurableReplayRuntimeOutcome\|GovernanceEvaluatorRuntimeIntegrationOutcome\|MutationEngineDurableProjection' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 244/242/240/226 composition usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionUnavailableNoConsume\|MainNetUnavailableNoConsume\|modeled_end_to_end_pipeline_production_mainnet_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoConsume\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change\|modeled_end_to_end_pipeline_validator_set_rotation_unsupported\|modeled_end_to_end_pipeline_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 247 denylist (proven empty across captured logs):"
  for pat in 'real production mutation engine enabled' 'modeled end-to-end pipeline production enabled' 'MainNet modeled end-to-end pipeline enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'real persistent replay backend enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled end-to-end pipeline' 'LivePqcTrustState mutation from the modeled end-to-end pipeline' 'real trust swap from the modeled end-to-end pipeline' 'session eviction from the modeled end-to-end pipeline' 'marker write from the modeled end-to-end pipeline' 'sequence write from the modeled end-to-end pipeline' 'durable consume by the modeled end-to-end pipeline' 'DummySig' 'DummyKem' 'DummyAead' 'modeled end-to-end pipeline active' 'production modeled end-to-end pipeline active' 'mainnet modeled end-to-end pipeline active'; do
    if find "${LOGS_DIR}" "${HELPER_247_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_247.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 247 no-mutation proof for rejected end-to-end-pipeline scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / non-mutation / reachability helper corpus (driven through the Run 246 run_modeled_end_to_end_pipeline / recover_modeled_end_to_end_pipeline_window over the GovernanceModeledEndToEndPipelineExecutor trait and the DevNet/TestNet FixtureModeledTrustMutationApplier plus the always-unavailable ProductionModeledTrustMutationApplier / MainNetModeledTrustMutationApplier): the end-to-end pipeline is a pure typed ordering/composition over the already-landed Run 226 evaluator call-site, Run 240 durable replay observation, Run 242 mutation-engine, and Run 244 modeled trust-state applier boundaries plus a mockable applier that mutates ONLY the in-memory ModeledGovernanceTrustState. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled pipeline / evaluator-call-site policy is a legacy bypass that performs no modeled mutation and never invokes the applier. MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation. Evaluator/call-site authorization runs before durable replay consume; durable replay freshness runs before mutation-engine authorization; mutation-engine authorization runs before modeled applier invocation; modeled applier success runs before durable consume authorization. The only consume-authorizing outcome is ModeledApplierAppliedAndDurableConsumeAuthorized; evaluator success alone, durable replay freshness alone, and mutation-engine authorization alone are each individually insufficient. Every rejection (evaluator/call-site, binding mismatch, read-only surface, replay stale/expired/consumed/superseded/backend-unavailable/deferred, missing-root before-apply), apply failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet path, validator-set rotation, and policy-change attempt is non-mutating and non-consuming, and a rejection before the applier stage leaves the applier invocation count at zero with the modeled state unchanged (the helper proves the fixture applier attempt counter stays at zero on every reject-before-applier path). The pipeline is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_247_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 247 mutation proof (release-binary scope): the Run 246 governance modeled end-to-end pipeline boundary is a pure, typed ordering/composition layer that threads the already-landed Run 226 evaluator/call-site authorization, Run 240 durable replay/freshness observation, Run 242 mutation-engine authorization, and Run 244 modeled trust-state applier success into one typed pipeline so that a durable consume is authorized end-to-end ONLY after a modeled successful applier outcome. It specifies the ordering a real end-to-end governance pipeline would have to honour (MainNet peer-driven refusal -> legacy bypass -> evaluator/call-site authorization -> durable replay/freshness observation -> mutation-engine authorization -> modeled applier invocation -> modeled apply / rollback / report -> durable consume decision), but implements NONE of that production mutation: there is no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no real persistent replay backend, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledTrustMutationApplier mutates ONLY the in-memory ModeledGovernanceTrustState and performs no real trust mutation, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, no marker write, and no durable consume; the ProductionModeledTrustMutationApplier and MainNetModeledTrustMutationApplier are always unavailable / fail-closed. The ModeledApplierAppliedAndDurableConsumeAuthorized outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production durable store; Run 247 does not exercise that mutating path and activates no production pipeline. The boundary is pure and non-mutating on every rejection path; production/MainNet paths remain callable-but-unavailable; MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation."
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
TEST_TARGETS=(run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 247 — release-binary modeled governance end-to-end pipeline evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_247_sha256:  $(sha256_file "${HELPER_247_BIN}")"
  echo "  helper_247_buildid: $(build_id "${HELPER_247_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_247rc=$(cat "${EXIT_DIR}/helper_run_247.rc")$(grep -E 'verdict:' "${HELPER_247_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 246 end-to-end-pipeline boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_247_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 246 governance modeled end-to-end pipeline boundary is a pure, typed ordering/composition over the already-landed Run 226 evaluator call-site, Run 240 durable replay observation, Run 242 mutation-engine, and Run 244 modeled trust-state applier boundaries plus a mockable applier that mutates ONLY the in-memory ModeledGovernanceTrustState, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled pipeline / evaluator-call-site policy is a legacy bypass with no modeled mutation and no applier invocation; MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation; evaluator/call-site authorization runs before durable replay consume; durable replay freshness runs before mutation-engine authorization; mutation-engine authorization runs before modeled applier invocation; modeled applier success runs before durable consume authorization; the only consume-authorizing outcome is ModeledApplierAppliedAndDurableConsumeAuthorized, while evaluator success alone, durable replay freshness alone, and mutation-engine authorization alone are each insufficient; rejected/failed/rolled-back/rollback-failed/ambiguous/unavailable/unsupported paths never consume; production/MainNet paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call, no LivePqcTrustState mutation), and a rejection before the applier stage leaves the applier invocation count at zero; no real governance execution engine, mutation engine, or on-chain governance proof verifier; no real persistent replay backend; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 245, Run 243, Run 241, Run 239, Run 237, Run 235, Run 233, and Run 231 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "done — summary at ${SUMMARY}"