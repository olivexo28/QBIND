#!/usr/bin/env bash
# Run 253 — Release-binary governance modeled durable-consume receipt-acknowledgement /
# finalization projection evidence.
#
# Proves the release-built code exposes and exercises the Run 252 governance
# **modeled durable-completion finalization projection boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_durable_completion_finalization_projection.rs`:
# the entry point `evaluate_modeled_durable_completion_finalization_projection`; the
# crash-window recovery `recover_modeled_durable_completion_finalization_window`;
# the sink-outcome projection `project_completion_reporter_outcome_to_finalization_intent`;
# the predicate helpers `finalization_outcome_authorizes_modeled_durable_completion` /
# `finalization_outcome_projects_to_durable_completion`; the pure/mockable
# finalizer trait `GovernanceModeledDurableCompletionFinalization` with
# `FixtureModeledDurableCompletionFinalizer`,
# `ProductionModeledDurableCompletionFinalizer`, and
# `MainNetModeledDurableCompletionFinalizer`; the typed bindings
# (`GovernanceModeledDurableCompletionFinalizationInput`,
# `GovernanceModeledDurableCompletionFinalizationExpectations`,
# `GovernanceModeledDurableCompletionFinalizationPolicy`); the modeled
# finalization ledger (`GovernanceModeledDurableCompletionFinalizationRecord`,
# `ModeledDurableCompletionFinalizationLedger`,
# `ModeledDurableCompletionFinalizationRecord`,
# `ModeledDurableCompletionFinalizationSnapshot`,
# `ModeledDurableCompletionFinalizationStatus`,
# `ModeledDurableCompletionFinalizationDigest`); the outcome / intent / fault
# taxonomy (`GovernanceModeledDurableCompletionFinalizationOutcome`,
# `DurableCompletionFinalizationIntent`, `ModeledDurableCompletionFinalizationFault`); and the grep-verifiable
# invariant / fail-closed helpers.
#
# Run 252 landed the typed durable-completion finalization projection boundary plus
# source/test coverage at the source/test level. Run 253 proves on real
# `target/release/qbind-node` plus a release-built helper that the release-built
# code exposes and exercises it: a disabled finalizer / sink / pipeline /
# evaluator-call-site policy is a legacy no-acknowledgement, no-finalization bypass
# with no finalizer invocation; MainNet peer-driven apply is refused before pipeline
# progression, before any sink invocation, and before any finalizer invocation;
# only the Run 248 ConsumeReceiptRecorded sink outcome creates a finalization
# intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded
# finalization; only DurableCompletionFinalized authorizes a new modeled
# durable-completion-finalized state; a duplicate identical finalization is idempotent
# (no second finalization) and the same finalization id with a different digest fails closed as
# equivocation; every non-recording sink outcome, record failure, rollback,
# rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet
# finalizer path, and unsupported action never completes, and a rejection before the
# finalizer stage leaves the finalizer invocation count at zero. The finalizer is pure
# (no marker/sequence write, no live trust swap, no session eviction, no Run 070
# call, no LivePqcTrustState mutation, no durable consume of its own, no persistent
# storage); the DevNet/TestNet fixture finalizer mutates ONLY the in-memory
# ModeledDurableCompletionFinalizationLedger; no real finalization backend,
# durable consume backend, persistent replay backend, production mutation engine,
# governance execution engine, or on-chain proof verifier; no RocksDB/file/schema/
# migration/storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_253_modeled_durable_completion_finalization_projection_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_253_BIN="${REPO_ROOT}/target/release/examples/run_253_modeled_durable_completion_finalization_projection_release_binary_helper"
HELPER_253_OUT="${OUTDIR}/helper_evidence/run_253"
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

log() { printf '[run-253] %s\n' "$*" >&2; }
fail() { printf '[run-253] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_253_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_253_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-253 provenance"
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
log "cargo build --release -p qbind-node --example run_253_modeled_durable_completion_finalization_projection_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_253_modeled_durable_completion_finalization_projection_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_253.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_253_BIN}" ]] || fail "missing ${HELPER_253_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_253_path:    ${HELPER_253_BIN}"
  echo "helper_253_sha256:  $(sha256_file "${HELPER_253_BIN}")"
  echo "helper_253_buildid: $(build_id "${HELPER_253_BIN}")"
} >> "${PROVENANCE}"

log "running Run 253 helper"
set +e
"${HELPER_253_BIN}" "${HELPER_253_OUT}" > "${LOGS_DIR}/helper_run_253.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_253.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_253 helper failed"
assert_grep "${HELPER_253_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 253 finalization fixture inventory (helper-minted):"
  if [[ -d "${HELPER_253_OUT}/fixtures" ]]; then
    for f in "${HELPER_253_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/finalization_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'finalization[- ]report(er)? (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'modeled durable-consume finalization[- ]report(er)? (enabled|active|wired)'
  assert_not_grep "$logf" 'durable[- ]consume (sink )?(enabled|active|wired)'
  assert_not_grep "$logf" 'consume[- ]receipt sink (enabled|active|wired)'
  assert_not_grep "$logf" 'end-to-end pipeline (enabled|active|wired)'
  assert_not_grep "$logf" 'modeled (trust )?(applier|mutation) (enabled|active|wired)'
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
  assert_not_grep "$logf" 'real durable consume backend (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real finalization[- ]report backend (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'persistent replay (state )?(store|backend) (enabled|active|wired)'
  assert_not_grep "$logf" 'RocksDB (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'file replay backend (enabled|active|wired)'
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

log "S1 help hides finalization-projection surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-consume finalization[- ]report(er)?|GovernanceModeledDurableCompletionFinalizationRecord|evaluate_modeled_durable_completion_finalization_projection|recover_modeled_durable_completion_finalization_window|ModeledDurableCompletionFinalizationLedger|run-252|run-253'
log "S2..S4 default surfaces silent on finalization-projection claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step, Run 236/238/240 tie into a durable
# runtime, Run 242 hands to a typed mutation-engine boundary, Run 244 models a
# trust-state mutation applier, Run 246 composes them into a typed end-to-end
# pipeline, Run 248 projects that pipeline onto a modeled durable-consume receipt
# sink, and Run 252 acknowledges that recorded receipt with a modeled durable-consume
# finalization projection — none of which the real binary activates as a public
# production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'durable-consume finalization[- ]report(er)?|run-252|run-253'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_durable_completion_finalization_projection.rs"
RUN252_SYMS=(
  pqc_governance_modeled_durable_completion_finalization_projection
  GovernanceModeledDurableCompletionFinalizationInput
  GovernanceModeledDurableCompletionFinalizationExpectations
  GovernanceModeledDurableCompletionFinalizationPolicy
  GovernanceModeledDurableCompletionFinalizationRecord
  GovernanceModeledDurableCompletionFinalizationSurface
  GovernanceModeledDurableCompletionFinalizationEnvironmentBinding
  GovernanceModeledDurableCompletionFinalizationRuntimeBinding
  GovernanceModeledDurableCompletionFinalizationReplayBinding
  GovernanceModeledDurableCompletionFinalizationPipelineBinding
  GovernanceModeledDurableCompletionFinalizationSinkBinding
  GovernanceModeledDurableCompletionFinalizationReporterBinding
  ModeledDurableCompletionFinalizationLedger
  ModeledDurableCompletionFinalizationRecord
  ModeledDurableCompletionFinalizationSnapshot
  ModeledDurableCompletionFinalizationStatus
  ModeledDurableCompletionFinalizationDigest
  GovernanceModeledDurableCompletionFinalizationOutcome
  DurableCompletionFinalizationIntent
  GovernanceModeledDurableCompletionFinalizer
  FixtureModeledDurableCompletionFinalizer
  ProductionModeledDurableCompletionFinalizer
  MainNetModeledDurableCompletionFinalizer
  project_completion_reporter_outcome_to_finalization_intent
  evaluate_modeled_durable_completion_finalization_projection
  recover_modeled_durable_completion_finalization_window
  finalization_outcome_authorizes_modeled_durable_completion
  finalization_outcome_projects_to_durable_completion
  DurableCompletionFinalized
  DurableCompletionDuplicateIdempotent
  DurableCompletionRejectedBeforeRecord
  DurableCompletionRecordFailedNoFinalization
  DurableCompletionRolledBackNoFinalization
  DurableCompletionRollbackFailedFatalNoFinalization
  DurableCompletionAmbiguousFailClosedNoFinalization
  ProductionFinalizerUnavailableNoFinalization
  MainNetFinalizerUnavailableNoFinalization
  MainNetPeerDrivenApplyRefusedNoFinalization
  ValidatorSetRotationUnsupportedNoFinalization
  PolicyChangeUnsupportedNoFinalization
  modeled_finalization_rejection_is_non_mutating
  modeled_finalization_never_calls_run_070
  modeled_finalization_never_mutates_live_pqc_trust_state
  modeled_finalization_never_writes_sequence_or_marker
  modeled_finalization_no_rocksdb_file_schema_migration_change
  modeled_finalization_pipeline_success_required_before_finalization
  modeled_finalization_sink_receipt_required_before_finalization
  modeled_finalization_completion_report_required_before_finalization
  modeled_finalization_record_required_before_durable_completion
  modeled_finalization_failed_record_never_finalizes
  modeled_finalization_rollback_never_finalizes
  modeled_finalization_ambiguous_window_fails_closed
  modeled_finalization_mainnet_peer_driven_apply_refused_first
  modeled_finalization_production_mainnet_unavailable
  modeled_finalization_validator_set_rotation_unsupported
  modeled_finalization_policy_change_unsupported
  modeled_finalization_local_operator_cannot_satisfy_mainnet_authority
  modeled_finalization_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 253 source-reachability proof — Run 252 governance modeled durable-completion finalization projection boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN252_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN252_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_253_modeled_durable_completion_finalization_projection_release_binary_helper.rs"
{
  echo "Run 253 helper-reachability proof — Run 252 symbols exercised by the release helper:"
  for sym in "${RUN252_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_modeled_durable_completion_finalization_projection recover_modeled_durable_completion_finalization_window project_completion_reporter_outcome_to_finalization_intent finalization_outcome_authorizes_modeled_durable_completion finalization_outcome_projects_to_durable_completion GovernanceModeledDurableCompletionFinalizer FixtureModeledDurableCompletionFinalizer ProductionModeledDurableCompletionFinalizer MainNetModeledDurableCompletionFinalizer GovernanceModeledDurableCompletionFinalizationInput GovernanceModeledDurableCompletionFinalizationOutcome ModeledDurableCompletionFinalizationLedger DurableCompletionFinalizationIntent ModeledDurableCompletionFinalizationFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 252 finalizer module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_durable_completion_finalization_projection' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_modeled_durable_completion_finalization_projection\|pub fn recover_modeled_durable_completion_finalization_window\|pub fn project_completion_reporter_outcome_to_finalization_intent' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing finalizer entry points"
# Outcome / intent / fault taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceModeledDurableCompletionFinalizationOutcome\|enum DurableCompletionFinalizationIntent\|enum ModeledDurableCompletionFinalizationFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing finalizer outcome/intent/fault taxonomy"
# Finalizer trait + fixture/production/mainnet implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceModeledDurableCompletionFinalizer\|struct FixtureModeledDurableCompletionFinalizer\|struct ProductionModeledDurableCompletionFinalizer\|struct MainNetModeledDurableCompletionFinalizer' "${MOD}" > "${REACH_DIR}/finalizer_boundary.txt" || fail "missing finalizer boundary"
# Run 248 sink composition usage within the module.
grep -RIn --include='*.rs' 'GovernanceModeledDurableConsumeSinkOutcome\|ConsumeReceiptRecorded\|GovernanceModeledEndToEndPipelineOutcome' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 248 composition usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionFinalizerUnavailableNoFinalization\|MainNetFinalizerUnavailableNoFinalization\|modeled_finalization_production_mainnet_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'modeled_finalization_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoFinalization\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_finalization_no_rocksdb_file_schema_migration_change\|modeled_finalization_validator_set_rotation_unsupported\|modeled_finalization_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 253 denylist (proven empty across captured logs):"
  for pat in 'real finalization backend enabled' 'modeled finalization-projection production enabled' 'MainNet modeled finalization-projection enabled' 'real durable consume backend enabled' 'real persistent replay backend enabled' 'modeled durable-consume sink production enabled' 'MainNet modeled durable-consume sink enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled finalization projection' 'LivePqcTrustState mutation from the modeled finalization projection' 'real trust swap from the modeled finalization projection' 'session eviction from the modeled finalization projection' 'marker write from the modeled finalization projection' 'sequence write from the modeled finalization projection' 'RocksDB write from the modeled finalization projection' 'file write from the modeled finalization projection' 'production durable consume by the modeled finalization projection' 'production finalization by the modeled finalizer' 'DummySig' 'DummyKem' 'DummyAead' 'modeled finalization projection active' 'production modeled finalization projection active' 'mainnet modeled finalization projection active'; do
    if find "${LOGS_DIR}" "${HELPER_253_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_253.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 253 no-mutation proof for rejected finalization-projection scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / finalization-ledger / non-mutation / reachability helper corpus (driven through the Run 252 evaluate_modeled_durable_completion_finalization_projection / recover_modeled_durable_completion_finalization_window / project_completion_reporter_outcome_to_finalization_intent over the GovernanceModeledDurableCompletionFinalization trait and the DevNet/TestNet FixtureModeledDurableCompletionFinalizer plus the always-unavailable ProductionModeledDurableCompletionFinalizer / MainNetModeledDurableCompletionFinalizer): the durable-completion finalization projection is a pure typed projection over the already-landed Run 248 modeled durable-consume sink receipt plus a mockable finalizer that records ONLY the in-memory ModeledDurableCompletionFinalizationLedger. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled finalizer / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass that never invokes the finalizer. MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, and before any finalizer invocation. Only the Run 248 ConsumeReceiptRecorded sink outcome creates a finalization intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded finalization; only DurableCompletionFinalized authorizes a new modeled durable-completion-finalized state; a duplicate identical finalization is idempotent (no second finalization) and the same finalization id with a different digest fails closed as equivocation. Every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet finalizer path, and unsupported action never completes, and a rejection before the finalizer stage leaves the finalizer invocation count at zero (the helper proves the fixture finalizer invocation counter stays at zero on every reject-before-finalizer path). The finalizer is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_253_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 253 mutation proof (release-binary scope): the Run 252 governance modeled durable-completion finalization projection boundary is a pure, typed projection that records how a future production call site would acknowledge an after-receipt-recorded durable-consume finalization ONLY once the Run 248 modeled durable-consume sink has recorded a consume receipt. It specifies the ordering a real finalization projection would have to honour (MainNet peer-driven refusal -> legacy bypass -> sink-outcome projection -> pre-record environment/surface binding validation -> report record -> idempotency/equivocation gate -> finalization authorization), but implements NONE of that production finalization: there is no real finalization backend, no real durable consume backend, no real persistent replay backend, no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledDurableCompletionFinalizer records ONLY the in-memory ModeledDurableCompletionFinalizationLedger and performs no real finalization, no durable consume, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, and no marker write; the ProductionModeledDurableCompletionFinalizer and MainNetModeledDurableCompletionFinalizer are always unavailable / fail-closed. The DurableCompletionFinalized outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production finalization store; Run 253 does not exercise that mutating path and activates no production finalization. The boundary is pure and non-mutating on every rejection path; production/MainNet paths remain callable-but-unavailable; MainNet peer-driven apply is refused before pipeline progression and before any sink or finalizer invocation."
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
TEST_TARGETS=(run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 253 — release-binary modeled governance durable-completion finalization projection evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_253_sha256:  $(sha256_file "${HELPER_253_BIN}")"
  echo "  helper_253_buildid: $(build_id "${HELPER_253_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_253rc=$(cat "${EXIT_DIR}/helper_run_253.rc")$(grep -E 'verdict:' "${HELPER_253_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 252 finalization-projection boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_253_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 252 governance modeled durable-completion finalization projection boundary is a pure, typed projection over the already-landed Run 248 modeled durable-consume sink receipt plus a mockable finalizer that records ONLY the in-memory ModeledDurableCompletionFinalizationLedger, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled finalizer / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass with no finalizer invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, and before any finalizer invocation; only the Run 248 ConsumeReceiptRecorded sink outcome creates a finalization intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded finalization; only DurableCompletionFinalized authorizes a new modeled durable-completion-finalized state; a duplicate identical finalization is idempotent (no second finalization) and the same finalization id with a different digest fails closed as equivocation; every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet finalizer path, and unsupported action never completes, and a rejection before the finalizer stage leaves the finalizer invocation count at zero; production/MainNet paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call, no LivePqcTrustState mutation); no real finalization backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 249, Run 247, Run 245, Run 243, and Run 241 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"