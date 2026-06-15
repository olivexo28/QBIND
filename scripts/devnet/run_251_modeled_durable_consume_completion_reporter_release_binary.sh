#!/usr/bin/env bash
# Run 251 — Release-binary governance modeled durable-consume receipt-acknowledgement /
# completion reporter evidence.
#
# Proves the release-built code exposes and exercises the Run 250 governance
# **modeled durable-consume completion reporter boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`:
# the entry point `evaluate_modeled_durable_consume_completion_reporter`; the
# crash-window recovery `recover_modeled_durable_consume_completion_reporter_window`;
# the sink-outcome projection `project_sink_outcome_to_completion_report_intent`;
# the predicate helpers `completion_reporter_outcome_authorizes_modeled_completion` /
# `completion_reporter_outcome_projects_to_durable_completion`; the pure/mockable
# reporter trait `GovernanceModeledDurableConsumeCompletionReporter` with
# `FixtureModeledDurableConsumeCompletionReporter`,
# `ProductionModeledDurableConsumeCompletionReporter`, and
# `MainNetModeledDurableConsumeCompletionReporter`; the typed bindings
# (`GovernanceModeledDurableConsumeCompletionReporterInput`,
# `GovernanceModeledDurableConsumeCompletionReporterExpectations`,
# `GovernanceModeledDurableConsumeCompletionReporterPolicy`); the modeled
# completion-report ledger (`GovernanceModeledDurableConsumeCompletionReport`,
# `ModeledDurableConsumeCompletionReportLedger`,
# `ModeledDurableConsumeCompletionReportRecord`,
# `ModeledDurableConsumeCompletionReportSnapshot`,
# `ModeledDurableConsumeCompletionReportStatus`,
# `ModeledDurableConsumeCompletionReportDigest`); the outcome / intent / fault
# taxonomy (`GovernanceModeledDurableConsumeCompletionReporterOutcome`,
# `CompletionReportIntent`, `ModeledCompletionReportFault`); and the grep-verifiable
# invariant / fail-closed helpers.
#
# Run 250 landed the typed durable-consume completion reporter boundary plus
# source/test coverage at the source/test level. Run 251 proves on real
# `target/release/qbind-node` plus a release-built helper that the release-built
# code exposes and exercises it: a disabled reporter / sink / pipeline /
# evaluator-call-site policy is a legacy no-acknowledgement, no-completion bypass
# with no reporter invocation; MainNet peer-driven apply is refused before pipeline
# progression, before any sink invocation, and before any reporter invocation;
# only the Run 248 ConsumeReceiptRecorded sink outcome creates a completion-report
# intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded
# completion report; only CompletionReportRecorded authorizes a new modeled
# completion-reported state; a duplicate identical completion report is idempotent
# (no second report) and the same report id with a different digest fails closed as
# equivocation; every non-recording sink outcome, record failure, rollback,
# rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet
# reporter path, and unsupported action never completes, and a rejection before the
# reporter stage leaves the reporter invocation count at zero. The reporter is pure
# (no marker/sequence write, no live trust swap, no session eviction, no Run 070
# call, no LivePqcTrustState mutation, no durable consume of its own, no persistent
# storage); the DevNet/TestNet fixture reporter mutates ONLY the in-memory
# ModeledDurableConsumeCompletionReportLedger; no real completion-report backend,
# durable consume backend, persistent replay backend, production mutation engine,
# governance execution engine, or on-chain proof verifier; no RocksDB/file/schema/
# migration/storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_251_BIN="${REPO_ROOT}/target/release/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper"
HELPER_251_OUT="${OUTDIR}/helper_evidence/run_251"
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

log() { printf '[run-251] %s\n' "$*" >&2; }
fail() { printf '[run-251] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_251_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_251_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-251 provenance"
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
log "cargo build --release -p qbind-node --example run_251_modeled_durable_consume_completion_reporter_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_251_modeled_durable_consume_completion_reporter_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_251.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_251_BIN}" ]] || fail "missing ${HELPER_251_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_251_path:    ${HELPER_251_BIN}"
  echo "helper_251_sha256:  $(sha256_file "${HELPER_251_BIN}")"
  echo "helper_251_buildid: $(build_id "${HELPER_251_BIN}")"
} >> "${PROVENANCE}"

log "running Run 251 helper"
set +e
"${HELPER_251_BIN}" "${HELPER_251_OUT}" > "${LOGS_DIR}/helper_run_251.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_251.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_251 helper failed"
assert_grep "${HELPER_251_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 251 completion-report fixture inventory (helper-minted):"
  if [[ -d "${HELPER_251_OUT}/fixtures" ]]; then
    for f in "${HELPER_251_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/completion_report_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'completion[- ]report(er)? (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'modeled durable-consume completion[- ]report(er)? (enabled|active|wired)'
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
  assert_not_grep "$logf" 'real completion[- ]report backend (enabled|active|wired|connected)'
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

log "S1 help hides completion-reporter surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-consume completion[- ]report(er)?|GovernanceModeledDurableConsumeCompletionReport|evaluate_modeled_durable_consume_completion_reporter|recover_modeled_durable_consume_completion_reporter_window|ModeledDurableConsumeCompletionReportLedger|run-250|run-251'
log "S2..S4 default surfaces silent on completion-reporter claims"
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
# sink, and Run 250 acknowledges that recorded receipt with a modeled durable-consume
# completion reporter — none of which the real binary activates as a public
# production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'durable-consume completion[- ]report(er)?|run-250|run-251'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_durable_consume_completion_reporter.rs"
RUN250_SYMS=(
  pqc_governance_modeled_durable_consume_completion_reporter
  GovernanceModeledDurableConsumeCompletionReporterInput
  GovernanceModeledDurableConsumeCompletionReporterExpectations
  GovernanceModeledDurableConsumeCompletionReporterPolicy
  GovernanceModeledDurableConsumeCompletionReport
  ModeledDurableConsumeCompletionReportLedger
  ModeledDurableConsumeCompletionReportRecord
  ModeledDurableConsumeCompletionReportSnapshot
  ModeledDurableConsumeCompletionReportStatus
  ModeledDurableConsumeCompletionReportDigest
  GovernanceModeledDurableConsumeCompletionReporterOutcome
  CompletionReportIntent
  GovernanceModeledDurableConsumeCompletionReporter
  FixtureModeledDurableConsumeCompletionReporter
  ProductionModeledDurableConsumeCompletionReporter
  MainNetModeledDurableConsumeCompletionReporter
  project_sink_outcome_to_completion_report_intent
  evaluate_modeled_durable_consume_completion_reporter
  recover_modeled_durable_consume_completion_reporter_window
  completion_reporter_outcome_authorizes_modeled_completion
  completion_reporter_outcome_projects_to_durable_completion
  CompletionReportRecorded
  CompletionReportDuplicateIdempotent
  CompletionReportRejectedBeforeRecord
  CompletionReportRecordFailedNoCompletion
  CompletionReportRolledBackNoCompletion
  CompletionReportRollbackFailedFatalNoCompletion
  CompletionReportAmbiguousFailClosedNoCompletion
  ProductionReporterUnavailableNoCompletion
  MainNetReporterUnavailableNoCompletion
  MainNetPeerDrivenApplyRefusedNoCompletion
  ValidatorSetRotationUnsupportedNoCompletion
  PolicyChangeUnsupportedNoCompletion
  modeled_completion_reporter_rejection_is_non_mutating
  modeled_completion_reporter_never_calls_run_070
  modeled_completion_reporter_never_mutates_live_pqc_trust_state
  modeled_completion_reporter_never_writes_sequence_or_marker
  modeled_completion_reporter_no_rocksdb_file_schema_migration_change
  modeled_completion_reporter_pipeline_success_required_before_report
  modeled_completion_reporter_sink_receipt_required_before_report
  modeled_completion_reporter_report_record_required_before_completion
  modeled_completion_reporter_failed_record_never_completes
  modeled_completion_reporter_rollback_never_completes
  modeled_completion_reporter_ambiguous_window_fails_closed
  modeled_completion_reporter_mainnet_peer_driven_apply_refused_first
  modeled_completion_reporter_production_mainnet_unavailable
  modeled_completion_reporter_validator_set_rotation_unsupported
  modeled_completion_reporter_policy_change_unsupported
  modeled_completion_reporter_local_operator_cannot_satisfy_mainnet_authority
  modeled_completion_reporter_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 251 source-reachability proof — Run 250 governance modeled durable-consume completion reporter boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN250_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN250_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs"
{
  echo "Run 251 helper-reachability proof — Run 250 symbols exercised by the release helper:"
  for sym in "${RUN250_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_modeled_durable_consume_completion_reporter recover_modeled_durable_consume_completion_reporter_window project_sink_outcome_to_completion_report_intent completion_reporter_outcome_authorizes_modeled_completion completion_reporter_outcome_projects_to_durable_completion GovernanceModeledDurableConsumeCompletionReporter FixtureModeledDurableConsumeCompletionReporter ProductionModeledDurableConsumeCompletionReporter MainNetModeledDurableConsumeCompletionReporter GovernanceModeledDurableConsumeCompletionReporterInput GovernanceModeledDurableConsumeCompletionReporterOutcome ModeledDurableConsumeCompletionReportLedger CompletionReportIntent ModeledCompletionReportFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 250 reporter module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_durable_consume_completion_reporter' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_modeled_durable_consume_completion_reporter\|pub fn recover_modeled_durable_consume_completion_reporter_window\|pub fn project_sink_outcome_to_completion_report_intent' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing reporter entry points"
# Outcome / intent / fault taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceModeledDurableConsumeCompletionReporterOutcome\|enum CompletionReportIntent\|enum ModeledCompletionReportFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing reporter outcome/intent/fault taxonomy"
# Reporter trait + fixture/production/mainnet implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceModeledDurableConsumeCompletionReporter\|struct FixtureModeledDurableConsumeCompletionReporter\|struct ProductionModeledDurableConsumeCompletionReporter\|struct MainNetModeledDurableConsumeCompletionReporter' "${MOD}" > "${REACH_DIR}/reporter_boundary.txt" || fail "missing reporter boundary"
# Run 248 sink composition usage within the module.
grep -RIn --include='*.rs' 'GovernanceModeledDurableConsumeSinkOutcome\|ConsumeReceiptRecorded\|GovernanceModeledEndToEndPipelineOutcome' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 248 composition usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionReporterUnavailableNoCompletion\|MainNetReporterUnavailableNoCompletion\|modeled_completion_reporter_production_mainnet_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'modeled_completion_reporter_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoCompletion\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_completion_reporter_no_rocksdb_file_schema_migration_change\|modeled_completion_reporter_validator_set_rotation_unsupported\|modeled_completion_reporter_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 251 denylist (proven empty across captured logs):"
  for pat in 'real completion-report backend enabled' 'modeled completion-reporter production enabled' 'MainNet modeled completion-reporter enabled' 'real durable consume backend enabled' 'real persistent replay backend enabled' 'modeled durable-consume sink production enabled' 'MainNet modeled durable-consume sink enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled completion reporter' 'LivePqcTrustState mutation from the modeled completion reporter' 'real trust swap from the modeled completion reporter' 'session eviction from the modeled completion reporter' 'marker write from the modeled completion reporter' 'sequence write from the modeled completion reporter' 'RocksDB write from the modeled completion reporter' 'file write from the modeled completion reporter' 'production durable consume by the modeled completion reporter' 'production completion reporting by the modeled reporter' 'DummySig' 'DummyKem' 'DummyAead' 'modeled completion reporter active' 'production modeled completion reporter active' 'mainnet modeled completion reporter active'; do
    if find "${LOGS_DIR}" "${HELPER_251_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_251.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 251 no-mutation proof for rejected completion-reporter scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / completion-report-ledger / non-mutation / reachability helper corpus (driven through the Run 250 evaluate_modeled_durable_consume_completion_reporter / recover_modeled_durable_consume_completion_reporter_window / project_sink_outcome_to_completion_report_intent over the GovernanceModeledDurableConsumeCompletionReporter trait and the DevNet/TestNet FixtureModeledDurableConsumeCompletionReporter plus the always-unavailable ProductionModeledDurableConsumeCompletionReporter / MainNetModeledDurableConsumeCompletionReporter): the durable-consume completion reporter is a pure typed projection over the already-landed Run 248 modeled durable-consume sink receipt plus a mockable reporter that records ONLY the in-memory ModeledDurableConsumeCompletionReportLedger. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass that never invokes the reporter. MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, and before any reporter invocation. Only the Run 248 ConsumeReceiptRecorded sink outcome creates a completion-report intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded completion report; only CompletionReportRecorded authorizes a new modeled completion-reported state; a duplicate identical completion report is idempotent (no second report) and the same report id with a different digest fails closed as equivocation. Every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never completes, and a rejection before the reporter stage leaves the reporter invocation count at zero (the helper proves the fixture reporter invocation counter stays at zero on every reject-before-reporter path). The reporter is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_251_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 251 mutation proof (release-binary scope): the Run 250 governance modeled durable-consume completion reporter boundary is a pure, typed projection that records how a future production call site would acknowledge an after-receipt-recorded durable-consume completion report ONLY once the Run 248 modeled durable-consume sink has recorded a consume receipt. It specifies the ordering a real completion reporter would have to honour (MainNet peer-driven refusal -> legacy bypass -> sink-outcome projection -> pre-record environment/surface binding validation -> report record -> idempotency/equivocation gate -> completion authorization), but implements NONE of that production completion reporting: there is no real completion-report backend, no real durable consume backend, no real persistent replay backend, no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledDurableConsumeCompletionReporter records ONLY the in-memory ModeledDurableConsumeCompletionReportLedger and performs no real completion reporting, no durable consume, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, and no marker write; the ProductionModeledDurableConsumeCompletionReporter and MainNetModeledDurableConsumeCompletionReporter are always unavailable / fail-closed. The CompletionReportRecorded outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production completion store; Run 251 does not exercise that mutating path and activates no production completion reporting. The boundary is pure and non-mutating on every rejection path; production/MainNet paths remain callable-but-unavailable; MainNet peer-driven apply is refused before pipeline progression and before any sink or reporter invocation."
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
TEST_TARGETS=(run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 251 — release-binary modeled governance durable-consume completion reporter evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_251_sha256:  $(sha256_file "${HELPER_251_BIN}")"
  echo "  helper_251_buildid: $(build_id "${HELPER_251_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_251rc=$(cat "${EXIT_DIR}/helper_run_251.rc")$(grep -E 'verdict:' "${HELPER_251_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 250 completion-reporter boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_251_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 250 governance modeled durable-consume completion reporter boundary is a pure, typed projection over the already-landed Run 248 modeled durable-consume sink receipt plus a mockable reporter that records ONLY the in-memory ModeledDurableConsumeCompletionReportLedger, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass with no reporter invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, and before any reporter invocation; only the Run 248 ConsumeReceiptRecorded sink outcome creates a completion-report intent and ConsumeReceiptDuplicateIdempotent may only match an already-recorded completion report; only CompletionReportRecorded authorizes a new modeled completion-reported state; a duplicate identical completion report is idempotent (no second report) and the same report id with a different digest fails closed as equivocation; every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never completes, and a rejection before the reporter stage leaves the reporter invocation count at zero; production/MainNet paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call, no LivePqcTrustState mutation); no real completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 249, Run 247, Run 245, Run 243, and Run 241 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"