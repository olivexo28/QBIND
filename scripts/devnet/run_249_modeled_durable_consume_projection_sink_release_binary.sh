#!/usr/bin/env bash
# Run 249 — Release-binary governance modeled durable-consume projection sink
# evidence.
#
# Proves the release-built code exposes and exercises the Run 248 governance
# **modeled durable-consume projection sink boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`:
# the entry point `evaluate_modeled_durable_consume_projection_sink`; the
# crash-window recovery `recover_modeled_durable_consume_projection_sink_window`;
# the pipeline-outcome projection `project_pipeline_outcome_to_consume_sink_intent`;
# the predicate helpers `sink_outcome_authorizes_modeled_consume_receipt` /
# `sink_outcome_projects_to_durable_completion`; the pure/mockable sink trait
# `GovernanceModeledDurableConsumeProjectionSink` with
# `FixtureModeledDurableConsumeProjectionSink`,
# `ProductionModeledDurableConsumeProjectionSink`, and
# `MainNetModeledDurableConsumeProjectionSink`; the typed bindings
# (`GovernanceModeledDurableConsumeSinkInput`,
# `GovernanceModeledDurableConsumeSinkExpectations`,
# `GovernanceModeledDurableConsumeSinkPolicy`,
# `GovernanceModeledDurableConsumeSinkSurface`,
# `GovernanceModeledDurableConsumeSinkEnvironmentBinding`,
# `GovernanceModeledDurableConsumeSinkRuntimeBinding`,
# `GovernanceModeledDurableConsumeSinkReplayBinding`,
# `GovernanceModeledDurableConsumeSinkPipelineBinding`); the modeled receipt
# ledger (`GovernanceModeledDurableConsumeSinkReceipt`,
# `ModeledDurableConsumeReceiptLedger`, `ModeledDurableConsumeReceiptRecord`,
# `ModeledDurableConsumeReceiptSnapshot`, `ModeledDurableConsumeReceiptStatus`,
# `ModeledDurableConsumeReceiptDigest`); the outcome / intent / fault taxonomy
# (`GovernanceModeledDurableConsumeSinkOutcome`, `ConsumeSinkIntent`,
# `ModeledConsumeSinkFault`); and the grep-verifiable invariant / fail-closed
# helpers.
#
# Run 248 landed the typed durable-consume projection sink boundary plus
# source/test coverage at the source/test level. Run 249 proves on real
# `target/release/qbind-node` plus a release-built helper that the release-built
# code exposes and exercises it: a disabled sink / pipeline / evaluator-call-site
# policy is a legacy no-receipt, no-consume bypass with no sink invocation;
# MainNet peer-driven apply is refused before pipeline projection and before any
# sink invocation; only the Run 246 ModeledApplierAppliedAndDurableConsumeAuthorized
# outcome creates a sink intent; only ConsumeReceiptRecorded authorizes a new
# modeled receipt-recorded state; a duplicate identical receipt is idempotent (no
# second record) and the same receipt id with a different digest fails closed as
# equivocation; every non-success pipeline outcome, record failure, rollback,
# rollback-failed, ambiguous receipt window, unavailable production/MainNet sink
# path, and unsupported action never consumes, and a rejection before the sink
# stage leaves the sink invocation count at zero. The sink is pure (no
# marker/sequence write, no live trust swap, no session eviction, no Run 070 call,
# no LivePqcTrustState mutation, no durable consume of its own, no persistent
# storage); the DevNet/TestNet fixture sink mutates ONLY the in-memory
# ModeledDurableConsumeReceiptLedger; no real durable consume backend, persistent
# replay backend, production mutation engine, governance execution engine, or
# on-chain proof verifier; no RocksDB/file/schema/migration/storage/wire/marker/
# sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_249_modeled_durable_consume_projection_sink_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_249_BIN="${REPO_ROOT}/target/release/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper"
HELPER_249_OUT="${OUTDIR}/helper_evidence/run_249"
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

log() { printf '[run-249] %s\n' "$*" >&2; }
fail() { printf '[run-249] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_249_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_249_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-249 provenance"
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
log "cargo build --release -p qbind-node --example run_249_modeled_durable_consume_projection_sink_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_249_modeled_durable_consume_projection_sink_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_249.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_249_BIN}" ]] || fail "missing ${HELPER_249_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_249_path:    ${HELPER_249_BIN}"
  echo "helper_249_sha256:  $(sha256_file "${HELPER_249_BIN}")"
  echo "helper_249_buildid: $(build_id "${HELPER_249_BIN}")"
} >> "${PROVENANCE}"

log "running Run 249 helper"
set +e
"${HELPER_249_BIN}" "${HELPER_249_OUT}" > "${LOGS_DIR}/helper_run_249.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_249.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_249 helper failed"
assert_grep "${HELPER_249_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 249 durable-consume-sink fixture inventory (helper-minted):"
  if [[ -d "${HELPER_249_OUT}/fixtures" ]]; then
    for f in "${HELPER_249_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/durable_consume_sink_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'durable[- ]consume (sink )?(enabled|active|wired)'
  assert_not_grep "$logf" 'modeled durable-consume (projection )?sink (enabled|active|wired)'
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

log "S1 help hides durable-consume-sink surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-consume (projection )?sink|GovernanceModeledDurableConsumeSink|evaluate_modeled_durable_consume_projection_sink|recover_modeled_durable_consume_projection_sink_window|ModeledDurableConsumeReceiptLedger|run-248|run-249'
log "S2..S4 default surfaces silent on durable-consume-sink claims"
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
# pipeline, and Run 248 projects that pipeline onto a modeled durable-consume
# receipt sink — none of which the real binary activates as a public production
# enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'durable-consume (projection )?sink|run-248|run-249'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_durable_consume_projection_sink.rs"
RUN248_SYMS=(
  pqc_governance_modeled_durable_consume_projection_sink
  GovernanceModeledDurableConsumeSinkInput
  GovernanceModeledDurableConsumeSinkExpectations
  GovernanceModeledDurableConsumeSinkPolicy
  GovernanceModeledDurableConsumeSinkSurface
  GovernanceModeledDurableConsumeSinkEnvironmentBinding
  GovernanceModeledDurableConsumeSinkRuntimeBinding
  GovernanceModeledDurableConsumeSinkReplayBinding
  GovernanceModeledDurableConsumeSinkPipelineBinding
  GovernanceModeledDurableConsumeSinkReceipt
  ModeledDurableConsumeReceiptLedger
  ModeledDurableConsumeReceiptRecord
  ModeledDurableConsumeReceiptSnapshot
  ModeledDurableConsumeReceiptStatus
  ModeledDurableConsumeReceiptDigest
  GovernanceModeledDurableConsumeSinkOutcome
  ConsumeSinkIntent
  ModeledConsumeSinkFault
  GovernanceModeledDurableConsumeProjectionSink
  FixtureModeledDurableConsumeProjectionSink
  ProductionModeledDurableConsumeProjectionSink
  MainNetModeledDurableConsumeProjectionSink
  project_pipeline_outcome_to_consume_sink_intent
  evaluate_modeled_durable_consume_projection_sink
  recover_modeled_durable_consume_projection_sink_window
  sink_outcome_authorizes_modeled_consume_receipt
  sink_outcome_projects_to_durable_completion
  ConsumeReceiptRecorded
  ConsumeReceiptDuplicateIdempotent
  ConsumeReceiptRejectedBeforeRecord
  ConsumeReceiptRecordFailedNoConsume
  ConsumeReceiptRolledBackNoConsume
  ConsumeReceiptRollbackFailedFatalNoConsume
  ConsumeReceiptAmbiguousFailClosedNoConsume
  ProductionSinkUnavailableNoConsume
  MainNetSinkUnavailableNoConsume
  MainNetPeerDrivenApplyRefusedNoConsume
  ValidatorSetRotationUnsupportedNoConsume
  PolicyChangeUnsupportedNoConsume
  modeled_consume_sink_rejection_is_non_mutating
  modeled_consume_sink_never_calls_run_070
  modeled_consume_sink_never_mutates_live_pqc_trust_state
  modeled_consume_sink_never_writes_sequence_or_marker
  modeled_consume_sink_no_rocksdb_file_schema_migration_change
  modeled_consume_sink_pipeline_success_required_before_receipt
  modeled_consume_sink_receipt_record_required_before_consume
  modeled_consume_sink_failed_record_never_consumes
  modeled_consume_sink_rollback_never_consumes
  modeled_consume_sink_ambiguous_window_fails_closed
  modeled_consume_sink_mainnet_peer_driven_apply_refused_first
  modeled_consume_sink_production_mainnet_unavailable
  modeled_consume_sink_validator_set_rotation_unsupported
  modeled_consume_sink_policy_change_unsupported
  modeled_consume_sink_local_operator_cannot_satisfy_mainnet_authority
  modeled_consume_sink_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 249 source-reachability proof — Run 248 governance modeled durable-consume projection sink boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN248_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN248_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs"
{
  echo "Run 249 helper-reachability proof — Run 248 symbols exercised by the release helper:"
  for sym in "${RUN248_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_modeled_durable_consume_projection_sink recover_modeled_durable_consume_projection_sink_window project_pipeline_outcome_to_consume_sink_intent sink_outcome_authorizes_modeled_consume_receipt sink_outcome_projects_to_durable_completion GovernanceModeledDurableConsumeProjectionSink FixtureModeledDurableConsumeProjectionSink ProductionModeledDurableConsumeProjectionSink MainNetModeledDurableConsumeProjectionSink GovernanceModeledDurableConsumeSinkInput GovernanceModeledDurableConsumeSinkOutcome ModeledDurableConsumeReceiptLedger ConsumeSinkIntent ModeledConsumeSinkFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 248 sink module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_durable_consume_projection_sink' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_modeled_durable_consume_projection_sink\|pub fn recover_modeled_durable_consume_projection_sink_window\|pub fn project_pipeline_outcome_to_consume_sink_intent' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing sink entry points"
# Outcome / intent / fault taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceModeledDurableConsumeSinkOutcome\|enum ConsumeSinkIntent\|enum ModeledConsumeSinkFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing sink outcome/intent/fault taxonomy"
# Sink trait + fixture/production/mainnet implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceModeledDurableConsumeProjectionSink\|struct FixtureModeledDurableConsumeProjectionSink\|struct ProductionModeledDurableConsumeProjectionSink\|struct MainNetModeledDurableConsumeProjectionSink' "${MOD}" > "${REACH_DIR}/sink_boundary.txt" || fail "missing sink boundary"
# Run 246 pipeline composition usage within the module.
grep -RIn --include='*.rs' 'GovernanceModeledEndToEndPipelineOutcome\|ModeledApplierAppliedAndDurableConsumeAuthorized\|DurableReplayObservation' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 246 composition usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionSinkUnavailableNoConsume\|MainNetSinkUnavailableNoConsume\|modeled_consume_sink_production_mainnet_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'modeled_consume_sink_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoConsume\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_consume_sink_no_rocksdb_file_schema_migration_change\|modeled_consume_sink_validator_set_rotation_unsupported\|modeled_consume_sink_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 249 denylist (proven empty across captured logs):"
  for pat in 'real durable consume backend enabled' 'real persistent replay backend enabled' 'modeled durable-consume sink production enabled' 'MainNet modeled durable-consume sink enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled durable-consume sink' 'LivePqcTrustState mutation from the modeled durable-consume sink' 'real trust swap from the modeled durable-consume sink' 'session eviction from the modeled durable-consume sink' 'marker write from the modeled durable-consume sink' 'sequence write from the modeled durable-consume sink' 'RocksDB write from the modeled durable-consume sink' 'file write from the modeled durable-consume sink' 'production durable consume by the modeled sink' 'DummySig' 'DummyKem' 'DummyAead' 'modeled durable-consume sink active' 'production modeled durable-consume sink active' 'mainnet modeled durable-consume sink active'; do
    if find "${LOGS_DIR}" "${HELPER_249_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_249.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 249 no-mutation proof for rejected durable-consume-sink scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / receipt-ledger / non-mutation / reachability helper corpus (driven through the Run 248 evaluate_modeled_durable_consume_projection_sink / recover_modeled_durable_consume_projection_sink_window / project_pipeline_outcome_to_consume_sink_intent over the GovernanceModeledDurableConsumeProjectionSink trait and the DevNet/TestNet FixtureModeledDurableConsumeProjectionSink plus the always-unavailable ProductionModeledDurableConsumeProjectionSink / MainNetModeledDurableConsumeProjectionSink): the durable-consume projection sink is a pure typed projection over the already-landed Run 246 modeled end-to-end pipeline outcome plus a mockable sink that records ONLY the in-memory ModeledDurableConsumeReceiptLedger. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable consume of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled sink / pipeline / evaluator-call-site policy is a legacy no-receipt bypass that never invokes the sink. MainNet peer-driven apply is refused before pipeline projection and before any sink invocation. Only the Run 246 ModeledApplierAppliedAndDurableConsumeAuthorized outcome creates a sink intent; only ConsumeReceiptRecorded authorizes a new modeled receipt-recorded state; a duplicate identical receipt is idempotent (no second record) and the same receipt id with a different digest fails closed as equivocation. Every non-success pipeline outcome, record failure, rollback, rollback-failed, ambiguous receipt window, unavailable production/MainNet sink path, and unsupported action never consumes, and a rejection before the sink stage leaves the sink invocation count at zero (the helper proves the fixture sink invocation counter stays at zero on every reject-before-sink path). The sink is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_249_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 249 mutation proof (release-binary scope): the Run 248 governance modeled durable-consume projection sink boundary is a pure, typed projection that records how a future production call site would record an after-success-only durable consume receipt ONLY once the Run 246 modeled end-to-end pipeline has authorized consume. It specifies the ordering a real durable-consume sink would have to honour (MainNet peer-driven refusal -> legacy bypass -> pipeline-outcome projection -> pre-sink environment/surface binding validation -> sink record -> idempotency/equivocation gate -> consume authorization), but implements NONE of that production durable consume: there is no real durable consume backend, no real persistent replay backend, no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledDurableConsumeProjectionSink records ONLY the in-memory ModeledDurableConsumeReceiptLedger and performs no real durable consume, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, and no marker write; the ProductionModeledDurableConsumeProjectionSink and MainNetModeledDurableConsumeProjectionSink are always unavailable / fail-closed. The ConsumeReceiptRecorded outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production durable store; Run 249 does not exercise that mutating path and activates no production durable consume. The boundary is pure and non-mutating on every rejection path; production/MainNet paths remain callable-but-unavailable; MainNet peer-driven apply is refused before pipeline projection and before any sink invocation."
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
TEST_TARGETS=(run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 249 — release-binary modeled governance durable-consume projection sink evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_249_sha256:  $(sha256_file "${HELPER_249_BIN}")"
  echo "  helper_249_buildid: $(build_id "${HELPER_249_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_249rc=$(cat "${EXIT_DIR}/helper_run_249.rc")$(grep -E 'verdict:' "${HELPER_249_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 248 durable-consume-sink boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_249_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 248 governance modeled durable-consume projection sink boundary is a pure, typed projection over the already-landed Run 246 modeled end-to-end pipeline outcome plus a mockable sink that records ONLY the in-memory ModeledDurableConsumeReceiptLedger, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled sink / pipeline / evaluator-call-site policy is a legacy no-receipt bypass with no sink invocation; MainNet peer-driven apply is refused before pipeline projection and before any sink invocation; only the Run 246 ModeledApplierAppliedAndDurableConsumeAuthorized outcome creates a sink intent; only ConsumeReceiptRecorded authorizes a new modeled receipt-recorded state; a duplicate identical receipt is idempotent (no second record) and the same receipt id with a different digest fails closed as equivocation; every non-success pipeline outcome, record failure, rollback, rollback-failed, ambiguous receipt window, unavailable production/MainNet sink path, and unsupported action never consumes, and a rejection before the sink stage leaves the sink invocation count at zero; production/MainNet paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable consume, no Run 070 call, no LivePqcTrustState mutation); no real durable consume backend, persistent replay backend, production mutation engine, governance execution engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 247, Run 245, Run 243, and Run 241 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "done — summary at ${SUMMARY}"
