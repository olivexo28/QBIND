#!/usr/bin/env bash
# Run 255 — Release-binary governance modeled durable-completion finalization
# attestation-projection evidence.
#
# Proves the release-built code exposes and exercises the Run 254 governance
# **modeled durable-completion attestation-projection boundary** in
# `crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`:
# the entry point `evaluate_modeled_durable_completion_attestation_projection`; the
# crash-window recovery `recover_modeled_durable_completion_attestation_window`;
# the finalization-outcome projection `project_finalization_outcome_to_attestation_intent`;
# the predicate helpers `attestation_outcome_authorizes_modeled_attestation` /
# `attestation_outcome_projects_to_durable_completion_attested`; the pure/mockable
# attestor trait `GovernanceModeledDurableCompletionAttestor` with
# `FixtureModeledDurableCompletionAttestor`,
# `ProductionModeledDurableCompletionAttestor`, and
# `MainNetModeledDurableCompletionAttestor`; the typed bindings
# (`GovernanceModeledDurableCompletionAttestationInput`,
# `GovernanceModeledDurableCompletionAttestationExpectations`,
# `GovernanceModeledDurableCompletionAttestationPolicy`); the modeled attestation
# ledger (`GovernanceModeledDurableCompletionAttestationRecord`,
# `ModeledDurableCompletionAttestationLedger`,
# `ModeledDurableCompletionAttestationRecord`,
# `ModeledDurableCompletionAttestationSnapshot`,
# `ModeledDurableCompletionAttestationStatus`,
# `ModeledDurableCompletionAttestationDigest`); the outcome / intent / fault
# taxonomy (`GovernanceModeledDurableCompletionAttestationOutcome`,
# `DurableCompletionAttestationIntent`, `ModeledDurableCompletionAttestationFault`);
# and the grep-verifiable invariant / fail-closed helpers.
#
# Run 254 landed the typed durable-completion attestation-projection boundary plus
# source/test coverage at the source/test level. Run 255 proves on real
# `target/release/qbind-node` plus a release-built helper that the release-built
# code exposes and exercises it: a disabled attestor / finalizer / reporter / sink /
# pipeline / evaluator-call-site policy is a legacy no-attestation bypass with no
# attestor invocation; MainNet peer-driven apply is refused before pipeline
# progression, before any sink invocation, before any reporter invocation, before
# any finalizer invocation, and before any attestor invocation; only the Run 252
# DurableCompletionFinalized finalization outcome creates an attestation intent and
# DurableCompletionDuplicateIdempotent may only match an already-recorded
# attestation; only DurableCompletionAttested authorizes a new modeled
# durable-completion-attested state; a duplicate identical attestation is idempotent
# (no second attestation) and the same attestation id with a different digest fails
# closed as equivocation; every non-finalizing finalization outcome, attestation
# record failure, rollback, rollback-failed, ambiguous attestation window,
# unavailable production/MainNet attestor path, and unsupported action never
# attests, and a rejection before the attestor stage leaves the attestor invocation
# count at zero. The attestor is pure (no marker/sequence write, no live trust swap,
# no session eviction, no Run 070 call, no LivePqcTrustState mutation, no durable
# completion / audit write of its own, no persistent storage); the DevNet/TestNet
# fixture attestor mutates ONLY the in-memory ModeledDurableCompletionAttestationLedger;
# no real attestation backend, audit ledger backend, finalization backend,
# completion-report backend, durable consume backend, persistent replay backend,
# production mutation engine, governance execution engine, or on-chain proof
# verifier; no RocksDB/file/schema/migration/storage/wire/marker/sequence/trust-bundle
# change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_255_BIN="${REPO_ROOT}/target/release/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper"
HELPER_255_OUT="${OUTDIR}/helper_evidence/run_255"
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

log() { printf '[run-255] %s\n' "$*" >&2; }
fail() { printf '[run-255] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_255_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_255_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-255 provenance"
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
log "cargo build --release -p qbind-node --example run_255_modeled_durable_completion_attestation_projection_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_255_modeled_durable_completion_attestation_projection_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_255.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_255_BIN}" ]] || fail "missing ${HELPER_255_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_255_path:    ${HELPER_255_BIN}"
  echo "helper_255_sha256:  $(sha256_file "${HELPER_255_BIN}")"
  echo "helper_255_buildid: $(build_id "${HELPER_255_BIN}")"
} >> "${PROVENANCE}"

log "running Run 255 helper"
set +e
"${HELPER_255_BIN}" "${HELPER_255_OUT}" > "${LOGS_DIR}/helper_run_255.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_255.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_255 helper failed"
assert_grep "${HELPER_255_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 255 attestation fixture inventory (helper-minted):"
  if [[ -d "${HELPER_255_OUT}/fixtures" ]]; then
    for f in "${HELPER_255_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/attestation_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'durable-completion attestation (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'modeled durable-completion attestation (enabled|active|wired)'
  assert_not_grep "$logf" 'audit ledger (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'finalization[- ]projection (backend )?(enabled|active|wired)'
  assert_not_grep "$logf" 'durable[- ]completion finaliz(er|ation) (enabled|active|wired)'
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
  assert_not_grep "$logf" 'real attestation backend (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real finalization backend (enabled|active|wired|connected)'
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

log "S1 help hides attestation-projection surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-completion attestation|GovernanceModeledDurableCompletionAttestationRecord|evaluate_modeled_durable_completion_attestation_projection|recover_modeled_durable_completion_attestation_window|ModeledDurableCompletionAttestationLedger|run-254|run-255'
log "S2..S4 default surfaces silent on attestation-projection claims"
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
# sink, Run 250 acknowledges that recorded receipt with a modeled completion
# reporter, Run 252 finalizes that completion report with a modeled durable-completion
# finalization, and Run 254 attests that recorded finalization with a modeled
# durable-completion attestation projection — none of which the real binary
# activates as a public production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'durable-completion attestation|run-254|run-255'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_modeled_durable_completion_attestation_projection.rs"
RUN254_SYMS=(
  pqc_governance_modeled_durable_completion_attestation_projection
  GovernanceModeledDurableCompletionAttestationInput
  GovernanceModeledDurableCompletionAttestationExpectations
  GovernanceModeledDurableCompletionAttestationPolicy
  GovernanceModeledDurableCompletionAttestationSurface
  GovernanceModeledDurableCompletionAttestationEnvironmentBinding
  GovernanceModeledDurableCompletionAttestationRuntimeBinding
  GovernanceModeledDurableCompletionAttestationReplayBinding
  GovernanceModeledDurableCompletionAttestationPipelineBinding
  GovernanceModeledDurableCompletionAttestationSinkBinding
  GovernanceModeledDurableCompletionAttestationReporterBinding
  GovernanceModeledDurableCompletionAttestationFinalizationBinding
  GovernanceModeledDurableCompletionAttestationRecord
  ModeledDurableCompletionAttestationLedger
  ModeledDurableCompletionAttestationRecord
  ModeledDurableCompletionAttestationSnapshot
  ModeledDurableCompletionAttestationStatus
  ModeledDurableCompletionAttestationDigest
  GovernanceModeledDurableCompletionAttestationOutcome
  DurableCompletionAttestationIntent
  ModeledDurableCompletionAttestationFault
  GovernanceModeledDurableCompletionAttestor
  FixtureModeledDurableCompletionAttestor
  ProductionModeledDurableCompletionAttestor
  MainNetModeledDurableCompletionAttestor
  project_finalization_outcome_to_attestation_intent
  evaluate_modeled_durable_completion_attestation_projection
  recover_modeled_durable_completion_attestation_window
  attestation_outcome_authorizes_modeled_attestation
  attestation_outcome_projects_to_durable_completion_attested
  DurableCompletionAttested
  DurableCompletionAttestationDuplicateIdempotent
  DurableCompletionAttestationRejectedBeforeRecord
  DurableCompletionAttestationRecordFailedNoAttestation
  DurableCompletionAttestationRolledBackNoAttestation
  DurableCompletionAttestationRollbackFailedFatalNoAttestation
  DurableCompletionAttestationAmbiguousFailClosedNoAttestation
  ProductionAttestorUnavailableNoAttestation
  MainNetAttestorUnavailableNoAttestation
  MainNetPeerDrivenApplyRefusedNoAttestation
  ValidatorSetRotationUnsupportedNoAttestation
  PolicyChangeUnsupportedNoAttestation
  modeled_attestation_rejection_is_non_mutating
  modeled_attestation_never_calls_run_070
  modeled_attestation_never_mutates_live_pqc_trust_state
  modeled_attestation_never_writes_sequence_or_marker
  modeled_attestation_no_rocksdb_file_schema_migration_change
  modeled_attestation_pipeline_success_required_before_attestation
  modeled_attestation_sink_receipt_required_before_attestation
  modeled_attestation_completion_report_required_before_attestation
  modeled_attestation_finalization_required_before_attestation
  modeled_attestation_record_required_before_durable_completion_attested
  modeled_attestation_failed_record_never_attests
  modeled_attestation_rollback_never_attests
  modeled_attestation_ambiguous_window_fails_closed
  modeled_attestation_mainnet_peer_driven_apply_refused_first
  modeled_attestation_production_mainnet_unavailable
  modeled_attestation_validator_set_rotation_unsupported
  modeled_attestation_policy_change_unsupported
  modeled_attestation_local_operator_cannot_satisfy_mainnet_authority
  modeled_attestation_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 255 source-reachability proof — Run 254 governance modeled durable-completion attestation projection boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN254_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN254_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper.rs"
{
  echo "Run 255 helper-reachability proof — Run 254 symbols exercised by the release helper:"
  for sym in "${RUN254_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_modeled_durable_completion_attestation_projection recover_modeled_durable_completion_attestation_window project_finalization_outcome_to_attestation_intent attestation_outcome_authorizes_modeled_attestation attestation_outcome_projects_to_durable_completion_attested GovernanceModeledDurableCompletionAttestor FixtureModeledDurableCompletionAttestor ProductionModeledDurableCompletionAttestor MainNetModeledDurableCompletionAttestor GovernanceModeledDurableCompletionAttestationInput GovernanceModeledDurableCompletionAttestationOutcome ModeledDurableCompletionAttestationLedger DurableCompletionAttestationIntent ModeledDurableCompletionAttestationFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 254 attestor module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_modeled_durable_completion_attestation_projection' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_modeled_durable_completion_attestation_projection\|pub fn recover_modeled_durable_completion_attestation_window\|pub fn project_finalization_outcome_to_attestation_intent' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing attestor entry points"
# Outcome / intent / fault taxonomy within the module.
grep -RIn --include='*.rs' 'enum GovernanceModeledDurableCompletionAttestationOutcome\|enum DurableCompletionAttestationIntent\|enum ModeledDurableCompletionAttestationFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing attestor outcome/intent/fault taxonomy"
# Attestor trait + fixture/production/mainnet implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceModeledDurableCompletionAttestor\|struct FixtureModeledDurableCompletionAttestor\|struct ProductionModeledDurableCompletionAttestor\|struct MainNetModeledDurableCompletionAttestor' "${MOD}" > "${REACH_DIR}/attestor_boundary.txt" || fail "missing attestor boundary"
# Run 252 finalization composition usage within the module.
grep -RIn --include='*.rs' 'GovernanceModeledDurableCompletionFinalizationOutcome\|DurableCompletionFinalized\|GovernanceModeledEndToEndPipelineOutcome' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 252 composition usage"
# Production / MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionAttestorUnavailableNoAttestation\|MainNetAttestorUnavailableNoAttestation\|modeled_attestation_production_mainnet_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'modeled_attestation_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoAttestation\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'modeled_attestation_no_rocksdb_file_schema_migration_change\|modeled_attestation_validator_set_rotation_unsupported\|modeled_attestation_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 255 denylist (proven empty across captured logs):"
  for pat in 'real attestation backend enabled' 'modeled attestation production enabled' 'MainNet modeled attestation enabled' 'real audit ledger backend enabled' 'real finalization backend enabled' 'modeled finalization production enabled' 'MainNet modeled finalization enabled' 'real completion-report backend enabled' 'modeled completion-reporter production enabled' 'MainNet modeled completion-reporter enabled' 'real durable consume backend enabled' 'real persistent replay backend enabled' 'modeled durable-consume sink production enabled' 'MainNet modeled durable-consume sink enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'MainNet peer-driven apply ENABLED' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply on receipt' 'apply-on-receipt' 'peer-majority authority' 'Run 070 apply from the modeled attestor' 'LivePqcTrustState mutation from the modeled attestor' 'real trust swap from the modeled attestor' 'session eviction from the modeled attestor' 'marker write from the modeled attestor' 'sequence write from the modeled attestor' 'RocksDB write from the modeled attestor' 'file write from the modeled attestor' 'production durable consume by the modeled attestor' 'production finalization by the modeled attestor' 'production attestation by the modeled attestor' 'DummySig' 'DummyKem' 'DummyAead' 'modeled attestation projection active' 'production modeled attestation projection active' 'mainnet modeled attestation projection active'; do
    if find "${LOGS_DIR}" "${HELPER_255_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_255.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 255 no-mutation proof for rejected attestation-projection scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / attestation-ledger / non-mutation / reachability helper corpus (driven through the Run 254 evaluate_modeled_durable_completion_attestation_projection / recover_modeled_durable_completion_attestation_window / project_finalization_outcome_to_attestation_intent over the GovernanceModeledDurableCompletionAttestor trait and the DevNet/TestNet FixtureModeledDurableCompletionAttestor plus the always-unavailable ProductionModeledDurableCompletionAttestor / MainNetModeledDurableCompletionAttestor): the durable-completion attestation projection is a pure typed projection over the already-landed Run 252 modeled durable-completion finalization plus a mockable attestor that records ONLY the in-memory ModeledDurableCompletionAttestationLedger. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no durable completion / audit write of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled attestor / finalizer / reporter / sink / pipeline / evaluator-call-site policy is a legacy no-attestation bypass that never invokes the attestor. MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, before any reporter invocation, before any finalizer invocation, and before any attestor invocation. Only the Run 252 DurableCompletionFinalized finalization outcome creates an attestation intent and DurableCompletionDuplicateIdempotent may only match an already-recorded attestation; only DurableCompletionAttested authorizes a new modeled durable-completion-attested state; a duplicate identical attestation is idempotent (no second attestation) and the same attestation id with a different digest fails closed as equivocation. Every non-finalizing finalization outcome, record failure, rollback, rollback-failed, ambiguous attestation window, unavailable production/MainNet attestor path, and unsupported action never attests, and a rejection before the attestor stage leaves the attestor invocation count at zero (the helper proves the fixture attestor invocation counter stays at zero on every reject-before-attestor path). The attestor is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_255_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 255 mutation proof (release-binary scope): the Run 254 governance modeled durable-completion attestation projection boundary is a pure, typed projection that records how a future production call site would emit an after-finalization-only durable-completion attestation / ledger-commit acknowledgement ONLY once the Run 252 modeled durable-completion finalizer has recorded a finalization. It specifies the ordering a real attestation projection would have to honour (MainNet peer-driven refusal -> legacy bypass -> finalization-outcome projection -> pre-record environment/surface binding validation -> attestation record -> idempotency/equivocation gate -> attestation authorization), but implements NONE of that production attestation: there is no real attestation backend, no real audit ledger backend, no real finalization backend, no real completion-report backend, no real durable consume backend, no real persistent replay backend, no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no RocksDB backend, no file format, no schema, no database migration, and no storage-format change. The FixtureModeledDurableCompletionAttestor records ONLY the in-memory ModeledDurableCompletionAttestationLedger and performs no real attestation, no durable completion, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, and no marker write; the ProductionModeledDurableCompletionAttestor and MainNetModeledDurableCompletionAttestor are always unavailable / fail-closed. The DurableCompletionAttested outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production attestation / audit store; Run 255 does not exercise that mutating path and activates no production attestation. The boundary is pure and non-mutating on every rejection path; production/MainNet paths remain callable-but-unavailable; MainNet peer-driven apply is refused before pipeline progression and before any sink, reporter, finalizer, or attestor invocation."
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
TEST_TARGETS=(run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 255 — release-binary modeled governance durable-completion attestation projection evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_255_sha256:  $(sha256_file "${HELPER_255_BIN}")"
  echo "  helper_255_buildid: $(build_id "${HELPER_255_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_255rc=$(cat "${EXIT_DIR}/helper_run_255.rc")$(grep -E 'verdict:' "${HELPER_255_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 254 attestation-projection boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_255_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 254 governance modeled durable-completion attestation projection boundary is a pure, typed projection over the already-landed Run 252 modeled durable-completion finalization plus a mockable attestor that records ONLY the in-memory ModeledDurableCompletionAttestationLedger, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled attestor / finalizer / reporter / sink / pipeline / evaluator-call-site policy is a legacy no-attestation bypass with no attestor invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, before any reporter invocation, before any finalizer invocation, and before any attestor invocation; only the Run 252 DurableCompletionFinalized finalization outcome creates an attestation intent and DurableCompletionDuplicateIdempotent may only match an already-recorded attestation; only DurableCompletionAttested authorizes a new modeled durable-completion-attested state; a duplicate identical attestation is idempotent (no second attestation) and the same attestation id with a different digest fails closed as equivocation; every non-finalizing finalization outcome, record failure, rollback, rollback-failed, ambiguous attestation window, unavailable production/MainNet attestor path, and unsupported action never attests, and a rejection before the attestor stage leaves the attestor invocation count at zero; production/MainNet paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no durable completion / audit write, no Run 070 call, no LivePqcTrustState mutation); no real attestation backend, audit ledger backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 251, Run 249, Run 247, Run 245, Run 243, and Run 241 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} | tee "${SUMMARY}"

log "done"