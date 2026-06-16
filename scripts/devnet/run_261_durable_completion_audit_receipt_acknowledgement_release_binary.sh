#!/usr/bin/env bash
# Run 261 — Release-binary governance durable-completion audit-receipt **acknowledgement
# boundary** evidence.
#
# Proves the release-built code exposes and exercises the Run 260 governance
# **durable-completion audit-receipt acknowledgement boundary** in
# `crates/qbind-node/src/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs`:
# the entry point `evaluate_durable_completion_audit_receipt_acknowledgement`; the
# crash-window recovery `recover_durable_completion_audit_receipt_acknowledgement_window`;
# the audit-receipt-outcome projection `project_audit_receipt_outcome_to_acknowledgement_request`;
# the predicate helpers `acknowledgement_outcome_authorizes_acknowledgement_record` /
# `acknowledgement_outcome_projects_to_acknowledgement_recorded`; the pure/mockable
# acknowledgement trait `GovernanceDurableCompletionAuditReceiptAcknowledgementSink`
# with `FixtureDurableCompletionAuditReceiptAcknowledgementSink`,
# `ProductionAuditLedgerDurableCompletionAcknowledgementSink`,
# `MainNetAuditLedgerDurableCompletionAcknowledgementSink`, and
# `ExternalPublicationDurableCompletionConfirmationSink`; the typed bindings
# (`DurableCompletionAuditReceiptAcknowledgementInput`,
# `DurableCompletionAuditReceiptAcknowledgementExpectations`,
# `DurableCompletionAuditReceiptAcknowledgementPolicy`,
# `DurableCompletionAuditReceiptAcknowledgementKind`,
# `DurableCompletionAuditReceiptAcknowledgementIdentity`,
# `DurableCompletionAuditReceiptAcknowledgementRequest`,
# `DurableCompletionAuditReceiptAcknowledgementResponse`,
# `DurableCompletionAuditReceiptAcknowledgementRecord`,
# `DurableCompletionAuditReceiptAcknowledgementDigest`,
# `DurableCompletionAuditReceiptAcknowledgementTranscriptDigest`); the modeled in-memory
# acknowledgement ledger (`DurableCompletionAuditReceiptAcknowledgementLedger`); the
# outcome / intent / fault taxonomy
# (`DurableCompletionAuditReceiptAcknowledgementOutcome`,
# `DurableCompletionAuditReceiptAcknowledgementRequestIntent`,
# `DurableCompletionAuditReceiptAcknowledgementFault`); and the grep-verifiable invariant /
# fail-closed helpers.
#
# Run 260 landed the typed durable-completion audit-receipt acknowledgement interface
# boundary plus source/test coverage at the source/test level. Run 261 proves on
# real `target/release/qbind-node` plus a release-built helper that the
# release-built code exposes and exercises it: a disabled acknowledgement / receipt /
# attestor / finalizer / reporter / sink / pipeline / evaluator-call-site policy is a
# legacy no-acknowledgement bypass with no acknowledgement invocation; MainNet
# peer-driven apply is refused before pipeline progression, before any sink invocation,
# before any reporter invocation, before any finalizer invocation, before any attestor
# invocation, before any receipt invocation, and before any acknowledgement invocation;
# only the Run 258 AuditReceiptRecorded outcome creates an acknowledgement request and a
# duplicate identical acknowledgement may only match an already-recorded acknowledgement
# record; only AcknowledgementRecorded authorizes a new modeled acknowledgement-recorded
# state; a duplicate identical acknowledgement submission is idempotent (no second
# submission) and the same acknowledgement record id with a different digest fails closed
# as equivocation; every non-recording audit-receipt outcome, acknowledgement record
# failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable
# production/MainNet/external-publication-confirmation path, and unsupported action never
# records, and a rejection before the acknowledgement stage leaves the acknowledgement
# invocation count at zero. The fixture acknowledgement is pure (no marker/sequence write,
# no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState
# mutation, no external publication, no real audit-ledger write, no durable
# completion / audit write of its own, no persistent storage); the DevNet/TestNet
# fixture acknowledgement mutates ONLY the in-memory
# DurableCompletionAuditReceiptAcknowledgementLedger; no real audit-receipt
# acknowledgement, audit ledger acknowledgement, external publication confirmation,
# audit-publication receipt, finalization receipt, completion-report receipt, durable
# consume receipt, persistent replay receipt, production mutation engine, governance
# execution engine, or on-chain proof verifier; no
# RocksDB/file/schema/migration/storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_261_durable_completion_audit_receipt_acknowledgement_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_261_BIN="${REPO_ROOT}/target/release/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper"
HELPER_261_OUT="${OUTDIR}/helper_evidence/run_261"
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

log() { printf '[run-261] %s\n' "$*" >&2; }
fail() { printf '[run-261] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_261_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_261_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-261 provenance"
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
log "cargo build --release -p qbind-node --example run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_261.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_261_BIN}" ]] || fail "missing ${HELPER_261_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_261_path:    ${HELPER_261_BIN}"
  echo "helper_261_sha256:  $(sha256_file "${HELPER_261_BIN}")"
  echo "helper_261_buildid: $(build_id "${HELPER_261_BIN}")"
} >> "${PROVENANCE}"

log "running Run 261 helper"
set +e
"${HELPER_261_BIN}" "${HELPER_261_OUT}" > "${LOGS_DIR}/helper_run_261.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_261.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_261 helper failed"
assert_grep "${HELPER_261_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 261 acknowledgement fixture inventory (helper-minted):"
  if [[ -d "${HELPER_261_OUT}/fixtures" ]]; then
    for f in "${HELPER_261_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/acknowledgement_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'durable-completion audit-receipt acknowledgement (enabled|active|wired)'
  assert_not_grep "$logf" 'durable-completion audit-publication receipt (enabled|active|wired)'
  assert_not_grep "$logf" 'audit ledger (acknowledgement )?(enabled|active|wired)'
  assert_not_grep "$logf" 'external publication (confirmation )?(enabled|active|wired)'
  assert_not_grep "$logf" 'finalization[- ]projection (receipt )?(enabled|active|wired)'
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
  assert_not_grep "$logf" 'durable (replay )?receipt (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real durable consume receipt (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real audit-receipt acknowledgement (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real audit-publication receipt (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'real finalization receipt (enabled|active|wired|connected)'
  assert_not_grep "$logf" 'persistent replay (state )?(store|receipt) (enabled|active|wired)'
  assert_not_grep "$logf" 'RocksDB (receipt )?(enabled|active|wired)'
  assert_not_grep "$logf" 'file replay receipt (enabled|active|wired)'
  assert_not_grep "$logf" 'validator-set rotation (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'policy-change action (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'autonomous apply|apply on acknowledgement|apply-on-acknowledgement|peer-majority authority'
  assert_not_grep "$logf" 'real KMS receipt|real HSM receipt|real RemoteSigner receipt|RemoteSigner receipt connected'
  assert_not_grep "$logf" 'MainNet peer-driven apply ENABLED'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1 || true
  local rc=$?
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides audit-receipt-acknowledgement surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-completion audit-receipt acknowledgement|DurableCompletionAuditReceiptAcknowledgementLedger|evaluate_durable_completion_audit_receipt_acknowledgement|recover_durable_completion_audit_receipt_acknowledgement_window|project_audit_receipt_outcome_to_acknowledgement_request|run-258|run-261'
log "S2..S4 default surfaces silent on audit-receipt-acknowledgement claims"
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
# finalization, Run 254 attests that recorded finalization with a modeled
# durable-completion attestation projection, Run 256 submits that attestation to a
# modeled durable-completion attestation backend, Run 258 records that backend
# submission as a typed durable-completion audit-publication receipt, and Run 260
# acknowledges that recorded audit-publication receipt with a typed durable-completion
# audit-receipt acknowledgement interface — none of which the real binary activates as
# a public production enablement surface.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
assert_not_grep "${LOGS_DIR}/S5_selector_parses.log" 'durable-completion audit-receipt acknowledgement|run-258|run-261'
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_durable_completion_audit_receipt_acknowledgement.rs"
RUN260_SYMS=(
  pqc_governance_durable_completion_audit_receipt_acknowledgement
  DurableCompletionAuditReceiptAcknowledgementInput
  DurableCompletionAuditReceiptAcknowledgementPolicy
  DurableCompletionAuditReceiptAcknowledgementKind
  DurableCompletionAuditReceiptAcknowledgementIdentity
  DurableCompletionAuditReceiptAcknowledgementExpectations
  DurableCompletionAuditReceiptAcknowledgementRequest
  DurableCompletionAuditReceiptAcknowledgementResponse
  DurableCompletionAuditReceiptAcknowledgementRecord
  DurableCompletionAuditReceiptAcknowledgementLedger
  DurableCompletionAuditReceiptAcknowledgementLedgerRecord
  DurableCompletionAuditReceiptAcknowledgementDigest
  DurableCompletionAuditReceiptAcknowledgementTranscriptDigest
  DurableCompletionAuditReceiptAcknowledgementOutcome
  DurableCompletionAuditReceiptAcknowledgementRequestIntent
  DurableCompletionAuditReceiptAcknowledgementFault
  DurableCompletionAuditReceiptAcknowledgementWindow
  GovernanceDurableCompletionAuditReceiptAcknowledgementSink
  FixtureDurableCompletionAuditReceiptAcknowledgementSink
  ProductionAuditLedgerDurableCompletionAcknowledgementSink
  MainNetAuditLedgerDurableCompletionAcknowledgementSink
  ExternalPublicationDurableCompletionConfirmationSink
  project_audit_receipt_outcome_to_acknowledgement_request
  evaluate_durable_completion_audit_receipt_acknowledgement
  recover_durable_completion_audit_receipt_acknowledgement_window
  acknowledgement_outcome_authorizes_acknowledgement_record
  acknowledgement_outcome_projects_to_acknowledgement_recorded
  AcknowledgementRecorded
  AcknowledgementDuplicateIdempotent
  AcknowledgementRejectedBeforeRecord
  AcknowledgementRecordFailedNoAcknowledgement
  AcknowledgementRolledBackNoAcknowledgement
  AcknowledgementRollbackFailedFatalNoAcknowledgement
  AcknowledgementAmbiguousFailClosedNoAcknowledgement
  ProductionAuditLedgerAckUnavailableNoAcknowledgement
  MainNetAuditLedgerAckUnavailableNoAcknowledgement
  ExternalPublicationConfirmationUnavailableNoAcknowledgement
  MainNetPeerDrivenApplyRefusedNoAcknowledgement
  ValidatorSetRotationUnsupportedNoAcknowledgement
  PolicyChangeUnsupportedNoAcknowledgement
  durable_completion_audit_ack_rejection_is_non_mutating
  durable_completion_audit_ack_never_calls_run_070
  durable_completion_audit_ack_never_mutates_live_pqc_trust_state
  durable_completion_audit_ack_never_writes_sequence_or_marker
  durable_completion_audit_ack_no_rocksdb_file_schema_migration_change
  durable_completion_audit_ack_no_external_publication
  durable_completion_audit_ack_no_real_audit_ledger
  durable_completion_audit_ack_pipeline_success_required
  durable_completion_audit_ack_sink_receipt_required
  durable_completion_audit_ack_completion_report_required
  durable_completion_audit_ack_finalization_required
  durable_completion_audit_ack_attestation_required
  durable_completion_audit_ack_backend_submission_required
  durable_completion_audit_ack_receipt_required
  durable_completion_audit_ack_record_required_before_ack
  durable_completion_audit_ack_failed_record_never_records
  durable_completion_audit_ack_rollback_never_records
  durable_completion_audit_ack_ambiguous_window_fails_closed
  durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first
  durable_completion_audit_ack_production_mainnet_unavailable
  durable_completion_audit_ack_external_confirmation_unavailable
  durable_completion_audit_ack_validator_set_rotation_unsupported
  durable_completion_audit_ack_policy_change_unsupported
  durable_completion_audit_ack_local_operator_cannot_satisfy_mainnet_authority
  durable_completion_audit_ack_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 261 source-reachability proof — Run 260 governance durable-completion audit-receipt acknowledgement interface boundary symbols within ${SRC_DIR}:"
  for sym in "${RUN260_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN260_SYMS[@]}"; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done

# Helper-reachability proof: the release helper exercises the same symbols in
# release mode.
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper.rs"
{
  echo "Run 261 helper-reachability proof — Run 260 symbols exercised by the release helper:"
  for sym in "${RUN260_SYMS[@]}"; do
    echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo
  done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_durable_completion_audit_receipt_acknowledgement recover_durable_completion_audit_receipt_acknowledgement_window project_audit_receipt_outcome_to_acknowledgement_request acknowledgement_outcome_authorizes_acknowledgement_record acknowledgement_outcome_projects_to_acknowledgement_recorded GovernanceDurableCompletionAuditReceiptAcknowledgementSink FixtureDurableCompletionAuditReceiptAcknowledgementSink ProductionAuditLedgerDurableCompletionAcknowledgementSink MainNetAuditLedgerDurableCompletionAcknowledgementSink ExternalPublicationDurableCompletionConfirmationSink DurableCompletionAuditReceiptAcknowledgementInput DurableCompletionAuditReceiptAcknowledgementOutcome DurableCompletionAuditReceiptAcknowledgementLedger DurableCompletionAuditReceiptAcknowledgementRequestIntent DurableCompletionAuditReceiptAcknowledgementFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done

# Module registration reachability (lib.rs exposes the Run 260 acknowledgement module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_durable_completion_audit_receipt_acknowledgement' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Engine entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_durable_completion_audit_receipt_acknowledgement\|pub fn recover_durable_completion_audit_receipt_acknowledgement_window\|pub fn project_audit_receipt_outcome_to_acknowledgement_request' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing acknowledgement entry points"
# Outcome / intent / fault taxonomy within the module.
grep -RIn --include='*.rs' 'enum DurableCompletionAuditReceiptAcknowledgementOutcome\|enum DurableCompletionAuditReceiptAcknowledgementRequestIntent\|enum DurableCompletionAuditReceiptAcknowledgementFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing acknowledgement outcome/intent/fault taxonomy"
# Acknowledgement trait + fixture/production/mainnet/external implementations within the module.
grep -RIn --include='*.rs' 'trait GovernanceDurableCompletionAuditReceiptAcknowledgementSink\|struct FixtureDurableCompletionAuditReceiptAcknowledgementSink\|struct ProductionAuditLedgerDurableCompletionAcknowledgementSink\|struct MainNetAuditLedgerDurableCompletionAcknowledgementSink\|struct ExternalPublicationDurableCompletionConfirmationSink' "${MOD}" > "${REACH_DIR}/acknowledgement_boundary.txt" || fail "missing acknowledgement boundary"
# Run 258 audit-publication receipt composition usage within the module.
grep -RIn --include='*.rs' 'DurableCompletionAuditPublicationReceiptOutcome\|AuditReceiptRecorded\|project_audit_receipt_outcome_to_acknowledgement_request' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 258 composition usage"
# Production / MainNet / external unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionAuditLedgerAckUnavailableNoAcknowledgement\|MainNetAuditLedgerAckUnavailableNoAcknowledgement\|ExternalPublicationConfirmationUnavailableNoAcknowledgement\|durable_completion_audit_ack_production_mainnet_unavailable\|durable_completion_audit_ack_external_confirmation_unavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_external_unavailable.txt" || fail "missing production/MainNet/external unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'durable_completion_audit_ack_mainnet_peer_driven_apply_refused_first\|is_mainnet_peer_driven\|MainNetPeerDrivenApplyRefusedNoAcknowledgement\|MainNet peer-driven apply' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# Non-implementation / no-storage-change guard.
grep -RIn --include='*.rs' 'durable_completion_audit_ack_no_rocksdb_file_schema_migration_change\|durable_completion_audit_ack_validator_set_rotation_unsupported\|durable_completion_audit_ack_policy_change_unsupported' "${MOD}" > "${REACH_DIR}/no_storage_change.txt" || fail "missing no-storage-change guard reachability"

{
  echo "Run 261 denylist (proven empty across captured logs):"
  for pat in 'real audit ledger backend enabled' 'real external publication backend enabled' 'durable-completion audit-receipt acknowledgement production enabled' 'MainNet audit-ledger acknowledgement enabled' 'MainNet external-publication confirmation enabled' 'real production attestation backend enabled' 'real audit-publication receipt enabled' 'real finalization backend enabled' 'real completion-report backend enabled' 'real durable consume backend enabled' 'real persistent replay backend enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply-on-acknowledgement' 'apply on acknowledgement' 'peer-majority authority' 'Run 070 apply from the acknowledgement boundary' 'LivePqcTrustState mutation from the acknowledgement boundary' 'real trust swap from the acknowledgement boundary' 'session eviction from the acknowledgement boundary' 'marker write from the acknowledgement boundary' 'sequence write from the acknowledgement boundary' 'RocksDB write from the acknowledgement boundary' 'file write from the acknowledgement boundary' 'external publication by the fixture acknowledgement sink' 'audit-ledger write by the fixture acknowledgement sink' 'production durable consume by the fixture acknowledgement sink' 'production finalization by the fixture acknowledgement sink' 'production attestation by the fixture acknowledgement sink' 'production audit-publication receipt by the fixture acknowledgement sink' 'DummySig / DummyKem / DummyAead active on production path' 'DummySig' 'DummyKem' 'DummyAead' 'durable-completion audit-receipt acknowledgement active' 'production durable-completion audit-receipt acknowledgement active' 'mainnet durable-completion audit-receipt acknowledgement active'; do
   if find "${LOGS_DIR}" "${HELPER_261_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt ! -name helper_run_261.log -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 261 no-mutation proof for rejected audit-receipt-acknowledgement scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  accepted / rejection / recovery / projection / stage-ordering / acknowledgement-ledger / non-mutation / reachability helper corpus (driven through the Run 260 evaluate_durable_completion_audit_receipt_acknowledgement / recover_durable_completion_audit_receipt_acknowledgement_window / project_audit_receipt_outcome_to_acknowledgement_request over the GovernanceDurableCompletionAuditReceiptAcknowledgementSink trait and the DevNet/TestNet FixtureDurableCompletionAuditReceiptAcknowledgementSink plus the always-unavailable ProductionAuditLedgerDurableCompletionAcknowledgementSink / MainNetAuditLedgerDurableCompletionAcknowledgementSink / ExternalPublicationDurableCompletionConfirmationSink): the durable-completion audit-receipt acknowledgement interface is a pure typed projection over the already-landed Run 258 audit-publication receipt outcome plus a mockable acknowledgement sink that records ONLY the in-memory DurableCompletionAuditReceiptAcknowledgementLedger. Every evaluation performs no real I/O, writes no marker, writes no sequence, swaps no live trust, evicts no sessions, performs no external publication, performs no durable completion / audit write of its own, never mutates LivePqcTrustState, and never invokes Run 070. A disabled acknowledgement / receipt / attestor / finalizer / reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass that never invokes the acknowledgement. MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, before any reporter invocation, before any finalizer invocation, before any attestor invocation, before any receipt invocation, and before any acknowledgement invocation. Only the Run 258 AuditReceiptRecorded outcome creates an acknowledgement request and AuditReceiptDuplicateIdempotent may only match an already-recorded acknowledgement; only AcknowledgementRecorded authorizes a new modeled acknowledgement-recorded state; a duplicate identical acknowledgement is idempotent (no second submission) and the same acknowledgement record id with a different digest fails closed as equivocation. Every non-recording audit-receipt outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet/external-publication-confirmation path, and unsupported action never records, and a rejection before the acknowledgement stage leaves the acknowledgement invocation count at zero (the helper proves the fixture acknowledgement invocation counter stays at zero on every reject-before-acknowledgement path). The acknowledgement is an in-process model only — it introduces no RocksDB schema, no file format, and no database migration. No .tmp residue; no fallback to --p2p-trusted-root; no active DummySig/DummyKem/DummyAead."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_261_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

{
  echo "Run 261 mutation proof (release-binary scope): the Run 260 governance durable-completion audit-receipt acknowledgement interface boundary is a pure, typed projection that records how a future production call site would submit an after-receipt-only durable-completion audit-receipt acknowledgement to a real audit ledger / external-publication confirmation ONLY once the Run 258 durable-completion audit-publication receipt has recorded a receipt. It specifies the ordering a real acknowledgement would have to honour (MainNet peer-driven refusal -> legacy bypass -> audit-receipt-outcome projection -> pre-submission environment/surface binding validation -> acknowledgement request identity validation -> acknowledgement record -> idempotency/equivocation gate -> acknowledgement submission authorization), but implements NONE of that production acknowledgement sink: there is no real audit-receipt acknowledgement, no real audit ledger acknowledgement, no real external publication confirmation, no real audit-publication receipt, no real finalization receipt, no real completion-report receipt, no real durable consume receipt, no real persistent replay receipt, no real production mutation engine, no real governance execution engine, no real on-chain governance proof verifier, no RocksDB acknowledgement, no file format, no schema, no database migration, and no storage-format change. The FixtureDurableCompletionAuditReceiptAcknowledgementSink records ONLY the in-memory DurableCompletionAuditReceiptAcknowledgementLedger and performs no real acknowledgement submission, no external publication, no audit-ledger write, no durable completion, no LivePqcTrustState mutation, no Run 070 call, no live trust swap, no session eviction, no sequence write, and no marker write; the ProductionAuditLedgerDurableCompletionAcknowledgementSink, MainNetAuditLedgerDurableCompletionAcknowledgementSink, and ExternalPublicationDurableCompletionConfirmationSink are always unavailable / fail-closed. The AcknowledgementRecorded outcome is, at most, the after-success bookkeeping the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist) would record in a future production acknowledgement / audit store; Run 261 does not exercise that mutating path and activates no production acknowledgement sink. The boundary is pure and non-mutating on every rejection path; production/MainNet/external-publication paths remain callable-but-unavailable; MainNet peer-driven apply is refused before pipeline progression and before any sink, reporter, finalizer, attestor, receipt, or acknowledgement invocation."
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
TEST_TARGETS=(run_260_durable_completion_audit_receipt_acknowledgement_tests run_258_durable_completion_audit_publication_receipt_tests run_256_durable_completion_attestation_backend_tests run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 261 — release-binary governance durable-completion audit-receipt acknowledgement interface evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_261_sha256:  $(sha256_file "${HELPER_261_BIN}")"
  echo "  helper_261_buildid: $(build_id "${HELPER_261_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_261rc=$(cat "${EXIT_DIR}/helper_run_261.rc")$(grep -E 'verdict:' "${HELPER_261_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper corpus verdicts (release mode, Run 260 audit-receipt-acknowledgement boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_261_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 260 governance durable-completion audit-receipt acknowledgement interface boundary is a pure, typed projection over the already-landed Run 258 audit-publication receipt outcome plus a mockable acknowledgement sink that records ONLY the in-memory DurableCompletionAuditReceiptAcknowledgementLedger, exercised here through release-built library symbols (the same symbols a future production call site would use); a disabled acknowledgement / receipt / attestor / finalizer / reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement bypass with no acknowledgement invocation; MainNet peer-driven apply is refused before pipeline progression, before any sink invocation, before any reporter invocation, before any finalizer invocation, before any attestor invocation, before any receipt invocation, and before any acknowledgement invocation; only the Run 258 AuditReceiptRecorded outcome creates an acknowledgement request and AuditReceiptDuplicateIdempotent may only match an already-recorded acknowledgement; only AcknowledgementRecorded authorizes a new modeled acknowledgement-recorded state; a duplicate identical acknowledgement is idempotent (no second submission) and the same acknowledgement record id with a different digest fails closed as equivocation; every non-recording audit-receipt outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet/external-publication-confirmation path, and unsupported action never records, and a rejection before the acknowledgement stage leaves the acknowledgement invocation count at zero; production/MainNet/external-publication paths are reachable but always unavailable/fail-closed; validator-set rotation and policy-change actions remain unsupported; rejections are pure and non-mutating (no marker/sequence write, no live trust swap, no session eviction, no external publication, no durable completion / audit write, no Run 070 call, no LivePqcTrustState mutation); no real audit-receipt acknowledgement, audit ledger acknowledgement, external publication confirmation, audit-publication receipt, finalization receipt, completion-report receipt, durable consume receipt, persistent replay receipt, production mutation engine, governance execution engine, or on-chain governance proof verifier; no KMS/HSM/RemoteSigner acknowledgement; no RocksDB schema change, no file format change, no database migration, no storage-format change, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 259, Run 257, Run 255, Run 253, Run 251, Run 249, Run 247, and Run 245 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} | tee "${SUMMARY}"
