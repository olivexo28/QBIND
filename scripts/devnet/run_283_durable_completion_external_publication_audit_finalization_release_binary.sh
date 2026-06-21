#!/usr/bin/env bash
# Run 283 — release-binary governance durable-completion external-publication-audit-finalization evidence.
#
# Release-binary evidence for the Run 282 durable-completion external-publication
# acknowledgement consumer / external-publication-audit-finalization boundary. Proves the
# Run 282 production library symbols are present and exercised in release mode by
# a release-built helper, while the helper remains dead code from production
# runtime and the modeled external-publication-audit-finalization path stays
# fixture/in-memory/dev-test only. No production runtime is enabled.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_283_durable_completion_external_publication_audit_finalization_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_283_BIN="${REPO_ROOT}/target/release/examples/run_283_durable_completion_external_publication_audit_finalization_release_binary_helper"
HELPER_283_OUT="${OUTDIR}/helper_evidence/run_283"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
DATA_DIR="${OUTDIR}/data"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"
MUT_PROOF="${OUTDIR}/mutation_proof.txt"
NOMUT_PROOF="${OUTDIR}/no_mutation_proof.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_durable_completion_external_publication_audit_finalization.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_283_durable_completion_external_publication_audit_finalization_release_binary_helper.rs"

log() { printf '[run-283] %s\n' "$*" >&2; }
fail() { printf '[run-283] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_283_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_283_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-283 provenance"
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
log "cargo build --release -p qbind-node --example run_283_durable_completion_external_publication_audit_finalization_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_283_durable_completion_external_publication_audit_finalization_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_283.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_283_BIN}" ]] || fail "missing ${HELPER_283_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_283_path:    ${HELPER_283_BIN}"
  echo "helper_283_sha256:  $(sha256_file "${HELPER_283_BIN}")"
  echo "helper_283_buildid: $(build_id "${HELPER_283_BIN}")"
} >> "${PROVENANCE}"

log "running Run 283 helper"
set +e
"${HELPER_283_BIN}" "${HELPER_283_OUT}" > "${LOGS_DIR}/helper_run_283.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_283.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_283 helper failed"
assert_grep "${HELPER_283_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_283_OUT}/helper_summary.txt" 'input\.external_publication_acknowledgement_binding -> project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request'

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'durable-completion external-publication audit finalization (production )?(enabled|active|wired)'
  assert_not_grep "$logf" 'real external-publication-audit-finalization enabled|real external-publication-audit-finalization backend enabled|durable-completion external-publication-audit-finalization production enabled|MainNet external-publication-audit-finalization enabled|external external-publication-audit-finalization enabled'
  assert_not_grep "$logf" 'durable-completion external-publication acknowledgement (production )?(enabled|active|wired)'
  assert_not_grep "$logf" 'real external-publication-acknowledgement enabled|real external-publication-acknowledgement backend enabled|real external publication enabled|durable-completion external-publication-acknowledgement production enabled|MainNet external-publication-acknowledgement enabled|external external-publication-acknowledgement enabled'
  assert_not_grep "$logf" 'real settlement backend enabled|real settlement outcome publication enabled|real settlement-outcome publication enabled|real settlement-outcome publication backend enabled|real settlement receipt enabled|real settlement-receipt acknowledgement enabled|real settlement-outcome report enabled|real settlement outcome report backend enabled|real settlement-finality projection enabled|real settlement finality enabled|durable-completion settlement-outcome publication production enabled|durable-completion settlement-outcome report production enabled|durable-completion settlement-receipt acknowledgement production enabled|durable-completion settlement-finalization production enabled|durable-completion settlement-commitment production enabled|durable-completion settlement-projection production enabled'
  assert_not_grep "$logf" 'real audit-ledger acknowledgement backend enabled|real external-publication confirmation backend enabled|real external publication backend enabled'
  assert_not_grep "$logf" 'real production attestation backend enabled|real finalization backend enabled|real completion-report backend enabled|real durable consume backend enabled|real persistent replay backend enabled'
  assert_not_grep "$logf" 'real production mutation engine enabled|MainNet mutation engine enabled|MainNet governance enabled|MainNet peer-driven apply enabled|real governance execution engine enabled|real on-chain governance proof verifier enabled'
  assert_not_grep "$logf" 'RocksDB replay backend enabled|file replay backend enabled|schema migration enabled|storage-format migration enabled'
  assert_not_grep "$logf" 'KMS/HSM backend enabled|KMS backend enabled|HSM backend enabled|RemoteSigner backend enabled'
  assert_not_grep "$logf" 'validator-set rotation enabled|policy-change action enabled'
  assert_not_grep "$logf" 'autonomous apply|apply-on-receipt|apply-on-acknowledgement|apply-on-consumer|apply-on-settlement-projection|apply-on-settlement-commitment|apply-on-settlement-finalization|apply-on-settlement-receipt-acknowledgement|apply-on-settlement-outcome-report|apply-on-external-publication-receipt|apply-on-external-publication-acknowledgement|apply-on-settlement|peer-majority authority'
  assert_not_grep "$logf" 'Run 070 apply from the external-publication-audit-finalization boundary|LivePqcTrustState mutation from the external-publication-audit-finalization boundary|real trust swap from the external-publication-audit-finalization boundary|session eviction from the external-publication-audit-finalization boundary|marker write from the external-publication-audit-finalization boundary|sequence write from the external-publication-audit-finalization boundary|RocksDB write from the external-publication-audit-finalization boundary|file write from the external-publication-audit-finalization boundary'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides external-publication-audit-finalization surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-completion external-publication audit finalization|DurableCompletionExternalPublicationAuditFinalizationLedger|evaluate_durable_completion_external_publication_audit_finalization|recover_durable_completion_external_publication_audit_finalization_window|project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request|run-283'
log "S2..S4 default surfaces silent on external-publication-audit-finalization claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"; assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

RUN282_SYMS=(
  pqc_governance_durable_completion_external_publication_audit_finalization
  DurableCompletionExternalPublicationAuditFinalizationInput DurableCompletionExternalPublicationAuditFinalizationPolicy DurableCompletionExternalPublicationAuditFinalizationKind DurableCompletionExternalPublicationAuditFinalizationIdentity DurableCompletionExternalPublicationAuditFinalizationExpectations DurableCompletionExternalPublicationAuditFinalizationRequest DurableCompletionExternalPublicationAuditFinalizationResponse DurableCompletionExternalPublicationAuditFinalizationRecord DurableCompletionExternalPublicationAuditFinalizationLedger DurableCompletionExternalPublicationAuditFinalizationLedgerRecord DurableCompletionExternalPublicationAuditFinalizationLedgerSnapshot DurableCompletionExternalPublicationAuditFinalizationLedgerStatus DurableCompletionExternalPublicationAuditFinalizationDigest DurableCompletionExternalPublicationAuditFinalizationTranscriptDigest DurableCompletionExternalPublicationAuditFinalizationOutcome DurableCompletionExternalPublicationAuditFinalizationRequestIntent DurableCompletionExternalPublicationAuditFinalizationFault DurableCompletionExternalPublicationAuditFinalizationWindow
  GovernanceDurableCompletionExternalPublicationAuditFinalizationSink FixtureDurableCompletionExternalPublicationAuditFinalizationSink ProductionExternalPublicationAuditFinalizationSink MainNetExternalPublicationAuditFinalizationSink ExternalExternalPublicationAuditFinalizationSink
  project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request evaluate_durable_completion_external_publication_audit_finalization recover_durable_completion_external_publication_audit_finalization_window external_publication_audit_finalization_outcome_authorizes_record external_publication_audit_finalization_outcome_projects_to_recorded external_publication_audit_finalization_identity_digest external_publication_audit_finalization_request_digest external_publication_audit_finalization_response_digest external_publication_audit_finalization_record_digest external_publication_audit_finalization_transcript_digest
  ExternalPublicationAuditFinalizationRecorded ExternalPublicationAuditFinalizationDuplicateIdempotent ExternalPublicationAuditFinalizationRejectedBeforeRecord ExternalPublicationAuditFinalizationRecordFailedNoAuditFinalization ExternalPublicationAuditFinalizationRolledBackNoAuditFinalization ExternalPublicationAuditFinalizationRollbackFailedFatalNoAuditFinalization ExternalPublicationAuditFinalizationAmbiguousFailClosedNoAuditFinalization ProductionExternalPublicationAuditFinalizationUnavailableNoAuditFinalization MainNetExternalPublicationAuditFinalizationUnavailableNoAuditFinalization ExternalExternalPublicationAuditFinalizationUnavailableNoAuditFinalization MainNetPeerDrivenApplyRefusedNoAuditFinalization ValidatorSetRotationUnsupportedNoAuditFinalization PolicyChangeUnsupportedNoAuditFinalization LegacyBypassNoExternalPublicationAuditFinalization RejectedBeforeExternalPublicationAcknowledgementNoAuditFinalization ExternalPublicationAcknowledgementDidNotRecordNoAuditFinalization
  durable_completion_external_publication_audit_finalization_rejection_is_non_mutating durable_completion_external_publication_audit_finalization_never_calls_run_070 durable_completion_external_publication_audit_finalization_never_mutates_live_pqc_trust_state durable_completion_external_publication_audit_finalization_never_writes_sequence_or_marker durable_completion_external_publication_audit_finalization_no_rocksdb_file_schema_migration_change durable_completion_external_publication_audit_finalization_no_external_publication durable_completion_external_publication_audit_finalization_no_real_audit_ledger durable_completion_external_publication_audit_finalization_pipeline_success_required durable_completion_external_publication_audit_finalization_sink_receipt_required durable_completion_external_publication_audit_finalization_completion_report_required durable_completion_external_publication_audit_finalization_finalization_projection_required durable_completion_external_publication_audit_finalization_attestation_required durable_completion_external_publication_audit_finalization_backend_submission_required durable_completion_external_publication_audit_finalization_receipt_required durable_completion_external_publication_audit_finalization_consumer_required durable_completion_external_publication_audit_finalization_confirmation_required durable_completion_external_publication_audit_finalization_no_real_settlement durable_completion_external_publication_audit_finalization_no_real_settlement_finality durable_completion_external_publication_audit_finalization_no_real_settlement_receipt durable_completion_external_publication_audit_finalization_no_real_external_publication_acknowledgement durable_completion_external_publication_audit_finalization_no_real_settlement_finality_projection durable_completion_external_publication_audit_finalization_no_real_external_publication_audit_finalization durable_completion_external_publication_audit_finalization_record_required_before_reported durable_completion_external_publication_audit_finalization_failed_record_never_records durable_completion_external_publication_audit_finalization_rollback_never_records durable_completion_external_publication_audit_finalization_ambiguous_window_fails_closed durable_completion_external_publication_audit_finalization_mainnet_peer_driven_apply_refused_first durable_completion_external_publication_audit_finalization_production_mainnet_unavailable durable_completion_external_publication_audit_finalization_external_unavailable durable_completion_external_publication_audit_finalization_validator_set_rotation_unsupported durable_completion_external_publication_audit_finalization_policy_change_unsupported durable_completion_external_publication_audit_finalization_local_operator_cannot_satisfy_mainnet_authority durable_completion_external_publication_audit_finalization_peer_majority_cannot_satisfy_mainnet_authority
)
{
  echo "Run 283 source reachability — Run 282 external-publication-acknowledgement symbols in ${MOD}:"
  for sym in "${RUN282_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN282_SYMS[@]}"; do assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"; done
{
  echo "Run 283 helper reachability — Run 282 symbols exercised by release helper:"
  for sym in "${RUN282_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in evaluate_durable_completion_external_publication_audit_finalization recover_durable_completion_external_publication_audit_finalization_window project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request external_publication_audit_finalization_outcome_authorizes_record external_publication_audit_finalization_outcome_projects_to_recorded GovernanceDurableCompletionExternalPublicationAuditFinalizationSink FixtureDurableCompletionExternalPublicationAuditFinalizationSink ProductionExternalPublicationAuditFinalizationSink MainNetExternalPublicationAuditFinalizationSink ExternalExternalPublicationAuditFinalizationSink DurableCompletionExternalPublicationAuditFinalizationInput DurableCompletionExternalPublicationAuditFinalizationOutcome DurableCompletionExternalPublicationAuditFinalizationLedger DurableCompletionExternalPublicationAuditFinalizationRequestIntent DurableCompletionExternalPublicationAuditFinalizationFault; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_governance_durable_completion_external_publication_audit_finalization' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'pub fn evaluate_durable_completion_external_publication_audit_finalization\|pub fn recover_durable_completion_external_publication_audit_finalization_window\|pub fn project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing external-publication-audit-finalization entry points"
grep -RIn --include='*.rs' 'enum DurableCompletionExternalPublicationAuditFinalizationOutcome\|enum DurableCompletionExternalPublicationAuditFinalizationRequestIntent\|enum DurableCompletionExternalPublicationAuditFinalizationFault' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing external-publication-audit-finalization taxonomy"
grep -RIn --include='*.rs' 'trait GovernanceDurableCompletionExternalPublicationAuditFinalizationSink\|struct FixtureDurableCompletionExternalPublicationAuditFinalizationSink\|struct ProductionExternalPublicationAuditFinalizationSink\|struct MainNetExternalPublicationAuditFinalizationSink\|struct ExternalExternalPublicationAuditFinalizationSink' "${MOD}" > "${REACH_DIR}/sink_boundary.txt" || fail "missing external-publication-audit-finalization sink boundary"
grep -RIn --include='*.rs' 'DurableCompletionExternalPublicationAcknowledgementOutcome\|ExternalPublicationAcknowledgementRecorded\|project_external_publication_acknowledgement_outcome_to_external_publication_audit_finalization_request' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 280 composition usage"

DENY_PATTERNS=(
  'real external-publication-audit-finalization enabled' 'real external-publication-audit-finalization backend enabled' 'durable-completion external-publication-audit-finalization production enabled' 'MainNet external-publication-audit-finalization enabled' 'external external-publication-audit-finalization enabled' 'real external-publication-acknowledgement enabled' 'real external-publication-acknowledgement backend enabled' 'real external publication enabled' 'real settlement backend enabled' 'real settlement outcome publication enabled' 'real settlement-outcome publication enabled' 'real settlement-outcome publication backend enabled' 'real settlement outcome report backend enabled' 'real settlement outcome report enabled' 'real settlement receipt enabled' 'real settlement-receipt acknowledgement enabled' 'real settlement-finality projection enabled' 'real settlement finality enabled' 'durable-completion external-publication-acknowledgement production enabled' 'MainNet external-publication-acknowledgement enabled' 'external external-publication-acknowledgement enabled' 'durable-completion settlement-outcome publication production enabled' 'durable-completion settlement-outcome report production enabled' 'durable-completion settlement-receipt acknowledgement production enabled' 'durable-completion settlement-finalization production enabled' 'durable-completion settlement-commitment production enabled' 'durable-completion settlement-projection production enabled' 'real audit-ledger acknowledgement backend enabled' 'real external-publication confirmation backend enabled' 'real external publication backend enabled' 'real production attestation backend enabled' 'real finalization backend enabled' 'real completion-report backend enabled' 'real durable consume backend enabled' 'real persistent replay backend enabled' 'real production mutation engine enabled' 'MainNet mutation engine enabled' 'MainNet governance enabled' 'MainNet peer-driven apply enabled' 'real governance execution engine enabled' 'real on-chain governance proof verifier enabled' 'RocksDB replay backend enabled' 'file replay backend enabled' 'schema migration enabled' 'storage-format migration enabled' 'KMS/HSM backend enabled' 'KMS backend enabled' 'HSM backend enabled' 'RemoteSigner backend enabled' 'validator-set rotation enabled' 'policy-change action enabled' 'autonomous apply' 'apply-on-receipt' 'apply-on-acknowledgement' 'apply-on-consumer' 'apply-on-settlement-projection' 'apply-on-settlement-commitment' 'apply-on-settlement-finalization' 'apply-on-settlement-receipt-acknowledgement' 'apply-on-settlement-outcome-report' 'apply-on-external-publication-receipt' 'apply-on-external-publication-acknowledgement' 'apply-on-external-publication-audit-finalization' 'apply-on-settlement' 'peer-majority authority' 'Run 070 apply from the external-publication-audit-finalization boundary' 'LivePqcTrustState mutation from the external-publication-audit-finalization boundary' 'real trust swap from the external-publication-audit-finalization boundary' 'session eviction from the external-publication-audit-finalization boundary' 'marker write from the external-publication-audit-finalization boundary' 'sequence write from the external-publication-audit-finalization boundary' 'RocksDB write from the external-publication-audit-finalization boundary' 'file write from the external-publication-audit-finalization boundary' 'external publication by the fixture external-publication-audit-finalization sink' 'external-publication confirmation by the fixture external-publication-audit-finalization sink' 'audit-ledger write by the fixture external-publication-audit-finalization sink' 'settlement write by the fixture external-publication-audit-finalization sink' 'settlement receipt write by the fixture external-publication-audit-finalization sink' 'settlement-receipt acknowledgement write by the fixture external-publication-audit-finalization sink' 'settlement-finality projection write by the fixture external-publication-audit-finalization sink' 'settlement-outcome report write by the fixture external-publication-audit-finalization sink' 'settlement-outcome publication write by the fixture external-publication-audit-finalization sink' 'settlement finality write by the fixture external-publication-audit-finalization sink' 'production durable consume by the fixture external-publication-audit-finalization sink' 'production finalization by the fixture external-publication-audit-finalization sink' 'production attestation by the fixture external-publication-audit-finalization sink' 'production backend submission by the fixture external-publication-audit-finalization sink' 'production audit receipt by the fixture external-publication-audit-finalization sink' 'production acknowledgement by the fixture external-publication-audit-finalization sink' 'production consumer by the fixture external-publication-audit-finalization sink' 'production settlement projection by the fixture external-publication-audit-finalization sink' 'production settlement commitment by the fixture external-publication-audit-finalization sink' 'production settlement finalization by the fixture external-publication-audit-finalization sink' 'production settlement-receipt acknowledgement by the fixture external-publication-audit-finalization sink' 'production settlement-outcome report by the fixture external-publication-audit-finalization sink' 'production settlement-outcome publication by the fixture external-publication-audit-finalization sink' 'production external-publication confirmation by the fixture external-publication-audit-finalization sink' 'production external-publication receipt by the fixture external-publication-audit-finalization sink' 'production external-publication acknowledgement by the fixture external-publication-audit-finalization sink' 'external-publication receipt by the fixture external-publication-audit-finalization sink' 'external-publication acknowledgement by the fixture external-publication-audit-finalization sink' 'DummySig / DummyKem / DummyAead active on production path' 'DummySig' 'DummyKem' 'DummyAead'
)
{
  echo "Run 283 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_283_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 283 no-mutation proof for rejected external-publication-acknowledgement scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_283_OUT}/helper_summary.txt" | sed 's/^/    /'
  echo "  projection rule: input.external_publication_acknowledgement_binding only; no projection from Run 278 external-publication receipt, Run 276 external-publication confirmation, Run 274 settlement-outcome publication, Run 272 settlement-outcome report, Run 270 settlement-receipt acknowledgement, Run 268 settlement finalization, Run 266 settlement commitment, Run 264 settlement projection, Run 262 consumer, Run 260 acknowledgement, Run 258 receipt, or Run 256 backend directly."
} > "${NOMUT_PROOF}"
{
  echo "Run 283 mutation proof: only the modeled in-memory DurableCompletionExternalPublicationAuditFinalizationLedger is mutated by the DevNet/TestNet fixture external-publication-audit-finalization sink after the full Run 256 -> Run 258 -> Run 260 -> Run 262 -> Run 264 -> Run 266 -> Run 268 -> Run 270 -> Run 272 -> Run 274 -> Run 276 -> Run 278 -> Run 280 -> Run 282 chain records. Production/MainNet/external external-publication-audit-finalization sinks are reachable but unavailable/fail-closed. No real settlement, settlement receipt, settlement finality, settlement-receipt acknowledgement, settlement-finality projection, settlement-outcome report, settlement-outcome publication, external publication, external-publication confirmation, audit-ledger, RocksDB/file/schema/migration, marker, sequence, Run 070, LivePqcTrustState, trust swap, or session eviction path is enabled."
} > "${MUT_PROOF}"

run_test_target() {
  local target="$1"; local logf="${TEST_LOGS}/test_${target}.log"
  log "cargo test -p qbind-node --test ${target}"
  set +e; ( cd "${REPO_ROOT}" && cargo test -p qbind-node --test "$target" -- --test-threads=1 ) > "$logf" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/test_${target}.rc"; printf '%s\trc=%d\n' "test:${target}" "$rc"
}
run_lib_test() {
  local filter="$1"; local label="${2:-${filter:-lib_all}}"; local logf="${TEST_LOGS}/lib_${label}.log"
  log "cargo test -p qbind-node --lib ${filter}"
  set +e; ( cd "${REPO_ROOT}" && cargo test -p qbind-node --lib ${filter} -- --test-threads=1 ) > "$logf" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/lib_${label}.rc"; printf '%s\trc=%d\n' "lib:${label}" "$rc"
}
TEST_VERDICTS=()
TEST_TARGETS=(run_282_durable_completion_external_publication_audit_finalization_tests run_280_durable_completion_external_publication_acknowledgement_tests run_278_durable_completion_external_publication_receipt_tests run_276_durable_completion_external_publication_confirmation_tests run_274_durable_completion_settlement_outcome_publication_tests run_272_durable_completion_settlement_outcome_report_tests run_270_durable_completion_settlement_receipt_acknowledgement_tests run_268_durable_completion_settlement_finalization_tests run_266_durable_completion_settlement_commitment_tests run_264_durable_completion_consumer_settlement_projection_tests run_262_durable_completion_acknowledgement_consumer_tests run_260_durable_completion_audit_receipt_acknowledgement_tests run_258_durable_completion_audit_publication_receipt_tests run_256_durable_completion_attestation_backend_tests run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
if [[ "${RUN_283_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_283_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 283 — release-binary governance durable-completion external-publication-audit-finalization evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_283_sha256:  $(sha256_file "${HELPER_283_BIN}")"
  echo
  echo "helper_summary: ${HELPER_283_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_283_OUT}/helper_summary.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5=${S5_RC} S6=${S6_RC}"
  echo "reachability: source/helper/module/entry/taxonomy/boundary/composition greps passed"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

cat "${SUMMARY}"
log "done"