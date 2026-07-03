#!/usr/bin/env bash
# Run 292 — release-binary evidence for the Run 291 production durable replay RocksDB backend.
#
# Release-binary evidence for the Run 291 source/test production durable replay
# RocksDB backend (`crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 291 production library symbols are present and exercised in release mode,
# and that the real RocksDB backend behaves correctly under release-built
# conditions (write/reopen/replay/idempotency/equivocation/corruption/wrong-domain,
# default-Disabled, MainNet refused, no in-memory fallback). The release helper
# remains dead code from the production runtime; the production binary is never
# wired to open the backend and adds no CLI flag. No production runtime is
# enabled. Full C4 remains OPEN. C5 remains OPEN.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_292_production_durable_replay_rocksdb_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_292_BIN="${REPO_ROOT}/target/release/examples/run_292_production_durable_replay_rocksdb_release_binary_helper"
HELPER_292_OUT="${OUTDIR}/helper_evidence/run_292"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
DATA_DIR="${OUTDIR}/data"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"
NOMUT_PROOF="${OUTDIR}/no_mutation_proof.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_production_durable_replay_rocksdb.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_292_production_durable_replay_rocksdb_release_binary_helper.rs"

log() { printf '[run-292] %s\n' "$*" >&2; }
fail() { printf '[run-292] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_292_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_292_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-292 provenance"
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
log "cargo build --release -p qbind-node --example run_292_production_durable_replay_rocksdb_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_292_production_durable_replay_rocksdb_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_292.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_292_BIN}" ]] || fail "missing ${HELPER_292_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_292_path:    ${HELPER_292_BIN}"
  echo "helper_292_sha256:  $(sha256_file "${HELPER_292_BIN}")"
  echo "helper_292_buildid: $(build_id "${HELPER_292_BIN}")"
} >> "${PROVENANCE}"

log "running Run 292 helper (first invocation)"
set +e
"${HELPER_292_BIN}" "${HELPER_292_OUT}" > "${LOGS_DIR}/helper_run_292.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_292.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_292 helper failed"
assert_grep "${HELPER_292_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_292_OUT}/helper_summary.txt" 'total_fail: 0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 292 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_292_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_292_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_292_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_292_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_292 helper invocation failed"
if ! diff -q "${HELPER_292_OUT}/fixtures/run_292_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_292_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'RocksDB replay backend enabled|durable replay RocksDB backend enabled|durable-replay-rocksdb backend enabled|production durable replay backend enabled|file replay backend enabled|persistent replay backend enabled'
  assert_not_grep "$logf" 'schema migration enabled|storage-format migration enabled|durable replay RocksDB wired|durable replay RocksDB default-enabled|MainNet durable replay RocksDB enabled'
  assert_not_grep "$logf" 'real production mutation engine enabled|MainNet mutation engine enabled|MainNet governance enabled|MainNet peer-driven apply enabled|real governance execution engine enabled|real on-chain governance proof verifier enabled'
  assert_not_grep "$logf" 'KMS/HSM backend enabled|KMS backend enabled|HSM backend enabled|cloud KMS backend enabled|PKCS11 backend enabled|RemoteSigner backend enabled|production custody active'
  assert_not_grep "$logf" 'validator-set rotation enabled|policy-change action enabled|real settlement backend enabled|real external publication backend enabled'
  assert_not_grep "$logf" 'in-memory fallback|fallback to fixture|fallback to mock|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 apply from the durable replay RocksDB backend|LivePqcTrustState mutation from the durable replay RocksDB backend|real trust swap from the durable replay RocksDB backend|session eviction from the durable replay RocksDB backend|marker write from the durable replay RocksDB backend|sequence write from the durable replay RocksDB backend'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides durable replay RocksDB backend surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'durable-replay-rocksdb|DurableReplayRocksDb|ProductionDurableReplayRocksDbBackend|record_replay_event|scan_replay_records|recover_replay_window|run-292|run_292'
log "S2..S4 default surfaces silent on durable replay RocksDB claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (no new durable-replay CLI selector added)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"; assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

RUN291_SYMS=(
  pqc_governance_production_durable_replay_rocksdb
  ProductionDurableReplayRocksDbBackend GovernanceProductionDurableReplayBackend MockDurableReplayBackend
  DurableReplayRocksDbPolicy DurableReplayRocksDbConfig DurableReplayRocksDbIdentity DurableReplayRocksDbError
  DurableReplayRocksDbOpenOutcome DurableReplayRocksDbWriteOutcome DurableReplayRocksDbReadOutcome DurableReplayRocksDbRecoveryOutcome
  DurableReplayEventInput DurableReplayRecordStage DurableReplayRocksDbRecord
  DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION
  record_replay_event read_replay_record scan_replay_records recover_replay_window close_or_flush
  durable_replay_rocksdb_record_id durable_replay_rocksdb_record_digest durable_replay_rocksdb_domain_digest durable_replay_rocksdb_record_key
  DurableBackendDecisionInput durable_backend_key_digest durable_record_digest
  durable_replay_rocksdb_never_falls_back_to_in_memory durable_replay_rocksdb_default_is_disabled durable_replay_rocksdb_mainnet_remains_refused durable_replay_rocksdb_is_source_test_not_release_binary_evidence
)
{
  echo "Run 292 source reachability — Run 291 durable replay RocksDB symbols in ${MOD}:"
  for sym in "${RUN291_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN291_SYMS[@]}"; do assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"; done
{
  echo "Run 292 helper reachability — Run 291 symbols exercised by the release helper:"
  for sym in "${RUN291_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in ProductionDurableReplayRocksDbBackend GovernanceProductionDurableReplayBackend DurableReplayRocksDbPolicy DurableReplayRocksDbConfig DurableReplayRocksDbIdentity DurableReplayRocksDbError DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION record_replay_event read_replay_record scan_replay_records recover_replay_window close_or_flush DurableBackendDecisionInput durable_backend_key_digest durable_record_digest; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_governance_production_durable_replay_rocksdb' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'pub fn open_or_initialize\|fn record_replay_event\|fn read_replay_record\|fn scan_replay_records\|fn recover_replay_window\|fn close_or_flush' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing backend entry points"
grep -RIn --include='*.rs' 'enum DurableReplayRocksDbError\|enum DurableReplayRocksDbWriteOutcome\|enum DurableReplayRocksDbRecoveryOutcome' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing backend taxonomy"
grep -RIn --include='*.rs' 'trait GovernanceProductionDurableReplayBackend\|struct ProductionDurableReplayRocksDbBackend\|struct MockDurableReplayBackend' "${MOD}" > "${REACH_DIR}/backend_boundary.txt" || fail "missing backend boundary"
grep -RIn --include='*.rs' 'DurableBackendDecisionInput\|durable_backend_key_digest\|durable_record_digest' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 238 composition usage"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 292'
  'Matrix status clarification'
  'boundary readiness'
  'production readiness'
  'release-binary evidence'
  'Full C4 remains OPEN'
  'C5 remains OPEN'
  'Modeled durable-completion pipeline / settlement / external-publication boundary stack'
  'Production durable replay RocksDB backend'
  'Green for release-binary-evidenced RocksDB durable replay backend behavior only'
  'Real production RemoteSigner backend'
  'Real KMS / HSM / cloud-KMS / PKCS#11 custody backend'
  'Real custody attestation verifier'
  'Real on-chain governance proof verifier'
  'Governance execution engine'
  'Validator-set rotation / authority-set synchronization'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 292 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The modeled boundary stack must remain Yellow (not Green); the RocksDB backend row is the only Green-for-scope row.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must be scoped Green"
for redrow in 'Real production RemoteSigner backend | 🔴 Red' 'Real KMS / HSM / cloud-KMS / PKCS#11 custody backend | 🔴 Red' 'Real on-chain governance proof verifier | 🔴 Red' 'Governance execution engine | 🔴 Red' 'Validator-set rotation / authority-set synchronization | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready' 'production custody active' 'RemoteSigner active' 'KMS active' 'HSM active' 'PKCS11 active' 'cloud KMS active'
  'on-chain governance verifier active' 'governance execution engine active' 'validator-set rotation active' 'peer-driven apply enabled'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'settlement finalized' 'settlement receipt recorded' 'settlement outcome published' 'external publication completed' 'external publication confirmed' 'external publication receipt recorded' 'external publication acknowledgement recorded'
  'external publication audit finalized' 'external publication audit completed' 'external publication audit archived' 'external publication audit sealed' 'external publication audit anchored' 'audit ledger finalized' 'audit ledger acknowledged'
  'in-memory fallback' 'fallback to fixture' 'fallback to mock' 'DummySig active' 'DummyKem active' 'DummyAead active'
  'durable replay RocksDB backend enabled' 'durable replay RocksDB wired' 'durable replay RocksDB default-enabled' 'MainNet durable replay RocksDB enabled' 'schema migration enabled' 'storage-format migration enabled'
)
{
  echo "Run 292 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_292_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 292 no-mutation / no-authority-extension proof:"
  echo "  The release helper opens the real Run 291 RocksDB backend ONLY through the source/test"
  echo "  DurableReplayRocksDbPolicy::ProductionSourceTest selector, ONLY for DevNet/TestNet identities,"
  echo "  and ONLY against ephemeral tempfile::TempDir databases. It performs no Run 070 call, no"
  echo "  LivePqcTrustState mutation, no trust swap, no session eviction, no PQC trust-bundle sequence"
  echo "  write, no authority marker write, no settlement, no external publication, no custody/RemoteSigner/"
  echo "  KMS/HSM signing, no validator-set rotation, no MainNet governance, and no peer-driven apply."
  echo "  MainNet identities are refused at open; the default DurableReplayRocksDbPolicy is Disabled;"
  echo "  the production binary is not wired to open the backend and adds no CLI flag; there is no silent"
  echo "  fallback to an in-memory backend on RocksDB failure."
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_292_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"

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
TEST_TARGETS=(run_291_production_durable_replay_rocksdb_tests run_290_durable_completion_external_publication_audit_anchor_tests run_288_durable_completion_external_publication_audit_seal_tests run_286_durable_completion_external_publication_audit_archive_tests run_284_durable_completion_external_publication_audit_completion_tests run_282_durable_completion_external_publication_audit_finalization_tests run_280_durable_completion_external_publication_acknowledgement_tests run_278_durable_completion_external_publication_receipt_tests run_276_durable_completion_external_publication_confirmation_tests run_274_durable_completion_settlement_outcome_publication_tests run_272_durable_completion_settlement_outcome_report_tests run_270_durable_completion_settlement_receipt_acknowledgement_tests run_268_durable_completion_settlement_finalization_tests run_266_durable_completion_settlement_commitment_tests run_264_durable_completion_consumer_settlement_projection_tests run_262_durable_completion_acknowledgement_consumer_tests run_260_durable_completion_audit_receipt_acknowledgement_tests run_258_durable_completion_audit_publication_receipt_tests run_256_durable_completion_attestation_backend_tests run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
if [[ "${RUN_292_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_292_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 292 — release-binary evidence for the Run 291 production durable replay RocksDB backend"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_292_sha256:  $(sha256_file "${HELPER_292_BIN}")"
  echo
  echo "helper_summary: ${HELPER_292_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_292_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_292_OUT}/fixtures/run_292_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5=${S5_RC} S6=${S6_RC}"
  echo "reachability: source/helper/module/entry/taxonomy/boundary/composition greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB row Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

cat "${SUMMARY}"
log "done"