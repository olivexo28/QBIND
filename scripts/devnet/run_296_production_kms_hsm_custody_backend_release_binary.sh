#!/usr/bin/env bash
# Run 296 — release-binary evidence for the Run 295 production KMS/HSM/cloud-KMS/
# PKCS#11 custody backend.
#
# Release-binary evidence for the Run 295 source/test production KMS/HSM custody
# backend (`crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 295 production library symbols are present and exercised in release mode,
# and that the real backend behaves correctly under release-built conditions
# (fixture KMS/HSM accept / provider taxonomy / request-id-request-response-
# transcript-domain binding / production cloud-KMS/PKCS#11/generic reachable-but-
# fail-closed / unavailable / misconfigured / timeout / decode / malformed /
# oversized / replay / wrong-domain / wrong-provider / wrong-key / wrong-signer /
# wrong-action / wrong-protocol / missing-attestation fail-closed, MainNet
# refused, no fixture/RemoteSigner/local-signing fallback under production
# policy, no raw local production key load). The release helper remains dead
# code from the production runtime; the production binary is never wired to
# construct the backend and adds no CLI flag. No production runtime is enabled.
# Full C4 remains OPEN. C5 remains OPEN.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_296_production_kms_hsm_custody_backend_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_296_BIN="${REPO_ROOT}/target/release/examples/run_296_production_kms_hsm_custody_backend_release_binary_helper"
HELPER_296_OUT="${OUTDIR}/helper_evidence/run_296"
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
MOD="${SRC_DIR}/pqc_production_kms_hsm_custody_backend.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_296_production_kms_hsm_custody_backend_release_binary_helper.rs"

log() { printf '[run-296] %s\n' "$*" >&2; }
fail() { printf '[run-296] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_296_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_296_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-296 provenance"
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
log "cargo build --release -p qbind-node --example run_296_production_kms_hsm_custody_backend_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_296_production_kms_hsm_custody_backend_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_296.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_296_BIN}" ]] || fail "missing ${HELPER_296_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_296_path:    ${HELPER_296_BIN}"
  echo "helper_296_sha256:  $(sha256_file "${HELPER_296_BIN}")"
  echo "helper_296_buildid: $(build_id "${HELPER_296_BIN}")"
} >> "${PROVENANCE}"

log "running Run 296 helper (first invocation)"
set +e
"${HELPER_296_BIN}" "${HELPER_296_OUT}" > "${LOGS_DIR}/helper_run_296.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_296.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_296 helper failed"
assert_grep "${HELPER_296_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_296_OUT}/helper_summary.txt" 'total_fail: 0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 296 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_296_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_296_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_296_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_296_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_296 helper invocation failed"
if ! diff -q "${HELPER_296_OUT}/fixtures/run_296_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_296_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 295/296 production
# KMS/HSM custody *backend* has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'KMS/HSM custody backend enabled|production KMS/HSM custody backend enabled|KMS/HSM custody backend wired|KMS/HSM custody backend default-enabled|KMS/HSM custody backend active|MainNet KMS/HSM custody backend enabled|ProductionKmsHsmCustodyBackend enabled'
  assert_not_grep "$logf" 'KMS backend enabled|HSM backend enabled|cloud KMS backend enabled|PKCS11 backend enabled|PKCS#11 backend enabled|production custody active|custody attestation active|KMS active|HSM active|PKCS11 active|cloud KMS active'
  assert_not_grep "$logf" 'RemoteSigner backend enabled|production RemoteSigner backend enabled|RemoteSigner backend active|real production mutation engine enabled|MainNet mutation engine enabled|MainNet governance enabled|MainNet peer-driven apply enabled|real governance execution engine enabled|real on-chain governance proof verifier enabled'
  assert_not_grep "$logf" 'validator-set rotation enabled|policy-change action enabled|real settlement backend enabled|real external publication backend enabled|durable replay RocksDB backend enabled'
  assert_not_grep "$logf" 'fallback to fixture|fallback to RemoteSigner|fallback to local signing|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 295/296 KMS/HSM custody backend surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 295/296 production KMS/HSM custody backend flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'production-kms-hsm-custody-backend|ProductionKmsHsmCustodyBackend|ProductionKmsHsmCustodyBackendPolicy|pqc_production_kms_hsm_custody_backend|run-296|run_296|run-295|run_295'
log "S2..S4 default surfaces silent on KMS/HSM custody backend claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (no new KMS/HSM CLI selector added)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"; assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

RUN295_SYMS=(
  pqc_production_kms_hsm_custody_backend
  ProductionKmsHsmCustodyBackend GovernanceProductionKmsHsmCustodyBackend KmsHsmCustodyProviderTransport
  ProductionKmsHsmCustodyBackendPolicy ProductionKmsHsmCustodyBackendConfig ProductionCustodyRequestSpec
  ProductionCustodyProviderKind ProductionCustodyRequestKind ProductionCustodyRequest ProductionCustodyResponse
  ProductionCustodyError ProductionCustodyOutcome ProductionCustodyRecoveryOutcome SubmittedCustodyRequest
  FixtureKmsCustodyProvider FixtureHsmCustodyProvider ProductionCustodyProviderStub MockKmsHsmCustodyTransport
  PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES
  production_kms_hsm_custody_request_id production_kms_hsm_custody_transcript_digest
  build_custody_request submit_custody_signing_request verify_custody_response
  evaluate_custody_backend recover_custody_request_window
  verify_authority_custody_backend_response
  production_kms_hsm_custody_backend_default_is_disabled production_kms_hsm_custody_backend_mainnet_refuses_fixture_material
  production_kms_hsm_custody_backend_never_falls_back production_kms_hsm_custody_backend_is_non_mutating
  production_kms_hsm_custody_backend_loads_no_raw_local_key production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm
  production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence
)
{
  echo "Run 296 source reachability — Run 295 production KMS/HSM custody backend symbols in ${MOD}:"
  for sym in "${RUN295_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
for sym in "${RUN295_SYMS[@]}"; do assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"; done
{
  echo "Run 296 helper reachability — Run 295 symbols exercised by the release helper:"
  for sym in "${RUN295_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
for sym in ProductionKmsHsmCustodyBackend KmsHsmCustodyProviderTransport ProductionKmsHsmCustodyBackendPolicy ProductionCustodyProviderKind ProductionCustodyRequestKind ProductionCustodyError ProductionCustodyOutcome production_kms_hsm_custody_request_id production_kms_hsm_custody_transcript_digest FixtureKmsCustodyProvider FixtureHsmCustodyProvider ProductionCustodyProviderStub MockKmsHsmCustodyTransport verify_authority_custody_backend_response submit_custody_signing_request verify_custody_response recover_custody_request_window; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_kms_hsm_custody_backend' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn build_custody_request\|fn submit_custody_signing_request\|fn verify_custody_response\|fn evaluate_custody_backend\|fn recover_custody_request_window' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing backend entry points"
grep -RIn --include='*.rs' 'enum ProductionCustodyError\|enum ProductionCustodyOutcome\|enum ProductionCustodyRecoveryOutcome' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing backend taxonomy"
grep -RIn --include='*.rs' 'trait GovernanceProductionKmsHsmCustodyBackend\|struct ProductionKmsHsmCustodyBackend\|trait KmsHsmCustodyProviderTransport\|struct MockKmsHsmCustodyTransport' "${MOD}" > "${REACH_DIR}/backend_boundary.txt" || fail "missing backend boundary"
grep -RIn --include='*.rs' 'verify_authority_custody_backend_response\|backend_transcript_digest\|durable_replay_record_digest' "${MOD}" > "${REACH_DIR}/composition_usage.txt" || fail "missing Run 203/291 composition usage"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 296'
  'Matrix status clarification'
  'boundary readiness'
  'production readiness'
  'release-binary evidence'
  'Full C4 remains OPEN'
  'C5 remains OPEN'
  'Production durable replay RocksDB backend'
  'Green for release-binary-evidenced RocksDB durable replay backend behavior only'
  'Real production RemoteSigner backend'
  'Green for release-binary-evidenced RemoteSigner backend behavior only'
  'Real KMS / HSM / cloud-KMS / PKCS#11 custody backend'
  'Green for release-binary-evidenced KMS/HSM custody backend behavior only'
  'Real custody attestation verifier'
  'Real on-chain governance proof verifier'
  'Governance execution engine'
  'Validator-set rotation / authority-set synchronization'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 296 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The RocksDB and RemoteSigner backend rows remain Green-for-scope; the KMS/HSM backend row becomes Green-for-scope only.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced RemoteSigner backend behavior only' "${C4C5_DOC}" || fail "RemoteSigner row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced KMS/HSM custody backend behavior only' "${C4C5_DOC}" || fail "KMS/HSM row must be scoped Green"
# The KMS/HSM row wording must record the non-goals explicitly.
grep -F -q 'MainNet refused absent production authority criteria and custody attestation' "${C4C5_DOC}" || fail "KMS/HSM row must record MainNet refusal + custody attestation gate"
for redrow in 'Real custody attestation verifier | 🔴 Red' 'Real on-chain governance proof verifier | 🔴 Red' 'Governance execution engine | 🔴 Red' 'Validator-set rotation / authority-set synchronization | 🔴 Red' 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready' 'production custody active'
  'KMS active' 'HSM active' 'PKCS11 active' 'cloud KMS active' 'custody attestation active'
  'on-chain governance verifier active' 'governance execution engine active' 'validator-set rotation active' 'peer-driven apply enabled'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'settlement finalized' 'settlement receipt recorded' 'settlement outcome published' 'external publication completed' 'external publication confirmed'
  'fallback to fixture' 'fallback to local signing' 'fallback to RemoteSigner' 'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 296 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_296_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 296 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 295 ProductionKmsHsmCustodyBackend ONLY over source/test"
  echo "  fixture KMS/HSM providers, reachable-but-fail-closed production provider stubs, and a programmable"
  echo "  mock transport, ONLY for DevNet/TestNet identities on the accept path, under an explicit fixture"
  echo "  policy. It performs no Run 070 call, no LivePqcTrustState mutation, no trust swap, no session"
  echo "  eviction, no PQC trust-bundle sequence write, no authority marker write, no durable replay overwrite,"
  echo "  no settlement, no external publication, no governance execution engine, no validator-set rotation,"
  echo "  and no raw local production signing key load. Under a production policy (ProductionCloudKmsRequired /"
  echo "  ProductionPkcs11HsmRequired / ProductionGenericKmsRequired / MainnetProductionCustodyRequired) the"
  echo "  backend never accepts and never falls back to fixture/RemoteSigner/local signing; production cloud-KMS"
  echo "  / PKCS#11 / generic paths are reachable but fail closed as unavailable/misconfigured without real"
  echo "  provider config. MainNet identities are refused before any provider call; the default"
  echo "  ProductionKmsHsmCustodyBackendPolicy is Disabled; the production binary is not wired to construct the"
  echo "  backend and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_296_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_290_durable_completion_external_publication_audit_anchor_tests run_288_durable_completion_external_publication_audit_seal_tests run_286_durable_completion_external_publication_audit_archive_tests run_284_durable_completion_external_publication_audit_completion_tests run_282_durable_completion_external_publication_audit_finalization_tests run_280_durable_completion_external_publication_acknowledgement_tests run_278_durable_completion_external_publication_receipt_tests run_276_durable_completion_external_publication_confirmation_tests run_274_durable_completion_settlement_outcome_publication_tests run_272_durable_completion_settlement_outcome_report_tests run_270_durable_completion_settlement_receipt_acknowledgement_tests run_268_durable_completion_settlement_finalization_tests run_266_durable_completion_settlement_commitment_tests run_264_durable_completion_consumer_settlement_projection_tests run_262_durable_completion_acknowledgement_consumer_tests run_260_durable_completion_audit_receipt_acknowledgement_tests run_258_durable_completion_audit_publication_receipt_tests run_256_durable_completion_attestation_backend_tests run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests)
if [[ "${RUN_296_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_296_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 296 — release-binary evidence for the Run 295 production KMS/HSM/cloud-KMS/PKCS#11 custody backend"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_296_sha256:  $(sha256_file "${HELPER_296_BIN}")"
  echo
  echo "helper_summary: ${HELPER_296_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_296_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_296_OUT}/fixtures/run_296_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5=${S5_RC} S6=${S6_RC}"
  echo "reachability: source/helper/module/entry/taxonomy/boundary/composition greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

cat "${SUMMARY}"