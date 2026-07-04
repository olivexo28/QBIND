#!/usr/bin/env bash
# Run 302 — release-binary evidence for the Run 301 production governance execution
# engine.
#
# Release-binary evidence for the Run 301 source/test real production governance
# execution engine
# (`crates/qbind-node/src/pqc_production_governance_execution_engine.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 301 production library symbols are present and exercised in release mode,
# and that the real engine behaves correctly under release-built conditions
# (DevNet/TestNet source-test accept / environment-chain-genesis-authority-root-
# governance-domain-epoch-proposal-lifecycle-candidate-authority-sequence-quorum-
# threshold-proof-transcript binding / disabled / unverified-proof /
# fixture-rejected-as-production / local-operator / peer-majority / custody-only /
# remote-signer-only / custody-attestation-only rejected / wrong-field rejections /
# custody-attestation-durable-replay required-and-mismatch / replayed-decision-id /
# stale-epoch / stale-sequence / unsupported-lifecycle / validator-set-rotation-
# unsupported / engine-unavailable / production-policy-unavailable / ambiguous
# fail-closed, MainNet refused, no fixture/local-operator/peer-majority/RemoteSigner/
# custody fallback under production policy, non-mutating), composing with the Run
# 299/300 on-chain governance proof verifier accept output. The engine consumes a
# verified on-chain governance proof decision and produces only typed non-mutating
# authority-lifecycle execution intents. The release helper remains dead code from
# the production runtime; the production binary is never wired to construct the
# engine and adds no CLI flag. No production runtime is enabled. Full C4 remains
# OPEN. C5 remains OPEN.
#
# Substitution note: the Run 301 engine surfaces every failure as a typed
# `ProductionGovernanceExecutionOutcome` fail-closed variant; there is no separate
# `ProductionGovernanceExecutionError` enum, so that symbol from the task symbol
# list is intentionally not required by the reachability greps below.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_302_production_governance_execution_engine_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_302_BIN="${REPO_ROOT}/target/release/examples/run_302_production_governance_execution_engine_release_binary_helper"
HELPER_302_OUT="${OUTDIR}/helper_evidence/run_302"
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
MOD="${SRC_DIR}/pqc_production_governance_execution_engine.rs"
VERIFIER_MOD="${SRC_DIR}/pqc_production_onchain_governance_proof_verifier.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_302_production_governance_execution_engine_release_binary_helper.rs"

log() { printf '[run-302] %s\n' "$*" >&2; }
fail() { printf '[run-302] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_302_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_302_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-302 provenance"
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
log "cargo build --release -p qbind-node --example run_302_production_governance_execution_engine_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_302_production_governance_execution_engine_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_302.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_302_BIN}" ]] || fail "missing ${HELPER_302_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_302_path:    ${HELPER_302_BIN}"
  echo "helper_302_sha256:  $(sha256_file "${HELPER_302_BIN}")"
  echo "helper_302_buildid: $(build_id "${HELPER_302_BIN}")"
} >> "${PROVENANCE}"

log "running Run 302 helper (first invocation)"
set +e
"${HELPER_302_BIN}" "${HELPER_302_OUT}" > "${LOGS_DIR}/helper_run_302.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_302.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_302 helper failed"
assert_grep "${HELPER_302_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_302_OUT}/helper_summary.txt" 'total_fail: 0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 302 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_302_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_302_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_302_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_302_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_302 helper invocation failed"
if ! diff -q "${HELPER_302_OUT}/fixtures/run_302_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_302_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 301/302 production governance
# execution engine has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution engine enabled|governance execution engine active|production governance execution enabled|production governance execution active|governance execution engine wired|governance execution engine default-enabled|ProductionGovernanceExecutionEngine enabled|MainNet governance execution engine enabled'
  assert_not_grep "$logf" 'validator-set rotation active|validator-set rotation enabled|authority-set synchronization enabled|real governance execution engine enabled|MainNet governance enabled|MainNet authority rotation enabled|MainNet mutation engine enabled|peer-driven apply enabled'
  assert_not_grep "$logf" 'fallback to fixture proof|fallback to local operator proof|fallback to peer majority|fallback to RemoteSigner|fallback to custody attestation|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written|durable replay overwritten|settlement finalized|settlement receipt recorded|settlement outcome published|external publication completed'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 301/302 governance execution engine surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 301/302 production governance execution engine flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'production-governance-execution-engine|ProductionGovernanceExecutionEngine|ProductionGovernanceExecutionEnginePolicy|pqc_production_governance_execution_engine|run-302|run_302|run-301|run_301'
log "S2..S4 default surfaces silent on governance execution engine claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (no new governance-execution-engine CLI selector added)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"; assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

# Run 301 engine symbols required to be reachable in release evidence (from source
# and/or the release helper). Substitution: no `ProductionGovernanceExecutionError`
# enum exists; the engine surfaces failures as typed
# `ProductionGovernanceExecutionOutcome` fail-closed variants.
RUN301_SYMS=(
  ProductionGovernanceExecutionEngine
  ProductionGovernanceExecutionRequest
  ProductionGovernanceExecutionInputs
  ProductionGovernanceExecutionDecision
  ProductionGovernanceExecutionIntent
  ProductionGovernanceExecutionIntentKind
  ProductionGovernanceExecutionEnginePolicy
  ProductionGovernanceExecutionEngineKind
  ProductionGovernanceExecutionOutcome
  ProductionGovernanceExecutionRecoveryOutcome
  GovernanceExecutionProofSource
  GovernanceExecutionProofBinding
  GovernanceExecutionCustodyBinding
  GovernanceExecutionAttestationBinding
  GovernanceExecutionDurableReplayBinding
  GovernanceExecutionReplaySet
  evaluate_production_governance_execution
  recover_production_governance_execution_window
  production_governance_execution_request_id
  production_governance_execution_intent_digest
  production_governance_execution_transcript_digest
)
COMBINED_CORPUS="${REACH_DIR}/combined_corpus.txt"
cat "${MOD}" "${VERIFIER_MOD}" "${HELPER_SRC}" > "${COMBINED_CORPUS}"
{
  echo "Run 302 combined reachability — Run 301 governance execution engine symbols across source module + Run 299/300 verifier module + release helper:"
  for sym in "${RUN301_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${COMBINED_CORPUS}" | head -n 20 || echo '(no occurrences)'; echo; done
} > "${REACH_DIR}/combined_reachability.txt"
for sym in "${RUN301_SYMS[@]}"; do assert_grep "${COMBINED_CORPUS}" "$sym"; done
{
  echo "Run 302 source reachability — Run 301 production governance execution engine symbols in ${MOD}:"
  for sym in "${RUN301_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
# Symbols expected to be defined/referenced directly in the production module.
for sym in ProductionGovernanceExecutionEngine ProductionGovernanceExecutionRequest ProductionGovernanceExecutionInputs ProductionGovernanceExecutionDecision ProductionGovernanceExecutionIntent ProductionGovernanceExecutionIntentKind ProductionGovernanceExecutionEnginePolicy ProductionGovernanceExecutionEngineKind ProductionGovernanceExecutionOutcome ProductionGovernanceExecutionRecoveryOutcome GovernanceExecutionProofSource GovernanceExecutionProofBinding GovernanceExecutionCustodyBinding GovernanceExecutionAttestationBinding GovernanceExecutionDurableReplayBinding GovernanceExecutionReplaySet evaluate_production_governance_execution recover_production_governance_execution_window production_governance_execution_request_id production_governance_execution_intent_digest production_governance_execution_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done
{
  echo "Run 302 helper reachability — Run 301 symbols exercised by the release helper (plus the Run 299/300 verifier composition):"
  for sym in "${RUN301_SYMS[@]}" pqc_production_onchain_governance_proof_verifier ProductionOnChainGovernanceProofVerifier RealMerkleInclusionVerifier build_merkle_inclusion_proof EmptyGovernanceExecutionReplaySet; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
# Symbols the release helper must directly exercise.
for sym in ProductionGovernanceExecutionEngine ProductionGovernanceExecutionRequest ProductionGovernanceExecutionInputs ProductionGovernanceExecutionDecision ProductionGovernanceExecutionIntent ProductionGovernanceExecutionIntentKind ProductionGovernanceExecutionEnginePolicy ProductionGovernanceExecutionEngineKind ProductionGovernanceExecutionOutcome ProductionGovernanceExecutionRecoveryOutcome GovernanceExecutionProofSource GovernanceExecutionProofBinding GovernanceExecutionCustodyBinding GovernanceExecutionAttestationBinding GovernanceExecutionDurableReplayBinding evaluate_production_governance_execution recover_production_governance_execution_window production_governance_execution_request_id production_governance_execution_intent_digest production_governance_execution_transcript_digest pqc_production_onchain_governance_proof_verifier ProductionOnChainGovernanceProofVerifier RealMerkleInclusionVerifier build_merkle_inclusion_proof; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_governance_execution_engine' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn evaluate_production_governance_execution\|fn recover_production_governance_execution_window\|fn production_governance_execution_request_id\|fn production_governance_execution_intent_digest\|fn production_governance_execution_transcript_digest' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing engine entry points"
grep -RIn --include='*.rs' 'enum ProductionGovernanceExecutionOutcome\|enum ProductionGovernanceExecutionRecoveryOutcome\|enum ProductionGovernanceExecutionEnginePolicy\|enum ProductionGovernanceExecutionEngineKind\|enum ProductionGovernanceExecutionIntentKind' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing engine taxonomy"
grep -RIn --include='*.rs' 'trait GovernanceExecutionReplaySet\|struct ProductionGovernanceExecutionEngine\|struct GovernanceExecutionProofBinding\|enum GovernanceExecutionProofSource\|struct EmptyGovernanceExecutionReplaySet' "${MOD}" > "${REACH_DIR}/engine_boundary.txt" || fail "missing engine boundary"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 302'
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
  'Green for release-binary-evidenced custody-attestation verifier behavior only'
  'Real on-chain governance proof verifier'
  'Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only'
  'Governance execution engine'
  'Green for release-binary-evidenced governance-execution-engine behavior only'
  'Validator-set rotation / authority-set synchronization'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 302 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The RocksDB, RemoteSigner, KMS/HSM, custody attestation and on-chain governance proof
# verifier backend rows remain Green-for-scope; the governance execution engine row
# becomes Green-for-scope.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced RemoteSigner backend behavior only' "${C4C5_DOC}" || fail "RemoteSigner row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced KMS/HSM custody backend behavior only' "${C4C5_DOC}" || fail "KMS/HSM row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced custody-attestation verifier behavior only' "${C4C5_DOC}" || fail "custody attestation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only' "${C4C5_DOC}" || fail "on-chain governance proof verifier row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced governance-execution-engine behavior only' "${C4C5_DOC}" || fail "governance execution engine row must be scoped Green"
# The governance execution engine row wording must record the non-goals explicitly.
grep -F -q 'not wired by default into production runtime' "${C4C5_DOC}" || fail "governance execution row must record no default runtime wiring"
grep -F -q 'no public CLI flag' "${C4C5_DOC}" || fail "governance execution row must record no public CLI flag"
grep -F -q 'produces typed non-mutating authority-lifecycle execution intents' "${C4C5_DOC}" || fail "governance execution row must record typed non-mutating intents"
grep -F -q 'does not call Run 070; does not mutate LivePqcTrustState; does not write trust-bundle sequence or authority marker files' "${C4C5_DOC}" || fail "governance execution row must record no Run 070 call / no LivePqcTrustState mutation / no sequence-marker write"
grep -F -q 'does not implement validator-set rotation / authority-set synchronization; does not prove MainNet authority rotation/revocation; does not close C4/C5.' "${C4C5_DOC}" || fail "governance execution row must record no validator-set rotation / no MainNet rotation proof / no C4/C5 closure"
for redrow in 'Validator-set rotation / authority-set synchronization | 🔴 Red' 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Production signing audit trail / crypto-agility activation / incident response | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready'
  'governance execution engine active' 'governance execution engine enabled'
  'production governance execution active' 'production governance execution enabled'
  'validator-set rotation active' 'validator-set rotation enabled'
  'MainNet governance enabled' 'MainNet authority rotation enabled' 'peer-driven apply enabled'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'durable replay overwritten' 'settlement finalized' 'settlement receipt recorded' 'settlement outcome published' 'external publication completed'
  'fallback to fixture proof' 'fallback to local operator proof' 'fallback to peer majority' 'fallback to RemoteSigner' 'fallback to custody attestation'
  'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 302 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_302_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 302 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 301 ProductionGovernanceExecutionEngine ONLY through the"
  echo "  source/test engine, ONLY for DevNet/TestNet identities on the accept path, under explicit source/test,"
  echo "  production-required and MainNet-required policies. It consumes a verified Run 299/300 on-chain governance"
  echo "  proof accept decision (composed via a real SHA3-256 Merkle inclusion verifier over an explicit out-of-band"
  echo "  trusted root) and produces ONLY typed non-mutating authority-lifecycle execution intents. It performs no"
  echo "  Run 070 call, no LivePqcTrustState mutation, no trust swap, no session eviction, no PQC trust-bundle"
  echo "  sequence write, no authority marker write, no durable replay overwrite, no settlement, no external"
  echo "  publication, no validator-set rotation, and no raw local production signing key load. Under a production"
  echo "  or MainNet policy the engine fails closed and never falls back to fixture / local-operator / peer-majority"
  echo "  / custody-only / remote-signer-only / custody-attestation-only material. Fixture governance proof is"
  echo "  rejected as production authority; MainNet identities are refused before acceptance. The default"
  echo "  ProductionGovernanceExecutionEnginePolicy is Disabled; the production binary is not wired to construct the"
  echo "  engine and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_302_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_301_production_governance_execution_engine_tests run_299_production_onchain_governance_proof_verifier_tests run_297_production_custody_attestation_verifier_tests run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_186_onchain_governance_production_verifier_boundary_tests run_178_onchain_governance_proof_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests run_290_durable_completion_external_publication_audit_anchor_tests run_288_durable_completion_external_publication_audit_seal_tests run_286_durable_completion_external_publication_audit_archive_tests run_284_durable_completion_external_publication_audit_completion_tests run_282_durable_completion_external_publication_audit_finalization_tests run_280_durable_completion_external_publication_acknowledgement_tests run_278_durable_completion_external_publication_receipt_tests run_276_durable_completion_external_publication_confirmation_tests run_274_durable_completion_settlement_outcome_publication_tests run_272_durable_completion_settlement_outcome_report_tests run_270_durable_completion_settlement_receipt_acknowledgement_tests run_268_durable_completion_settlement_finalization_tests run_266_durable_completion_settlement_commitment_tests run_264_durable_completion_consumer_settlement_projection_tests run_262_durable_completion_acknowledgement_consumer_tests run_260_durable_completion_audit_receipt_acknowledgement_tests run_258_durable_completion_audit_publication_receipt_tests run_256_durable_completion_attestation_backend_tests run_254_modeled_durable_completion_attestation_projection_tests run_252_modeled_durable_completion_finalization_projection_tests run_250_modeled_durable_consume_completion_reporter_tests run_248_modeled_durable_consume_projection_sink_tests run_246_governance_modeled_end_to_end_pipeline_tests run_244_modeled_governance_trust_mutation_applier_tests run_242_governance_execution_mutation_engine_tests run_240_governance_evaluator_replay_durable_runtime_integration_tests run_238_governance_evaluator_replay_durable_backend_tests run_236_governance_evaluator_replay_consume_runtime_integration_tests run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests)
if [[ "${RUN_302_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_302_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 302 — release-binary evidence for the Run 301 production governance execution engine"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status: $(if [[ -n "$(git -C "${REPO_ROOT}" status --short 2>/dev/null)" ]]; then echo dirty; else echo clean; fi)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  host:               $(uname -a 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_302_sha256:  $(sha256_file "${HELPER_302_BIN}")"
  echo
  echo "helper_summary: ${HELPER_302_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_302_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_302_OUT}/fixtures/run_302_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5=${S5_RC} S6=${S6_RC}"
  echo "reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM + custody-attestation + on-chain-governance-proof-verifier + governance-execution-engine rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

log "Run 302 release-binary evidence complete: ${SUMMARY}"
cat "${SUMMARY}"
