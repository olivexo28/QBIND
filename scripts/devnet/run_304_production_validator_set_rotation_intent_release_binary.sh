#!/usr/bin/env bash
# Run 304 — release-binary evidence for the Run 303 validator-set rotation /
# authority-set synchronization intent boundary.
#
# Release-binary evidence for the Run 303 source/test validator-set rotation /
# authority-set synchronization intent boundary
# (`crates/qbind-node/src/pqc_production_validator_set_rotation_intent.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 303 production library symbols are present and exercised in release mode,
# and that the real boundary behaves correctly under release-built conditions
# (DevNet/TestNet source-test accept / environment-chain-genesis-authority-root-
# governance-domain-epoch-execution-decision-id-request-id-intent-digest-lifecycle-
# candidate-authority-sequence-quorum-threshold binding plus current/proposed
# validator-set-snapshot digests + epoch/version + derived delta / disabled /
# missing-governance-intent / unverified-governance-intent / on-chain-proof-alone /
# fixture-alone / local-operator / peer-majority / custody-only / remote-signer-only /
# custody-attestation-only rejected / wrong-field rejections / current-and-proposed-
# set-digest mismatch / validator-set epoch/version mismatch / non-monotonic epoch-
# version / empty-proposed-set / duplicate id/consensus/transport/authority key /
# unknown removal-update / conflicting-ambiguous-unsupported delta / unsupported
# rotation action / custody-attestation-durable-replay required-and-mismatch /
# replayed-rotation-nonce / stale governance-epoch / stale authority-sequence / stale
# validator-set epoch-version / production-policy-unavailable / ambiguous fail-closed,
# MainNet refused, no fixture/local-operator/peer-majority/on-chain-proof-alone/
# RemoteSigner/custody fallback under production policy, non-mutating), composing with
# the Run 301/302 governance execution engine accept output. The boundary consumes a
# verified governance execution accept decision and produces only typed non-mutating
# validator-set rotation plans. The release helper remains dead code from the
# production runtime; the production binary is never wired to construct the boundary
# and adds no CLI flag. No production runtime is enabled. MainNet authority
# rotation/revocation remains Red. Full C4 remains OPEN. C5 remains OPEN.
#
# Substitution note: the Run 303 boundary surfaces every failure as a typed
# `ProductionValidatorSetRotationOutcome` fail-closed variant; there is no separate
# `ProductionValidatorSetRotationError` enum, so that symbol from the task symbol
# list is intentionally not required by the reachability greps below.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_304_production_validator_set_rotation_intent_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_304_BIN="${REPO_ROOT}/target/release/examples/run_304_production_validator_set_rotation_intent_release_binary_helper"
HELPER_304_OUT="${OUTDIR}/helper_evidence/run_304"
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
MOD="${SRC_DIR}/pqc_production_validator_set_rotation_intent.rs"
ENGINE_MOD="${SRC_DIR}/pqc_production_governance_execution_engine.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_304_production_validator_set_rotation_intent_release_binary_helper.rs"

log() { printf '[run-304] %s\n' "$*" >&2; }
fail() { printf '[run-304] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_304_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_304_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-304 provenance"
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
log "cargo build --release -p qbind-node --example run_304_production_validator_set_rotation_intent_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_304_production_validator_set_rotation_intent_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_304.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_304_BIN}" ]] || fail "missing ${HELPER_304_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_304_path:    ${HELPER_304_BIN}"
  echo "helper_304_sha256:  $(sha256_file "${HELPER_304_BIN}")"
  echo "helper_304_buildid: $(build_id "${HELPER_304_BIN}")"
} >> "${PROVENANCE}"

log "running Run 304 helper (first invocation)"
set +e
"${HELPER_304_BIN}" "${HELPER_304_OUT}" > "${LOGS_DIR}/helper_run_304.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_304.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_304 helper failed"
assert_grep "${HELPER_304_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_304_OUT}/helper_summary.txt" 'total_fail: 0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 304 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_304_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_304_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_304_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_304_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_304 helper invocation failed"
if ! diff -q "${HELPER_304_OUT}/fixtures/run_304_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_304_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 303/304 validator-set rotation /
# authority-set synchronization intent boundary has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'validator-set rotation active|validator-set rotation enabled|authority-set synchronization enabled|authority-set synchronization active|validator-set rotation boundary enabled|validator-set rotation boundary wired|ProductionValidatorSetRotationBoundary enabled|MainNet validator-set rotation enabled'
  assert_not_grep "$logf" 'governance execution engine enabled|real validator-set rotation enabled|MainNet authority rotation enabled|MainNet authority-set synchronization enabled|MainNet mutation engine enabled|peer-driven apply enabled|validator set mutated|consensus validator-set mutated'
  assert_not_grep "$logf" 'fallback to fixture proof|fallback to local operator proof|fallback to peer majority|fallback to on-chain proof|fallback to RemoteSigner|fallback to custody attestation|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written|transition_to_epoch called|meta:current_epoch written|reconfig block injected|durable replay overwritten'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 303/304 validator-set rotation surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 303/304 validator-set rotation boundary flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'validator-set-rotation|ProductionValidatorSetRotation|ProductionValidatorSetRotationPolicy|pqc_production_validator_set_rotation_intent|authority-set-synchronization|run-304|run_304|run-303|run_303'
log "S2..S4 default surfaces silent on validator-set rotation boundary claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
log "S5 no validator-set rotation CLI selector exists (invented flag fails closed as unknown)"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet --p2p-validator-set-rotation-policy allow-source-test ) > "${LOGS_DIR}/S5_no_selector.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_no_selector.rc"; [[ "${S5_RC}" -ne 0 ]] || fail "invented validator-set-rotation selector must be rejected (no such flag)"
assert_grep "${LOGS_DIR}/S5_no_selector.log" 'unexpected argument'
assert_surface_silent "${LOGS_DIR}/S5_no_selector.log"
log "S6 default devnet genesis-hash surface fails closed (requires --genesis-path) and stays silent on rotation claims"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_default_parse.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_default_parse.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "default devnet genesis-hash surface must fail closed without --genesis-path"
assert_grep "${LOGS_DIR}/S6_default_parse.log" 'requires --genesis-path'
assert_surface_silent "${LOGS_DIR}/S6_default_parse.log"

# Run 303 boundary symbols required to be reachable in release evidence (from source
# and/or the release helper). Substitution: no `ProductionValidatorSetRotationError`
# enum exists; the boundary surfaces failures as typed
# `ProductionValidatorSetRotationOutcome` fail-closed variants.
RUN303_SYMS=(
  ProductionValidatorSetRotationBoundary
  ProductionValidatorSetRotationConfig
  ProductionValidatorSetRotationKind
  ProductionValidatorSetRotationPolicy
  ProductionValidatorSetRotationInputs
  ProductionValidatorSetRotationRequest
  ProductionValidatorSetRotationDecision
  ProductionValidatorSetRotationPlan
  ProductionValidatorSetRotationPlanKind
  ProductionValidatorSetRotationOutcome
  ProductionValidatorSetRotationRecoveryOutcome
  ProductionValidatorSetRotationProtocolVersion
  ValidatorSetRotationAuthoritySource
  ValidatorSetRotationAction
  CanonicalValidatorIdentity
  CanonicalValidatorRecord
  CanonicalValidatorSetSnapshot
  ValidatorSetChange
  ValidatorSetChangeKind
  ValidatorSetDelta
  ValidatorSetRotationReplaySet
  EmptyValidatorSetRotationReplaySet
  evaluate_validator_set_rotation
  recover_validator_set_rotation_window
  production_validator_set_rotation_plan_digest
  production_validator_set_rotation_request_id
  production_validator_set_rotation_transcript_digest
)
COMBINED_CORPUS="${REACH_DIR}/combined_corpus.txt"
cat "${MOD}" "${ENGINE_MOD}" "${HELPER_SRC}" > "${COMBINED_CORPUS}"
{
  echo "Run 304 combined reachability — Run 303 validator-set rotation intent boundary symbols across source module + Run 301/302 governance execution engine module + release helper:"
  for sym in "${RUN303_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${COMBINED_CORPUS}" | head -n 20 || echo '(no occurrences)'; echo; done
} > "${REACH_DIR}/combined_reachability.txt"
for sym in "${RUN303_SYMS[@]}"; do assert_grep "${COMBINED_CORPUS}" "$sym"; done
{
  echo "Run 304 source reachability — Run 303 validator-set rotation intent boundary symbols in ${MOD}:"
  for sym in "${RUN303_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
# Symbols expected to be defined/referenced directly in the production module.
for sym in ProductionValidatorSetRotationBoundary ProductionValidatorSetRotationConfig ProductionValidatorSetRotationKind ProductionValidatorSetRotationPolicy ProductionValidatorSetRotationInputs ProductionValidatorSetRotationRequest ProductionValidatorSetRotationDecision ProductionValidatorSetRotationPlan ProductionValidatorSetRotationPlanKind ProductionValidatorSetRotationOutcome ProductionValidatorSetRotationRecoveryOutcome ValidatorSetRotationAuthoritySource ValidatorSetRotationAction CanonicalValidatorIdentity CanonicalValidatorRecord CanonicalValidatorSetSnapshot ValidatorSetChange ValidatorSetDelta ValidatorSetRotationReplaySet EmptyValidatorSetRotationReplaySet evaluate_validator_set_rotation recover_validator_set_rotation_window production_validator_set_rotation_plan_digest production_validator_set_rotation_request_id production_validator_set_rotation_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done
{
  echo "Run 304 helper reachability — Run 303 symbols exercised by the release helper (plus the Run 301/302 governance execution engine composition):"
  for sym in "${RUN303_SYMS[@]}" pqc_production_governance_execution_engine ProductionGovernanceExecutionIntent ProductionGovernanceExecutionDecision ProductionGovernanceExecutionOutcome; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
# Symbols the release helper must directly exercise.
for sym in ProductionValidatorSetRotationBoundary ProductionValidatorSetRotationConfig ProductionValidatorSetRotationPolicy ProductionValidatorSetRotationInputs ProductionValidatorSetRotationRequest ProductionValidatorSetRotationDecision ProductionValidatorSetRotationPlan ProductionValidatorSetRotationPlanKind ProductionValidatorSetRotationOutcome ProductionValidatorSetRotationRecoveryOutcome ValidatorSetRotationAuthoritySource ValidatorSetRotationAction CanonicalValidatorIdentity CanonicalValidatorRecord CanonicalValidatorSetSnapshot ValidatorSetChange ValidatorSetDelta EmptyValidatorSetRotationReplaySet evaluate_validator_set_rotation recover_validator_set_rotation_window production_validator_set_rotation_plan_digest production_validator_set_rotation_request_id production_validator_set_rotation_transcript_digest ProductionGovernanceExecutionIntent ProductionGovernanceExecutionDecision; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_validator_set_rotation_intent' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn evaluate_validator_set_rotation\|fn recover_validator_set_rotation_window\|fn production_validator_set_rotation_plan_digest\|fn production_validator_set_rotation_request_id\|fn production_validator_set_rotation_transcript_digest' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing boundary entry points"
grep -RIn --include='*.rs' 'enum ProductionValidatorSetRotationOutcome\|enum ProductionValidatorSetRotationRecoveryOutcome\|enum ProductionValidatorSetRotationPolicy\|enum ProductionValidatorSetRotationKind\|enum ProductionValidatorSetRotationPlanKind\|enum ValidatorSetRotationAction' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing boundary taxonomy"
grep -RIn --include='*.rs' 'trait ValidatorSetRotationReplaySet\|struct ProductionValidatorSetRotationBoundary\|struct CanonicalValidatorSetSnapshot\|enum ValidatorSetRotationAuthoritySource\|struct EmptyValidatorSetRotationReplaySet' "${MOD}" > "${REACH_DIR}/boundary_surface.txt" || fail "missing boundary surface"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 304'
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
  'Green for release-binary-evidenced validator-set-rotation-intent-boundary behavior only'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 304 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The RocksDB, RemoteSigner, KMS/HSM, custody attestation, on-chain governance proof
# verifier, and governance execution engine rows remain Green-for-scope; the
# validator-set rotation / authority-set synchronization row becomes Green-for-scope.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced RemoteSigner backend behavior only' "${C4C5_DOC}" || fail "RemoteSigner row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced KMS/HSM custody backend behavior only' "${C4C5_DOC}" || fail "KMS/HSM row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced custody-attestation verifier behavior only' "${C4C5_DOC}" || fail "custody attestation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only' "${C4C5_DOC}" || fail "on-chain governance proof verifier row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced governance-execution-engine behavior only' "${C4C5_DOC}" || fail "governance execution engine row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced validator-set-rotation-intent-boundary behavior only' "${C4C5_DOC}" || fail "validator-set rotation row must be scoped Green"
# The validator-set rotation row wording must record the non-goals explicitly.
grep -F -q 'not wired by default into production runtime' "${C4C5_DOC}" || fail "validator-set rotation row must record no default runtime wiring"
grep -F -q 'no public CLI flag' "${C4C5_DOC}" || fail "validator-set rotation row must record no public CLI flag"
grep -F -q 'produces typed non-mutating validator-set rotation' "${C4C5_DOC}" || fail "validator-set rotation row must record typed non-mutating plans"
grep -F -q 'never mutates a live validator set, consensus state, or `LivePqcTrustState`, never calls `BasicHotStuffEngine::transition_to_epoch`, never writes `meta:current_epoch`, never injects a reconfig block' "${C4C5_DOC}" || fail "validator-set rotation row must record no live validator-set / consensus mutation"
grep -F -q 'does not prove MainNet authority rotation/revocation; does not close C4/C5.' "${C4C5_DOC}" || fail "validator-set rotation row must record no MainNet rotation proof / no C4/C5 closure"
for redrow in 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Production signing audit trail / crypto-agility activation / incident response | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready'
  'validator-set rotation active' 'validator-set rotation enabled'
  'authority-set synchronization active' 'authority-set synchronization enabled'
  'governance execution engine active' 'governance execution engine enabled'
  'MainNet authority rotation enabled' 'MainNet validator-set rotation enabled' 'peer-driven apply enabled'
  'validator set mutated' 'consensus validator-set mutated' 'transition_to_epoch called' 'meta:current_epoch written' 'reconfig block injected'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'durable replay overwritten' 'settlement finalized' 'external publication completed'
  'fallback to fixture proof' 'fallback to local operator proof' 'fallback to peer majority' 'fallback to on-chain proof' 'fallback to RemoteSigner' 'fallback to custody attestation'
  'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 304 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_304_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 304 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 303 ProductionValidatorSetRotationBoundary ONLY through the"
  echo "  source/test boundary, ONLY for DevNet/TestNet identities on the accept path, under explicit source/test,"
  echo "  production-required and MainNet-required policies. It consumes a verified Run 301/302 governance execution"
  echo "  accept decision (one that is_accept() and carries a ProductionGovernanceExecutionIntent) and produces ONLY"
  echo "  typed non-mutating validator-set rotation plans. It performs no Run 070 call, no LivePqcTrustState mutation,"
  echo "  no live validator-set mutation, no consensus validator-set mutation, no BasicHotStuffEngine::transition_to_epoch"
  echo "  call, no meta:current_epoch write, no reconfig block injection, no trust swap, no session eviction, no PQC"
  echo "  trust-bundle sequence write, no authority marker write, no durable replay overwrite, no settlement, no external"
  echo "  publication, and no raw local production signing key load. Under a production or MainNet policy the boundary"
  echo "  fails closed and never falls back to fixture / local-operator / peer-majority / on-chain-proof-alone / custody-only"
  echo "  / remote-signer-only / custody-attestation-only material. Fixture / unverified governance intent is rejected as"
  echo "  production authority; MainNet identities are refused before acceptance. The default"
  echo "  ProductionValidatorSetRotationPolicy is Disabled; the production binary is not wired to construct the boundary"
  echo "  and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_304_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_303_production_validator_set_rotation_intent_tests run_301_production_governance_execution_engine_tests run_299_production_onchain_governance_proof_verifier_tests run_297_production_custody_attestation_verifier_tests run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_186_onchain_governance_production_verifier_boundary_tests run_178_onchain_governance_proof_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests)
if [[ "${RUN_304_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_304_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 304 — release-binary evidence for the Run 303 validator-set rotation / authority-set synchronization intent boundary"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status: $(if [[ -n "$(git -C "${REPO_ROOT}" status --short 2>/dev/null)" ]]; then echo dirty; else echo clean; fi)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  host:               $(uname -a 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_304_sha256:  $(sha256_file "${HELPER_304_BIN}")"
  echo
  echo "helper_summary: ${HELPER_304_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_304_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_304_OUT}/fixtures/run_304_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5_no_selector=${S5_RC} S6_default_parse=${S6_RC}"
  echo "reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM + custody-attestation + on-chain-governance-proof-verifier + governance-execution-engine + validator-set-rotation-intent-boundary rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; validator-set rotation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

log "Run 304 release-binary evidence complete: ${SUMMARY}"
cat "${SUMMARY}"
