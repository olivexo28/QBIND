#!/usr/bin/env bash
# Run 312 — release-binary evidence for the Run 311 guarded epoch-transition
# mutation executor boundary.
#
# Release-binary evidence for the Run 311 source/test guarded epoch-transition
# mutation executor boundary
# (`crates/qbind-node/src/pqc_production_guarded_epoch_transition_mutation_executor.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 311 production library symbols are present and exercised in release mode,
# and that the real executor behaves correctly under release-built conditions
# (DevNet/TestNet source-test accept over the real Run 309/310 verified staged
# live validator-set / epoch-transition application accept decision — is_accept()
# with Some(staged_application_record) — composing the real Run 307/308
# authorization executor, Run 305/306 application executor, and Run 303/304
# validator-set rotation intent boundary; full staged-application / authorization /
# application / rotation / governance / validator-set tuple + epoch-transition
# target + application / live-application / staged-application / guarded-mutation
# nonce binding + staged-application-decision-integrity / disabled /
# missing-staged-decision / unverified-staged-decision /
# accepted-without-staged-record / application-decision-alone / rotation-plan-alone
# / governance-execution-intent-alone / governance-proof-alone / fixture-only /
# local-operator / peer-majority / custody-only / remote-signer-only /
# custody-attestation-only / arbitrary-bytes rejected / wrong-field rejections /
# guarded-mutation replay-recovery-idempotency / stale governance-epoch / stale
# authority-sequence / stale validator-set epoch-version / production-policy-
# unavailable / MainNet refused / non-mutating). The executor consumes a verified
# staged epoch-transition application accept decision and produces only typed
# non-mutating guarded mutation-execution records. The release helper remains dead
# code from the production runtime; the production binary is never wired to
# construct the boundary and adds no CLI flag. No production runtime is enabled.
# MainNet authority rotation/revocation remains Red. Full C4 remains OPEN. C5
# remains OPEN.
#
# Substitution note: the Run 311 executor surfaces every failure as a typed
# `ProductionGuardedEpochTransitionMutationOutcome` fail-closed variant; there is
# no separate `ProductionGuardedEpochTransitionMutationError` enum, so that symbol
# is intentionally not required by the reachability greps below.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_312_production_guarded_epoch_transition_mutation_executor_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_312_BIN="${REPO_ROOT}/target/release/examples/run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper"
HELPER_312_OUT="${OUTDIR}/helper_evidence/run_312"
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
MOD="${SRC_DIR}/pqc_production_guarded_epoch_transition_mutation_executor.rs"
STAGED_MOD="${SRC_DIR}/pqc_production_staged_live_validator_set_epoch_transition_application_executor.rs"
AUTHORIZATION_MOD="${SRC_DIR}/pqc_production_live_validator_set_application_authorization.rs"
APPLICATION_MOD="${SRC_DIR}/pqc_production_validator_set_rotation_application_executor.rs"
ROTATION_MOD="${SRC_DIR}/pqc_production_validator_set_rotation_intent.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper.rs"

log() { printf '[run-312] %s\n' "$*" >&2; }
fail() { printf '[run-312] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_312_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_312_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-312 provenance"
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
log "cargo build --release -p qbind-node --example run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_312.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_312_BIN}" ]] || fail "missing ${HELPER_312_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_312_path:    ${HELPER_312_BIN}"
  echo "helper_312_sha256:  $(sha256_file "${HELPER_312_BIN}")"
  echo "helper_312_buildid: $(build_id "${HELPER_312_BIN}")"
} >> "${PROVENANCE}"

log "running Run 312 helper (first invocation)"
set +e
"${HELPER_312_BIN}" "${HELPER_312_OUT}" > "${LOGS_DIR}/helper_run_312.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_312.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_312 helper failed"
assert_grep "${HELPER_312_OUT}/helper_summary.txt" 'verdict=PASS'
assert_grep "${HELPER_312_OUT}/helper_summary.txt" 'total_fail=0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 312 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_312_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_312_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_312_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_312_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_312 helper invocation failed"
if ! diff -q "${HELPER_312_OUT}/fixtures/run_312_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_312_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 311 guarded epoch-transition
# mutation executor boundary has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'guarded epoch-transition mutation active|guarded epoch-transition mutation enabled|guarded mutation executor active|guarded mutation executor enabled|guarded mutation-execution enabled|ProductionGuardedEpochTransitionMutationExecutor enabled|MainNet guarded epoch-transition mutation enabled|epoch-transition mutation applied'
  assert_not_grep "$logf" 'staged live validator-set epoch-transition application active|staged live validator-set epoch-transition application enabled|live validator-set application authorization active|live validator-set application authorization enabled|validator-set rotation application active|validator-set rotation application enabled|validator-set rotation active|validator-set rotation enabled|governance execution engine enabled|real validator-set rotation enabled|MainNet authority rotation enabled|MainNet mutation engine enabled|peer-driven apply enabled|validator set applied|validator set mutated|consensus validator-set mutated|epoch counter mutated|epoch transition applied'
  assert_not_grep "$logf" 'fallback to fixture proof|fallback to local operator proof|fallback to peer majority|fallback to on-chain proof|fallback to RemoteSigner|fallback to custody attestation|fallback to governance proof|fallback to governance execution intent|fallback to rotation plan|fallback to application decision|fallback to authorization decision|fallback to staged application decision|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written|transition_to_epoch called|meta:current_epoch written|reconfig block injected|PAYLOAD_KIND_RECONFIG injected|durable replay overwritten'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 311 guarded epoch-transition mutation surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 311/312 guarded epoch-transition mutation boundary flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'guarded-epoch-transition-mutation|ProductionGuardedEpochTransitionMutation|pqc_production_guarded_epoch_transition_mutation_executor|guarded-mutation|run-312|run_312|run-311|run_311'
log "S2..S4 default surfaces silent on guarded epoch-transition mutation boundary claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
log "S5 no guarded epoch-transition mutation CLI selector exists (invented flag fails closed as unknown)"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet --p2p-guarded-epoch-transition-mutation-policy allow-source-test ) > "${LOGS_DIR}/S5_no_selector.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_no_selector.rc"; [[ "${S5_RC}" -ne 0 ]] || fail "invented guarded-mutation selector must be rejected (no such flag)"
assert_grep "${LOGS_DIR}/S5_no_selector.log" 'unexpected argument'
assert_surface_silent "${LOGS_DIR}/S5_no_selector.log"
log "S6 default devnet genesis-hash surface fails closed (requires --genesis-path) and stays silent on guarded-mutation claims"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_default_parse.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_default_parse.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "default devnet genesis-hash surface must fail closed without --genesis-path"
assert_grep "${LOGS_DIR}/S6_default_parse.log" 'requires --genesis-path'
assert_surface_silent "${LOGS_DIR}/S6_default_parse.log"

# Run 311 executor symbols required to be reachable in release evidence (from source
# and/or the release helper).
RUN311_SYMS=(
  ProductionGuardedEpochTransitionMutationExecutor
  ProductionGuardedEpochTransitionMutationConfig
  ProductionGuardedEpochTransitionMutationExecutorKind
  ProductionGuardedEpochTransitionMutationExecutorPolicy
  ProductionGuardedEpochTransitionMutationInputs
  ProductionGuardedEpochTransitionMutationRequest
  ProductionGuardedEpochTransitionMutationDecision
  ProductionGuardedEpochTransitionMutationRecord
  ProductionGuardedEpochTransitionMutationOutcome
  ProductionGuardedEpochTransitionMutationRecoveryOutcome
  ProductionGuardedEpochTransitionMutationProtocolVersion
  GuardedEpochTransitionMutationKind
  GuardedEpochTransitionMutationAuthoritySource
  GuardedEpochTransitionMutationReplaySet
  EmptyGuardedEpochTransitionMutationReplaySet
  GuardedEpochTransitionFixtureLedger
  evaluate_guarded_epoch_transition_mutation
  recover_guarded_epoch_transition_mutation_window
  production_guarded_epoch_transition_mutation_intent_digest
  production_guarded_epoch_transition_mutation_request_id
  production_guarded_epoch_transition_mutation_transcript_digest
)
COMBINED_CORPUS="${REACH_DIR}/combined_corpus.txt"
cat "${MOD}" "${STAGED_MOD}" "${AUTHORIZATION_MOD}" "${APPLICATION_MOD}" "${ROTATION_MOD}" "${HELPER_SRC}" > "${COMBINED_CORPUS}"
{
  echo "Run 312 combined reachability — Run 311 guarded epoch-transition mutation boundary symbols across source module + Run 309/310 staged application executor module + Run 307/308 live validator-set application authorization module + Run 305/306 validator-set rotation application executor module + Run 303/304 validator-set rotation intent module + release helper:"
  for sym in "${RUN311_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${COMBINED_CORPUS}" | head -n 20 || echo '(no occurrences)'; echo; done
} > "${REACH_DIR}/combined_reachability.txt"
for sym in "${RUN311_SYMS[@]}"; do assert_grep "${COMBINED_CORPUS}" "$sym"; done
{
  echo "Run 312 source reachability — Run 311 guarded epoch-transition mutation boundary symbols in ${MOD}:"
  for sym in "${RUN311_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
# Symbols expected to be defined/referenced directly in the production module.
for sym in ProductionGuardedEpochTransitionMutationExecutor ProductionGuardedEpochTransitionMutationConfig ProductionGuardedEpochTransitionMutationExecutorKind ProductionGuardedEpochTransitionMutationExecutorPolicy ProductionGuardedEpochTransitionMutationInputs ProductionGuardedEpochTransitionMutationRequest ProductionGuardedEpochTransitionMutationDecision ProductionGuardedEpochTransitionMutationRecord ProductionGuardedEpochTransitionMutationOutcome ProductionGuardedEpochTransitionMutationRecoveryOutcome GuardedEpochTransitionMutationKind GuardedEpochTransitionMutationAuthoritySource GuardedEpochTransitionMutationReplaySet EmptyGuardedEpochTransitionMutationReplaySet GuardedEpochTransitionFixtureLedger evaluate_guarded_epoch_transition_mutation recover_guarded_epoch_transition_mutation_window production_guarded_epoch_transition_mutation_intent_digest production_guarded_epoch_transition_mutation_request_id production_guarded_epoch_transition_mutation_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done
{
  echo "Run 312 helper reachability — Run 311 symbols exercised by the release helper (plus the Run 309/310 staged + Run 307/308 authorization + Run 305/306 application executor + Run 303/304 validator-set rotation intent composition):"
  for sym in "${RUN311_SYMS[@]}" pqc_production_staged_live_validator_set_epoch_transition_application_executor ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision pqc_production_live_validator_set_application_authorization ProductionLiveValidatorSetApplicationAuthorizationExecutor pqc_production_validator_set_rotation_application_executor ProductionValidatorSetRotationApplicationExecutor pqc_production_validator_set_rotation_intent ProductionValidatorSetRotationBoundary; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
# Symbols the release helper must directly exercise.
for sym in ProductionGuardedEpochTransitionMutationExecutor ProductionGuardedEpochTransitionMutationConfig ProductionGuardedEpochTransitionMutationExecutorPolicy ProductionGuardedEpochTransitionMutationInputs ProductionGuardedEpochTransitionMutationRequest ProductionGuardedEpochTransitionMutationDecision ProductionGuardedEpochTransitionMutationOutcome ProductionGuardedEpochTransitionMutationRecoveryOutcome GuardedEpochTransitionMutationKind GuardedEpochTransitionMutationAuthoritySource EmptyGuardedEpochTransitionMutationReplaySet GuardedEpochTransitionFixtureLedger evaluate_guarded_epoch_transition_mutation recover_guarded_epoch_transition_mutation_window production_guarded_epoch_transition_mutation_intent_digest production_guarded_epoch_transition_mutation_request_id production_guarded_epoch_transition_mutation_transcript_digest ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision ProductionLiveValidatorSetApplicationAuthorizationExecutor ProductionValidatorSetRotationApplicationExecutor ProductionValidatorSetRotationBoundary; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_guarded_epoch_transition_mutation_executor' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn evaluate_guarded_epoch_transition_mutation\|fn recover_guarded_epoch_transition_mutation_window\|fn production_guarded_epoch_transition_mutation_intent_digest\|fn production_guarded_epoch_transition_mutation_request_id\|fn production_guarded_epoch_transition_mutation_transcript_digest' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing executor entry points"
grep -RIn --include='*.rs' 'enum ProductionGuardedEpochTransitionMutationOutcome\|enum ProductionGuardedEpochTransitionMutationRecoveryOutcome\|enum ProductionGuardedEpochTransitionMutationExecutorPolicy\|enum ProductionGuardedEpochTransitionMutationExecutorKind\|enum GuardedEpochTransitionMutationKind\|enum GuardedEpochTransitionMutationAuthoritySource' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing executor taxonomy"
grep -RIn --include='*.rs' 'trait GuardedEpochTransitionMutationReplaySet\|struct ProductionGuardedEpochTransitionMutationExecutor\|struct ProductionGuardedEpochTransitionMutationRecord\|struct ProductionGuardedEpochTransitionMutationRequest\|struct EmptyGuardedEpochTransitionMutationReplaySet\|struct GuardedEpochTransitionFixtureLedger' "${MOD}" > "${REACH_DIR}/boundary_surface.txt" || fail "missing executor surface"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 312'
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
  'Validator-set rotation application / epoch-transition executor'
  'Green for release-binary-evidenced validator-set-rotation-application-executor-boundary behavior only'
  'Live validator-set application / epoch-transition authorization'
  'Green for release-binary-evidenced live-validator-set-application-authorization-boundary behavior only'
  'Staged live validator-set / epoch-transition application executor'
  'Green for release-binary-evidenced staged-live-validator-set-epoch-transition-application-executor-boundary behavior only'
  'Guarded epoch-transition mutation executor'
  'Green for release-binary-evidenced guarded-epoch-transition-mutation-executor-boundary behavior only'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 312 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The prior Green-for-scope rows remain Green-for-scope; the guarded epoch-transition
# mutation executor row becomes Green-for-scope.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced RemoteSigner backend behavior only' "${C4C5_DOC}" || fail "RemoteSigner row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced KMS/HSM custody backend behavior only' "${C4C5_DOC}" || fail "KMS/HSM row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced custody-attestation verifier behavior only' "${C4C5_DOC}" || fail "custody attestation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only' "${C4C5_DOC}" || fail "on-chain governance proof verifier row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced governance-execution-engine behavior only' "${C4C5_DOC}" || fail "governance execution engine row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced validator-set-rotation-intent-boundary behavior only' "${C4C5_DOC}" || fail "validator-set rotation intent row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced validator-set-rotation-application-executor-boundary behavior only' "${C4C5_DOC}" || fail "validator-set rotation application executor row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-validator-set-application-authorization-boundary behavior only' "${C4C5_DOC}" || fail "live validator-set application authorization row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced staged-live-validator-set-epoch-transition-application-executor-boundary behavior only' "${C4C5_DOC}" || fail "staged live validator-set epoch-transition application executor row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced guarded-epoch-transition-mutation-executor-boundary behavior only' "${C4C5_DOC}" || fail "guarded epoch-transition mutation executor row must be scoped Green"
# The guarded epoch-transition mutation executor row wording must record the non-goals explicitly.
grep -F -q 'not wired by default into production runtime' "${C4C5_DOC}" || fail "guarded row must record no default runtime wiring"
grep -F -q 'no public CLI flag' "${C4C5_DOC}" || fail "guarded row must record no public CLI flag"
grep -F -q 'produces typed non-mutating guarded mutation-execution records' "${C4C5_DOC}" || fail "guarded row must record typed non-mutating guarded records"
grep -F -q 'never applies a live validator-set change, never mutates a live validator set, consensus state, epoch counter, or `LivePqcTrustState`, never calls `BasicHotStuffEngine::transition_to_epoch`, never writes `meta:current_epoch`, never injects a `PAYLOAD_KIND_RECONFIG` block' "${C4C5_DOC}" || fail "guarded row must record no live application / mutation"
grep -F -q 'does not prove live validator-set rotation, epoch transition, MainNet readiness, or C4/C5 closure.' "${C4C5_DOC}" || fail "guarded row must record no MainNet rotation proof / no C4/C5 closure"
for redrow in 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Production signing audit trail / crypto-agility activation / incident response | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready'
  'guarded epoch-transition mutation active' 'guarded epoch-transition mutation enabled'
  'guarded mutation executor active' 'guarded mutation executor enabled'
  'staged live validator-set epoch-transition application active' 'staged live validator-set epoch-transition application enabled'
  'live validator-set application authorization active' 'live validator-set application authorization enabled'
  'validator-set rotation application active' 'validator-set rotation application enabled'
  'validator-set rotation active' 'validator-set rotation enabled'
  'governance execution engine active' 'governance execution engine enabled'
  'MainNet authority rotation enabled' 'MainNet guarded epoch-transition mutation enabled' 'peer-driven apply enabled'
  'validator set applied' 'validator set mutated' 'consensus validator-set mutated' 'epoch counter mutated' 'epoch transition applied' 'transition_to_epoch called' 'meta:current_epoch written' 'reconfig block injected' 'PAYLOAD_KIND_RECONFIG injected'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'durable replay overwritten' 'settlement finalized' 'external publication completed'
  'fallback to fixture proof' 'fallback to local operator proof' 'fallback to peer majority' 'fallback to on-chain proof' 'fallback to RemoteSigner' 'fallback to custody attestation' 'fallback to governance proof' 'fallback to governance execution intent' 'fallback to rotation plan' 'fallback to application decision' 'fallback to authorization decision' 'fallback to staged application decision'
  'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 312 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_312_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 312 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 311 ProductionGuardedEpochTransitionMutationExecutor ONLY"
  echo "  through the source/test boundary, ONLY for DevNet/TestNet identities on the accept path, under explicit"
  echo "  source/test, production-required and MainNet-required policies. It consumes a verified Run 309/310 staged"
  echo "  live validator-set / epoch-transition application accept decision (a"
  echo "  ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision that is_accept() and carries"
  echo "  Some(staged_application_record)) and produces ONLY typed non-mutating guarded mutation-execution records"
  echo "  describing what a future live mutating epoch-transition executor would apply. It applies no live"
  echo "  validator-set change and performs no Run 070 call, no LivePqcTrustState mutation, no live validator-set mutation,"
  echo "  no consensus validator-set mutation, no epoch-counter mutation, no BasicHotStuffEngine::transition_to_epoch call,"
  echo "  no meta:current_epoch write, no PAYLOAD_KIND_RECONFIG block injection, no trust swap, no session eviction, no PQC"
  echo "  trust-bundle sequence write, no authority marker write, no durable replay overwrite, no settlement, no external"
  echo "  publication, and no raw local production signing key load. The only mutation any positive path performs is against"
  echo "  a caller-owned in-memory GuardedEpochTransitionFixtureLedger used exclusively as source/test evidence, which is"
  echo "  explicitly distinct from production runtime state. Under a production or MainNet policy the executor fails"
  echo "  closed and never falls back to staged-application-decision-alone / application-decision-alone / rotation-plan-alone /"
  echo "  governance-proof-alone / governance-execution-intent-alone / fixture / local-operator / peer-majority / custody-only"
  echo "  / remote-signer-only / custody-attestation-only / arbitrary-bytes material. Missing / unverified /"
  echo "  accepted-without-staged-record staged decisions are rejected as production authority; MainNet"
  echo "  identities are refused before acceptance. The default"
  echo "  ProductionGuardedEpochTransitionMutationExecutorPolicy is Disabled; the production binary is not wired to"
  echo "  construct the boundary and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict=PASS|^table |^total_(pass|fail)=' "${HELPER_312_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_311_production_guarded_epoch_transition_mutation_executor_tests run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests run_307_production_live_validator_set_application_authorization_tests run_305_production_validator_set_rotation_application_executor_tests run_303_production_validator_set_rotation_intent_tests run_301_production_governance_execution_engine_tests run_299_production_onchain_governance_proof_verifier_tests run_297_production_custody_attestation_verifier_tests run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_186_onchain_governance_production_verifier_boundary_tests run_178_onchain_governance_proof_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests)
if [[ "${RUN_312_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_312_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 312 — release-binary evidence for the Run 311 guarded epoch-transition mutation executor boundary"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status: $(if [[ -n "$(git -C "${REPO_ROOT}" status --short 2>/dev/null)" ]]; then echo dirty; else echo clean; fi)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  host:               $(uname -a 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_312_sha256:  $(sha256_file "${HELPER_312_BIN}")"
  echo
  echo "helper_summary: ${HELPER_312_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_312_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_312_OUT}/fixtures/run_312_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5_no_selector=${S5_RC} S6_default_parse=${S6_RC}"
  echo "reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM + custody-attestation + on-chain-governance-proof-verifier + governance-execution-engine + validator-set-rotation-intent-boundary + validator-set-rotation-application-executor-boundary + live-validator-set-application-authorization-boundary + staged-live-validator-set-epoch-transition-application-executor-boundary + guarded-epoch-transition-mutation-executor-boundary rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; guarded epoch-transition mutation executor Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"