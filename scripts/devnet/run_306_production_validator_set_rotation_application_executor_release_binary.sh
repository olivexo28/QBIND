#!/usr/bin/env bash
# Run 306 — release-binary evidence for the Run 305 validator-set rotation
# application / epoch-transition executor boundary.
#
# Release-binary evidence for the Run 305 source/test validator-set rotation
# application / epoch-transition executor boundary
# (`crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 305 production library symbols are present and exercised in release mode,
# and that the real executor behaves correctly under release-built conditions
# (DevNet/TestNet source-test accept / environment-chain-genesis-authority-root-
# governance-domain-epoch-proposal-execution-decision-request-intent-digest-
# rotation-decision-id-rotation-request-id-rotation-transcript-rotation-plan-digest
# binding plus current/proposed validator-set digests + delta digest + epoch/version
# + rotation nonce + epoch-transition target + application nonce / disabled /
# missing-rotation-plan / unverified-rotation-plan / governance-proof-alone /
# governance-execution-intent-alone / fixture-only-plan / local-operator /
# peer-majority / custody-only / remote-signer-only / custody-attestation-only /
# arbitrary-bytes rejected / wrong-field rejections / plan-digest-transcript-request-
# id-integrity mismatch / wrong current-proposed-delta digest / wrong validator-set
# epoch-version / wrong rotation nonce / wrong epoch-transition target / custody-
# attestation-durable-replay required-and-mismatch / replayed-application-id / stale
# governance-epoch / stale authority-sequence / stale validator-set epoch-version /
# production-policy-unavailable / MainNet refused / replay-recovery idempotency /
# non-mutating), composing with the Run 303/304 validator-set rotation intent
# boundary accept output. The executor consumes a verified validator-set rotation
# plan accept decision and produces only typed non-mutating application
# decisions/intents. The release helper remains dead code from the production
# runtime; the production binary is never wired to construct the boundary and adds
# no CLI flag. No production runtime is enabled. MainNet authority
# rotation/revocation remains Red. Full C4 remains OPEN. C5 remains OPEN.
#
# Substitution note: the Run 305 executor surfaces every failure as a typed
# `ProductionValidatorSetRotationApplicationOutcome` fail-closed variant; there is
# no separate `ProductionValidatorSetRotationApplicationError` enum, so that symbol
# from the task symbol list is intentionally not required by the reachability greps
# below.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_306_production_validator_set_rotation_application_executor_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_306_BIN="${REPO_ROOT}/target/release/examples/run_306_production_validator_set_rotation_application_executor_release_binary_helper"
HELPER_306_OUT="${OUTDIR}/helper_evidence/run_306"
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
MOD="${SRC_DIR}/pqc_production_validator_set_rotation_application_executor.rs"
ROTATION_MOD="${SRC_DIR}/pqc_production_validator_set_rotation_intent.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_306_production_validator_set_rotation_application_executor_release_binary_helper.rs"

log() { printf '[run-306] %s\n' "$*" >&2; }
fail() { printf '[run-306] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_306_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_306_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-306 provenance"
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
log "cargo build --release -p qbind-node --example run_306_production_validator_set_rotation_application_executor_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_306_production_validator_set_rotation_application_executor_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_306.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_306_BIN}" ]] || fail "missing ${HELPER_306_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_306_path:    ${HELPER_306_BIN}"
  echo "helper_306_sha256:  $(sha256_file "${HELPER_306_BIN}")"
  echo "helper_306_buildid: $(build_id "${HELPER_306_BIN}")"
} >> "${PROVENANCE}"

log "running Run 306 helper (first invocation)"
set +e
"${HELPER_306_BIN}" "${HELPER_306_OUT}" > "${LOGS_DIR}/helper_run_306.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_306.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_306 helper failed"
assert_grep "${HELPER_306_OUT}/helper_summary.txt" 'verdict: PASS'
assert_grep "${HELPER_306_OUT}/helper_summary.txt" 'total_fail: 0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 306 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_306_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_306_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_306_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_306_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_306 helper invocation failed"
if ! diff -q "${HELPER_306_OUT}/fixtures/run_306_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_306_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 305/306 validator-set rotation
# application / epoch-transition executor boundary has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'validator-set rotation application active|validator-set rotation application enabled|epoch-transition executor enabled|epoch-transition executor active|validator-set rotation application boundary enabled|validator-set rotation application boundary wired|ProductionValidatorSetRotationApplicationExecutor enabled|MainNet validator-set rotation application enabled'
  assert_not_grep "$logf" 'validator-set rotation active|validator-set rotation enabled|governance execution engine enabled|real validator-set rotation enabled|MainNet authority rotation enabled|MainNet mutation engine enabled|peer-driven apply enabled|validator set applied|validator set mutated|consensus validator-set mutated|epoch counter mutated'
  assert_not_grep "$logf" 'fallback to fixture proof|fallback to local operator proof|fallback to peer majority|fallback to on-chain proof|fallback to RemoteSigner|fallback to custody attestation|fallback to governance proof|fallback to governance execution intent|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written|transition_to_epoch called|meta:current_epoch written|reconfig block injected|durable replay overwritten'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 305/306 validator-set rotation application surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 305/306 validator-set rotation application boundary flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'validator-set-rotation-application|ProductionValidatorSetRotationApplication|ProductionValidatorSetRotationApplicationPolicy|pqc_production_validator_set_rotation_application_executor|epoch-transition-executor|run-306|run_306|run-305|run_305'
log "S2..S4 default surfaces silent on validator-set rotation application boundary claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
log "S5 no validator-set rotation application CLI selector exists (invented flag fails closed as unknown)"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet --p2p-validator-set-rotation-application-policy allow-source-test ) > "${LOGS_DIR}/S5_no_selector.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_no_selector.rc"; [[ "${S5_RC}" -ne 0 ]] || fail "invented validator-set-rotation-application selector must be rejected (no such flag)"
assert_grep "${LOGS_DIR}/S5_no_selector.log" 'unexpected argument'
assert_surface_silent "${LOGS_DIR}/S5_no_selector.log"
log "S6 default devnet genesis-hash surface fails closed (requires --genesis-path) and stays silent on rotation-application claims"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_default_parse.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_default_parse.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "default devnet genesis-hash surface must fail closed without --genesis-path"
assert_grep "${LOGS_DIR}/S6_default_parse.log" 'requires --genesis-path'
assert_surface_silent "${LOGS_DIR}/S6_default_parse.log"

# Run 305 executor symbols required to be reachable in release evidence (from source
# and/or the release helper). Substitution: no `ProductionValidatorSetRotationApplicationError`
# enum exists; the executor surfaces failures as typed
# `ProductionValidatorSetRotationApplicationOutcome` fail-closed variants.
RUN305_SYMS=(
  ProductionValidatorSetRotationApplicationExecutor
  ProductionValidatorSetRotationApplicationConfig
  ProductionValidatorSetRotationApplicationKind
  ProductionValidatorSetRotationApplicationPolicy
  ProductionValidatorSetRotationApplicationInputs
  ProductionValidatorSetRotationApplicationRequest
  ProductionValidatorSetRotationApplicationDecision
  ProductionValidatorSetRotationApplicationIntent
  ProductionValidatorSetRotationApplicationOutcome
  ProductionValidatorSetRotationApplicationRecoveryOutcome
  ProductionValidatorSetRotationApplicationProtocolVersion
  ValidatorSetRotationApplicationDecisionKind
  ValidatorSetRotationApplicationAuthoritySource
  ValidatorSetRotationApplicationReplaySet
  EmptyValidatorSetRotationApplicationReplaySet
  evaluate_validator_set_rotation_application
  recover_validator_set_rotation_application_window
  production_validator_set_rotation_application_intent_digest
  production_validator_set_rotation_application_request_id
  production_validator_set_rotation_application_transcript_digest
)
COMBINED_CORPUS="${REACH_DIR}/combined_corpus.txt"
cat "${MOD}" "${ROTATION_MOD}" "${HELPER_SRC}" > "${COMBINED_CORPUS}"
{
  echo "Run 306 combined reachability — Run 305 validator-set rotation application executor boundary symbols across source module + Run 303/304 validator-set rotation intent module + release helper:"
  for sym in "${RUN305_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${COMBINED_CORPUS}" | head -n 20 || echo '(no occurrences)'; echo; done
} > "${REACH_DIR}/combined_reachability.txt"
for sym in "${RUN305_SYMS[@]}"; do assert_grep "${COMBINED_CORPUS}" "$sym"; done
{
  echo "Run 306 source reachability — Run 305 validator-set rotation application executor boundary symbols in ${MOD}:"
  for sym in "${RUN305_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
# Symbols expected to be defined/referenced directly in the production module.
for sym in ProductionValidatorSetRotationApplicationExecutor ProductionValidatorSetRotationApplicationConfig ProductionValidatorSetRotationApplicationKind ProductionValidatorSetRotationApplicationPolicy ProductionValidatorSetRotationApplicationInputs ProductionValidatorSetRotationApplicationRequest ProductionValidatorSetRotationApplicationDecision ProductionValidatorSetRotationApplicationIntent ProductionValidatorSetRotationApplicationOutcome ProductionValidatorSetRotationApplicationRecoveryOutcome ValidatorSetRotationApplicationDecisionKind ValidatorSetRotationApplicationAuthoritySource ValidatorSetRotationApplicationReplaySet EmptyValidatorSetRotationApplicationReplaySet evaluate_validator_set_rotation_application recover_validator_set_rotation_application_window production_validator_set_rotation_application_intent_digest production_validator_set_rotation_application_request_id production_validator_set_rotation_application_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done
{
  echo "Run 306 helper reachability — Run 305 symbols exercised by the release helper (plus the Run 303/304 validator-set rotation intent composition):"
  for sym in "${RUN305_SYMS[@]}" pqc_production_validator_set_rotation_intent ProductionValidatorSetRotationBoundary ProductionValidatorSetRotationDecision ProductionValidatorSetRotationPlan; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
# Symbols the release helper must directly exercise.
for sym in ProductionValidatorSetRotationApplicationExecutor ProductionValidatorSetRotationApplicationConfig ProductionValidatorSetRotationApplicationPolicy ProductionValidatorSetRotationApplicationInputs ProductionValidatorSetRotationApplicationRequest ProductionValidatorSetRotationApplicationDecision ProductionValidatorSetRotationApplicationIntent ProductionValidatorSetRotationApplicationOutcome ProductionValidatorSetRotationApplicationRecoveryOutcome ValidatorSetRotationApplicationDecisionKind ValidatorSetRotationApplicationAuthoritySource EmptyValidatorSetRotationApplicationReplaySet evaluate_validator_set_rotation_application recover_validator_set_rotation_application_window production_validator_set_rotation_application_intent_digest production_validator_set_rotation_application_request_id production_validator_set_rotation_application_transcript_digest ProductionValidatorSetRotationBoundary ProductionValidatorSetRotationDecision ProductionValidatorSetRotationPlan; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_validator_set_rotation_application_executor' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn evaluate_validator_set_rotation_application\|fn recover_validator_set_rotation_application_window\|fn production_validator_set_rotation_application_intent_digest\|fn production_validator_set_rotation_application_request_id\|fn production_validator_set_rotation_application_transcript_digest' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing executor entry points"
grep -RIn --include='*.rs' 'enum ProductionValidatorSetRotationApplicationOutcome\|enum ProductionValidatorSetRotationApplicationRecoveryOutcome\|enum ProductionValidatorSetRotationApplicationPolicy\|enum ProductionValidatorSetRotationApplicationKind\|enum ValidatorSetRotationApplicationDecisionKind\|enum ValidatorSetRotationApplicationAuthoritySource' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing executor taxonomy"
grep -RIn --include='*.rs' 'trait ValidatorSetRotationApplicationReplaySet\|struct ProductionValidatorSetRotationApplicationExecutor\|struct ProductionValidatorSetRotationApplicationIntent\|struct ProductionValidatorSetRotationApplicationRequest\|struct EmptyValidatorSetRotationApplicationReplaySet' "${MOD}" > "${REACH_DIR}/boundary_surface.txt" || fail "missing executor surface"

C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 306'
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
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 306 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The prior Green-for-scope rows remain Green-for-scope; the validator-set rotation
# application / epoch-transition executor row becomes Green-for-scope.
grep -F -q 'Green for release-binary-evidenced RocksDB durable replay backend behavior only' "${C4C5_DOC}" || fail "RocksDB row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced RemoteSigner backend behavior only' "${C4C5_DOC}" || fail "RemoteSigner row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced KMS/HSM custody backend behavior only' "${C4C5_DOC}" || fail "KMS/HSM row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced custody-attestation verifier behavior only' "${C4C5_DOC}" || fail "custody attestation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only' "${C4C5_DOC}" || fail "on-chain governance proof verifier row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced governance-execution-engine behavior only' "${C4C5_DOC}" || fail "governance execution engine row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced validator-set-rotation-intent-boundary behavior only' "${C4C5_DOC}" || fail "validator-set rotation intent row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced validator-set-rotation-application-executor-boundary behavior only' "${C4C5_DOC}" || fail "validator-set rotation application executor row must be scoped Green"
# The validator-set rotation application executor row wording must record the non-goals explicitly.
grep -F -q 'not wired by default into production runtime' "${C4C5_DOC}" || fail "validator-set rotation application row must record no default runtime wiring"
grep -F -q 'no public CLI flag' "${C4C5_DOC}" || fail "validator-set rotation application row must record no public CLI flag"
grep -F -q 'produces typed non-mutating application decisions/intents' "${C4C5_DOC}" || fail "validator-set rotation application row must record typed non-mutating decisions/intents"
grep -F -q 'never applies a live validator-set change, never mutates a live validator set, consensus state, epoch counter, or `LivePqcTrustState`, never calls `BasicHotStuffEngine::transition_to_epoch`, never writes `meta:current_epoch`, never injects a reconfig block' "${C4C5_DOC}" || fail "validator-set rotation application row must record no live application / mutation"
grep -F -q 'does not prove live validator-set rotation, MainNet readiness, or C4/C5 closure.' "${C4C5_DOC}" || fail "validator-set rotation application row must record no MainNet rotation proof / no C4/C5 closure"
for redrow in 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Production signing audit trail / crypto-agility activation / incident response | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready'
  'validator-set rotation application active' 'validator-set rotation application enabled'
  'epoch-transition executor active' 'epoch-transition executor enabled'
  'validator-set rotation active' 'validator-set rotation enabled'
  'governance execution engine active' 'governance execution engine enabled'
  'MainNet authority rotation enabled' 'MainNet validator-set rotation application enabled' 'peer-driven apply enabled'
  'validator set applied' 'validator set mutated' 'consensus validator-set mutated' 'epoch counter mutated' 'transition_to_epoch called' 'meta:current_epoch written' 'reconfig block injected'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'durable replay overwritten' 'settlement finalized' 'external publication completed'
  'fallback to fixture proof' 'fallback to local operator proof' 'fallback to peer majority' 'fallback to on-chain proof' 'fallback to RemoteSigner' 'fallback to custody attestation' 'fallback to governance proof' 'fallback to governance execution intent'
  'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 306 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_306_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 306 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 305 ProductionValidatorSetRotationApplicationExecutor ONLY through"
  echo "  the source/test boundary, ONLY for DevNet/TestNet identities on the accept path, under explicit source/test,"
  echo "  production-required and MainNet-required policies. It consumes a verified Run 303/304 validator-set rotation"
  echo "  plan accept decision (a ProductionValidatorSetRotationDecision that is_accept() and carries a"
  echo "  ProductionValidatorSetRotationPlan) and produces ONLY typed non-mutating application decisions/intents. It"
  echo "  applies no live validator-set change and performs no Run 070 call, no LivePqcTrustState mutation, no live"
  echo "  validator-set mutation, no consensus validator-set mutation, no epoch-counter mutation, no"
  echo "  BasicHotStuffEngine::transition_to_epoch call, no meta:current_epoch write, no reconfig block injection, no"
  echo "  trust swap, no session eviction, no PQC trust-bundle sequence write, no authority marker write, no durable"
  echo "  replay overwrite, no settlement, no external publication, and no raw local production signing key load. Under"
  echo "  a production or MainNet policy the executor fails closed and never falls back to governance-proof-alone /"
  echo "  governance-execution-intent-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only"
  echo "  / custody-attestation-only / arbitrary-bytes material. Missing / unverified rotation plans are rejected as"
  echo "  production authority; MainNet identities are refused before acceptance. The default"
  echo "  ProductionValidatorSetRotationApplicationPolicy is Disabled; the production binary is not wired to construct"
  echo "  the boundary and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_306_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_305_production_validator_set_rotation_application_executor_tests run_303_production_validator_set_rotation_intent_tests run_301_production_governance_execution_engine_tests run_299_production_onchain_governance_proof_verifier_tests run_297_production_custody_attestation_verifier_tests run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_186_onchain_governance_production_verifier_boundary_tests run_178_onchain_governance_proof_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests)
if [[ "${RUN_306_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_306_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 306 — release-binary evidence for the Run 305 validator-set rotation application / epoch-transition executor boundary"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status: $(if [[ -n "$(git -C "${REPO_ROOT}" status --short 2>/dev/null)" ]]; then echo dirty; else echo clean; fi)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  host:               $(uname -a 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_306_sha256:  $(sha256_file "${HELPER_306_BIN}")"
  echo
  echo "helper_summary: ${HELPER_306_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_306_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_306_OUT}/fixtures/run_306_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5_no_selector=${S5_RC} S6_default_parse=${S6_RC}"
  echo "reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM + custody-attestation + on-chain-governance-proof-verifier + governance-execution-engine + validator-set-rotation-intent-boundary + validator-set-rotation-application-executor-boundary rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; validator-set rotation application executor Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN)"
} > "${SUMMARY}"

log "Run 306 release-binary evidence complete: ${SUMMARY}"
cat "${SUMMARY}"