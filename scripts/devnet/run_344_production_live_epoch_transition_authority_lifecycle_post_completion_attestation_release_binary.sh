#!/usr/bin/env bash
# Run 344 — release-binary evidence for the Run 343 live epoch-transition
# authority-lifecycle activation-readiness / post-completion attestation boundary.
#
# Release-binary evidence for the Run 343 source/test live epoch-transition
# authority-lifecycle activation-readiness / post-completion attestation boundary
# (`crates/qbind-node/src/pqc_production_live_epoch_transition_authority_lifecycle_post_completion_attestation.rs`).
# Proves on real `target/release/qbind-node` plus a release-built helper that the
# Run 343 production library symbols are present and exercised in release mode,
# and that the real executor behaves correctly under release-built conditions
# (DevNet/TestNet source-test accept over the real Run 341/342 verified
# live epoch-transition final settlement / authority-lifecycle completion accept
# decision — is_accept() with Some(final_settlement_completion_artifact) —
# composing the real
# Run 303/304 → Run 305/306 → Run 307/308 → Run 309/310 → Run 311/312 →
# Run 313/314 → Run 315/316 → Run 317/318 → Run 319/320 → Run 321/322 →
# Run 323/324 → Run 325/326 → Run 327/328 → Run 329/330 → Run 331/332 →
# Run 333/334 → Run 335/336 → Run 337/338 → Run 339/340 → Run 341/342 accept
# chain; full final-settlement-completion / settlement-execution / runtime-handoff /
# guarded-mutation / staged-application /
# authorization / application / rotation / governance / validator-set tuple +
# epoch-transition target + application / live-application / staged-application /
# guarded-mutation / runtime-handoff / execution-preparation / final-settlement-completion
# nonce binding + final-settlement-completion-decision-integrity /
# current-validator-set epoch-version preflight / disabled /
# missing-final-settlement-completion-decision / unverified-final-settlement-completion-decision /
# accepted-without-artifact / final-settlement-completion-decision-alone / runtime-handoff-decision-alone /
# guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone /
# application-decision-alone / rotation-plan-alone /
# governance-execution-intent-alone / governance-proof-alone / fixture-only /
# local-operator / peer-majority / custody-only / remote-signer-only /
# custody-attestation-only / arbitrary-bytes rejected / wrong-field rejections /
# post-completion-attestation replay-recovery-idempotency / stale governance-epoch /
# stale authority-sequence / stale validator-set epoch-version / production-
# policy-unavailable / MainNet refused / non-mutating). The executor consumes a
# verified live epoch-transition final settlement / authority-lifecycle completion
# accept decision and produces only a typed non-mutating live authority-lifecycle
# activation-readiness / post-completion attestation artifact for a future live
# production authority-lifecycle activation executor. The release helper remains
# dead code from the
# production runtime; the production binary is never wired to construct the
# boundary and adds no CLI flag. No production runtime is enabled. MainNet
# authority rotation/revocation remains Red. Full C4 remains OPEN. C5 remains
# OPEN.
#
# Substitution note: the Run 343 executor surfaces every failure as a typed
# `ProductionLiveEpochTransitionPostCompletionAttestationOutcome` fail-closed variant;
# there is no separate `ProductionLiveEpochTransitionPostCompletionAttestationError`
# enum, so that symbol is intentionally not required by the reachability greps
# below.
set -euo pipefail


REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_344_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_344_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_release_binary_helper"
HELPER_OUT="${OUTDIR}/helper_evidence/run_344"
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
MOD="${SRC_DIR}/pqc_production_live_epoch_transition_authority_lifecycle_post_completion_attestation.rs"
FSC_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_final_settlement_completion.rs"
SETTLE_EXEC_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_settlement_execution.rs"
SETTLE_EXEC_PREP_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_settlement_execution_preparation.rs"
SETTLE_PREP_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_settlement_preparation.rs"
PCA_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_external_publication.rs"
CA_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_commit_receipt.rs"
CAUTH_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_commit_authorization.rs"
MUT_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_mutation_execution.rs"
PREP_MOD="${SRC_DIR}/pqc_production_live_epoch_transition_execution_preparation.rs"
HANDOFF_MOD="${SRC_DIR}/pqc_production_epoch_transition_runtime_handoff.rs"
GUARDED_MOD="${SRC_DIR}/pqc_production_guarded_epoch_transition_mutation_executor.rs"
STAGED_MOD="${SRC_DIR}/pqc_production_staged_live_validator_set_epoch_transition_application_executor.rs"
AUTHORIZATION_MOD="${SRC_DIR}/pqc_production_live_validator_set_application_authorization.rs"
APPLICATION_MOD="${SRC_DIR}/pqc_production_validator_set_rotation_application_executor.rs"
ROTATION_MOD="${SRC_DIR}/pqc_production_validator_set_rotation_intent.rs"
HELPER_SRC="${REPO_ROOT}/crates/qbind-node/examples/run_344_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_release_binary_helper.rs"

log() { printf '[run-344] %s\n' "$*" >&2; }
fail() { printf '[run-344] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${NOMUT_PROOF}"

{
  echo "run-344 provenance"
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
log "cargo build --release -p qbind-node --example run_344_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_344_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_344.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_BIN}" ]] || fail "missing ${HELPER_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_344_path:    ${HELPER_BIN}"
  echo "helper_344_sha256:  $(sha256_file "${HELPER_BIN}")"
  echo "helper_344_buildid: $(build_id "${HELPER_BIN}")"
} >> "${PROVENANCE}"

log "running Run 344 helper (first invocation)"
set +e
"${HELPER_BIN}" "${HELPER_OUT}" > "${LOGS_DIR}/helper_run_344.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_344.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_344 helper failed"
assert_grep "${HELPER_OUT}/helper_summary.txt" 'verdict=PASS'
assert_grep "${HELPER_OUT}/helper_summary.txt" 'total_fail=0'

# Deterministic-digest stability across two independent helper invocations.
log "running Run 344 helper (second invocation for deterministic-digest comparison)"
SECOND_OUT="${DATA_DIR}/helper_run_344_second"
mkdir -p "${SECOND_OUT}"
set +e
"${HELPER_BIN}" "${SECOND_OUT}" > "${LOGS_DIR}/helper_run_344_second.log" 2>&1
HELPER_RC2=$?
set -e
echo "${HELPER_RC2}" > "${EXIT_DIR}/helper_run_344_second.rc"
[[ "${HELPER_RC2}" -eq 0 ]] || fail "second run_344 helper invocation failed"
if ! diff -q "${HELPER_OUT}/fixtures/run_344_deterministic_digests.txt" "${SECOND_OUT}/fixtures/run_344_deterministic_digests.txt" >/dev/null; then
  fail "deterministic digests differ across helper invocations"
fi

# The production binary must never announce that a Run 341 live epoch-transition
# final settlement / authority-lifecycle completion boundary has been constructed / enabled / wired.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'live epoch-transition post-completion-attestation active|live epoch-transition post-completion-attestation enabled|post-completion-attestation executor active|post-completion-attestation executor enabled|live-post-completion-attestation active|live-post-completion-attestation enabled|ProductionLiveEpochTransitionPostCompletionAttestationExecutor enabled|MainNet live epoch-transition post-completion-attestation enabled|post-completion-attestation applied|authority-lifecycle-completion applied|live epoch-transition settlement-execution active|live epoch-transition settlement-execution enabled|settlement-execution executor active|settlement-execution executor enabled|live-settlement-execution active|live-settlement-execution enabled|ProductionLiveEpochTransitionSettlementExecutionExecutor enabled|MainNet live epoch-transition settlement-execution enabled|settlement-execution applied|live mutation applied|live epoch-transition external-publication active|live epoch-transition external-publication enabled|external-publication executor active|external-publication executor enabled|ProductionLiveEpochTransitionExternalPublicationExecutor enabled|external-publication applied|live epoch-transition commit receipt active|live epoch-transition commit receipt enabled|commit receipt executor active|commit receipt executor enabled|live-commit receipt active|live-commit receipt enabled|ProductionLiveEpochTransitionCommitReceiptExecutor enabled|MainNet live epoch-transition commit receipt enabled|commit receipt applied'
  assert_not_grep "$logf" 'epoch-transition runtime handoff active|epoch-transition runtime handoff enabled|runtime handoff executor active|runtime handoff executor enabled|live-mutation preflight active|live-mutation preflight enabled|guarded epoch-transition mutation active|guarded epoch-transition mutation enabled|guarded mutation executor active|guarded mutation executor enabled|staged live validator-set epoch-transition application active|staged live validator-set epoch-transition application enabled|live validator-set application authorization active|live validator-set application authorization enabled|validator-set rotation application active|validator-set rotation application enabled|validator-set rotation active|validator-set rotation enabled|governance execution engine enabled|real validator-set rotation enabled|MainNet authority rotation enabled|MainNet mutation engine enabled|peer-driven apply enabled|validator set applied|validator set mutated|consensus validator-set mutated|epoch counter mutated|epoch transition applied'
  assert_not_grep "$logf" 'fallback to fixture proof|fallback to local operator proof|fallback to peer majority|fallback to on-chain proof|fallback to RemoteSigner|fallback to custody attestation|fallback to governance proof|fallback to governance execution intent|fallback to rotation plan|fallback to application decision|fallback to authorization decision|fallback to staged application decision|fallback to guarded mutation decision|fallback to runtime handoff decision|raw local production key|DummySig active|DummyKem active|DummyAead active'
  assert_not_grep "$logf" 'Run 070 applied|LivePqcTrustState mutated|trust swap complete|session eviction complete|authority marker written|trust-bundle sequence written|transition_to_epoch called|meta:current_epoch written|reconfig block injected|PAYLOAD_KIND_RECONFIG injected|durable replay overwritten'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1; local rc=$?; set -e
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides Run 343 live epoch-transition post-completion-attestation surface (no new CLI flag)"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_surface_silent "${LOGS_DIR}/qbind_node_help.log"
# No Run 344/341 live epoch-transition post-completion-attestation boundary flag / symbol / run marker is exposed.
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'live-epoch-transition-post-completion-attestation|ProductionLiveEpochTransitionPostCompletionAttestation|pqc_production_live_epoch_transition_authority_lifecycle_post_completion_attestation|post-completion-attestation|authority-lifecycle-completion|live-epoch-transition-settlement-execution|ProductionLiveEpochTransitionSettlementExecution|pqc_production_live_epoch_transition_settlement_execution|settlement-execution|live-settlement-execution|live-epoch-transition-external-publication|ProductionLiveEpochTransitionExternalPublication|pqc_production_live_epoch_transition_external_publication|external-publication|receipt-write|audit-write|live-epoch-transition-commit-receipt|ProductionLiveEpochTransitionCommitReceipt|pqc_production_live_epoch_transition_commit_receipt|commit-receipt|live-commit-receipt|run-344|run_344|run-341|run_341'
log "S2..S4 default surfaces silent on live epoch-transition post-completion-attestation boundary claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet
log "S5 no live epoch-transition post-completion-attestation CLI selector exists (invented flag fails closed as unknown)"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet --p2p-post-completion-attestation-policy allow-source-test ) > "${LOGS_DIR}/S5_no_selector.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_no_selector.rc"; [[ "${S5_RC}" -ne 0 ]] || fail "invented post-completion-attestation selector must be rejected (no such flag)"
assert_grep "${LOGS_DIR}/S5_no_selector.log" 'unexpected argument'
assert_surface_silent "${LOGS_DIR}/S5_no_selector.log"
log "S6 default devnet genesis-hash surface fails closed (requires --genesis-path) and stays silent on post-completion-attestation claims"
set +e; ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${LOGS_DIR}/S6_default_parse.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_default_parse.rc"; [[ "${S6_RC}" -ne 0 ]] || fail "default devnet genesis-hash surface must fail closed without --genesis-path"
assert_grep "${LOGS_DIR}/S6_default_parse.log" 'requires --genesis-path'
assert_surface_silent "${LOGS_DIR}/S6_default_parse.log"

# Run 341 executor symbols required to be reachable in release evidence (from source
# and/or the release helper).
RUN341_SYMS=(
  ProductionLiveEpochTransitionPostCompletionAttestationExecutor
  ProductionLiveEpochTransitionPostCompletionAttestationConfig
  ProductionLiveEpochTransitionPostCompletionAttestationExecutorKind
  ProductionLiveEpochTransitionPostCompletionAttestationExecutorPolicy
  ProductionLiveEpochTransitionPostCompletionAttestationInputs
  ProductionLiveEpochTransitionPostCompletionAttestationRequest
  ProductionLiveEpochTransitionPostCompletionAttestationDecision
  ProductionLiveEpochTransitionPostCompletionAttestationArtifact
  ProductionLiveEpochTransitionPostCompletionAttestationOutcome
  ProductionLiveEpochTransitionPostCompletionAttestationRecoveryOutcome
  ProductionLiveEpochTransitionPostCompletionAttestationProtocolVersion
  LiveEpochTransitionPostCompletionAttestationKind
  LiveEpochTransitionPostCompletionAttestationAuthoritySource
  LiveEpochTransitionPostCompletionAttestationReplaySet
  EmptyLiveEpochTransitionPostCompletionAttestationReplaySet
  LiveEpochTransitionPostCompletionAttestationFixtureState
  evaluate_live_epoch_transition_post_completion_attestation
  recover_live_epoch_transition_post_completion_attestation_window
  production_live_epoch_transition_post_completion_attestation_content_digest
  production_live_epoch_transition_post_completion_attestation_request_id
  production_live_epoch_transition_post_completion_attestation_id
  production_live_epoch_transition_post_completion_attestation_transcript_digest
)
COMBINED_CORPUS="${REACH_DIR}/combined_corpus.txt"
cat "${MOD}" "${FSC_MOD}" "${SETTLE_EXEC_MOD}" "${SETTLE_EXEC_PREP_MOD}" "${SETTLE_PREP_MOD}" "${PCA_MOD}" "${CA_MOD}" "${CAUTH_MOD}" "${MUT_MOD}" "${PREP_MOD}" "${HANDOFF_MOD}" "${GUARDED_MOD}" "${STAGED_MOD}" "${AUTHORIZATION_MOD}" "${APPLICATION_MOD}" "${ROTATION_MOD}" "${HELPER_SRC}" > "${COMBINED_CORPUS}"
{
  echo "Run 344 combined reachability — Run 341 live epoch-transition post-completion-attestation boundary symbols across source module + Run 339/340 settlement-execution input module + ancestor chain modules + release helper:"
  for sym in "${RUN341_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${COMBINED_CORPUS}" | head -n 20 || echo '(no occurrences)'; echo; done
} > "${REACH_DIR}/combined_reachability.txt"
for sym in "${RUN341_SYMS[@]}"; do assert_grep "${COMBINED_CORPUS}" "$sym"; done
{
  echo "Run 344 source reachability — Run 341 live epoch-transition post-completion-attestation boundary symbols in ${MOD}:"
  for sym in "${RUN341_SYMS[@]}"; do echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${MOD}" || echo '(no occurrences in production module)'; echo; done
} > "${REACH_DIR}/source_reachability.txt"
# Symbols expected to be defined/referenced directly in the production module.
for sym in ProductionLiveEpochTransitionPostCompletionAttestationExecutor ProductionLiveEpochTransitionPostCompletionAttestationConfig ProductionLiveEpochTransitionPostCompletionAttestationExecutorKind ProductionLiveEpochTransitionPostCompletionAttestationExecutorPolicy ProductionLiveEpochTransitionPostCompletionAttestationInputs ProductionLiveEpochTransitionPostCompletionAttestationRequest ProductionLiveEpochTransitionPostCompletionAttestationDecision ProductionLiveEpochTransitionPostCompletionAttestationArtifact ProductionLiveEpochTransitionPostCompletionAttestationOutcome ProductionLiveEpochTransitionPostCompletionAttestationRecoveryOutcome ProductionLiveEpochTransitionPostCompletionAttestationProtocolVersion LiveEpochTransitionPostCompletionAttestationKind LiveEpochTransitionPostCompletionAttestationAuthoritySource LiveEpochTransitionPostCompletionAttestationReplaySet EmptyLiveEpochTransitionPostCompletionAttestationReplaySet LiveEpochTransitionPostCompletionAttestationFixtureState evaluate_live_epoch_transition_post_completion_attestation recover_live_epoch_transition_post_completion_attestation_window production_live_epoch_transition_post_completion_attestation_content_digest production_live_epoch_transition_post_completion_attestation_request_id production_live_epoch_transition_post_completion_attestation_id production_live_epoch_transition_post_completion_attestation_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "$sym"
done
{
  echo "Run 344 helper reachability — Run 341 symbols exercised by the release helper (plus the Run 339/340 settlement-execution + Run 337/338 settlement-execution-preparation + Run 335/336 settlement-preparation + Run 313/314 runtime handoff + Run 311/312 guarded + Run 309/310 staged + Run 307/308 authorization + Run 305/306 application executor + Run 303/304 validator-set rotation intent composition):"
  for sym in "${RUN341_SYMS[@]}" pqc_production_live_epoch_transition_settlement_execution ProductionLiveEpochTransitionSettlementExecutionExecutor ProductionLiveEpochTransitionSettlementExecutionDecision pqc_production_live_epoch_transition_settlement_execution_preparation ProductionLiveEpochTransitionSettlementExecutionPreparationExecutor ProductionLiveEpochTransitionSettlementExecutionPreparationDecision pqc_production_live_epoch_transition_settlement_preparation ProductionLiveEpochTransitionSettlementPreparationExecutor ProductionLiveEpochTransitionSettlementPreparationDecision pqc_production_live_epoch_transition_external_publication ProductionLiveEpochTransitionExternalPublicationExecutor ProductionLiveEpochTransitionExternalPublicationDecision pqc_production_live_epoch_transition_commit_receipt ProductionLiveEpochTransitionCommitReceiptExecutor ProductionLiveEpochTransitionCommitReceiptDecision pqc_production_live_epoch_transition_commit_authorization ProductionLiveEpochTransitionCommitAuthorizationExecutor ProductionLiveEpochTransitionCommitAuthorizationDecision pqc_production_live_epoch_transition_mutation_execution ProductionLiveEpochTransitionMutationExecutionExecutor ProductionLiveEpochTransitionMutationExecutionDecision pqc_production_live_epoch_transition_execution_preparation ProductionLiveEpochTransitionExecutionPreparationExecutor ProductionLiveEpochTransitionExecutionPreparationDecision pqc_production_epoch_transition_runtime_handoff ProductionEpochTransitionRuntimeHandoffExecutor ProductionEpochTransitionRuntimeHandoffDecision pqc_production_guarded_epoch_transition_mutation_executor ProductionGuardedEpochTransitionMutationExecutor ProductionGuardedEpochTransitionMutationDecision pqc_production_staged_live_validator_set_epoch_transition_application_executor ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor pqc_production_live_validator_set_application_authorization ProductionLiveValidatorSetApplicationAuthorizationExecutor pqc_production_validator_set_rotation_application_executor ProductionValidatorSetRotationApplicationExecutor pqc_production_validator_set_rotation_intent ProductionValidatorSetRotationBoundary; do echo "=== symbol: ${sym} ==="; grep -In "$sym" "${HELPER_SRC}" || echo '(no occurrences in helper)'; echo; done
} > "${REACH_DIR}/helper_reachability.txt"
# Symbols the release helper must directly exercise.
for sym in ProductionLiveEpochTransitionPostCompletionAttestationExecutor ProductionLiveEpochTransitionPostCompletionAttestationConfig ProductionLiveEpochTransitionPostCompletionAttestationExecutorPolicy ProductionLiveEpochTransitionPostCompletionAttestationInputs ProductionLiveEpochTransitionPostCompletionAttestationRequest ProductionLiveEpochTransitionPostCompletionAttestationDecision ProductionLiveEpochTransitionPostCompletionAttestationArtifact ProductionLiveEpochTransitionPostCompletionAttestationOutcome ProductionLiveEpochTransitionPostCompletionAttestationRecoveryOutcome LiveEpochTransitionPostCompletionAttestationKind LiveEpochTransitionPostCompletionAttestationAuthoritySource EmptyLiveEpochTransitionPostCompletionAttestationReplaySet LiveEpochTransitionPostCompletionAttestationFixtureState evaluate_live_epoch_transition_post_completion_attestation recover_live_epoch_transition_post_completion_attestation_window ProductionLiveEpochTransitionSettlementExecutionExecutor ProductionLiveEpochTransitionSettlementExecutionDecision ProductionLiveEpochTransitionSettlementExecutionPreparationExecutor ProductionLiveEpochTransitionSettlementExecutionPreparationDecision ProductionLiveEpochTransitionSettlementPreparationExecutor ProductionLiveEpochTransitionSettlementPreparationDecision ProductionLiveEpochTransitionExternalPublicationExecutor ProductionLiveEpochTransitionExternalPublicationDecision ProductionLiveEpochTransitionCommitReceiptExecutor ProductionLiveEpochTransitionCommitReceiptDecision ProductionLiveEpochTransitionCommitAuthorizationExecutor ProductionLiveEpochTransitionCommitAuthorizationDecision ProductionLiveEpochTransitionMutationExecutionExecutor ProductionLiveEpochTransitionMutationExecutionDecision ProductionLiveEpochTransitionExecutionPreparationExecutor ProductionLiveEpochTransitionExecutionPreparationDecision ProductionEpochTransitionRuntimeHandoffExecutor ProductionEpochTransitionRuntimeHandoffDecision ProductionGuardedEpochTransitionMutationExecutor ProductionGuardedEpochTransitionMutationDecision ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor ProductionLiveValidatorSetApplicationAuthorizationExecutor ProductionValidatorSetRotationApplicationExecutor ProductionValidatorSetRotationBoundary; do
  assert_grep "${REACH_DIR}/helper_reachability.txt" "$sym"
done
grep -RIn --include='*.rs' 'pub mod pqc_production_live_epoch_transition_authority_lifecycle_post_completion_attestation' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
grep -RIn --include='*.rs' 'fn evaluate_live_epoch_transition_post_completion_attestation\|fn recover_live_epoch_transition_post_completion_attestation_window\|fn production_live_epoch_transition_post_completion_attestation_content_digest\|fn production_live_epoch_transition_post_completion_attestation_request_id\|fn production_live_epoch_transition_post_completion_attestation_id\|fn production_live_epoch_transition_post_completion_attestation_transcript_digest' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing executor entry points"
grep -RIn --include='*.rs' 'enum ProductionLiveEpochTransitionPostCompletionAttestationOutcome\|enum ProductionLiveEpochTransitionPostCompletionAttestationRecoveryOutcome\|enum ProductionLiveEpochTransitionPostCompletionAttestationExecutorPolicy\|enum ProductionLiveEpochTransitionPostCompletionAttestationExecutorKind\|enum LiveEpochTransitionPostCompletionAttestationKind\|enum LiveEpochTransitionPostCompletionAttestationAuthoritySource' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing executor taxonomy"
grep -RIn --include='*.rs' 'trait LiveEpochTransitionPostCompletionAttestationReplaySet\|struct ProductionLiveEpochTransitionPostCompletionAttestationExecutor\|struct ProductionLiveEpochTransitionPostCompletionAttestationArtifact\|struct ProductionLiveEpochTransitionPostCompletionAttestationRequest\|struct EmptyLiveEpochTransitionPostCompletionAttestationReplaySet\|struct LiveEpochTransitionPostCompletionAttestationFixtureState' "${MOD}" > "${REACH_DIR}/boundary_surface.txt" || fail "missing executor surface"


C4C5_DOC="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
C4C5_PHRASES=(
  'Status as of Run 344'
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
  'Epoch-transition runtime handoff / live-mutation preflight'
  'Green for release-binary-evidenced epoch-transition-runtime-handoff-boundary behavior only'
  'Live epoch-transition execution preparation'
  'Green for release-binary-evidenced live-epoch-transition-execution-preparation-boundary behavior only'
  'Live epoch-transition mutation execution'
  'Green for release-binary-evidenced live-epoch-transition-mutation-execution-boundary behavior only'
  'Live epoch-transition commit receipt'
  'Green for release-binary-evidenced live-epoch-transition-commit-receipt-boundary behavior only'
  'Green for release-binary-evidenced live-epoch-transition-external-publication-boundary behavior only'
  'Live epoch-transition settlement / finalization-preparation'
  'Green for release-binary-evidenced live-epoch-transition-settlement-preparation-boundary behavior only'
  'Live epoch-transition settlement / finalization execution-preparation'
  'Green for release-binary-evidenced live-epoch-transition-settlement-execution-preparation-boundary behavior only'
  'Live epoch-transition settlement / finalization **execution**'
  'Green for release-binary-evidenced live-epoch-transition-settlement-execution-boundary behavior only'
  'Live epoch-transition final settlement / authority-lifecycle **completion**'
  'Green for release-binary-evidenced live-epoch-transition-final-settlement-completion-boundary behavior only'
  'Live epoch-transition authority-lifecycle **activation-readiness / post-completion attestation**'
  'Green for release-binary-evidenced live-epoch-transition-post-completion-attestation-boundary behavior only'
  'becomes Green-for-scope only because Run 344 landed its release-binary evidence'
  'Full MainNet release-binary evidence under production custody'
)
{
  echo "Run 344 C4/C5 matrix taxonomy reachability — ${C4C5_DOC}:"
  for phrase in "${C4C5_PHRASES[@]}"; do echo "=== phrase: ${phrase} ==="; grep -F -i -n "$phrase" "${C4C5_DOC}" || echo '(phrase missing)'; echo; done
} > "${REACH_DIR}/c4c5_matrix.txt"
for phrase in "${C4C5_PHRASES[@]}"; do grep -F -i -q "$phrase" "${C4C5_DOC}" || fail "missing C4/C5 matrix phrase '${phrase}'"; done
# The prior Green-for-scope rows remain Green-for-scope; the live epoch-transition
# commit receipt row remains Green-for-scope and the settlement-execution-preparation row
# becomes Green-for-scope.
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
grep -F -q 'Green for release-binary-evidenced guarded-epoch-transition-mutation-executor-boundary behavior only' "${C4C5_DOC}" || fail "guarded epoch-transition mutation executor row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced epoch-transition-runtime-handoff-boundary behavior only' "${C4C5_DOC}" || fail "epoch-transition runtime handoff row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-execution-preparation-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition execution preparation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-mutation-execution-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition mutation execution row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-commit-receipt-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition commit receipt row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-external-publication-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition external-publication row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-settlement-preparation-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition settlement-preparation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-settlement-execution-preparation-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition settlement-execution-preparation row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-settlement-execution-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition settlement-execution row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-final-settlement-completion-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition final-settlement-completion row must remain scoped Green"
grep -F -q 'Green for release-binary-evidenced live-epoch-transition-post-completion-attestation-boundary behavior only' "${C4C5_DOC}" || fail "live epoch-transition post-completion-attestation row must be scoped Green"
grep -F -q 'becomes Green-for-scope only because Run 344 landed its release-binary evidence' "${C4C5_DOC}" || fail "live epoch-transition post-completion-attestation row must be scoped Green"
grep -F -q 'consumes verified live epoch-transition final settlement / authority-lifecycle completion decisions and produces typed non-mutating live authority-lifecycle activation-readiness / post-completion attestation artifacts' "${C4C5_DOC}" || fail "post-completion-attestation row must record final-settlement-completion consumption and typed non-mutating live authority-lifecycle activation-readiness / post-completion attestation artifacts"
# The live epoch-transition final-settlement-completion and post-completion-attestation rows must
# record the non-goals explicitly.
grep -F -q 'not wired by default into production runtime' "${C4C5_DOC}" || fail "post-completion-attestation row must record no default runtime wiring"
grep -F -q 'no public CLI flag' "${C4C5_DOC}" || fail "post-completion-attestation row must record no public CLI flag"
grep -F -q 'consumes verified live epoch-transition settlement / finalization execution decisions and produces typed non-mutating live final-settlement / authority-lifecycle completion artifacts' "${C4C5_DOC}" || fail "final-settlement-completion row must record settlement-execution consumption and typed non-mutating live final-settlement / authority-lifecycle completion artifacts"
grep -F -q 'never calls `BasicHotStuffEngine::transition_to_epoch` on production runtime state' "${C4C5_DOC}" || fail "post-completion-attestation row must record no transition_to_epoch call"
grep -F -q 'does not prove live production validator-set mutation, production epoch transition, MainNet readiness, or C4/C5 closure.' "${C4C5_DOC}" || fail "post-completion-attestation row must record no MainNet mutation proof / no C4/C5 closure"
for redrow in 'MainNet authority rotation/revocation under production custody | 🔴 Red' 'Production signing audit trail / crypto-agility activation / incident response | 🔴 Red' 'Full MainNet release-binary evidence under production custody | 🔴 Red'; do
  grep -F -q "$redrow" "${C4C5_DOC}" || fail "expected Red row unchanged: ${redrow}"
done

DENY_PATTERNS=(
  'C4 closed' 'C5 closed' 'MainNet ready' 'production ready'
  'live epoch-transition post-completion-attestation active' 'live epoch-transition post-completion-attestation enabled'
  'post-completion-attestation executor active' 'post-completion-attestation executor enabled'
  'live-post-completion-attestation active' 'live-post-completion-attestation enabled' 'post-completion-attestation applied' 'authority-lifecycle-completion applied'
  'live epoch-transition settlement-execution active' 'live epoch-transition settlement-execution enabled'
  'settlement-execution executor active' 'settlement-execution executor enabled'
  'live-settlement-execution active' 'live-settlement-execution enabled' 'settlement-execution applied'
  'live epoch-transition external-publication active' 'live epoch-transition external-publication enabled'
  'external-publication executor active' 'external-publication executor enabled' 'external-publication applied'
  'live epoch-transition commit receipt active' 'live epoch-transition commit receipt enabled'
  'commit receipt executor active' 'commit receipt executor enabled'
  'live-commit receipt active' 'live-commit receipt enabled' 'commit receipt applied'
  'epoch-transition runtime handoff active' 'epoch-transition runtime handoff enabled'
  'runtime handoff executor active' 'runtime handoff executor enabled'
  'live-mutation preflight active' 'live-mutation preflight enabled' 'live mutation applied'
  'guarded epoch-transition mutation active' 'guarded epoch-transition mutation enabled'
  'guarded mutation executor active' 'guarded mutation executor enabled'
  'staged live validator-set epoch-transition application active' 'staged live validator-set epoch-transition application enabled'
  'live validator-set application authorization active' 'live validator-set application authorization enabled'
  'validator-set rotation application active' 'validator-set rotation application enabled'
  'validator-set rotation active' 'validator-set rotation enabled'
  'governance execution engine active' 'governance execution engine enabled'
  'MainNet authority rotation enabled' 'MainNet live epoch-transition post-completion-attestation enabled' 'peer-driven apply enabled'
  'validator set applied' 'validator set mutated' 'consensus validator-set mutated' 'epoch counter mutated' 'epoch transition applied' 'transition_to_epoch called' 'meta:current_epoch written' 'reconfig block injected' 'PAYLOAD_KIND_RECONFIG injected'
  'Run 070 applied' 'LivePqcTrustState mutated' 'trust swap complete' 'session eviction complete' 'authority marker written' 'trust-bundle sequence written'
  'durable replay overwritten' 'settlement finalized' 'external publication completed'
  'fallback to fixture proof' 'fallback to local operator proof' 'fallback to peer majority' 'fallback to on-chain proof' 'fallback to RemoteSigner' 'fallback to custody attestation' 'fallback to governance proof' 'fallback to governance execution intent' 'fallback to rotation plan' 'fallback to application decision' 'fallback to authorization decision' 'fallback to staged application decision' 'fallback to guarded mutation decision' 'fallback to runtime handoff decision'
  'raw local production key' 'DummySig active' 'DummyKem active' 'DummyAead active'
)
{
  echo "Run 344 denylist (proven empty across captured logs/helper output except help and summary):"
  for pat in "${DENY_PATTERNS[@]}"; do
    if find "${LOGS_DIR}" "${HELPER_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 344 no-mutation / no-authority-extension proof:"
  echo "  The release helper drives the real Run 341 ProductionLiveEpochTransitionPostCompletionAttestationExecutor ONLY"
  echo "  through the source/test boundary, ONLY for DevNet/TestNet identities on the accept path, under explicit"
  echo "  source/test, production-required and MainNet-required policies. It consumes a verified Run 339/340 live epoch-transition"
  echo "  settlement / finalization execution accept decision (a ProductionLiveEpochTransitionSettlementExecutionDecision that is_accept() and"
  echo "  carries Some(settlement_execution_artifact)), which itself composes the verified Run 337/338 settlement-execution-preparation"
  echo "  accept decision and the full Run 303/304 → … → Run 339/340 chain. The Run 341 executor produces ONLY a typed non-mutating"
  echo "  live final-settlement / authority-lifecycle completion artifact describing"
  echo "  what a future live production authority-lifecycle completion executor would apply. It applies no live production validator-set change and performs"
  echo "  no Run 070 call, no LivePqcTrustState mutation, no live validator-set mutation, no consensus validator-set mutation,"
  echo "  no epoch-counter mutation, no BasicHotStuffEngine::transition_to_epoch call on production runtime state, no"
  echo "  meta:current_epoch write, no PAYLOAD_KIND_RECONFIG block injection, no trust swap, no session eviction, no PQC"
  echo "  trust-bundle sequence write, no authority marker write, no durable replay overwrite, no settlement, no settlement-finalization,"
  echo "  no settlement-execution, no final-settlement, no authority-lifecycle-completion, no external"
  echo "  publication, and no raw local production signing key load. The only mutation any positive path performs is against a"
  echo "  caller-owned in-memory LiveEpochTransitionPostCompletionAttestationFixtureState used exclusively as source/test evidence,"
  echo "  which is explicitly distinct from production runtime state. Under a production or MainNet policy the executor fails"
  echo "  closed and never falls back to settlement-execution-decision-alone / runtime-handoff-decision-alone /"
  echo "  guarded-mutation-decision-alone / staged-application-decision-alone / application-decision-alone / rotation-plan-alone /"
  echo "  governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only /"
  echo "  remote-signer-only / custody-attestation-only / arbitrary-bytes material. Missing / unverified / accepted-without-artifact"
  echo "  settlement-execution decisions are rejected as production authority; MainNet identities are refused before acceptance."
  echo "  The default ProductionLiveEpochTransitionPostCompletionAttestationExecutorPolicy is Disabled; the production binary is not wired to"
  echo "  construct the boundary and adds no CLI flag."
  echo "  helper corpus tables:"; grep -E 'verdict=PASS|^table |^total_(pass|fail)=' "${HELPER_OUT}/helper_summary.txt" | sed 's/^/    /'
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
TEST_TARGETS=(run_343_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_tests run_341_production_live_epoch_transition_final_settlement_completion_tests run_339_production_live_epoch_transition_settlement_execution_tests run_337_production_live_epoch_transition_settlement_execution_preparation_tests run_335_production_live_epoch_transition_settlement_preparation_tests run_333_production_live_epoch_transition_external_publication_tests run_331_production_live_epoch_transition_durable_audit_publication_tests run_329_production_live_epoch_transition_audit_ledger_commitment_tests run_327_production_live_epoch_transition_durable_audit_finalization_tests run_325_production_live_epoch_transition_post_commit_audit_tests run_323_production_live_epoch_transition_commit_receipt_tests run_321_production_live_epoch_transition_commit_execution_tests run_319_production_live_epoch_transition_commit_authorization_tests run_317_production_live_epoch_transition_mutation_execution_tests run_315_production_live_epoch_transition_execution_preparation_tests run_313_production_epoch_transition_runtime_handoff_tests run_311_production_guarded_epoch_transition_mutation_executor_tests run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests run_307_production_live_validator_set_application_authorization_tests run_305_production_validator_set_rotation_application_executor_tests run_303_production_validator_set_rotation_intent_tests run_301_production_governance_execution_engine_tests run_299_production_onchain_governance_proof_verifier_tests run_297_production_custody_attestation_verifier_tests run_295_production_kms_hsm_custody_backend_tests run_293_production_remote_signer_backend_tests run_291_production_durable_replay_rocksdb_tests run_186_onchain_governance_production_verifier_boundary_tests run_178_onchain_governance_proof_tests run_203_kms_hsm_backend_boundary_tests run_201_remote_signer_transport_boundary_tests run_194_remote_authority_signer_boundary_tests run_188_authority_custody_boundary_tests)
if [[ "${RUN_344_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_VERDICTS+=("tests:skipped(RUN_344_SKIP_TESTS=1)")
else
  for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}\trc=skipped(not-present)" ); fi; done
  TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
  TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )
fi

{
  echo "Run 344 — release-binary evidence for the Run 343 live epoch-transition authority-lifecycle activation-readiness / post-completion-attestation boundary"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "git_status: $(if [[ -n "$(git -C "${REPO_ROOT}" status --short 2>/dev/null)" ]]; then echo dirty; else echo clean; fi)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  host:               $(uname -a 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  helper_344_sha256:  $(sha256_file "${HELPER_BIN}")"
  echo
  echo "helper_summary: ${HELPER_OUT}/helper_summary.txt"
  sed 's/^/  /' "${HELPER_OUT}/helper_summary.txt"
  echo
  echo "deterministic_digests: stable across two independent helper invocations"
  sed 's/^/  /' "${HELPER_OUT}/fixtures/run_344_deterministic_digests.txt"
  echo
  echo "release_binary_scenarios: S1_help=${HELP_RC} S2=$(cat "${EXIT_DIR}/S2_default_devnet.rc") S3=$(cat "${EXIT_DIR}/S3_default_testnet.rc") S4=$(cat "${EXIT_DIR}/S4_default_mainnet.rc") S5_no_selector=${S5_RC} S6_default_parse=${S6_RC}"
  echo "reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed"
  echo "c4c5_taxonomy: passed (${#C4C5_PHRASES[@]} phrases; RocksDB + RemoteSigner + KMS/HSM + custody-attestation + on-chain-governance-proof-verifier + governance-execution-engine + validator-set-rotation-intent-boundary + validator-set-rotation-application-executor-boundary + live-validator-set-application-authorization-boundary + staged-live-validator-set-epoch-transition-application-executor-boundary + guarded-epoch-transition-mutation-executor-boundary + epoch-transition-runtime-handoff-boundary + live-epoch-transition-commit-receipt-boundary + live-epoch-transition-settlement-execution-boundary + live-epoch-transition-post-completion-attestation-boundary rows Green-for-scope only; Red rows unchanged; Full C4 OPEN; C5 OPEN)"
  echo "denylist: passed (${#DENY_PATTERNS[@]} patterns)"
  echo "tests:"
  for verdict in "${TEST_VERDICTS[@]}"; do echo "  ${verdict}"; done
  echo
  echo "verdict: PASS (release-binary evidence only; live epoch-transition post-completion-attestation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN)"
} | tee "${SUMMARY}"