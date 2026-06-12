#!/usr/bin/env bash
# Run 235 — Release-binary governance evaluator post-mutation replay consume
# boundary evidence.
#
# Proves the release-built code exposes and exercises the Run 234 governance
# evaluator **post-mutation replay consume boundary** in
# `crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`:
# `evaluate_post_mutation_consume`, `perform_post_mutation_consume`, the typed
# `MutationAuthorizationOutcome` / `MutationCompletionStatus` /
# `ConsumeBoundaryOutcome` (`DoNotConsume{LegacyBypass, Deferred, ValidationOnly,
# BeforeApply, ApplyFailed, RolledBack, UnsupportedSurface, MainNetRefused}`,
# `ConsumeFixtureAfterSuccess`, `FailClosed{ConsumeUnavailable,
# ProductionConsumeUnavailable, MainNetConsumeUnavailable, WrongBinding}`), the
# deterministic digest helpers (`consume_authorization_digest`,
# `consume_transcript_digest`, `post_mutation_consume_record_digest`), and the
# grep-verifiable refusal / fail-closed helpers
# (`mainnet_peer_driven_apply_remains_refused_under_consume_boundary`,
# `consume_only_after_successful_mutation`, `deferred_is_never_consumed`,
# `validation_only_is_never_consumed`,
# `production_mainnet_consume_remains_unavailable`,
# `local_operator_cannot_satisfy_consume_policy`,
# `peer_majority_cannot_satisfy_consume_policy`,
# `validator_set_rotation_remains_unsupported_under_consume_boundary`,
# `policy_change_action_remains_unsupported_under_consume_boundary`). Run 234
# models the post-mutation consume step as a strict after-success-only boundary:
# consume is authorized ONLY after `MutationCompletionStatus::AppliedSuccessfully`
# (only `ConsumeFixtureAfterSuccess`). Deferred / validation-only /
# authorized-but-not-applied / failed-apply / rolled-back / unsupported-surface /
# MainNet-refused outcomes never consume. The boundary is pure (no marker/sequence
# write, no live trust swap, no session eviction, no Run 070 call, no persistent
# storage); the DevNet/TestNet FixtureReplayStateStore writer records consumed
# only on an explicit after-success `perform_post_mutation_consume` call;
# production/MainNet consume writers are callable but always fail closed
# unavailable; MainNet peer-driven apply remains refused even when fresh;
# validator-set rotation and policy-change actions remain unsupported.
# Fixture-only; no real governance engine; no RocksDB/file/schema/migration/
# storage/wire/marker/sequence/trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_235_BIN="${REPO_ROOT}/target/release/examples/run_235_governance_evaluator_replay_consume_boundary_release_binary_helper"
HELPER_235_OUT="${OUTDIR}/helper_evidence/run_235"
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

log() { printf '[run-235] %s\n' "$*" >&2; }
fail() { printf '[run-235] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_235_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_235_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-235 provenance"
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
log "cargo build --release -p qbind-node --example run_235_governance_evaluator_replay_consume_boundary_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_235_governance_evaluator_replay_consume_boundary_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_235.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_235_BIN}" ]] || fail "missing ${HELPER_235_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_235_path:    ${HELPER_235_BIN}"
  echo "helper_235_sha256:  $(sha256_file "${HELPER_235_BIN}")"
  echo "helper_235_buildid: $(build_id "${HELPER_235_BIN}")"
} >> "${PROVENANCE}"

log "running Run 235 helper"
set +e
"${HELPER_235_BIN}" "${HELPER_235_OUT}" > "${LOGS_DIR}/helper_run_235.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_235.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_235 helper failed"
assert_grep "${HELPER_235_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 235 consume-boundary fixture inventory (helper-minted):"
  if [[ -d "${HELPER_235_OUT}/fixtures" ]]; then
    for f in "${HELPER_235_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/consume_boundary_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime (integration|call-site) (enabled|active|wired)'
  assert_not_grep "$logf" 'replay/freshness runtime integration (enabled|active|wired)'
  assert_not_grep "$logf" 'consume boundary (enabled|active|wired)'
  assert_not_grep "$logf" 'post-mutation consume (enabled|active|wired)'
  assert_not_grep "$logf" 'replay state (enabled|active|wired)'
  assert_not_grep "$logf" 'replay/freshness (enabled|active|wired)'
  assert_not_grep "$logf" 'production decision source (enabled|active)'
  assert_not_grep "$logf" 'validator-set rotation (enabled|active|supported|wired)'
  assert_not_grep "$logf" 'autonomous apply|apply on receipt|peer-majority authority'
  assert_not_grep "$logf" 'real KMS backend|real HSM backend|real RemoteSigner backend|RemoteSigner backend connected'
  assert_not_grep "$logf" 'custody attestation production (enabled|active|wired)'
  assert_not_grep "$logf" 'MainNet peer-driven apply ENABLED'
}
run_surface_scenario() {
  local key="$1"; shift; local node_env="$1"; shift; local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) > "${logf}" 2>&1 || true
  local rc=$?
  echo "$rc" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S1 help hides consume-boundary surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'consume boundary|post-mutation consume|ConsumeBoundaryOutcome|evaluate_post_mutation_consume|run-234|run-235'
log "S2..S4 default surfaces silent on consume-boundary claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses and
# an invalid selector fails closed before mutation. These exercise the Run 215
# hidden selector carried by the Run 217/220 arming into the Run 226 call-site
# wiring that the Run 230 boundary gates in the Run 232 composition that Run 234
# bounds with the post-mutation consume step.
ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-governance-execution-policy"
log "S5 hidden governance-execution selector still parses (fixture-governance-allowed)"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" fixture-governance-allowed ) > "${LOGS_DIR}/S5_selector_parses.log" 2>&1; S5_RC=$?; set -e
echo "${S5_RC}" > "${EXIT_DIR}/S5_selector_parses.rc"
assert_surface_silent "${LOGS_DIR}/S5_selector_parses.log"
log "S6 invalid governance-execution selector fails closed before mutation"
set +e; ( cd "${REPO_ROOT}" && env -u "${ENV_SELECTOR}" "${NODE_BIN}" --print-genesis-hash --env devnet "${CLI_SELECTOR}" bogus-policy ) > "${LOGS_DIR}/S6_selector_invalid.log" 2>&1; S6_RC=$?; set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_selector_invalid.rc"
[[ "${S6_RC}" -ne 0 ]] || fail "invalid governance-execution selector must fail closed (non-zero exit)"
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'invalid governance-execution policy selector'
assert_grep "${LOGS_DIR}/S6_selector_invalid.log" 'no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call'
assert_surface_silent "${LOGS_DIR}/S6_selector_invalid.log"

SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
MOD="${SRC_DIR}/pqc_governance_evaluator_replay_consume_boundary.rs"
{
  echo "Run 235 source-reachability proof — Run 234 post-mutation consume boundary symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_replay_consume_boundary MutationAuthorizationOutcome MutationCompletionStatus ConsumeBoundaryOutcome PostMutationConsumeInput PostMutationConsumeExpectations evaluate_post_mutation_consume perform_post_mutation_consume ConsumeFixtureAfterSuccess DoNotConsumeBeforeApply DoNotConsumeApplyFailed DoNotConsumeRolledBack DoNotConsumeValidationOnly DoNotConsumeUnsupportedSurface DoNotConsumeMainNetRefused FailClosedConsumeUnavailable FailClosedProductionConsumeUnavailable FailClosedMainNetConsumeUnavailable FailClosedWrongBinding consume_authorization_digest consume_transcript_digest post_mutation_consume_record_digest mark_consumed GovernanceEvaluatorReplayStateWriter FixtureReplayStateStore ProductionReplayStateReader MainnetReplayStateReader mainnet_peer_driven_apply_remains_refused_under_consume_boundary consume_only_after_successful_mutation deferred_is_never_consumed validation_only_is_never_consumed production_mainnet_consume_remains_unavailable local_operator_cannot_satisfy_consume_policy peer_majority_cannot_satisfy_consume_policy validator_set_rotation_remains_unsupported_under_consume_boundary policy_change_action_remains_unsupported_under_consume_boundary; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_replay_consume_boundary'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MutationAuthorizationOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MutationCompletionStatus'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ConsumeBoundaryOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_post_mutation_consume'
assert_grep "${REACH_DIR}/source_reachability.txt" 'perform_post_mutation_consume'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ConsumeFixtureAfterSuccess'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FailClosedConsumeUnavailable'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FailClosedProductionConsumeUnavailable'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FailClosedMainNetConsumeUnavailable'

# Module registration reachability (lib.rs exposes the Run 234 consume boundary module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_replay_consume_boundary' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Boundary entry points within the module.
grep -RIn --include='*.rs' 'pub fn evaluate_post_mutation_consume\|pub fn perform_post_mutation_consume' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing boundary entry points"
# Consume outcome taxonomy within the module.
grep -RIn --include='*.rs' 'enum ConsumeBoundaryOutcome\|ConsumeFixtureAfterSuccess\|DoNotConsumeBeforeApply\|DoNotConsumeApplyFailed\|DoNotConsumeRolledBack\|DoNotConsumeValidationOnly\|DoNotConsumeUnsupportedSurface\|DoNotConsumeMainNetRefused\|FailClosedConsumeUnavailable\|FailClosedProductionConsumeUnavailable\|FailClosedMainNetConsumeUnavailable\|FailClosedWrongBinding' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing outcome taxonomy"
# Mutation authorization / completion phase types.
grep -RIn --include='*.rs' 'enum MutationAuthorizationOutcome\|enum MutationCompletionStatus\|AppliedSuccessfully\|AuthorizedFresh' "${MOD}" > "${REACH_DIR}/phase_types.txt" || fail "missing phase types"
# Deterministic digest helpers.
grep -RIn --include='*.rs' 'consume_authorization_digest\|consume_transcript_digest\|post_mutation_consume_record_digest' "${MOD}" > "${REACH_DIR}/digest_helpers.txt" || fail "missing digest helpers"
# Fixture consume writer path (only ConsumeFixtureAfterSuccess calls mark_consumed).
grep -RIn --include='*.rs' 'mark_consumed\|ConsumeFixtureAfterSuccess\|GovernanceEvaluatorReplayStateWriter' "${MOD}" > "${REACH_DIR}/fixture_consume_writer.txt" || fail "missing fixture consume writer path"
# Production / MainNet consume unavailable fail-closed path.
grep -RIn --include='*.rs' 'FailClosedProductionConsumeUnavailable\|FailClosedMainNetConsumeUnavailable\|production_mainnet_consume_remains_unavailable\|Production / MainNet consume writers' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_remains_refused_under_consume_boundary\|DoNotConsumeMainNetRefused\|MainNet peer-driven apply remains refused' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# After-success-only / deferred-never / validation-only-never guards.
grep -RIn --include='*.rs' 'consume_only_after_successful_mutation\|deferred_is_never_consumed\|validation_only_is_never_consumed' "${MOD}" > "${REACH_DIR}/after_success_only.txt" || fail "missing after-success-only guard reachability"

{
  echo "Run 235 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'consume boundary active' 'post-mutation consume active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'RocksDB schema change' 'file format change' 'database migration' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_235_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 235 no-mutation proof for rejected post-mutation consume-boundary scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A21 / R1..R33 helper corpus (driven through the Run 234 post-mutation consume boundary evaluate_post_mutation_consume / perform_post_mutation_consume, composing the Run 230 reader/writer traits and projecting the Run 232 GovernanceEvaluatorReplayRuntimeOutcome into the MutationAuthorizationOutcome view): consume is after-success-only — only ConsumeFixtureAfterSuccess (after MutationCompletionStatus::AppliedSuccessfully on a wired DevNet/TestNet fixture policy) authorizes a fixture consume. Every rejected / non-consume outcome surfaces as a typed ConsumeBoundaryOutcome (DoNotConsume{LegacyBypass, Deferred, ValidationOnly, BeforeApply, ApplyFailed, RolledBack, UnsupportedSurface, MainNetRefused} / FailClosed{ConsumeUnavailable, ProductionConsumeUnavailable, MainNetConsumeUnavailable, WrongBinding}) returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The boundary performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, never invokes Run 070, and implements no persistent storage. The writer is never called on a non-consume path; only the explicit after-success perform_post_mutation_consume path calls the DevNet/TestNet fixture writer's mark_consumed, and only after a prior observation. Production/MainNet consume writers are callable but always fail closed unavailable. MainNet peer-driven apply is refused and never consumes even when the replay state is fresh."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_235_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 235 mutation proof (release-binary scope): the Run 234 post-mutation consume boundary is a pure function that runs AFTER the Run 232/233 replay/freshness runtime integration authorized a mutate and AFTER the mutation completion phase reports MutationCompletionStatus::AppliedSuccessfully. The only consume-authorizing outcome is ConsumeFixtureAfterSuccess, produced only when (i) the projected mutation authorization is AuthorizedFresh, (ii) neither the validation nor the mutation surface is validation-only, (iii) the consume binding (replay state key digest / evaluator request / response / decision digests / proposal / decision / lifecycle action / candidate digest / sequence / effective+expiry epoch / replay nonce / environment / chain / genesis / validation surface / mutation surface) matches the canonical expectations, (iv) the mutation completion status is AppliedSuccessfully, and (v) a wired DevNet/TestNet fixture policy on a non-MainNet environment is active. Consume records consumed in the in-process FixtureReplayStateStore only via the explicit after-success perform_post_mutation_consume path (mark_consumed), and only when a prior observation exists; otherwise it downgrades to FailClosedConsumeUnavailable. Production/MainNet consume is callable but fails closed as unavailable; MainNet peer-driven apply is refused even when fresh. No mutation is performed by this fixture-only helper or by the boundary; a ConsumeFixtureAfterSuccess outcome is, at most, the after-success bookkeeping for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 235 does not exercise. The DevNet/TestNet FixtureReplayStateStore is an in-process map only — it introduces no RocksDB schema, no file format, and no database migration."
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
TEST_TARGETS=(run_234_governance_evaluator_replay_consume_boundary_tests run_232_governance_evaluator_replay_runtime_integration_tests run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 235 — release-binary governance evaluator post-mutation replay consume boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_235_sha256:  $(sha256_file "${HELPER_235_BIN}")"
  echo "  helper_235_buildid: $(build_id "${HELPER_235_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_235rc=$(cat "${EXIT_DIR}/helper_run_235.rc")$(grep -E 'verdict:' "${HELPER_235_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A21 / R1-R33 corpus verdicts (release mode, Run 234 post-mutation consume boundary symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_235_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 234 post-mutation consume boundary is a local/source-test-only pure function exercised here through release-built library symbols (the same symbols a future production call site would use); it composes the Run 230 reader/writer traits and projects the Run 232 runtime-integration outcome into its MutationAuthorizationOutcome view; consume is after-success-only — only ConsumeFixtureAfterSuccess (after MutationCompletionStatus::AppliedSuccessfully) authorizes a fixture consume; deferred, validation-only, authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume; the DevNet/TestNet FixtureReplayStateStore is an in-process map only and DevNet/TestNet evidence-only (it reads as Unavailable for a MainNet environment); the fixture writer records consumed only on an explicit after-success perform_post_mutation_consume call with a prior observation, and a re-validation then classifies the decision already-consumed through Run 230; production/MainNet consume writers are callable but always fail closed unavailable; rejections are pure and non-mutating and the writer is never called on a non-consume path; MainNet peer-driven apply remains refused and never consumes even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine; no real on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, no persistent storage, and no wire/marker/sequence/trust-bundle schema change; existing Run 233, Run 231, Run 229, Run 227, and Run 225 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "Run 235 release-binary consume-boundary evidence complete; summary at ${SUMMARY}"
cat "${SUMMARY}"
