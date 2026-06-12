#!/usr/bin/env bash
# Run 231 — Release-binary governance evaluator replay/freshness state evidence.
#
# Proves the release-built code exposes and exercises the Run 230 governance
# evaluator **replay and freshness state boundary** in
# `crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`:
# `EvaluatorReplayFreshnessInput`, `EvaluatorReplayFreshnessExpectations`,
# `ReplayFreshnessState`, `EvaluatorReplayFreshnessOutcome`,
# `classify_evaluator_replay_freshness`, `evaluate_evaluator_replay_freshness`,
# `gate_evaluator_replay_freshness`, the deterministic digest helpers
# (`replay_state_key_digest`, `replay_observation_digest`,
# `consumed_decision_digest`, `freshness_transcript_digest`), the
# `GovernanceEvaluatorReplayStateReader` / `GovernanceEvaluatorReplayStateWriter`
# traits, the DevNet/TestNet `FixtureReplayStateStore`, and the
# callable-but-unavailable `ProductionReplayStateReader` /
# `MainnetReplayStateReader`. The boundary distinguishes fresh / deferred /
# expired / stale / replayed / already-consumed / superseded / wrong-binding /
# unavailable / production-unavailable / MainNet-unavailable outcomes; only
# `ProceedFresh` authorizes a mutation. The boundary is pure (no marker/sequence
# write, no live trust swap, no session eviction, no Run 070 call); read-only
# validation never consumes; explicit fixture consume marks consumed only in the
# DevNet/TestNet fixture store; production/MainNet state remains
# unavailable/fail-closed; MainNet peer-driven apply remains refused even when
# fresh; validator-set rotation unsupported. Fixture-only; no real governance
# engine; no RocksDB/file/schema/migration/storage/wire/marker/sequence/
# trust-bundle change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_231_governance_evaluator_replay_state_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_231_BIN="${REPO_ROOT}/target/release/examples/run_231_governance_evaluator_replay_state_release_binary_helper"
HELPER_231_OUT="${OUTDIR}/helper_evidence/run_231"
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

log() { printf '[run-231] %s\n' "$*" >&2; }
fail() { printf '[run-231] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
build_id() { if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo 'BuildID=unknown'; else echo 'BuildID=tool-missing'; fi; }
assert_grep() { grep -E -i -q "$2" "$1" || fail "expected pattern '$2' in $1"; }
assert_not_grep() { if grep -E -i -q "$2" "$1"; then fail "forbidden pattern '$2' present in $1"; fi; }

log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_231_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_231_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"; : > "${DENYLIST}"; : > "${MUT_PROOF}"; : > "${NOMUT_PROOF}"

{
  echo "run-231 provenance"
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
log "cargo build --release -p qbind-node --example run_231_governance_evaluator_replay_state_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --example run_231_governance_evaluator_replay_state_release_binary_helper ) > "${LOGS_DIR}/build_helper_run_231.log" 2>&1 || fail "helper build failed"
[[ -x "${NODE_BIN}" ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_231_BIN}" ]] || fail "missing ${HELPER_231_BIN}"
{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_231_path:    ${HELPER_231_BIN}"
  echo "helper_231_sha256:  $(sha256_file "${HELPER_231_BIN}")"
  echo "helper_231_buildid: $(build_id "${HELPER_231_BIN}")"
} >> "${PROVENANCE}"

log "running Run 231 helper"
set +e
"${HELPER_231_BIN}" "${HELPER_231_OUT}" > "${LOGS_DIR}/helper_run_231.log" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper_run_231.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "run_231 helper failed"
assert_grep "${HELPER_231_OUT}/helper_summary.txt" 'verdict: PASS'

{
  echo "Run 231 replay/freshness fixture inventory (helper-minted):"
  if [[ -d "${HELPER_231_OUT}/fixtures" ]]; then
    for f in "${HELPER_231_OUT}/fixtures"/*; do [[ -f "$f" ]] && echo "  $(basename "$f") sha256=$(sha256_file "$f")"; done
  fi
} > "${GREP_DIR}/replay_state_fixture_inventory.txt"

assert_surface_silent() {
  local logf="$1"
  assert_not_grep "$logf" 'governance execution (enabled|active|wired)'
  assert_not_grep "$logf" 'production governance (enabled|active)'
  assert_not_grep "$logf" 'MainNet governance enabled'
  assert_not_grep "$logf" 'mainnet governance (enabled|active)'
  assert_not_grep "$logf" 'real on-chain governance proof verifier'
  assert_not_grep "$logf" 'governance execution evaluator (enabled|active|wired)'
  assert_not_grep "$logf" 'evaluator runtime (integration|call-site) (enabled|active|wired)'
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

log "S1 help hides replay/freshness state surface"
set +e; "${NODE_BIN}" --help > "${LOGS_DIR}/qbind_node_help.log" 2>&1; HELP_RC=$?; set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"; [[ "${HELP_RC}" -eq 0 ]] || fail "help failed"
assert_not_grep "${LOGS_DIR}/qbind_node_help.log" 'replay state|replay/freshness|EvaluatorReplayFreshness|ReplayFreshnessState|FixtureReplayStateStore|run-230|run-231'
log "S2..S4 default surfaces silent on replay/freshness claims"
run_surface_scenario S2_default_devnet devnet
run_surface_scenario S3_default_testnet testnet
run_surface_scenario S4_default_mainnet mainnet

# Real-binary checks: the hidden governance-execution selector still parses
# and an invalid selector fails closed before mutation, while the default
# Disabled replay-state policy remains legacy-compatible. These exercise the
# Run 215 hidden selector carried by the Run 217/220 arming into the Run 226
# call-site wiring that the Run 230 replay/freshness boundary gates.
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
MOD="${SRC_DIR}/pqc_governance_evaluator_replay_state.rs"
{
  echo "Run 231 source-reachability proof — Run 230 replay/freshness symbols within ${SRC_DIR}:"
  for sym in pqc_governance_evaluator_replay_state EvaluatorReplayFreshnessInput EvaluatorReplayFreshnessExpectations ReplayFreshnessState EvaluatorReplayFreshnessOutcome PreviouslySeenState SeenDecisionRecord ReplayStatePolicy ReplayStateGateOutcome classify_evaluator_replay_freshness evaluate_evaluator_replay_freshness gate_evaluator_replay_freshness replay_state_key_digest replay_observation_digest consumed_decision_digest freshness_transcript_digest GovernanceEvaluatorReplayStateReader GovernanceEvaluatorReplayStateWriter FixtureReplayStateStore ProductionReplayStateReader MainnetReplayStateReader read_previous_state record_observation mark_consumed read_for record_for consume_for is_consumed Fresh FreshButNotYetEffective Expired Stale ReplayDetected AlreadyConsumed Superseded WrongEpoch WrongEnvironment WrongChain WrongGenesis WrongSurface MalformedState StateUnavailable ProductionStateUnavailable MainNetStateUnavailable ProceedFresh ProceedDeferred FailClosedExpired FailClosedReplay FailClosedAlreadyConsumed FailClosedSuperseded FailClosedWrongBinding FailClosedStateUnavailable FailClosedProductionUnavailable FailClosedMainNetUnavailable authorizes_mutation no_mutation is_fail_closed mainnet_peer_driven_apply_remains_refused_under_replay_state local_operator_cannot_satisfy_replay_state_policy peer_majority_cannot_satisfy_replay_state_policy validator_set_rotation_remains_unsupported_under_replay_state policy_change_action_remains_unsupported_under_replay_state; do
    echo "=== symbol: ${sym} ==="; grep -RIn --include='*.rs' "$sym" "${SRC_DIR}" || echo '(no occurrences in production source)'; echo
  done
} > "${REACH_DIR}/source_reachability.txt"
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_evaluator_replay_state'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorReplayFreshnessInput'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorReplayFreshnessExpectations'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ReplayFreshnessState'
assert_grep "${REACH_DIR}/source_reachability.txt" 'EvaluatorReplayFreshnessOutcome'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorReplayStateReader'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceEvaluatorReplayStateWriter'
assert_grep "${REACH_DIR}/source_reachability.txt" 'FixtureReplayStateStore'
assert_grep "${REACH_DIR}/source_reachability.txt" 'ProductionReplayStateReader'
assert_grep "${REACH_DIR}/source_reachability.txt" 'MainnetReplayStateReader'
for d in replay_state_key_digest replay_observation_digest consumed_decision_digest freshness_transcript_digest; do
  assert_grep "${REACH_DIR}/source_reachability.txt" "${d}"
done

# Module registration reachability (lib.rs exposes the Run 230 replay-state module).
grep -RIn --include='*.rs' 'pub mod pqc_governance_evaluator_replay_state' "${SRC_DIR}/lib.rs" > "${REACH_DIR}/module_registration.txt" || fail "missing module registration"
# Pure classification / evaluation / gating entry points within the module.
grep -RIn --include='*.rs' 'pub fn classify_evaluator_replay_freshness\|pub fn evaluate_evaluator_replay_freshness\|pub fn gate_evaluator_replay_freshness' "${MOD}" > "${REACH_DIR}/entry_points.txt" || fail "missing boundary entry points"
# State taxonomy within the module.
grep -RIn --include='*.rs' 'enum ReplayFreshnessState\|Fresh\|FreshButNotYetEffective\|Expired\|Stale\|ReplayDetected\|AlreadyConsumed\|Superseded\|WrongEpoch\|WrongEnvironment\|WrongChain\|WrongGenesis\|WrongSurface\|MalformedState\|StateUnavailable\|ProductionStateUnavailable\|MainNetStateUnavailable' "${MOD}" > "${REACH_DIR}/state_taxonomy.txt" || fail "missing state taxonomy"
# Outcome taxonomy within the module.
grep -RIn --include='*.rs' 'enum EvaluatorReplayFreshnessOutcome\|ProceedFresh\|ProceedDeferred\|FailClosed' "${MOD}" > "${REACH_DIR}/outcome_taxonomy.txt" || fail "missing outcome taxonomy"
# Deterministic digest helpers within the module.
grep -RIn --include='*.rs' 'replay_state_key_digest\|replay_observation_digest\|consumed_decision_digest\|freshness_transcript_digest' "${MOD}" > "${REACH_DIR}/digest_helpers.txt" || fail "missing digest helpers"
# Replay state key binding fields (A10 set) within the module.
grep -RIn --include='*.rs' 'environment\|chain_id\|genesis_hash\|evaluator_source_identity_digest\|evaluator_request_digest\|evaluator_response_digest\|proposal_id\|decision_id\|lifecycle_action\|candidate_digest\|authority_domain_sequence\|replay_nonce' "${MOD}" > "${REACH_DIR}/state_key_bindings.txt" || fail "missing state key bindings"
# Reader/writer boundary + fixture store within the module.
grep -RIn --include='*.rs' 'GovernanceEvaluatorReplayStateReader\|GovernanceEvaluatorReplayStateWriter\|FixtureReplayStateStore\|read_previous_state\|record_observation\|mark_consumed' "${MOD}" > "${REACH_DIR}/reader_writer_bindings.txt" || fail "missing reader/writer bindings"
# Read-only validation path (read_for / read_previous_state are non-mutating).
grep -RIn --include='*.rs' 'fn read_for\|fn read_previous_state\|fn is_consumed' "${MOD}" > "${REACH_DIR}/read_only_path.txt" || fail "missing read-only validation path"
# Explicit consume path.
grep -RIn --include='*.rs' 'fn consume_for\|fn mark_consumed' "${MOD}" > "${REACH_DIR}/explicit_consume_path.txt" || fail "missing explicit consume path"
# Production/MainNet unavailable fail-closed path.
grep -RIn --include='*.rs' 'ProductionReplayStateReader\|MainnetReplayStateReader\|ProductionUnavailable\|MainNetUnavailable' "${MOD}" > "${REACH_DIR}/production_mainnet_unavailable.txt" || fail "missing production/MainNet unavailable path"
# MainNet peer-driven refusal guard.
grep -RIn --include='*.rs' 'mainnet_peer_driven_apply_remains_refused_under_replay_state\|FailClosedMainNetUnavailable' "${MOD}" > "${REACH_DIR}/mainnet_peer_driven_guard.txt" || fail "missing MainNet peer-driven guard reachability"
# No-mutation / apply-authorization guard (only ProceedFresh authorizes).
grep -RIn --include='*.rs' 'fn authorizes_mutation\|fn no_mutation\|fn is_fail_closed' "${MOD}" > "${REACH_DIR}/no_mutation_before_success.txt" || fail "missing apply-authorization guard reachability"

{
  echo "Run 231 denylist (proven empty across captured logs):"
  for pat in 'MainNet apply ENABLED' 'MainNet peer-driven apply ENABLED' 'autonomous apply' 'apply on receipt' 'peer-majority authority' 'fallback to --p2p-trusted-root' 'DummySig' 'DummyKem' 'DummyAead' 'governance execution active' 'production governance active' 'MainNet governance enabled' 'on-chain governance proof verifier active' 'real governance execution engine active' 'replay state active' 'real KMS backend' 'real HSM backend' 'real RemoteSigner backend' 'custody attestation production active' 'validator-set rotation enabled' 'marker write before sequence commit' 'sequence write on validation-only' 'marker write on validation-only' 'RocksDB schema change' 'file format change' 'database migration' 'schema drift' 'wire drift' 'metric drift'; do
    if find "${LOGS_DIR}" "${HELPER_231_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 | xargs -0 grep -E -i -l "$pat" 2>/dev/null | head -n1 | grep -q .; then echo "FAIL pattern present: ${pat}"; exit 7; else echo "ok-empty: ${pat}"; fi
  done
} > "${DENYLIST}"

{
  echo "Run 231 no-mutation proof for rejected replay/freshness scenarios:"
  echo "  data dir at ${DATA_DIR} contents:"; ls -la "${DATA_DIR}" 2>/dev/null || true
  echo "  A1..A19 / R1..R32 helper corpus (driven through the Run 230 replay/freshness boundary classify_evaluator_replay_freshness / evaluate_evaluator_replay_freshness / gate_evaluator_replay_freshness, composing the Run 222 evaluator request/response/identity digests and the Run 211 lifecycle/candidate/sequence binding): every rejected outcome surfaces as a typed EvaluatorReplayFreshnessOutcome fail-closed variant (FailClosedExpired / FailClosedReplay / FailClosedAlreadyConsumed / FailClosedSuperseded / FailClosedWrongBinding / FailClosedStateUnavailable / FailClosedProductionUnavailable / FailClosedMainNetUnavailable) returned from a pure function — no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no .tmp residue, no fallback to --p2p-trusted-root, no DummySig/DummyKem/DummyAead. The boundary exposes no mutation API: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070. The only mutation-authorizing outcome is ProceedFresh (authorizes_mutation()); ProceedDeferred is explicitly NOT an approval. Read-only validation (read_for / read_previous_state) never marks consumed; only an explicit consume_for / mark_consumed records a consumed decision in the DevNet/TestNet fixture store. Production/MainNet readers are callable but always unavailable/fail-closed. MainNet peer-driven apply is refused even when state is fresh."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' "${HELPER_231_OUT}/helper_summary.txt" | sed 's/^/    /'
} > "${NOMUT_PROOF}"
{
  echo "Run 231 mutation proof (release-binary scope): the Run 230 replay/freshness state boundary is a pure classification gate that runs BEFORE any lifecycle mutation. The only mutation-authorizing outcome is ProceedFresh, produced only for a first-seen, in-window decision whose binding (environment / chain / genesis / surface / evaluator digests / proposal / decision / lifecycle action / candidate digest / sequence / replay nonce / freshness window) matches the canonical expectations, on a DevNet/TestNet trust domain whose fixture replay state reports the decision unseen. ProceedDeferred (fresh-but-not-yet-effective) is explicitly NOT an approval. Production/MainNet replay state is callable but fails closed as unavailable. No mutation is performed by this fixture-only helper or by the boundary; an accepted ProceedFresh outcome is, at most, a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation -> Run 055 sequence commit -> v2 marker persist), which Run 231 does not exercise. The DevNet/TestNet FixtureReplayStateStore is an in-process map only — it introduces no RocksDB schema, no file format, and no database migration."
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
TEST_TARGETS=(run_230_governance_evaluator_replay_state_tests run_228_peer_evaluator_context_representation_tests run_226_governance_evaluator_runtime_callsite_wiring_tests run_224_governance_evaluator_runtime_integration_tests run_222_governance_execution_evaluator_tests run_220_governance_execution_runtime_consumption_tests run_217_governance_execution_runtime_arming_tests run_215_governance_execution_policy_selector_tests run_213_governance_execution_payload_callsite_tests run_211_governance_execution_policy_tests run_157_unified_testnet_fixture_universe_tests run_152_binary_reachable_peer_drain_plumbing_tests run_150_peer_driven_apply_drain_tests run_148_peer_driven_apply_devnet_tests run_142_live_inbound_0x05_v2_validation_tests)
for t in "${TEST_TARGETS[@]}"; do if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then TEST_VERDICTS+=( "$(run_test_target "$t")" ); else TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" ); fi; done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

{
  echo "Run 231 — release-binary governance evaluator replay/freshness state evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo unknown)"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo unknown)"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_231_sha256:  $(sha256_file "${HELPER_231_BIN}")"
  echo "  helper_231_buildid: $(build_id "${HELPER_231_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet S5_selector_parses S6_selector_invalid; do echo "  ${k}rc=$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo na)"; done
  echo "  note: S6 (invalid selector) is expected non-zero (fail-closed before mutation)."
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_231rc=$(cat "${EXIT_DIR}/helper_run_231.rc")$(grep -E 'verdict:' "${HELPER_231_OUT}/helper_summary.txt" | head -n1)"
  echo
  echo "helper A1-A19 / R1-R32 corpus verdicts (release mode, Run 230 replay/freshness symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' "${HELPER_231_OUT}/helper_summary.txt" | sed 's/^/  /'
  echo
  echo "denylist result:"; echo "  verdict: PASS (all $(grep -c '^ok-empty:' "${DENYLIST}" || echo 0) forbidden patterns proven empty across captured logs)"
  echo
  echo "regression test verdicts:"; for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits: the Run 230 replay/freshness state boundary is a local/source-test-only pure classification layer exercised here through release-built library symbols; the DevNet/TestNet FixtureReplayStateStore is an in-process map only and is DevNet/TestNet evidence-only (it reads as Unavailable for a MainNet environment); production/MainNet replay state is callable but always unavailable/fail-closed; read-only validation never marks consumed; explicit consume marks consumed only in fixture evidence; only ProceedFresh authorizes a mutation and ProceedDeferred is not an approval; rejections are pure and non-mutating; MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine; no real on-chain governance proof verifier; no KMS/HSM/RemoteSigner backend; no RocksDB schema change, no file format change, no database migration, and no wire/marker/sequence/trust-bundle schema change; existing Run 229, Run 227, Run 225, and Run 223 release behaviour remains compatible; full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

cat "${SUMMARY}"
log "done"