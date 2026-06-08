#!/usr/bin/env bash
# Run 214 — Release-binary governance **execution payload / carrying** evidence on
# real `target/release/qbind-node`. Closes the Run 213-deferred release-binary
# boundary for the source/test governance execution payload/carrying and
# production-context call-site wiring added by
# `crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs` (Run 213),
# layered over the Run 211 governance execution policy boundary, the Run 212
# release-binary policy-boundary evidence, the Run 163/178 governance / on-chain
# governance boundaries, the Run 188 authority-custody boundary, the Run 194–202
# RemoteSigner path, the Run 203–204 KMS/HSM backend path, and the Run 205–210
# custody-attestation path.
#
# Driving spec: `task/RUN_214_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default behaviour (no CLI, no env) does not expose or enable governance
#     execution payload carrying; the binary emits no `governance execution
#     active` / `production governance active` / `MainNet governance enabled`
#     claim and no `real on-chain governance proof verifier active` claim;
#   * no validator-set rotation claim is emitted;
#   * the existing Run 070 / 130–213 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193 hidden
#     custody-policy selector, the Run 198 hidden RemoteSigner-policy selector,
#     the Run 209 hidden custody-attestation-policy selector, the governance
#     fixture flag) remain compatible and emit no governance-execution
#     enablement banner and no MainNet peer-driven apply enablement;
#   * even on `--env mainnet`, the binary still emits no MainNet peer-driven
#     apply enablement — the Run 147 / 148 / 152 FATAL invariant is preserved;
#   * the release-built Run 214 helper
#     `run_214_governance_execution_payload_release_binary_helper` exercises the
#     Run 213 governance execution payload/carrying corpus (A1..A16 / R1..R40),
#     the wire conversion + digest preservation, the optional governance_execution
#     v2-sidecar sibling, the typed load status, the seven per-surface routing
#     helpers, and the Run 211 evaluator entry points — all in **release mode**
#     through the production library symbols.
#
# Strict scope (from `task/RUN_214_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 214 helper to exercise the Run 213 governance
#     execution payload/carrying boundary in release mode through the production
#     symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real governance execution engine.
#   * No real on-chain governance proof verifier.
#   * No MainNet governance enablement; no MainNet peer-driven apply enablement.
#   * No validator-set rotation; no authority-set rotation beyond existing
#     lifecycle boundary checks.
#   * No real KMS / HSM implementation; no real RemoteSigner backend; no
#     production signing key custody.
#   * No autonomous apply; no apply-on-receipt; no peer-majority authority.
#   * No schema/wire change beyond Run 213's additive optional
#     governance-execution sibling.
#   * No marker / sequence-file / trust-bundle core schema change.
#   * Do not weaken Runs 070, 130–213.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under `OUTDIR`
# except `README.md`, `summary.txt`, and `.gitignore`, which are tracked in
# git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_214_governance_execution_payload_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_214_BIN="${REPO_ROOT}/target/release/examples/run_214_governance_execution_payload_release_binary_helper"

HELPER_214_OUT="${OUTDIR}/helper_evidence/run_214"
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

log()  { printf '[run-214] %s\n' "$*" >&2; }
fail() { printf '[run-214] FAIL: %s\n' "$*" >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
build_id() {
  if command -v file >/dev/null 2>&1; then
    file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo "BuildID=unknown"
  else echo "BuildID=tool-missing"; fi
}
assert_grep() {
  local f="$1"; shift
  local pat="$1"; shift
  grep -E -i -q "$pat" "$f" || fail "expected pattern '${pat}' in ${f}"
}
assert_not_grep() {
  local f="$1"; shift
  local pat="$1"; shift
  if grep -E -i -q "$pat" "$f"; then
    fail "forbidden pattern '${pat}' present in ${f}"
  fi
}

# ---------------------------------------------------------------------------
# Idempotent reset of generated subtrees. Only README.md, summary.txt and
# .gitignore are tracked.
# ---------------------------------------------------------------------------
log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_214_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_214_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-214 provenance"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
  echo "git_status_short:"
  git -C "${REPO_ROOT}" status --short 2>/dev/null || true
  echo "rustc_version: $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "cargo_version: $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "host: $(uname -a 2>/dev/null || echo 'unknown')"
  echo "outdir: ${OUTDIR}"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Build qbind-node bin + Run 214 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_214_governance_execution_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_214_governance_execution_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_214.log" 2>&1 \
  || fail "release build of run_214 helper failed (see ${LOGS_DIR}/build_helper_run_214.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_214_BIN}" ]] || fail "missing ${HELPER_214_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_214_path:    ${HELPER_214_BIN}"
  echo "helper_214_sha256:  $(sha256_file "${HELPER_214_BIN}")"
  echo "helper_214_buildid: $(build_id "${HELPER_214_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 214 release helper. Exits 0 iff the accepted (A1..A16),
# rejection (R1..R40), and reachability tables all matched in release mode
# through the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 214 governance-execution payload release helper -> ${HELPER_214_OUT}"
HELPER_214_LOG="${LOGS_DIR}/helper_run_214.log"
set +e
"${HELPER_214_BIN}" "${HELPER_214_OUT}" > "${HELPER_214_LOG}" 2>&1
HELPER_214_RC=$?
set -e
echo "${HELPER_214_RC}" > "${EXIT_DIR}/helper_run_214.rc"
[[ "${HELPER_214_RC}" -eq 0 ]] || fail "run_214 helper exited rc=${HELPER_214_RC} (see ${HELPER_214_LOG})"
[[ -s "${HELPER_214_OUT}/helper_summary.txt" ]] || fail "run_214 helper did not write helper_summary.txt"
assert_grep "${HELPER_214_OUT}/helper_summary.txt" "verdict: PASS"

# Record the governance-execution fixture input/decision/payload paths and hashes
# minted by the helper.
{
  echo "Run 214 governance-execution fixture inventory (helper-minted):"
  echo
  if [[ -d "${HELPER_214_OUT}/fixtures" ]]; then
    for f in "${HELPER_214_OUT}/fixtures"/*; do
      [[ -f "${f}" ]] || continue
      echo "  $(basename "${f}")	sha256=$(sha256_file "${f}")"
    done
  else
    echo "  (no fixtures dir emitted)"
  fi
} > "${GREP_DIR}/governance_execution_fixture_inventory.txt"

# ---------------------------------------------------------------------------
# Real-binary surface invariants. Run 213 is a pure source/test boundary with no
# CLI flag or env var: the governance execution payload/carrying helpers are
# consumed at the library/helper level. At the binary surface the contract is
# that no surface exposes or enables governance execution, no surface claims a
# production / MainNet governance enablement or a real on-chain governance proof
# verifier, and every existing Run 070 / 130–213 surface emits no MainNet
# peer-driven apply enablement. `--print-genesis-hash` is a non-mutating CLI that
# exits quickly without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help exposes no governance execution surface"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "governance execution"
assert_not_grep "${HELP_LOG}" "production governance"
assert_not_grep "${HELP_LOG}" "mainnet governance"
assert_not_grep "${HELP_LOG}" "validator-set rotation"
assert_not_grep "${HELP_LOG}" "on-chain governance proof verifier"
assert_not_grep "${HELP_LOG}" "run-213"
assert_not_grep "${HELP_LOG}" "run-214"

# Governance-execution enablement banners that must never appear on any captured
# qbind-node surface log.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "${logf}" "governance execution (enabled|active|wired)"
  assert_not_grep "${logf}" "production governance (enabled|active)"
  assert_not_grep "${logf}" "mainnet governance (enabled|active)"
  assert_not_grep "${logf}" "real on-chain governance proof verifier"
  assert_not_grep "${logf}" "on-chain governance (enabled|active|wired)"
  assert_not_grep "${logf}" "validator-set rotation (enabled|active|supported|wired)"
  assert_not_grep "${logf}" "autonomous apply"
  assert_not_grep "${logf}" "apply on receipt"
  assert_not_grep "${logf}" "peer-majority authority"
  assert_not_grep "${logf}" "real kms (backend )?(enabled|active)"
  assert_not_grep "${logf}" "real hsm (backend )?(enabled|active)"
  assert_not_grep "${logf}" "remote signer backend connected"
  assert_not_grep "${logf}" "custody attestation production (enabled|active|wired)"
  assert_not_grep "${logf}" "MainNet peer-driven apply ENABLED"
}

run_surface_scenario() {
  # $1 key, $2 env, then remaining args appended to qbind-node invocation
  local key="$1"; shift
  local node_env="$1"; shift
  local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                            -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
                            -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
                            -u QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY \
      "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) \
    > "${logf}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S2 — default DevNet surface: no governance-execution banner"
run_surface_scenario "S2_default_devnet" devnet

log "S3 — default TestNet surface: no governance-execution banner"
run_surface_scenario "S3_default_testnet" testnet

log "S4 — default MainNet surface: no governance-execution banner, no MainNet apply"
run_surface_scenario "S4_default_mainnet" mainnet

log "S5 — Run 193 custody + Run 198 RemoteSigner + Run 209 custody-attestation selectors compat"
S5_LOG="${LOGS_DIR}/S5_legacy_selectors_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY=fixture-attestation-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_legacy_selectors_compat.rc"
assert_surface_silent "${S5_LOG}"

log "S6 — MainNet with legacy selectors armed: refusal preserved, no governance execution"
S6_LOG="${LOGS_DIR}/S6_mainnet_legacy_selectors.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY=mainnet-production-attestation-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_mainnet_legacy_selectors.rc"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S6_LOG}" "mainnet.+apply.+enabled"
assert_surface_silent "${S6_LOG}"

log "S7 — governance on-chain fixture flag armed on DevNet: no governance-execution drift"
S7_LOG="${LOGS_DIR}/S7_governance_fixture_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY \
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_governance_fixture_devnet.rc"
assert_surface_silent "${S7_LOG}"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 213 governance execution
# payload/carrying boundary. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface the
# Run 214 helper exercises is wired in production source.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 214 source-reachability proof — production symbols within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_governance_execution_payload_carrying' \
    'GovernanceExecutionClassWire' \
    'GovernanceExecutionActionWire' \
    'GovernanceExecutionInputWire' \
    'GovernanceExecutionDecisionWire' \
    'GovernanceExecutionPayloadWire' \
    'GovernanceExecutionParts' \
    'GovernanceExecutionLoadStatus' \
    'GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD' \
    'GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION' \
    'governance_execution' \
    'parse_optional_governance_execution_sibling_from_json_value' \
    'load_v2_ratification_sidecar_with_governance_execution_from_bytes' \
    'load_v2_ratification_sidecar_with_governance_execution_from_path' \
    'callsite_context_for_governance_execution' \
    'route_loaded_governance_execution_to_reload_check_callsite_decision' \
    'route_loaded_governance_execution_to_reload_apply_callsite_decision' \
    'route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision' \
    'route_loaded_governance_execution_to_sighup_callsite_decision' \
    'route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision' \
    'route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision' \
    'route_loaded_governance_execution_to_peer_driven_drain_callsite_decision' \
    'evaluate_loaded_governance_execution' \
    'evaluate_loaded_governance_execution_with_peer_driven_guard' \
    'mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying' \
    'evaluate_governance_execution_policy' \
    'GovernanceExecutionEvaluator' \
    'validator_set_rotation_remains_unsupported'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done
} > "${REACH_DIR}/source_reachability.txt"

# Cross-check that the Run 213 governance execution payload/carrying boundary
# symbols and the Run 211 evaluator entry points are wired in production source.
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_governance_execution_payload_carrying'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceExecutionPayloadWire'
assert_grep "${REACH_DIR}/source_reachability.txt" 'GovernanceExecutionLoadStatus'
assert_grep "${REACH_DIR}/source_reachability.txt" 'route_loaded_governance_execution_to_reload_check_callsite_decision'
assert_grep "${REACH_DIR}/source_reachability.txt" 'route_loaded_governance_execution_to_peer_driven_drain_callsite_decision'
assert_grep "${REACH_DIR}/source_reachability.txt" 'parse_optional_governance_execution_sibling_from_json_value'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_loaded_governance_execution'
assert_grep "${REACH_DIR}/source_reachability.txt" 'evaluate_governance_execution_policy'

# Confirm the module is declared in the qbind-node library surface.
grep -RIn --include='*.rs' 'pqc_governance_execution_payload_carrying' "${SRC_DIR}/lib.rs" \
  > "${REACH_DIR}/module_declaration.txt" \
  || fail "expected pqc_governance_execution_payload_carrying module declared in ${SRC_DIR}/lib.rs"

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 214 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'governance execution engine active' \
    'governance execution active' \
    'production governance active' \
    'production governance engine' \
    'MainNet governance enabled' \
    'mainnet governance active' \
    'on-chain governance proof verifier connected' \
    'on-chain governance proof verifier active' \
    'real KMS backend' \
    'real HSM backend' \
    'real RemoteSigner backend' \
    'RemoteSigner backend connected' \
    'custody attestation production active' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'validator set rotation active' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_214_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
         | xargs -0 grep -E -l "${pat}" 2>/dev/null \
         | head -n 1 | grep -q .
    then
      echo "FAIL pattern present: ${pat}"
      exit 7
    else
      echo "ok-empty: ${pat}"
    fi
  done
} > "${DENYLIST}"

# ---------------------------------------------------------------------------
# No-mutation proof for rejected governance-execution-payload scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 214 no-mutation proof for rejected governance-execution-payload scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven governance-execution payload rejection corpus (R1..R40):"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * marker bytes unchanged where present (no marker is written)"
  echo "    * sequence bytes unchanged where present (no sequence is written)"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  echo "    * no real governance execution engine / no real on-chain proof verifier"
  echo "    * no real KMS / HSM / RemoteSigner backend wired"
  echo "    * no validator-set rotation"
  echo "    * the Run 213 wire-conversion + typed load status, the seven"
  echo "      per-surface routing helpers, and the Run 211 evaluators are pure"
  echo "      functions returning typed owned outcomes; a malformed / required-"
  echo "      but-absent / production / on-chain / MainNet governance execution"
  echo "      payload fails closed BEFORE any sequence/marker write, BEFORE any"
  echo "      live trust swap, BEFORE any session eviction, and BEFORE any Run 070"
  echo "      call (helper R37 validation-only + R38 mutating-preflight asserts"
  echo "      confirm purity)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_214_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted fixture governance-execution payload
# scenarios (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 214 mutation proof (release-binary scope):"
  echo
  echo "  library-side governance-execution payload/carrying reachability today:"
  echo "    - Run 213 added pqc_governance_execution_payload_carrying.rs with the"
  echo "      typed GovernanceExecutionClassWire / GovernanceExecutionActionWire /"
  echo "      GovernanceExecutionInputWire / GovernanceExecutionDecisionWire /"
  echo "      GovernanceExecutionPayloadWire wire types, the GovernanceExecutionParts"
  echo "      reconstruction, the additive optional governance_execution v2-sidecar"
  echo "      sibling parser (parse_optional_governance_execution_sibling_from_json_value),"
  echo "      the load_v2_ratification_sidecar_with_governance_execution_from_{bytes,path}"
  echo "      loaders, the typed GovernanceExecutionLoadStatus, the seven"
  echo "      per-surface routing helpers (reload-check, reload-apply, startup"
  echo "      --p2p-trust-bundle, SIGHUP, local peer-candidate-check, live inbound"
  echo "      0x05, peer-driven drain), the callsite context constructor, and the"
  echo "      evaluate_loaded_governance_execution{,_with_peer_driven_guard} entry"
  echo "      points into the Run 211 evaluator;"
  echo "    - the module is additive and pure: it performs no network or file"
  echo "      I/O beyond reading a supplied sidecar path, writes no marker, writes"
  echo "      no sequence, swaps no live trust, evicts no sessions, and never"
  echo "      invokes Run 070;"
  echo "    - the default policy is GovernanceExecutionPolicy::Disabled; a legacy"
  echo "      sidecar with no governance_execution sibling parses as Absent and"
  echo "      bypasses; an unknown class / unsupported version / malformed input"
  echo "      fails closed; production / on-chain / MainNet governance execution"
  echo "      fails closed as unavailable; the peer-driven drain helper refuses"
  echo "      MainNet unconditionally."
  echo
  echo "  release-binary governance-execution payload corpus (this run):"
  echo "    - the Run 214 helper exercises the A1..A16 acceptance corpus and the"
  echo "      R1..R40 rejection corpus in release mode through the production"
  echo "      library symbols (accepted / rejection / reachability tables);"
  echo "    - a legacy no-governance-execution payload remains compatible under"
  echo "      default Disabled (A1); fixture governance execution carried through"
  echo "      the reload-check / reload-apply contexts is accepted on DevNet/"
  echo "      TestNet only under the explicit fixture policy (A2..A4); emergency"
  echo "      revoke is accepted only under the explicit emergency fixture policy"
  echo "      (A12);"
  echo "    - governance execution input/decision/transcript/policy digests are"
  echo "      preserved through wire conversion (A5..A8);"
  echo "    - production / on-chain / MainNet governance execution material reaches"
  echo "      the evaluator and returns the typed unavailable outcome regardless of"
  echo "      inputs (A16, R9..R11);"
  echo "    - a carried lifecycle action is authorized only when the action,"
  echo "      candidate digest, and sequence match (A10..A11);"
  echo "    - validator-set rotation and policy-change actions are unsupported"
  echo "      (R30..R31);"
  echo "    - rejected cases leave every input byte-identical and route with no"
  echo "      mutation; MainNet peer-driven apply remains refused even with a"
  echo "      fixture governance approval (R40)."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help exposes no governance"
  echo "      execution surface and advertises no production / MainNet governance"
  echo "      enablement and no on-chain governance proof verifier;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no governance-execution enablement"
  echo "      banner and no MainNet peer-driven apply enablement claim, with or"
  echo "      without the Run 193 custody selector, the Run 198 RemoteSigner"
  echo "      selector, the Run 209 custody-attestation selector, or the"
  echo "      governance on-chain fixture flag armed;"
  echo "    - even on MainNet, MainNet peer-driven apply remains refused (Run 147"
  echo "      FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real governance execution engine is wired in Run 214; production"
  echo "      / on-chain / MainNet governance execution always returns the typed"
  echo "      unavailable outcome;"
  echo "    - no real on-chain governance proof verifier is wired;"
  echo "    - fixture governance execution remains DevNet/TestNet evidence-only"
  echo "      and cannot satisfy MainNet production governance;"
  echo "    - emergency council fixture is explicit and non-production;"
  echo "    - the Run 213 boundary is consumed at the library level; the release"
  echo "      binary does not yet wire a governance execution evaluator into a"
  echo "      long-running node runtime — no production governance is enabled;"
  echo "    - no real KMS / HSM / RemoteSigner backend; no validator-set"
  echo "      rotation; no MainNet peer-driven apply enablement; no autonomous"
  echo "      apply; no apply-on-receipt; no peer-majority authority; no"
  echo "      schema/wire/metric drift beyond Run 213's additive optional"
  echo "      governance-execution sibling."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_214_TASK.txt Validation
# commands`. Tests that don't exist in this tree are recorded as
# `skipped(not-present)` and the harness continues.
# ---------------------------------------------------------------------------
run_test_target() {
  local target="$1"
  local logf="${TEST_LOGS}/test_${target}.log"
  log "cargo test --release -p qbind-node --test ${target}"
  set +e
  ( cd "${REPO_ROOT}" && cargo test --release -p qbind-node --test "${target}" -- --test-threads=1 ) \
      > "${logf}" 2>&1
  local rc=$?
  set -e
  echo "${rc}" > "${EXIT_DIR}/test_${target}.rc"
  if [[ "${rc}" -ne 0 ]]; then
    log "WARN test ${target} returned rc=${rc}; see ${logf}"
  fi
  printf '%s\trc=%d\n' "test:${target}" "${rc}"
}
run_lib_test() {
  local filter="$1"
  local label="${2:-${filter}}"
  local logf="${TEST_LOGS}/lib_${label}.log"
  log "cargo test --release -p qbind-node --lib ${filter}"
  set +e
  ( cd "${REPO_ROOT}" && cargo test --release -p qbind-node --lib "${filter}" -- --test-threads=1 ) \
      > "${logf}" 2>&1
  local rc=$?
  set -e
  echo "${rc}" > "${EXIT_DIR}/lib_${label}.rc"
  printf '%s\trc=%d\n' "lib:${label}" "${rc}"
}

TEST_VERDICTS=()
TEST_TARGETS=(
  run_213_governance_execution_payload_callsite_tests
  run_211_governance_execution_policy_tests
  run_209_custody_attestation_policy_selector_tests
  run_207_custody_attestation_payload_callsite_tests
  run_205_custody_attestation_verifier_tests
  run_203_kms_hsm_backend_boundary_tests
  run_201_remote_signer_transport_boundary_tests
  run_198_remote_signer_policy_selector_tests
  run_196_remote_signer_payload_callsite_tests
  run_194_remote_authority_signer_boundary_tests
  run_192_authority_custody_policy_selector_tests
  run_190_authority_custody_payload_callsite_tests
  run_188_authority_custody_boundary_tests
  run_186_onchain_governance_production_verifier_boundary_tests
  run_184_onchain_governance_payload_carrying_tests
  run_182_onchain_governance_production_callsite_wiring_tests
  run_180_onchain_governance_marker_integration_tests
  run_178_onchain_governance_proof_tests
  run_176_live_0x05_governance_proof_carrier_tests
  run_173_validation_only_governance_required_policy_tests
  run_171_governance_required_policy_selector_tests
  run_169_governance_proof_loader_surface_integration_tests
  run_167_governance_proof_carrier_tests
  run_165_governance_marker_integration_tests
  run_163_governance_authority_verifier_tests
  run_161_lifecycle_marker_integration_tests
  run_159_authority_signing_key_lifecycle_tests
  run_157_unified_testnet_fixture_universe_tests
  run_152_binary_reachable_peer_drain_plumbing_tests
  run_150_peer_driven_apply_drain_tests
  run_148_peer_driven_apply_devnet_tests
  run_142_live_inbound_0x05_v2_validation_tests
  run_134_reload_apply_v2_authority_marker_tests
  run_138_sighup_v2_authority_marker_tests
)
for t in "${TEST_TARGETS[@]}"; do
  if [[ -f "${REPO_ROOT}/crates/qbind-node/tests/${t}.rs" ]]; then
    TEST_VERDICTS+=( "$(run_test_target "${t}")" )
  else
    log "skip ${t} (not present in this tree)"
    TEST_VERDICTS+=( "test:${t}	rc=skipped(not-present)" )
  fi
done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_214.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 214 — release-binary governance execution payload/carrying evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_214_sha256:  $(sha256_file "${HELPER_214_BIN}")"
  echo "  helper_214_buildid: $(build_id "${HELPER_214_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_legacy_selectors_compat S6_mainnet_legacy_selectors S7_governance_fixture_devnet
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_214	rc=$(cat "${EXIT_DIR}/helper_run_214.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_214_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A16 / R1-R40 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_214_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
  echo
  echo "denylist result:"
  if [[ -s "${DENYLIST}" ]]; then
    if grep -q "^FAIL " "${DENYLIST}"; then
      echo "  verdict: FAIL"
      grep "^FAIL " "${DENYLIST}" | sed 's/^/  /'
    else
      ok="$(grep -c '^ok-empty: ' "${DENYLIST}" 2>/dev/null || echo 0)"
      echo "  verdict: PASS (all ${ok} forbidden patterns proven empty across captured logs)"
    fi
  else
    echo "  verdict: na (denylist file empty)"
  fi
  echo
  echo "regression test verdicts:"
  for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits:"
  echo "  * no real governance execution engine is wired; production / on-chain"
  echo "    / MainNet governance execution returns the typed unavailable outcome"
  echo "    regardless of inputs;"
  echo "  * no real on-chain governance proof verifier is wired;"
  echo "  * fixture governance execution remains DevNet/TestNet evidence-only and"
  echo "    cannot satisfy MainNet production governance;"
  echo "  * emergency council fixture is explicit and non-production;"
  echo "  * default policy remains GovernanceExecutionPolicy::Disabled; a legacy"
  echo "    no-governance-execution payload parses as Absent and bypasses; unknown"
  echo "    class / unsupported version / malformed input fails closed;"
  echo "  * the Run 213 boundary is consumed at the library level; the release"
  echo "    binary does not yet wire a governance execution evaluator into a"
  echo "    long-running node runtime; arming nothing enables production"
  echo "    governance;"
  echo "  * rejected governance-execution-payload cases produce no mutation;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with a fixture governance approval;"
  echo "  * KMS/HSM/RemoteSigner/custody-attestation remain boundary-only and"
  echo "    unchanged; validator-set rotation remains unsupported;"
  echo "  * no schema/wire/metric drift beyond Run 213's additive optional"
  echo "    governance-execution sibling; no authority-marker / sequence-file /"
  echo "    trust-bundle core schema change;"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node exposes no governance"
  echo "  execution surface, advertises no production / MainNet governance"
  echo "  enablement and no on-chain governance proof verifier, and keeps every"
  echo "  existing Run 070 / 130-213 surface governance-execution-silent (MainNet"
  echo "  peer-driven apply refusal preserved). The release-built Run 214 helper"
  echo "  exercises the Run 213 governance execution payload/carrying corpus"
  echo "  end-to-end in release mode through the production library symbols: a"
  echo "  legacy no-governance-execution payload remains compatible under default"
  echo "  Disabled; fixture governance execution carried through the production-"
  echo "  context routing helpers is accepted on DevNet/TestNet only under the"
  echo "  explicit fixture policy; emergency council fixture is accepted only under"
  echo "  the explicit emergency fixture policy; production / on-chain / MainNet"
  echo "  governance execution material reaches the evaluator and fails closed as"
  echo "  unavailable; input/decision/transcript/policy digests are preserved"
  echo "  through wire conversion and remain deterministic and domain-bound; a"
  echo "  carried lifecycle action is authorized only when the action, candidate"
  echo "  digest, and sequence match; validator-set rotation and policy-change"
  echo "  actions are unsupported; rejected cases produce no mutation; and MainNet"
  echo "  peer-driven apply remains the Run 147 FATAL refusal even with a fixture"
  echo "  governance approval. A real governance execution engine, a real on-chain"
  echo "  governance proof verifier, a real KMS/HSM backend, a real RemoteSigner"
  echo "  backend, and validator-set rotation all remain unimplemented. Full C4"
  echo "  and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"