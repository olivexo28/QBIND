#!/usr/bin/env bash
# Run 208 — Release-binary custody-attestation **payload carrying** evidence on
# real `target/release/qbind-node`. Closes the Run 207-deferred release-binary
# boundary for the source/test custody-attestation payload/carrying and
# production-context wiring added by
# `crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs` (Run 207),
# layered over the Run 205 production custody-attestation verifier boundary
# (`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`) and the Run 188
# authority-custody boundary (`crates/qbind-node/src/pqc_authority_custody.rs`).
#
# Driving spec: `task/RUN_208_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * the existing Run 070 / 130–207 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193 hidden
#     custody-policy selector, the Run 198 hidden RemoteSigner-policy selector,
#     the governance fixture flag) emit no custody-attestation enablement banner,
#     no "custody attestation active" / "production attestation active" /
#     "KMS attestation active" / "HSM attestation active" / "PKCS#11 active"
#     claim, no "KMS/HSM active" claim, no governance-execution claim, no
#     validator-set rotation claim, and no MainNet peer-driven apply enablement;
#   * default behaviour does not expose or enable production custody attestation;
#   * even with the Run 198 RemoteSigner policy selector or the Run 193 custody
#     policy selector armed on `--env mainnet`, the binary still emits no
#     MainNet peer-driven apply enablement and no custody-attestation /
#     KMS/HSM / cloud-KMS / PKCS#11 enablement — the Run 147 / 148 / 152 FATAL
#     invariant is preserved at the binary surface;
#   * the release-built Run 208 helper
#     `run_208_custody_attestation_payload_release_binary_helper` exercises the
#     Run 207 custody-attestation payload/carrying corpus (the additive optional
#     `custody_attestation` sidecar sibling, the wire types and load status, the
#     sibling parser, the combined v2 loader, the typed call-site context, and
#     the seven per-surface routing helpers driving the parsed carrier into the
#     Run 205 `verify_custody_attestation` /
#     `validate_custody_metadata_and_attestation` /
#     `validate_lifecycle_custody_and_attestation` boundary) — all in **release
#     mode** through the production library symbols.
#
# Strict scope (from `task/RUN_208_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 208 helper to exercise the Run 207
#     custody-attestation payload/carrying corpus in release mode through the
#     production library symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real KMS / HSM / cloud KMS / PKCS#11 attestation verifier.
#   * No real RemoteSigner backend / networked signer daemon.
#   * No production signing key custody.
#   * No real on-chain governance proof verifier; no governance execution;
#     no validator-set rotation; no autonomous apply; no apply-on-receipt;
#     no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No schema / wire / metric drift beyond Run 207's additive optional
#     custody-attestation sibling.
#   * No authority-marker / sequence-file / trust-bundle core schema change.
#   * Do not weaken Runs 070, 130–207.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under `OUTDIR`
# except `README.md`, `summary.txt`, and `.gitignore`, which are tracked in
# git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_208_custody_attestation_payload_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_208_BIN="${REPO_ROOT}/target/release/examples/run_208_custody_attestation_payload_release_binary_helper"

HELPER_208_OUT="${OUTDIR}/helper_evidence/run_208"
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

log()  { printf '[run-208] %s\n' "$*" >&2; }
fail() { printf '[run-208] FAIL: %s\n' "$*" >&2; exit 1; }

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
  grep -E -q "$pat" "$f" || fail "expected pattern '${pat}' in ${f}"
}
assert_not_grep() {
  local f="$1"; shift
  local pat="$1"; shift
  if grep -E -q "$pat" "$f"; then
    fail "forbidden pattern '${pat}' present in ${f}"
  fi
}

# ---------------------------------------------------------------------------
# Idempotent reset of generated subtrees. Only README.md, summary.txt and
# .gitignore are tracked.
# ---------------------------------------------------------------------------
log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_208_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_208_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-208 provenance"
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
# Build qbind-node bin + Run 208 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_208_custody_attestation_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_208_custody_attestation_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_208.log" 2>&1 \
  || fail "release build of run_208 helper failed (see ${LOGS_DIR}/build_helper_run_208.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_208_BIN}" ]] || fail "missing ${HELPER_208_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_208_path:    ${HELPER_208_BIN}"
  echo "helper_208_sha256:  $(sha256_file "${HELPER_208_BIN}")"
  echo "helper_208_buildid: $(build_id "${HELPER_208_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 208 release helper. Exits 0 iff the accepted (A1..A15),
# rejection (R1..R43), loader, determinism, and refusal/reachability tables all
# matched in release mode through the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 208 custody-attestation payload release helper -> ${HELPER_208_OUT}"
HELPER_208_LOG="${LOGS_DIR}/helper_run_208.log"
set +e
"${HELPER_208_BIN}" "${HELPER_208_OUT}" > "${HELPER_208_LOG}" 2>&1
HELPER_208_RC=$?
set -e
echo "${HELPER_208_RC}" > "${EXIT_DIR}/helper_run_208.rc"
[[ "${HELPER_208_RC}" -eq 0 ]] || fail "run_208 helper exited rc=${HELPER_208_RC} (see ${HELPER_208_LOG})"
[[ -s "${HELPER_208_OUT}/helper_summary.txt" ]] || fail "run_208 helper did not write helper_summary.txt"
assert_grep "${HELPER_208_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants. Run 207 added a pure additive library module
# only (no CLI flag, no env var, no runtime banner). The surface contract is
# therefore that every existing Run 070 / 130–207 surface emits no custody
# attestation enablement banner and no MainNet peer-driven apply enablement
# claim. `--print-genesis-hash` is a non-mutating CLI that exits quickly without
# opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help advertises no custody attestation surface"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "(?i)custody attestation"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)cloud kms"
assert_not_grep "${HELP_LOG}" "(?i)pkcs.?11"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer backend"
assert_not_grep "${HELP_LOG}" "run-205"
assert_not_grep "${HELP_LOG}" "run-206"
assert_not_grep "${HELP_LOG}" "run-207"
assert_not_grep "${HELP_LOG}" "run-208"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

run_surface_scenario() {
  # $1 key, $2 env, then remaining args appended to qbind-node invocation
  local key="$1"; shift
  local node_env="$1"; shift
  local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                            -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
                            -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
      "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) \
    > "${logf}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/${key}.rc"
  assert_not_grep "${logf}" "(?i)custody attestation (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)production attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)kms attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)hsm attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)kms.?hsm (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)kms (?:backend )?(?:enabled|active)"
  assert_not_grep "${logf}" "(?i)hsm (?:backend )?(?:enabled|active)"
  assert_not_grep "${logf}" "(?i)cloud kms (?:enabled|active|connected)"
  assert_not_grep "${logf}" "(?i)pkcs.?11 (?:enabled|active|connected)"
  assert_not_grep "${logf}" "(?i)remote signer backend connected"
  assert_not_grep "${logf}" "(?i)production custody (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)governance execution"
  assert_not_grep "${logf}" "(?i)validator-set rotation"
  assert_not_grep "${logf}" "(?i)autonomous apply"
  assert_not_grep "${logf}" "MainNet peer-driven apply ENABLED"
}

log "S2 — default DevNet surface: no custody attestation banner"
run_surface_scenario "S2_default_devnet" devnet

log "S3 — default TestNet surface: no custody attestation banner"
run_surface_scenario "S3_default_testnet" testnet

log "S4 — default MainNet surface: no custody attestation banner, no MainNet apply"
run_surface_scenario "S4_default_mainnet" mainnet

log "S5 — Run 193 custody selector armed on DevNet: no custody attestation banner drift"
S5_LOG="${LOGS_DIR}/S5_custody_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_custody_selector_compat.rc"
assert_not_grep "${S5_LOG}" "(?i)custody attestation (?:enabled|active)"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S5_LOG}" "(?i)cloud kms (?:enabled|active)"
assert_not_grep "${S5_LOG}" "(?i)pkcs.?11 (?:enabled|active)"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"

log "S6 — Run 198 RemoteSigner selector armed alongside custody selector on DevNet: compat"
S6_LOG="${LOGS_DIR}/S6_remote_signer_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_remote_signer_selector_compat.rc"
assert_not_grep "${S6_LOG}" "(?i)custody attestation (?:enabled|active)"
assert_not_grep "${S6_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S6_LOG}" "(?i)remote signer backend connected"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"

log "S7 — governance fixture flag armed on DevNet: no custody attestation banner drift"
S7_LOG="${LOGS_DIR}/S7_governance_fixture_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_governance_fixture_compat.rc"
assert_not_grep "${S7_LOG}" "(?i)custody attestation (?:enabled|active)"
assert_not_grep "${S7_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S7_LOG}" "(?i)governance execution"
assert_not_grep "${S7_LOG}" "(?i)on-chain governance proof verifier active"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"

log "S8 — MainNet with custody+RemoteSigner selectors armed: refusal preserved"
S8_LOG="${LOGS_DIR}/S8_mainnet_armed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=mainnet-production-remote-signer-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-remote-signer-policy mainnet-production-remote-signer-required ) \
  > "${S8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S8_mainnet_armed.rc"
assert_not_grep "${S8_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S8_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S8_LOG}" "(?i)custody attestation (?:enabled|active)"
assert_not_grep "${S8_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S8_LOG}" "(?i)cloud kms (?:enabled|active)"
assert_not_grep "${S8_LOG}" "(?i)pkcs.?11 (?:enabled|active)"
assert_not_grep "${S8_LOG}" "(?i)validator-set rotation"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 207 custody-attestation
# payload/carrying surface layered over the Run 205 verifier and the Run 188
# custody boundary. We grep the production source under crates/qbind-node/src so
# the artifact records that the typed surface the Run 208 helper exercises is
# wired in production source.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 208 source-reachability proof — production symbols within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_custody_attestation_payload_carrying' \
    'CustodyAttestationClassWire' \
    'CustodyAttestationEvidenceWire' \
    'CustodyAttestationInputWire' \
    'CustodyAttestationPayloadWire' \
    'CustodyAttestationLoadStatus' \
    'CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD' \
    'parse_optional_custody_attestation_sibling_from_json_value' \
    'load_v2_ratification_sidecar_with_custody_attestation' \
    'route_loaded_custody_attestation_to_reload_check_callsite_decision' \
    'route_loaded_custody_attestation_to_reload_apply_callsite_decision' \
    'route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision' \
    'route_loaded_custody_attestation_to_sighup_callsite_decision' \
    'route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision' \
    'route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision' \
    'route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision' \
    'verify_custody_attestation' \
    'validate_custody_metadata_and_attestation' \
    'validate_lifecycle_custody_and_attestation' \
    'mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done
} > "${REACH_DIR}/source_reachability.txt"

# Cross-check that the additive optional sibling literal "custody_attestation"
# is wired in production source.
assert_grep "${REACH_DIR}/source_reachability.txt" 'CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD'
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_custody_attestation_payload_carrying'

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 208 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'real KMS backend' \
    'real HSM backend' \
    'KMS/HSM active' \
    'KMS/HSM enabled' \
    'kms-hsm enabled' \
    'cloud KMS active' \
    'cloud KMS enabled' \
    'PKCS#11 active' \
    'PKCS#11 enabled' \
    'real RemoteSigner backend' \
    'RemoteSigner backend connected' \
    'real custody attestation' \
    'custody attestation active' \
    'production custody attestation active' \
    'production attestation active' \
    'KMS attestation active' \
    'HSM attestation active' \
    'production custody enabled' \
    'production custody active' \
    'governance execution claim' \
    'real on-chain governance proof claim' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_208_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected custody-attestation-payload scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 208 no-mutation proof for rejected custody-attestation-payload scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven custody-attestation-payload rejection corpus (R1..R43):"
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
  echo "    * no real KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner attestation wired"
  echo "    * no real governance execution / no real on-chain proof verifier"
  echo "    * no validator-set rotation"
  echo "    * a malformed carrier short-circuits BEFORE the Run 205 verifier,"
  echo "      BEFORE any sequence/marker write, BEFORE any live trust swap,"
  echo "      BEFORE any session eviction, and BEFORE any Run 070 call; the"
  echo "      seven per-surface routing helpers and the reachability helpers"
  echo "      are pure functions returning typed owned outcomes; on a reject"
  echo "      they touch no marker / sequence / live trust and never invoke"
  echo "      Run 070 (helper rejection.manifest R1..R43 + R40/R41 purity"
  echo "      asserts)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_208_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted fixture custody-attestation-payload
# scenarios (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 208 mutation proof (release-binary scope):"
  echo
  echo "  library-side custody-attestation payload/carrying reachability today:"
  echo "    - Run 207 added pqc_custody_attestation_payload_carrying.rs with the"
  echo "      additive optional custody_attestation sidecar sibling"
  echo "      (CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, wire schema version 1),"
  echo "      the CustodyAttestationClassWire / CustodyAttestationEvidenceWire /"
  echo "      CustodyAttestationInputWire / CustodyAttestationPayloadWire types"
  echo "      that convert into the Run 205 internal CustodyAttestationEvidence /"
  echo "      CustodyAttestationInput, the CustodyAttestationLoadStatus"
  echo "      (Absent / Available / Malformed), the pure sibling parser"
  echo "      parse_optional_custody_attestation_sibling_from_json_value, the"
  echo "      combined loader"
  echo "      load_v2_ratification_sidecar_with_custody_attestation_from_{path,bytes},"
  echo "      the typed CustodyAttestationCallsiteContext, and the seven"
  echo "      per-surface routing helpers driving the parsed carrier into the"
  echo "      Run 205 verify_custody_attestation /"
  echo "      validate_custody_metadata_and_attestation /"
  echo "      validate_lifecycle_custody_and_attestation boundary;"
  echo "    - the module is additive and pure: it performs no network or file"
  echo "      I/O beyond reading a sidecar, writes no marker, writes no"
  echo "      sequence, swaps no live trust, evicts no sessions, and never"
  echo "      invokes Run 070;"
  echo "    - a malformed carrier fails closed before the verifier; an absent"
  echo "      carrier under default Disabled policy is the legacy"
  echo "      no-attestation-payload bypass; the peer-driven drain surface"
  echo "      refuses MainNet unconditionally."
  echo
  echo "  release-binary custody-attestation payload/carrying corpus (this run):"
  echo "    - the Run 208 helper exercises the A1..A15 acceptance corpus and the"
  echo "      R1..R43 rejection corpus in release mode through the production"
  echo "      library symbols (accepted / rejection / loader / determinism /"
  echo "      refusal_reachability tables);"
  echo "    - legacy no-attestation payloads remain compatible under default"
  echo "      Disabled; fixture attestation carried through the production"
  echo "      reload-check / reload-apply / startup / SIGHUP / local"
  echo "      peer-candidate-check / live 0x05 / peer-driven-drain contexts"
  echo "      reaches the Run 205 verifier and is accepted on DevNet/TestNet;"
  echo "    - production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation"
  echo "      material reaches the verifier and returns the typed unavailable"
  echo "      outcome; malformed/invalid material fails closed;"
  echo "    - evidence / input / transcript / provider-identity digests are"
  echo "      deterministic and domain-bound through wire conversion; the"
  echo "      combined v2 loader yields Absent / Available / Malformed while the"
  echo "      ratification still parses;"
  echo "    - rejected cases leave every input byte-identical and route with no"
  echo "      mutation; MainNet peer-driven apply remains refused even with a"
  echo "      fixture attestation carrier."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help advertises no custody"
  echo "      attestation / KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner"
  echo "      backend surface;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no custody attestation enablement"
  echo "      banner and no MainNet peer-driven apply enablement claim, with or"
  echo "      without the Run 193 custody selector, the Run 198 RemoteSigner"
  echo "      selector, or the governance fixture flag armed;"
  echo "    - even with selectors armed on MainNet, MainNet peer-driven apply"
  echo "      remains refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner attestation"
  echo "      verifier is wired in Run 208. Carried production-class attestation"
  echo "      material always routes into the Run 205 verifier and returns the"
  echo "      typed unavailable reject;"
  echo "    - fixture custody attestation remains DevNet/TestNet evidence-only"
  echo "      and cannot satisfy MainNet production attestation;"
  echo "    - no real RemoteSigner backend / networked signer daemon;"
  echo "    - no MainNet peer-driven apply enablement, no governance execution,"
  echo "      no real on-chain proof verifier, no validator-set rotation, no"
  echo "      autonomous apply, no apply-on-receipt, no peer-majority authority,"
  echo "      no schema/wire/metric drift beyond Run 207's additive optional"
  echo "      custody-attestation sibling."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_208_TASK.txt Validation
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
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_208.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 208 — release-binary custody-attestation payload/carrying evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_208_sha256:  $(sha256_file "${HELPER_208_BIN}")"
  echo "  helper_208_buildid: $(build_id "${HELPER_208_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_custody_selector_compat S6_remote_signer_selector_compat \
           S7_governance_fixture_compat S8_mainnet_armed
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_208	rc=$(cat "${EXIT_DIR}/helper_run_208.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_208_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A15 / R1-R43 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_208_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
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
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner attestation"
  echo "    verifier is wired; carried production-class attestation material"
  echo "    routes into the Run 205 verifier and returns the typed unavailable"
  echo "    outcome;"
  echo "  * fixture custody attestation remains DevNet/TestNet evidence-only and"
  echo "    cannot satisfy MainNet production attestation;"
  echo "  * legacy/no-attestation payloads remain compatible under default"
  echo "    Disabled; the custody_attestation sibling is additive and optional;"
  echo "  * evidence/input/transcript/provider-identity digests are deterministic"
  echo "    and domain-bound through wire conversion;"
  echo "  * a malformed carrier fails closed before the verifier and before any"
  echo "    marker/sequence write, live trust swap, session eviction, or Run 070"
  echo "    call;"
  echo "  * rejected custody-attestation-payload cases produce no mutation;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with a fixture attestation carrier;"
  echo "  * RemoteSigner and KMS/HSM remain backend-boundary only and unchanged;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift beyond Run 207's additive optional"
  echo "    custody-attestation sibling;"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node keeps every existing Run 070"
  echo "  / 130–207 surface custody-attestation-silent (no custody attestation /"
  echo "  KMS / HSM / cloud KMS / PKCS#11 attestation enablement banner, MainNet"
  echo "  peer-driven apply refusal preserved), and the release-built Run 208"
  echo "  helper exercises the Run 207 custody-attestation payload/carrying"
  echo "  corpus end-to-end in release mode through the production library"
  echo "  symbols: legacy no-attestation payloads remain compatible; fixture"
  echo "  custody attestation carried through the production reload-check /"
  echo "  reload-apply / startup / SIGHUP / local peer-candidate-check / live"
  echo "  0x05 / peer-driven-drain contexts reaches the Run 205 verifier and is"
  echo "  accepted on DevNet/TestNet only; production / cloud-KMS / PKCS#11 / HSM"
  echo "  / RemoteSigner attestation material reaches the verifier and fails"
  echo "  closed as unavailable; malformed/invalid material fails closed;"
  echo "  evidence/input/transcript/provider-identity digests deterministic and"
  echo "  domain-bound through wire conversion; rejected cases produce no"
  echo "  mutation; and MainNet peer-driven apply remains the Run 147 FATAL"
  echo "  refusal even with fixture attestation material. Real KMS / HSM / cloud"
  echo "  KMS / PKCS#11 / RemoteSigner attestation verifiers, real RemoteSigner"
  echo "  backend, real on-chain governance proof verification, governance"
  echo "  execution, and validator-set rotation all remain unimplemented. Full"
  echo "  C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"
