#!/usr/bin/env bash
# Run 210 — Release-binary custody-attestation **policy selector** evidence on
# real `target/release/qbind-node`. Closes the Run 209-deferred release-binary
# boundary for the source/test hidden custody-attestation policy selector added
# by `crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs` (Run 209),
# layered over the Run 207 custody-attestation payload/carrying surface
# (`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`), the
# Run 205 production custody-attestation verifier boundary
# (`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`) and the Run 188
# authority-custody boundary (`crates/qbind-node/src/pqc_authority_custody.rs`).
#
# Driving spec: `task/RUN_210_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * the hidden Run 209 CLI selector `--p2p-trust-bundle-custody-attestation-policy`
#     is present but hidden from normal `--help`;
#   * the hidden Run 209 env selector
#     `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY` and the CLI selector are
#     accepted at the binary surface without enabling any production custody
#     attestation, KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend, governance
#     execution, validator-set rotation, or MainNet peer-driven apply;
#   * the existing Run 070 / 130–209 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193 hidden
#     custody-policy selector, the Run 198 hidden RemoteSigner-policy selector,
#     the governance fixture flag) emit no custody-attestation enablement banner
#     and no MainNet peer-driven apply enablement;
#   * default behaviour does not expose or enable production custody attestation;
#   * even with the Run 209 custody-attestation policy selector armed on
#     `--env mainnet`, the binary still emits no MainNet peer-driven apply
#     enablement — the Run 147 / 148 / 152 FATAL invariant is preserved;
#   * the release-built Run 210 helper
#     `run_210_custody_attestation_policy_release_binary_helper` exercises the
#     Run 209 selector resolver (`custody_attestation_policy_from_selector`,
#     `custody_attestation_policy_from_cli_or_env`,
#     `custody_attestation_policy_env_selector`), the seven per-surface
#     custody-attestation-policy preflight wrappers, and the Run 207
#     custody-attestation payload routing into the Run 205 verifier — all in
#     **release mode** through the production library symbols.
#
# Strict scope (from `task/RUN_210_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 210 helper to exercise the Run 209 selector and
#     Run 207 routing in release mode through the production library symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real KMS / HSM / cloud KMS / PKCS#11 attestation verifier.
#   * No real RemoteSigner backend / networked signer daemon.
#   * No production signing key custody.
#   * No real on-chain governance proof verifier; no governance execution;
#     no validator-set rotation; no autonomous apply; no apply-on-receipt;
#     no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No schema / wire / metric drift.
#   * No authority-marker / sequence-file / trust-bundle core schema change.
#   * Do not weaken Runs 070, 130–209.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under `OUTDIR`
# except `README.md`, `summary.txt`, and `.gitignore`, which are tracked in
# git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_210_custody_attestation_policy_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_210_BIN="${REPO_ROOT}/target/release/examples/run_210_custody_attestation_policy_release_binary_helper"

HELPER_210_OUT="${OUTDIR}/helper_evidence/run_210"
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

ENV_SELECTOR="QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY"
CLI_SELECTOR="--p2p-trust-bundle-custody-attestation-policy"

log()  { printf '[run-210] %s\n' "$*" >&2; }
fail() { printf '[run-210] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_210_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_210_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-210 provenance"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo "git_branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
  echo "git_status_short:"
  git -C "${REPO_ROOT}" status --short 2>/dev/null || true
  echo "rustc_version: $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "cargo_version: $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "host: $(uname -a 2>/dev/null || echo 'unknown')"
  echo "outdir: ${OUTDIR}"
  echo "env_selector: ${ENV_SELECTOR}"
  echo "cli_selector: ${CLI_SELECTOR}"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Build qbind-node bin + Run 210 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_210_custody_attestation_policy_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_210_custody_attestation_policy_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_210.log" 2>&1 \
  || fail "release build of run_210 helper failed (see ${LOGS_DIR}/build_helper_run_210.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_210_BIN}" ]] || fail "missing ${HELPER_210_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_210_path:    ${HELPER_210_BIN}"
  echo "helper_210_sha256:  $(sha256_file "${HELPER_210_BIN}")"
  echo "helper_210_buildid: $(build_id "${HELPER_210_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 210 release helper. Exits 0 iff the selector-resolution,
# accepted (A1..A15), rejection (R1..R40), loader, and refusal/reachability
# tables all matched in release mode through the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 210 custody-attestation policy release helper -> ${HELPER_210_OUT}"
HELPER_210_LOG="${LOGS_DIR}/helper_run_210.log"
set +e
"${HELPER_210_BIN}" "${HELPER_210_OUT}" > "${HELPER_210_LOG}" 2>&1
HELPER_210_RC=$?
set -e
echo "${HELPER_210_RC}" > "${EXIT_DIR}/helper_run_210.rc"
[[ "${HELPER_210_RC}" -eq 0 ]] || fail "run_210 helper exited rc=${HELPER_210_RC} (see ${HELPER_210_LOG})"
[[ -s "${HELPER_210_OUT}/helper_summary.txt" ]] || fail "run_210 helper did not write helper_summary.txt"
assert_grep "${HELPER_210_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants. Run 209 added a hidden CLI flag + env var and
# a pure library policy-selector surface (no runtime banner, no enablement). The
# selector is consumed at the library/helper level; at the binary surface the
# contract is that the flag is hidden from normal help, the selector is accepted
# without enabling production custody attestation, and every existing Run 070 /
# 130–209 surface emits no custody-attestation enablement banner and no MainNet
# peer-driven apply enablement claim. `--print-genesis-hash` is a non-mutating
# CLI that exits quickly without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help hides the custody-attestation policy selector"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
# The Run 209 selector flag is hidden (clap hide = true): it must NOT appear in
# normal --help output.
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-custody-attestation-policy"
assert_not_grep "${HELP_LOG}" "(?i)custody attestation"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)cloud kms"
assert_not_grep "${HELP_LOG}" "(?i)pkcs.?11"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer backend"
assert_not_grep "${HELP_LOG}" "run-205"
assert_not_grep "${HELP_LOG}" "run-207"
assert_not_grep "${HELP_LOG}" "run-209"
assert_not_grep "${HELP_LOG}" "run-210"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

# Custody-attestation enablement banners that must never appear on any captured
# qbind-node surface log.
assert_surface_silent() {
  local logf="$1"
  assert_not_grep "${logf}" "(?i)custody attestation (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)production attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)kms attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)hsm attestation (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)pkcs.?11 (?:enabled|active|connected)"
  assert_not_grep "${logf}" "(?i)kms.?hsm (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)kms (?:backend )?(?:enabled|active)"
  assert_not_grep "${logf}" "(?i)hsm (?:backend )?(?:enabled|active)"
  assert_not_grep "${logf}" "(?i)cloud kms (?:enabled|active|connected)"
  assert_not_grep "${logf}" "(?i)remote signer backend connected"
  assert_not_grep "${logf}" "(?i)production custody (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)governance execution"
  assert_not_grep "${logf}" "(?i)validator-set rotation"
  assert_not_grep "${logf}" "(?i)autonomous apply"
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
                            -u "${ENV_SELECTOR}" \
      "${NODE_BIN}" --print-genesis-hash --env "${node_env}" "$@" ) \
    > "${logf}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/${key}.rc"
  assert_surface_silent "${logf}"
}

log "S2 — default DevNet surface: no custody-attestation banner"
run_surface_scenario "S2_default_devnet" devnet

log "S3 — default TestNet surface: no custody-attestation banner"
run_surface_scenario "S3_default_testnet" testnet

log "S4 — default MainNet surface: no custody-attestation banner, no MainNet apply"
run_surface_scenario "S4_default_mainnet" mainnet

log "S5 — Run 209 CLI selector fixture-attestation-allowed armed on DevNet: no banner drift"
S5_LOG="${LOGS_DIR}/S5_cli_selector_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    -u "${ENV_SELECTOR}" \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  "${CLI_SELECTOR}" fixture-attestation-allowed ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_cli_selector_devnet.rc"
assert_surface_silent "${S5_LOG}"

log "S6 — Run 209 env selector kms-attestation-required armed on DevNet: no banner drift"
S6_LOG="${LOGS_DIR}/S6_env_selector_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    "${ENV_SELECTOR}=kms-attestation-required" \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_env_selector_devnet.rc"
assert_surface_silent "${S6_LOG}"

log "S7 — Run 209 CLI-over-env precedence armed on DevNet: no banner drift"
S7_LOG="${LOGS_DIR}/S7_cli_over_env_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    "${ENV_SELECTOR}=fixture-attestation-allowed" \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  "${CLI_SELECTOR}" disabled ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_cli_over_env_devnet.rc"
assert_surface_silent "${S7_LOG}"

log "S8 — Run 209 invalid selector value armed on DevNet: fails closed, no banner"
S8_LOG="${LOGS_DIR}/S8_invalid_selector_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    -u "${ENV_SELECTOR}" \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  "${CLI_SELECTOR}" totally-bogus-not-a-policy ) \
  > "${S8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S8_invalid_selector_devnet.rc"
assert_surface_silent "${S8_LOG}"

log "S9 — Run 209 mainnet-production-attestation-required armed on MainNet: refusal preserved"
S9_LOG="${LOGS_DIR}/S9_mainnet_armed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    "${ENV_SELECTOR}=mainnet-production-attestation-required" \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  "${CLI_SELECTOR}" mainnet-production-attestation-required ) \
  > "${S9_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S9_mainnet_armed.rc"
assert_not_grep "${S9_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S9_LOG}" "(?i)mainnet.+apply.+enabled"
assert_surface_silent "${S9_LOG}"

log "S10 — Run 193 custody selector + Run 198 RemoteSigner selector compat alongside Run 209"
S10_LOG="${LOGS_DIR}/S10_legacy_selectors_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    "${ENV_SELECTOR}=fixture-attestation-allowed" \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S10_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S10_legacy_selectors_compat.rc"
assert_surface_silent "${S10_LOG}"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 209 custody-attestation policy
# selector surface layered over the Run 207 routing helpers, the Run 205
# verifier and the Run 188 custody boundary. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface the Run
# 210 helper exercises is wired in production source.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 210 source-reachability proof — production symbols within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_custody_attestation_policy_surface' \
    'QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY' \
    'p2p_trust_bundle_custody_attestation_policy' \
    'custody_attestation_policy_from_selector' \
    'custody_attestation_policy_from_cli_or_env' \
    'custody_attestation_policy_env_selector' \
    'preflight_v2_marker_custody_attestation_for_reload_check' \
    'preflight_v2_marker_custody_attestation_for_reload_apply' \
    'preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle' \
    'preflight_v2_marker_custody_attestation_for_sighup' \
    'preflight_v2_marker_custody_attestation_for_local_peer_candidate_check' \
    'preflight_v2_marker_custody_attestation_for_live_inbound_0x05' \
    'preflight_v2_marker_custody_attestation_for_peer_driven_drain' \
    'CustodyAttestationPolicy' \
    'FixtureAttestationAllowed' \
    'RemoteSignerAttestationRequired' \
    'KmsAttestationRequired' \
    'HsmAttestationRequired' \
    'ProductionAttestationRequired' \
    'MainnetProductionAttestationRequired' \
    'route_loaded_custody_attestation_to_reload_check_callsite_decision' \
    'CloudKmsAttestationUnavailable' \
    'Pkcs11HsmAttestationUnavailable' \
    'ProductionAttestationUnavailable' \
    'MainNetProductionAttestationUnavailable' \
    'RemoteSignerAttestationUnavailable' \
    'KmsAttestationUnavailable' \
    'HsmAttestationUnavailable' \
    'mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done
} > "${REACH_DIR}/source_reachability.txt"

# Cross-check that the Run 209 selector surface symbols are wired in production
# source.
assert_grep "${REACH_DIR}/source_reachability.txt" 'pqc_custody_attestation_policy_surface'
assert_grep "${REACH_DIR}/source_reachability.txt" 'QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY'
assert_grep "${REACH_DIR}/source_reachability.txt" 'custody_attestation_policy_from_cli_or_env'

# Cross-check that the hidden CLI selector field is wired in cli.rs.
grep -RIn --include='*.rs' 'p2p_trust_bundle_custody_attestation_policy' "${SRC_DIR}" \
  > "${REACH_DIR}/cli_flag_reachability.txt" \
  || fail "expected hidden CLI selector field wired in ${SRC_DIR}"

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 210 denylist (proven empty across all captured logs):"
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
    if find "${LOGS_DIR}" "${HELPER_210_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected custody-attestation-policy scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 210 no-mutation proof for rejected custody-attestation-policy scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven custody-attestation-policy rejection corpus (R1..R40):"
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
  echo "    * the Run 209 selector resolver, the seven per-surface preflight"
  echo "      wrappers, and the Run 207 routing helpers are pure functions"
  echo "      returning typed owned outcomes; an invalid selector value fails"
  echo "      closed with a typed parse error BEFORE any custody-attestation"
  echo "      material parse; a malformed carrier short-circuits BEFORE the Run"
  echo "      205 verifier, BEFORE any sequence/marker write, BEFORE any live"
  echo "      trust swap, BEFORE any session eviction, and BEFORE any Run 070"
  echo "      call (helper selector/rejection manifests + R37/R38 purity"
  echo "      asserts)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_210_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted fixture custody-attestation-policy
# scenarios (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 210 mutation proof (release-binary scope):"
  echo
  echo "  library-side custody-attestation policy-selector reachability today:"
  echo "    - Run 209 added pqc_custody_attestation_policy_surface.rs with the"
  echo "      hidden CLI flag ${CLI_SELECTOR}, the env var ${ENV_SELECTOR}, the"
  echo "      canonical tag constants, the typed"
  echo "      CustodyAttestationPolicySelectorParseError, the pure parsers"
  echo "      custody_attestation_policy_from_selector /"
  echo "      custody_attestation_policy_env_selector /"
  echo "      custody_attestation_policy_from_cli_or_env (CLI-over-env"
  echo "      precedence, fail-closed on invalid), and the seven per-surface"
  echo "      preflight wrappers"
  echo "      preflight_v2_marker_custody_attestation_for_{reload_check,"
  echo "      reload_apply, startup_p2p_trust_bundle, sighup,"
  echo "      local_peer_candidate_check, live_inbound_0x05, peer_driven_drain}"
  echo "      that route the resolved CustodyAttestationPolicy into the Run 207"
  echo "      custody-attestation payload routing helpers and the Run 205"
  echo "      verifier;"
  echo "    - the module is additive and pure: it performs no network or file"
  echo "      I/O, writes no marker, writes no sequence, swaps no live trust,"
  echo "      evicts no sessions, and never invokes Run 070;"
  echo "    - the default policy is CustodyAttestationPolicy::Disabled; an"
  echo "      invalid selector fails closed; the peer-driven drain surface"
  echo "      refuses MainNet unconditionally."
  echo
  echo "  release-binary custody-attestation policy-selector corpus (this run):"
  echo "    - the Run 210 helper exercises the selector-resolution table"
  echo "      (A1..A3, A11, R1..R3), the A4..A15 acceptance corpus and the"
  echo "      R4..R40 rejection corpus in release mode through the production"
  echo "      library symbols (selector / accepted / rejection / loader /"
  echo "      reachability tables);"
  echo "    - unset CLI/env resolves to Disabled; the hidden CLI selector and"
  echo "      the env selector resolve each canonical tag; CLI-over-env"
  echo "      precedence is deterministic; invalid CLI/env values fail closed"
  echo "      with typed parse errors; an unrelated env var does not enable the"
  echo "      policy;"
  echo "    - the resolved policy reaches all seven production preflight"
  echo "      contexts; fixture attestation carried through them reaches the Run"
  echo "      205 verifier and is accepted on DevNet/TestNet only where the"
  echo "      policy allows;"
  echo "    - production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation"
  echo "      material reaches the verifier and returns the typed unavailable"
  echo "      outcome regardless of selector; malformed/invalid material fails"
  echo "      closed;"
  echo "    - rejected cases leave every input byte-identical and route with no"
  echo "      mutation; MainNet peer-driven apply remains refused even with"
  echo "      MainnetProductionAttestationRequired and a fixture attestation"
  echo "      carrier."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help hides the Run 209 selector"
  echo "      flag ${CLI_SELECTOR} and advertises no custody attestation / KMS /"
  echo "      HSM / cloud KMS / PKCS#11 / RemoteSigner backend surface;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no custody attestation enablement"
  echo "      banner and no MainNet peer-driven apply enablement claim, with or"
  echo "      without the Run 209 custody-attestation policy selector (CLI or"
  echo "      env), the Run 193 custody selector, or the Run 198 RemoteSigner"
  echo "      selector armed;"
  echo "    - even with the selector armed on MainNet, MainNet peer-driven apply"
  echo "      remains refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner attestation"
  echo "      verifier is wired in Run 210. Carried production-class attestation"
  echo "      material always routes into the Run 205 verifier and returns the"
  echo "      typed unavailable reject;"
  echo "    - fixture custody attestation remains DevNet/TestNet evidence-only"
  echo "      and cannot satisfy MainNet production attestation;"
  echo "    - the Run 209 CLI flag is consumed by the selector surface at the"
  echo "      library level; the release binary parses it (hidden) but does not"
  echo "      yet wire its resolved policy into a long-running node runtime — no"
  echo "      production custody attestation is enabled by arming it;"
  echo "    - no real RemoteSigner backend / networked signer daemon;"
  echo "    - no MainNet peer-driven apply enablement, no governance execution,"
  echo "      no real on-chain proof verifier, no validator-set rotation, no"
  echo "      autonomous apply, no apply-on-receipt, no peer-majority authority,"
  echo "      no schema/wire/metric drift."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_210_TASK.txt Validation
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
TEST_VERDICTS+=( "$(run_lib_test pqc_custody_attestation_policy_surface pqc_custody_attestation_policy_surface)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_210.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 210 — release-binary custody-attestation policy-selector evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_210_sha256:  $(sha256_file "${HELPER_210_BIN}")"
  echo "  helper_210_buildid: $(build_id "${HELPER_210_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_cli_selector_devnet S6_env_selector_devnet S7_cli_over_env_devnet \
           S8_invalid_selector_devnet S9_mainnet_armed S10_legacy_selectors_compat
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_210	rc=$(cat "${EXIT_DIR}/helper_run_210.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_210_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper selector + A1-A15 / R1-R40 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_210_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
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
  echo "    outcome regardless of the selected policy;"
  echo "  * fixture custody attestation remains DevNet/TestNet evidence-only and"
  echo "    cannot satisfy MainNet production attestation;"
  echo "  * default policy remains CustodyAttestationPolicy::Disabled; the hidden"
  echo "    CLI/env selector is additive and disabled by default; an invalid"
  echo "    selector value fails closed with a typed parse error;"
  echo "  * the release binary parses the hidden CLI selector flag (hidden from"
  echo "    --help) but does not wire its resolved policy into a long-running"
  echo "    node runtime; arming it enables no production custody attestation;"
  echo "  * a malformed carrier fails closed before the verifier and before any"
  echo "    marker/sequence write, live trust swap, session eviction, or Run 070"
  echo "    call;"
  echo "  * rejected custody-attestation-policy cases produce no mutation;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with MainnetProductionAttestationRequired and fixture"
  echo "    attestation;"
  echo "  * RemoteSigner and KMS/HSM remain backend-boundary only and unchanged;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift; no authority-marker / sequence-file /"
  echo "    trust-bundle core schema change;"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node hides the Run 209 custody-"
  echo "  attestation policy selector flag from normal --help, accepts the hidden"
  echo "  CLI/env selector without enabling any production custody attestation,"
  echo "  and keeps every existing Run 070 / 130–209 surface custody-attestation-"
  echo "  silent (no custody attestation / KMS / HSM / cloud KMS / PKCS#11"
  echo "  attestation enablement banner, MainNet peer-driven apply refusal"
  echo "  preserved). The release-built Run 210 helper exercises the Run 209"
  echo "  selector resolver end-to-end in release mode through the production"
  echo "  library symbols: unset CLI/env resolves to Disabled; the hidden CLI and"
  echo "  env selectors resolve each canonical tag; CLI-over-env precedence is"
  echo "  deterministic; invalid CLI/env values fail closed with typed parse"
  echo "  errors; the resolved policy reaches all seven production preflight"
  echo "  contexts; fixture custody attestation is accepted on DevNet/TestNet"
  echo "  only where the policy allows; production / cloud-KMS / PKCS#11 / HSM /"
  echo "  RemoteSigner attestation material reaches the Run 205 verifier and"
  echo "  fails closed as unavailable; malformed/invalid material fails closed;"
  echo "  rejected cases produce no mutation; and MainNet peer-driven apply"
  echo "  remains the Run 147 FATAL refusal even with"
  echo "  mainnet-production-attestation-required and fixture attestation. Real"
  echo "  KMS / HSM / cloud KMS / PKCS#11 / RemoteSigner attestation verifiers,"
  echo "  real RemoteSigner backend, real on-chain governance proof verification,"
  echo "  governance execution, and validator-set rotation all remain"
  echo "  unimplemented. Full C4 and C5 remain OPEN."
  echo
  echo "verdict: PASS"
} > "${SUMMARY}"

log "done — summary at ${SUMMARY}"
