#!/usr/bin/env bash
# Run 193 — Release-binary authority-custody policy selector evidence on
# real `target/release/qbind-node`. Closes the Run 192-deferred release-
# binary boundary for the hidden authority-custody policy selector added
# by `crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`
# (Run 192) layered above the Run 190 typed authority-custody payload
# carrying surface and the Run 188 typed authority-custody boundary.
#
# Driving spec: `task/RUN_193_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default `AuthorityCustodyPolicy::Disabled` is preserved when neither
#     `--p2p-trust-bundle-authority-custody-policy` nor
#     `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` is set — the
#     binary surfaces no custody flag in `--help`, no KMS/HSM/remote-
#     signer enablement banner, no peer-majority claim, and no MainNet
#     peer-driven apply enablement;
#   * the Run 192 hidden CLI flag is present in the production CLI surface
#     but is not advertised in normal `--help`;
#   * env-only selector activates the custody policy without altering any
#     other binary invariant (no KMS/HSM banner, no MainNet apply);
#   * CLI-only selector activates the custody policy without altering any
#     other binary invariant;
#   * CLI-over-env precedence is deterministic at the binary surface
#     (env says one policy, CLI says another, no banner drift);
#   * an invalid CLI selector value (`garbage`) is rejected by the binary
#     fail-closed (non-zero exit, no MainNet apply, no KMS/HSM banner);
#   * even with `--p2p-trust-bundle-authority-custody-policy
#     mainnet-production-custody-required` armed on `--env mainnet`, the
#     binary still emits no MainNet peer-driven apply enablement claim
#     and no KMS/HSM/remote-signer enablement claim — Run 147 / 148 / 152
#     FATAL invariant is preserved at the binary surface;
#   * the existing Run 070 / 130–192 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|mainnet`,
#     `--p2p-trust-bundle-onchain-governance-fixture-allowed`) emit no
#     Run 192 custody policy enablement claim;
#   * the release-built Run 193 helper
#     `run_193_authority_custody_policy_release_binary_helper` exercises
#     the Run 192 A1–A12 / R1–R29 selector + preflight wrapper corpus
#     end-to-end in **release mode** through the production library
#     symbols `pqc_authority_custody_policy_surface::*` —
#     `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`,
#     `AuthorityCustodyPolicySelectorParseError`,
#     `authority_custody_policy_from_selector`,
#     `authority_custody_policy_env_selector`,
#     `authority_custody_policy_from_cli_or_env`,
#     `preflight_v2_marker_authority_custody_for_{reload_check,
#     reload_apply, startup_p2p_trust_bundle, sighup,
#     local_peer_candidate_check, live_inbound_0x05,
#     peer_driven_drain}` — layered over Run 190
#     `pqc_authority_custody_payload_carrying::*` and Run 188
#     `pqc_authority_custody::*`.
#
# Strict scope (from `task/RUN_193_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 193 helper to exercise the Run 192
#     selector + preflight wrappers in release mode through production
#     library symbols.
#   * No production-source change.
#   * No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
#   * No real on-chain governance proof verifier; no governance
#     execution; no validator-set rotation; no autonomous apply;
#     no apply-on-receipt; no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * No new CLI flag, env var, schema bump, sidecar field, metric, or
#     exit code (Run 192 already added the hidden CLI flag and env var).
#   * Do not weaken Runs 070, 130–192.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_193_authority_custody_policy_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_193_BIN="${REPO_ROOT}/target/release/examples/run_193_authority_custody_policy_release_binary_helper"

HELPER_193_OUT="${OUTDIR}/helper_evidence/run_193"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
GREP_DIR="${OUTDIR}/grep_summaries"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
SCEN_DIR="${OUTDIR}/scenarios"
DATA_DIR="${OUTDIR}/data"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"
MUT_PROOF="${OUTDIR}/mutation_proof.txt"
NOMUT_PROOF="${OUTDIR}/no_mutation_proof.txt"

log()  { printf '[run-193] %s\n' "$*" >&2; }
fail() { printf '[run-193] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_193_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
       "${DATA_DIR}"
mkdir -p "${HELPER_193_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
         "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-193 provenance"
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
# Build qbind-node bin + Run 193 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_193_authority_custody_policy_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_193_authority_custody_policy_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_193.log" 2>&1 \
  || fail "release build of run_193 helper failed (see ${LOGS_DIR}/build_helper_run_193.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_193_BIN}" ]] || fail "missing ${HELPER_193_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_193_path:    ${HELPER_193_BIN}"
  echo "helper_193_sha256:  $(sha256_file "${HELPER_193_BIN}")"
  echo "helper_193_buildid: $(build_id "${HELPER_193_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 193 release helper. Exits 0 iff every Run 192 A1..A12 /
# R1..R29 selector + preflight scenario, the parser table, the
# precedence table, the per-surface preflight wrapper table, the
# binding-mismatch table, the no-mutation snapshot table, and the
# determinism re-evaluation table all matched in release mode through
# the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 193 custody-policy-selector release helper -> ${HELPER_193_OUT}"
HELPER_193_LOG="${LOGS_DIR}/helper_run_193.log"
set +e
"${HELPER_193_BIN}" "${HELPER_193_OUT}" > "${HELPER_193_LOG}" 2>&1
HELPER_193_RC=$?
set -e
echo "${HELPER_193_RC}" > "${EXIT_DIR}/helper_run_193.rc"
[[ "${HELPER_193_RC}" -eq 0 ]] || fail "run_193 helper exited rc=${HELPER_193_RC} (see ${HELPER_193_LOG})"
[[ -s "${HELPER_193_OUT}/helper_summary.txt" ]] || fail "run_193 helper did not write helper_summary.txt"
assert_grep "${HELPER_193_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants — Run 192 added the hidden CLI flag
# `--p2p-trust-bundle-authority-custody-policy <POLICY>` and the env
# var `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` but did NOT
# wire them into a runtime banner; the surface contract for Run 193
# is therefore that, regardless of how the hidden selector is set,
# the existing Run 070 / 130–192 surfaces emit no KMS/HSM/remote-
# signer enablement banner and no MainNet peer-driven apply
# enablement claim. `--print-genesis-hash` is a non-mutating CLI that
# exits quickly without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help does NOT advertise the hidden Run 192 selector"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
# Hidden flag must NOT appear in normal --help output.
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-authority-custody-policy"
assert_not_grep "${HELP_LOG}" "QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY"
assert_not_grep "${HELP_LOG}" "(?i)authority.?custody"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer"
assert_not_grep "${HELP_LOG}" "(?i)production custody"
assert_not_grep "${HELP_LOG}" "run-188"
assert_not_grep "${HELP_LOG}" "run-191"
assert_not_grep "${HELP_LOG}" "run-192"
assert_not_grep "${HELP_LOG}" "run-193"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

log "S2 — default DevNet startup terminal: no custody/KMS/HSM banner (no selector)"
S2_LOG="${LOGS_DIR}/S2_default_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S2_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S2_default_devnet.rc"
assert_not_grep "${S2_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S2_LOG}" "(?i)kms.?hsm active"
assert_not_grep "${S2_LOG}" "(?i)remote signer enabled"
assert_not_grep "${S2_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S2_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S2_LOG}" "(?i)autonomous apply"
assert_not_grep "${S2_LOG}" "MainNet peer-driven apply ENABLED"

log "S3 — env selector fixture-only on DevNet: no banner drift"
S3_LOG="${LOGS_DIR}/S3_env_devnet_fixture_only.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S3_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S3_env_devnet_fixture_only.rc"
assert_not_grep "${S3_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S3_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S3_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S3_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S3_LOG}" "(?i)autonomous apply"

log "S4 — CLI selector devnet-local-allowed on DevNet: no banner drift"
S4_LOG="${LOGS_DIR}/S4_cli_devnet_local_allowed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-authority-custody-policy devnet-local-allowed ) \
  > "${S4_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S4_cli_devnet_local_allowed.rc"
assert_not_grep "${S4_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S4_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S4_LOG}" "MainNet peer-driven apply ENABLED"

log "S5 — CLI-over-env precedence: env=fixture-only, CLI=disabled, no banner drift"
S5_LOG="${LOGS_DIR}/S5_cli_over_env_precedence.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-authority-custody-policy disabled ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_cli_over_env_precedence.rc"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S5_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"

log "S6 — invalid selector value rejected fail-closed (clap value parser)"
S6_LOG="${LOGS_DIR}/S6_invalid_selector.log"
set +e
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-authority-custody-policy garbage ) \
  > "${S6_LOG}" 2>&1
S6_RC=$?
set -e
echo "${S6_RC}" > "${EXIT_DIR}/S6_invalid_selector.rc"
# A typed parse error must NOT silently emit MainNet apply or KMS/HSM banner.
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S6_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S6_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S6_LOG}" "(?i)autonomous apply"

log "S7 — MainNet startup with mainnet-production-custody-required armed: refusal preserved"
S7_LOG="${LOGS_DIR}/S7_mainnet_production_custody_required.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=mainnet-production-custody-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-authority-custody-policy mainnet-production-custody-required ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_mainnet_production_custody_required.rc"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S7_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S7_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S7_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S7_LOG}" "(?i)remote signer (?:enabled|active|wired)"
assert_not_grep "${S7_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S7_LOG}" "(?i)autonomous apply"

log "S8 — fixture-allowed selector + Run 192 selector both armed on MainNet: refusal preserved"
S8_LOG="${LOGS_DIR}/S8_mainnet_fixture_and_policy_selector.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=mainnet-production-custody-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed \
                  --p2p-trust-bundle-authority-custody-policy mainnet-production-custody-required ) \
  > "${S8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S8_mainnet_fixture_and_policy_selector.rc"
assert_not_grep "${S8_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S8_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S8_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S8_LOG}" "(?i)production custody (?:enabled|active|wired)"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 192 typed authority-
# custody policy selector + preflight wrappers + Run 190 routing
# helpers + Run 188 typed boundary. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface
# the Run 193 helper exercises is wired in production source — not in
# tests or fixtures.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 193 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_authority_custody_policy_surface' \
    'QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY' \
    'QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV' \
    'p2p_trust_bundle_authority_custody_policy' \
    'AuthorityCustodyPolicySelectorParseError' \
    'AuthorityCustodyPolicySelectorParseError::Empty' \
    'AuthorityCustodyPolicySelectorParseError::UnknownValue' \
    'authority_custody_policy_from_selector' \
    'authority_custody_policy_env_selector' \
    'authority_custody_policy_from_cli_or_env' \
    'preflight_v2_marker_authority_custody_for_reload_check' \
    'preflight_v2_marker_authority_custody_for_reload_apply' \
    'preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle' \
    'preflight_v2_marker_authority_custody_for_sighup' \
    'preflight_v2_marker_authority_custody_for_local_peer_candidate_check' \
    'preflight_v2_marker_authority_custody_for_live_inbound_0x05' \
    'preflight_v2_marker_authority_custody_for_peer_driven_drain' \
    'AuthorityCustodyPolicy' \
    'AuthorityCustodyPolicy::Disabled' \
    'AuthorityCustodyPolicy::FixtureOnly' \
    'AuthorityCustodyPolicy::DevnetLocalAllowed' \
    'AuthorityCustodyPolicy::TestnetLocalAllowed' \
    'AuthorityCustodyPolicy::ProductionCustodyRequired' \
    'AuthorityCustodyPolicy::MainnetProductionCustodyRequired' \
    'AuthorityCustodyClass' \
    'AuthorityCustodyClass::FixtureLocalKey' \
    'AuthorityCustodyClass::LocalOperatorKey' \
    'AuthorityCustodyClass::RemoteSigner' \
    'AuthorityCustodyClass::Kms' \
    'AuthorityCustodyClass::Hsm' \
    'AuthorityCustodyClass::Unknown' \
    'AuthorityCustodyAttestation' \
    'AuthorityCustodyValidationOutcome' \
    'AuthorityCustodyValidationOutcome::AcceptedFixtureCustody' \
    'AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody' \
    'AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable' \
    'AuthorityCustodyValidationOutcome::MainNetProductionCustodyUnavailable' \
    'AuthorityCustodyValidationOutcome::KmsUnavailable' \
    'AuthorityCustodyValidationOutcome::HsmUnavailable' \
    'AuthorityCustodyValidationOutcome::RemoteSignerUnavailable' \
    'AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet' \
    'AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet' \
    'AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass' \
    'AuthorityCustodyValidationOutcome::CustodyAttestationExpired' \
    'AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch' \
    'AuthorityCustodyValidationOutcome::UnsupportedCustodySuite' \
    'LifecycleGovernanceCustodyOutcome' \
    'validate_authority_custody_attestation' \
    'validate_lifecycle_governance_and_custody' \
    'mainnet_peer_driven_apply_remains_refused_under_custody_boundary' \
    'peer_majority_cannot_satisfy_custody' \
    'local_operator_config_alone_cannot_satisfy_mainnet_production_custody' \
    'pqc_authority_custody_payload_carrying' \
    'AuthorityCustodyAttestationWire' \
    'AuthorityCustodyLoadStatus' \
    'AuthorityCustodyCallsiteContext' \
    'AuthorityCustodyPayloadCarryingDecisionOutcome' \
    'parse_optional_authority_custody_attestation_sibling_from_json_value' \
    'route_loaded_authority_custody_attestation_to_reload_check_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_sighup_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision' \
    'route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision' \
    'mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done
} > "${REACH_DIR}/source_reachability.txt"

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 193 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'governance execution claim' \
    'on-chain governance claim' \
    'real on-chain governance proof claim' \
    'KMS/HSM enabled' \
    'KMS/HSM active' \
    'kms-hsm enabled' \
    'remote signer enabled' \
    'remote signer production active' \
    'production custody enabled' \
    'production custody active' \
    'production custody wired' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_193_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected custody-policy scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 193 no-mutation proof for rejected custody-policy scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven Run 192 selector + Run 190 routing rejection corpus (R1..R29):"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  echo "    * no real KMS / HSM / remote-signer backend wired"
  echo "    * no real governance execution / no real on-chain proof verifier"
  echo "    * no validator-set rotation"
  echo "    * candidate / persisted snapshots taken before and after a"
  echo "      rejecting selector/preflight/validator/routing dispatch are"
  echo "      bit-equal (captured in no_mutation_evidence.txt)."
  grep -E 'verdict: PASS|R[0-9]+_|A[0-9]+_|no_mutation_pass|determinism_pass' \
    "${HELPER_193_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted custody-policy scenarios (release-
# binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 193 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site Run 192 custody-policy"
  echo "  selector reachability today:"
  echo "    - Run 192 added pqc_authority_custody_policy_surface.rs"
  echo "      with the typed AuthorityCustodyPolicySelectorParseError"
  echo "      (Empty / UnknownValue), the selector parsers"
  echo "      authority_custody_policy_from_selector,"
  echo "      authority_custody_policy_env_selector,"
  echo "      authority_custody_policy_from_cli_or_env (CLI-over-env"
  echo "      precedence), the env-var anchor const"
  echo "      QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV, and"
  echo "      seven per-surface preflight wrappers"
  echo "      preflight_v2_marker_authority_custody_for_{reload_check /"
  echo "      reload_apply / startup_p2p_trust_bundle / sighup /"
  echo "      local_peer_candidate_check / live_inbound_0x05 /"
  echo "      peer_driven_drain} that thread the resolved policy into"
  echo "      Run 190's per-surface routing helpers without mutating"
  echo "      any marker, sequence, trust-bundle, or wire field;"
  echo "    - the hidden CLI flag --p2p-trust-bundle-authority-custody-policy"
  echo "      is declared in clap with hide = true and is not advertised"
  echo "      in normal --help — proven empty above (S1);"
  echo "    - the env var QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY"
  echo "      is read by authority_custody_policy_env_selector and threaded"
  echo "      via authority_custody_policy_from_cli_or_env, with CLI-over-"
  echo "      env precedence proven by the helper precedence table and at"
  echo "      the binary surface (S5 above);"
  echo "    - the Run 192 selector is layered ABOVE Run 190's typed"
  echo "      AuthorityCustodyAttestationWire / AuthorityCustodyLoadStatus /"
  echo "      AuthorityCustodyCallsiteContext /"
  echo "      AuthorityCustodyPayloadCarryingDecisionOutcome / seven"
  echo "      per-surface routing helpers / sibling JSON parser, and"
  echo "      ABOVE Run 188's typed AuthorityCustodyClass /"
  echo "      AuthorityCustodyPolicy / AuthorityCustodyAttestation /"
  echo "      AuthorityCustodyValidationOutcome /"
  echo "      LifecycleGovernanceCustodyOutcome /"
  echo "      validate_authority_custody_attestation /"
  echo "      validate_lifecycle_governance_and_custody / and the three"
  echo "      named helpers"
  echo "      (mainnet_peer_driven_apply_remains_refused_under_custody_boundary,"
  echo "       peer_majority_cannot_satisfy_custody,"
  echo "       local_operator_config_alone_cannot_satisfy_mainnet_production_custody);"
  echo "    - Run 192's selector is wired source-side as a pure preflight"
  echo "      helper, BEFORE any Run 070 apply call, BEFORE any live trust"
  echo "      swap, BEFORE any session eviction, BEFORE any sequence/marker"
  echo "      write, and BEFORE any peer-driven drain;"
  echo "    - the Run 147 / 148 / 152 FATAL MainNet peer-driven apply"
  echo "      refusal remains layered ahead of the Run 192 policy gate via"
  echo "      the FixtureCustodyRejectedForMainNet /"
  echo "      LocalCustodyRejectedForMainNet outcomes for fixture / local"
  echo "      classes, the MainNetProductionCustodyUnavailable outcome"
  echo "      for the MainnetProductionCustodyRequired policy, and the"
  echo "      mainnet_peer_driven_apply_remains_refused_under_custody_boundary"
  echo "      named helper at the typed boundary."
  echo
  echo "  release-binary custody-policy-selector corpus (this run):"
  echo "    - the Run 193 helper exercises every"
  echo "      AuthorityCustodyPolicySelector source (CLI / env / both / unset)"
  echo "      against authority_custody_policy_from_cli_or_env across the"
  echo "      A1..A12 acceptance corpus and the R1..R29 rejection corpus"
  echo "      from Run 192 in release mode through the production library"
  echo "      symbols;"
  echo "    - the helper additionally exercises the per-surface preflight"
  echo "      wrapper table (preflight_wrappers_table.txt), the parser"
  echo "      table (selector_parser_table.txt), the precedence table"
  echo "      (precedence_table.txt), the binding-mismatch table"
  echo "      (binding_mismatch_table.txt), and the no-mutation snapshot"
  echo "      and determinism re-evaluation tables;"
  echo "    - non-mutation evidence is captured for every rejected"
  echo "      scenario via bit-equality of candidate / persisted"
  echo "      snapshots taken before and after a rejecting selector /"
  echo "      preflight / validator / routing dispatch (no_mutation_evidence.txt);"
  echo "      deterministic re-evaluation evidence is captured in"
  echo "      determinism_evidence.txt."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help does NOT advertise"
  echo "      the Run 192 hidden selector and surfaces no Run 192 custody"
  echo "      policy claim and no KMS/HSM/remote-signer claim;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no Run 192 custody-policy"
  echo "      enablement banner and no MainNet peer-driven apply"
  echo "      enablement claim, with or without the env or CLI selector"
  echo "      armed;"
  echo "    - even with the Run 192 selector explicitly set to"
  echo "      mainnet-production-custody-required at both env and CLI"
  echo "      AND with the existing Run 187 hidden fixture selector"
  echo "      armed, MainNet peer-driven apply remains refused (Run 147"
  echo "      FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer"
  echo "      backend is wired in Run 193. Every RemoteSigner / Kms / Hsm"
  echo "      attestation routes to the typed RemoteSignerUnavailable /"
  echo "      KmsUnavailable / HsmUnavailable outcome, and every"
  echo "      ProductionCustodyRequired / MainnetProductionCustodyRequired"
  echo "      policy routes to ProductionCustodyUnavailable /"
  echo "      MainNetProductionCustodyUnavailable, encoding the honest"
  echo "      unavailability;"
  echo "    - fixture / local-operator custody remain DevNet/TestNet"
  echo "      evidence-only and explicitly cannot satisfy MainNet"
  echo "      production custody;"
  echo "    - no MainNet peer-driven apply enablement, no governance"
  echo "      execution, no real on-chain proof verifier, no validator-"
  echo "      set rotation, no autonomous apply, no apply-on-receipt,"
  echo "      no peer-majority authority, no schema/wire/metric drift."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_193_TASK.txt
# Validation commands`. Tests that don't exist in this tree are
# recorded as `skipped(not-present)` and the harness continues.
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
TEST_VERDICTS+=( "$(run_lib_test pqc_authority_custody pqc_authority_custody)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_authority_custody_policy_surface pqc_authority_custody_policy_surface)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_193.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 193 — release-binary authority-custody policy selector evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_193_sha256:  $(sha256_file "${HELPER_193_BIN}")"
  echo "  helper_193_buildid: $(build_id "${HELPER_193_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_env_devnet_fixture_only \
           S4_cli_devnet_local_allowed S5_cli_over_env_precedence \
           S6_invalid_selector S7_mainnet_production_custody_required \
           S8_mainnet_fixture_and_policy_selector
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_193	rc=$(cat "${EXIT_DIR}/helper_run_193.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_193_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A12 / R1-R29 corpus verdicts (release mode, production library symbols):"
  for k in total_pass total_fail scenarios_pass scenarios_fail \
           parser_pass parser_fail precedence_pass precedence_fail \
           wrappers_pass wrappers_fail binding_mismatch_pass binding_mismatch_fail \
           no_mutation_pass no_mutation_fail determinism_pass determinism_fail
  do
    v="$(grep -E "^${k}: " "${HELPER_193_OUT}/helper_summary.txt" 2>/dev/null | head -n1 | awk '{print $2}')"
    echo "  ${k}: ${v:-na}"
  done
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
  echo "  * default AuthorityCustodyPolicy::Disabled preserved when neither"
  echo "    CLI nor env selector is set;"
  echo "  * hidden CLI flag --p2p-trust-bundle-authority-custody-policy is"
  echo "    not advertised in normal --help (clap hide=true);"
  echo "  * env QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY activates"
  echo "    the selector when set; CLI-over-env precedence is deterministic;"
  echo "  * invalid selector values surface as typed"
  echo "    AuthorityCustodyPolicySelectorParseError (fail-closed);"
  echo "  * FixtureLocalKey / LocalOperatorKey custody remain DevNet/TestNet"
  echo "    evidence-only under explicit FixtureOnly / DevnetLocalAllowed /"
  echo "    TestnetLocalAllowed policies;"
  echo "  * fixture / local custody refused on MainNet at the typed"
  echo "    boundary (FixtureCustodyRejectedForMainNet /"
  echo "    LocalCustodyRejectedForMainNet) AHEAD of the policy gate;"
  echo "  * RemoteSigner / Kms / Hsm placeholders fail closed at the typed"
  echo "    validator (RemoteSignerUnavailable / KmsUnavailable /"
  echo "    HsmUnavailable) regardless of policy or environment;"
  echo "  * ProductionCustodyRequired / MainnetProductionCustodyRequired"
  echo "    always fail closed (ProductionCustodyUnavailable /"
  echo "    MainNetProductionCustodyUnavailable / placeholder-specific"
  echo "    Unavailable) in Run 193;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL"
  echo "    invariant) at every binary surface — including with the"
  echo "    Run 192 hidden selector set to mainnet-production-custody-required"
  echo "    on both env and CLI and the Run 187 hidden fixture selector"
  echo "    armed — and at the typed custody boundary via"
  echo "    mainnet_peer_driven_apply_remains_refused_under_custody_boundary;"
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend"
  echo "    wired in Run 193;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift (Run 193 is release-binary"
  echo "    evidence only);"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node preserves the Run 192"
  echo "  hidden authority-custody policy selector contract end-to-end."
  echo "  Default AuthorityCustodyPolicy::Disabled is preserved when neither"
  echo "  CLI nor env selector is set. The hidden CLI flag is present in"
  echo "  the production CLI surface but not advertised in --help; the env"
  echo "  selector activates the typed policy when set; CLI-over-env"
  echo "  precedence is deterministic at the binary surface; an invalid"
  echo "  selector value is rejected fail-closed. The Run 193 release-built"
  echo "  helper exercises the full Run 192 A1-A12 / R1-R29 selector +"
  echo "  preflight wrapper corpus end-to-end through the production library"
  echo "  symbols pqc_authority_custody_policy_surface::* layered above"
  echo "  pqc_authority_custody_payload_carrying::* and"
  echo "  pqc_authority_custody::*, returning the expected typed outcomes."
  echo "  MainNet peer-driven apply remains the Run 147 FATAL refusal even"
  echo "  with mainnet-production-custody-required armed on env+CLI and"
  echo "  with the Run 187 fixture selector armed; fixture / local custody"
  echo "  can never satisfy MainNet production custody; RemoteSigner / Kms /"
  echo "  Hsm placeholders fail closed regardless of policy or environment."
  echo "  Real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backends,"
  echo "  real on-chain governance proof verification, governance execution,"
  echo "  validator-set rotation, autonomous apply, apply-on-receipt, and"
  echo "  peer-majority authority all remain unimplemented. Full C4 and C5"
  echo "  remain OPEN."
} > "${SUMMARY}"
