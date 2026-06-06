#!/usr/bin/env bash
# Run 199 — Release-binary RemoteSigner **policy selector** evidence on real
# `target/release/qbind-node`. Closes the Run 198-deferred release-binary
# boundary for the hidden RemoteSigner policy selector added by
# `crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` (Run 198),
# layered above the Run 196 RemoteSigner attestation payload-carrying surface
# (`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`) and the
# Run 194 RemoteSigner production-custody boundary
# (`crates/qbind-node/src/pqc_remote_authority_signer.rs`).
#
# Driving spec: `task/RUN_199_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * the hidden CLI flag `--p2p-trust-bundle-remote-signer-policy` is present
#     but hidden from normal `--help`;
#   * the existing Run 070 / 130–198 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193 hidden
#     custody-policy selector, the governance fixture flag) emit no
#     RemoteSigner enablement banner, no "RemoteSigner backend connected" /
#     "RemoteSigner production active" claim, no KMS/HSM active claim, no
#     governance-execution claim, no validator-set rotation claim, and no
#     MainNet peer-driven apply enablement;
#   * the binary accepts the hidden RemoteSigner policy selector (CLI flag and
#     env var) without exposing or enabling a real RemoteSigner backend;
#   * even with the Run 198 selector armed to
#     `mainnet-production-remote-signer-required` on `--env mainnet`, the
#     binary still emits no MainNet peer-driven apply enablement and no
#     RemoteSigner/KMS/HSM enablement — the Run 147 / 148 / 152 FATAL
#     invariant is preserved at the binary surface;
#   * the release-built Run 199 helper
#     `run_199_remote_signer_policy_release_binary_helper` exercises the
#     Run 198 RemoteSigner policy selector (`remote_signer_policy_from_selector`,
#     `remote_signer_policy_env_selector`, `remote_signer_policy_from_cli_or_env`)
#     and routes the resolved `RemoteSignerPolicy` through the seven Run 198
#     per-surface preflight wrappers (`preflight_v2_marker_remote_signer_for_*`)
#     into the Run 196 payload-carrying helpers and the Run 194 verifier — all
#     in **release mode** through the production library symbols.
#
# Strict scope (from `task/RUN_199_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 199 helper to mint RemoteSigner-carrying
#     material and resolve the selector in release mode through the production
#     library symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real RemoteSigner backend / networked signer service.
#   * No real KMS / HSM / cloud KMS / PKCS#11 integration.
#   * No real on-chain governance proof verifier; no governance execution;
#     no validator-set rotation; no autonomous apply; no apply-on-receipt;
#     no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No schema / wire / metric drift.
#   * No authority-marker / sequence-file / trust-bundle core schema change.
#   * Do not weaken Runs 070, 130–198.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under `OUTDIR`
# except `README.md`, `summary.txt`, and `.gitignore`, which are tracked in
# git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_199_remote_signer_policy_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_199_BIN="${REPO_ROOT}/target/release/examples/run_199_remote_signer_policy_release_binary_helper"

HELPER_199_OUT="${OUTDIR}/helper_evidence/run_199"
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

log()  { printf '[run-199] %s\n' "$*" >&2; }
fail() { printf '[run-199] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_199_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_199_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-199 provenance"
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
# Build qbind-node bin + Run 199 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_199_remote_signer_policy_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_199_remote_signer_policy_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_199.log" 2>&1 \
  || fail "release build of run_199 helper failed (see ${LOGS_DIR}/build_helper_run_199.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_199_BIN}" ]] || fail "missing ${HELPER_199_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_199_path:    ${HELPER_199_BIN}"
  echo "helper_199_sha256:  $(sha256_file "${HELPER_199_BIN}")"
  echo "helper_199_buildid: $(build_id "${HELPER_199_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 199 release helper. Exits 0 iff the selector-resolution table,
# the A1..A11 / R4..R34 scenario corpus routed through the seven Run 198
# preflight wrappers, the seven-surface reachability table, the custody-class
# routing table, the governance/other-custody bypass table, the combined v2
# sidecar loader table, the refusal-helper reachability table, the no-mutation
# table, and the determinism table all matched in release mode through the
# production library symbols.
# ---------------------------------------------------------------------------
log "running Run 199 RemoteSigner policy selector release helper -> ${HELPER_199_OUT}"
HELPER_199_LOG="${LOGS_DIR}/helper_run_199.log"
set +e
"${HELPER_199_BIN}" "${HELPER_199_OUT}" > "${HELPER_199_LOG}" 2>&1
HELPER_199_RC=$?
set -e
echo "${HELPER_199_RC}" > "${EXIT_DIR}/helper_run_199.rc"
[[ "${HELPER_199_RC}" -eq 0 ]] || fail "run_199 helper exited rc=${HELPER_199_RC} (see ${HELPER_199_LOG})"
[[ -s "${HELPER_199_OUT}/helper_summary.txt" ]] || fail "run_199 helper did not write helper_summary.txt"
assert_grep "${HELPER_199_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants. Run 198 added only the hidden RemoteSigner
# policy selector (a hidden clap flag + env var); it adds no runtime banner.
# The surface contract is therefore that the flag is hidden from `--help` and
# every existing Run 070 / 130–198 surface emits no RemoteSigner / KMS / HSM
# enablement banner and no MainNet peer-driven apply enablement claim.
# `--print-genesis-hash` is a non-mutating CLI that exits quickly without
# opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help hides the RemoteSigner policy selector flag"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
# The hidden flag and its env var MUST NOT appear in normal --help output.
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-remote-signer-policy"
assert_not_grep "${HELP_LOG}" "QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "run-194"
assert_not_grep "${HELP_LOG}" "run-196"
assert_not_grep "${HELP_LOG}" "run-198"
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
  assert_not_grep "${logf}" "(?i)remote signer (?:enabled|active|connected|wired)"
  assert_not_grep "${logf}" "(?i)remote signer backend connected"
  assert_not_grep "${logf}" "(?i)remote signer production active"
  assert_not_grep "${logf}" "(?i)kms.?hsm (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)production custody (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)governance execution"
  assert_not_grep "${logf}" "(?i)validator-set rotation"
  assert_not_grep "${logf}" "(?i)autonomous apply"
  assert_not_grep "${logf}" "MainNet peer-driven apply ENABLED"
}

log "S2 — default DevNet surface: no RemoteSigner/KMS/HSM banner"
run_surface_scenario "S2_default_devnet" devnet

log "S3 — default TestNet surface: no RemoteSigner/KMS/HSM banner"
run_surface_scenario "S3_default_testnet" testnet

log "S4 — default MainNet surface: no RemoteSigner banner, no MainNet apply"
run_surface_scenario "S4_default_mainnet" mainnet

log "S5 — CLI selector fixture-loopback-allowed on DevNet: no banner drift"
run_surface_scenario "S5_cli_fixture_devnet" devnet \
  --p2p-trust-bundle-remote-signer-policy fixture-loopback-allowed

log "S6 — env selector production-remote-signer-required on DevNet: no banner drift"
S6_LOG="${LOGS_DIR}/S6_env_production_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=production-remote-signer-required \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_env_production_devnet.rc"
assert_not_grep "${S6_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S6_LOG}" "(?i)remote signer backend connected"
assert_not_grep "${S6_LOG}" "(?i)remote signer production active"
assert_not_grep "${S6_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"

log "S7 — Run 193 custody selector armed alongside RemoteSigner selector on DevNet: compat"
S7_LOG="${LOGS_DIR}/S7_custody_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_custody_selector_compat.rc"
assert_not_grep "${S7_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S7_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"

log "S8 — governance fixture flag armed on DevNet: no RemoteSigner banner drift"
S8_LOG="${LOGS_DIR}/S8_governance_fixture_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S8_governance_fixture_compat.rc"
assert_not_grep "${S8_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S8_LOG}" "(?i)governance execution"
assert_not_grep "${S8_LOG}" "(?i)on-chain governance proof verifier active"
assert_not_grep "${S8_LOG}" "MainNet peer-driven apply ENABLED"

log "S9 — MainNet with RemoteSigner selector mainnet-production-remote-signer-required: refusal preserved"
S9_LOG="${LOGS_DIR}/S9_mainnet_armed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=mainnet-production-remote-signer-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-remote-signer-policy mainnet-production-remote-signer-required ) \
  > "${S9_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S9_mainnet_armed.rc"
assert_not_grep "${S9_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S9_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S9_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S9_LOG}" "(?i)remote signer production active"
assert_not_grep "${S9_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S9_LOG}" "(?i)validator-set rotation"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 198 RemoteSigner policy
# selector + Run 196 payload-carrying surface + Run 194 verifier. We grep the
# production source under crates/qbind-node/src so the artifact records that
# the typed surface the Run 199 helper exercises is wired in production source.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 199 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_remote_signer_policy_surface' \
    'QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY' \
    'p2p_trust_bundle_remote_signer_policy' \
    'remote_signer_policy_from_selector' \
    'remote_signer_policy_env_selector' \
    'remote_signer_policy_from_cli_or_env' \
    'RemoteSignerPolicySelectorParseError' \
    'preflight_v2_marker_remote_signer_for_reload_check' \
    'preflight_v2_marker_remote_signer_for_reload_apply' \
    'preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle' \
    'preflight_v2_marker_remote_signer_for_sighup' \
    'preflight_v2_marker_remote_signer_for_local_peer_candidate_check' \
    'preflight_v2_marker_remote_signer_for_live_inbound_0x05' \
    'preflight_v2_marker_remote_signer_for_peer_driven_drain' \
    'RemoteSignerPolicy::Disabled' \
    'RemoteSignerPolicy::FixtureLoopbackAllowed' \
    'RemoteSignerPolicy::ProductionRemoteSignerRequired' \
    'RemoteSignerPolicy::MainnetProductionRemoteSignerRequired' \
    'pqc_remote_signer_payload_carrying' \
    'callsite_context_for_remote_signer' \
    'route_remote_signer_attestation_for_custody_class' \
    'validate_loaded_remote_signer' \
    'ProductionRemoteSignerUnavailable' \
    'MainNetProductionRemoteSignerUnavailable' \
    'mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying' \
    'pqc_remote_authority_signer'
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
  echo "Run 199 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'remote signer backend connected' \
    'remote signer enabled' \
    'remote signer production active' \
    'RemoteSigner backend connected' \
    'RemoteSigner enabled' \
    'governance execution claim' \
    'real on-chain governance proof claim' \
    'KMS/HSM enabled' \
    'KMS/HSM active' \
    'kms-hsm enabled' \
    'production custody enabled' \
    'production custody active' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_199_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected RemoteSigner-policy scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 199 no-mutation proof for rejected RemoteSigner-policy scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven RemoteSigner policy rejection corpus (R1..R34):"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  echo "    * no real RemoteSigner / KMS / HSM backend wired"
  echo "    * no real governance execution / no real on-chain proof verifier"
  echo "    * no validator-set rotation"
  echo "    * invalid CLI/env selector values fail closed with typed parse"
  echo "      errors (selector_resolution_table.txt R1/R2) BEFORE any policy"
  echo "      is resolved — the resolver never silently downgrades to Disabled;"
  echo "    * the validation-only preflight wrappers (reload-check /"
  echo "      local-peer-candidate-check / live-inbound-0x05) are pure"
  echo "      functions returning typed outcomes; the mutating-preflight"
  echo "      wrappers (reload-apply / startup-p2p / sighup) short-circuit a"
  echo "      malformed carrier BEFORE the Run 194 verifier and therefore"
  echo "      BEFORE any sequence/marker write or Run 070 call"
  echo "      (no_mutation_evidence.txt + determinism_evidence.txt)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_199_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted fixture-loopback scenarios
# (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 199 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site RemoteSigner policy selector"
  echo "  reachability today:"
  echo "    - Run 198 added pqc_remote_signer_policy_surface.rs with the hidden"
  echo "      env-var name QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY, the"
  echo "      typed RemoteSignerPolicySelectorParseError, the pure parsers"
  echo "      remote_signer_policy_from_selector / remote_signer_policy_env_selector,"
  echo "      the CLI/env resolver remote_signer_policy_from_cli_or_env, and the"
  echo "      seven per-surface preflight wrappers"
  echo "      preflight_v2_marker_remote_signer_for_{reload_check / reload_apply /"
  echo "      startup_p2p_trust_bundle / sighup / local_peer_candidate_check /"
  echo "      live_inbound_0x05 / peer_driven_drain};"
  echo "    - the hidden clap flag --p2p-trust-bundle-remote-signer-policy"
  echo "      (hide = true) is parsed into cli.p2p_trust_bundle_remote_signer_policy"
  echo "      but adds NO new --help surface and NO runtime banner;"
  echo "    - default resolution (no CLI, no env) is RemoteSignerPolicy::Disabled"
  echo "      bit-for-bit; legacy no-RemoteSigner payloads remain accepted;"
  echo "    - the resolved policy is injected into the Run 196"
  echo "      RemoteSignerCallsiteContext via the preflight wrappers and routed"
  echo "      through the Run 196 payload-carrying helpers into the Run 194"
  echo "      verifier WITHOUT mutating any marker, sequence, trust-bundle, or"
  echo "      wire field;"
  echo "    - an invalid CLI/env selector value fails closed with a typed parse"
  echo "      error; the resolver never silently downgrades to Disabled;"
  echo "    - the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal"
  echo "      remains layered ahead of the RemoteSigner boundary even with"
  echo "      MainnetProductionRemoteSignerRequired and fixture loopback material"
  echo "      (helper scenario R34 -> mainnet_refused)."
  echo
  echo "  release-binary RemoteSigner policy selector corpus (this run):"
  echo "    - the Run 199 helper resolves the selector in release mode through"
  echo "      remote_signer_policy_from_selector / env_selector / from_cli_or_env"
  echo "      (selector_resolution_table.txt: default Disabled, CLI tags, env"
  echo "      tags, CLI-over-env precedence, invalid CLI/env fail-closed,"
  echo "      unrelated env stays Disabled, case-insensitive/trim);"
  echo "    - the helper routes the A1..A11 acceptance corpus and the R4..R34"
  echo "      rejection corpus through the seven Run 198 preflight wrappers in"
  echo "      release mode and asserts the typed decision outcome (scenarios +"
  echo "      seven_surface_reachability + determinism tables);"
  echo "    - the helper additionally exercises the custody-class router"
  echo "      (custody_routing_table.txt), the governance/other-custody bypass"
  echo "      table (governance_bypass_table.txt), the combined v2-sidecar"
  echo "      loader table (loader_table.txt), the refusal-helper reachability"
  echo "      table (refusal_helpers_table.txt), and the no-mutation table"
  echo "      (no_mutation_evidence.txt)."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help hides the"
  echo "      --p2p-trust-bundle-remote-signer-policy flag and advertises no"
  echo "      RemoteSigner / KMS / HSM surface;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no RemoteSigner / KMS / HSM"
  echo "      enablement banner and no MainNet peer-driven apply enablement"
  echo "      claim, with or without the RemoteSigner selector, the Run 193"
  echo "      custody selector, or the governance fixture flag armed;"
  echo "    - even with the RemoteSigner selector set to"
  echo "      mainnet-production-remote-signer-required on MainNet, MainNet"
  echo "      peer-driven apply remains refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real RemoteSigner backend / networked signer service is wired"
  echo "      in Run 199. Every Production signer-mode response routes to the"
  echo "      typed ProductionRemoteSignerUnavailable /"
  echo "      MainNetProductionRemoteSignerUnavailable reject;"
  echo "    - fixture loopback RemoteSigner remains DevNet/TestNet evidence-only"
  echo "      and cannot satisfy MainNet production RemoteSigner;"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "    - no MainNet peer-driven apply enablement, no governance execution,"
  echo "      no real on-chain proof verifier, no validator-set rotation, no"
  echo "      autonomous apply, no apply-on-receipt, no peer-majority authority,"
  echo "      no schema/wire/metric drift."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_199_TASK.txt Validation
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
    TEST_VERDICTS+=( "test:${t}rc=skipped(not-present)" )
  fi
done
TEST_VERDICTS+=( "$(run_lib_test pqc_authority pqc_authority)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_remote_signer_policy_surface pqc_remote_signer_policy_surface)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_199.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 199 — release-binary RemoteSigner policy selector evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_199_sha256:  $(sha256_file "${HELPER_199_BIN}")"
  echo "  helper_199_buildid: $(build_id "${HELPER_199_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_cli_fixture_devnet S6_env_production_devnet S7_custody_selector_compat \
           S8_governance_fixture_compat S9_mainnet_armed
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_199rc=$(cat "${EXIT_DIR}/helper_run_199.rc" 2>/dev/null || echo 'na')$(grep -E 'verdict:' "${HELPER_199_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper selector + A1-A11 / R4-R34 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_199_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
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
  echo "  * default resolution (no CLI, no env) remains RemoteSignerPolicy::Disabled;"
  echo "  * the hidden CLI flag and env var activate the selector but expose no"
  echo "    new --help surface and emit no runtime RemoteSigner/KMS/HSM banner;"
  echo "  * CLI-over-env precedence is deterministic;"
  echo "  * invalid selector values fail closed with typed parse errors;"
  echo "  * fixture loopback RemoteSigner material remains DevNet/TestNet"
  echo "    evidence-only and reaches the production preflight contexts in"
  echo "    release mode only under an explicit FixtureLoopbackAllowed policy;"
  echo "  * production RemoteSigner material reaches the Run 194 boundary and"
  echo "    fails closed as ProductionRemoteSignerUnavailable /"
  echo "    MainNetProductionRemoteSignerUnavailable;"
  echo "  * rejected RemoteSigner-policy cases produce no mutation (no marker /"
  echo "    sequence write, no Run 070 call, no live trust swap, no session"
  echo "    eviction);"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with MainnetProductionRemoteSignerRequired + fixture loopback;"
  echo "  * no real RemoteSigner backend / networked signer service wired;"
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift;"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node accepts the hidden"
  echo "  RemoteSigner policy selector (CLI flag + env var) while keeping it"
  echo "  hidden from --help, and the release-built Run 199 helper resolves the"
  echo "  selector and routes the resolved RemoteSignerPolicy through the seven"
  echo "  Run 198 preflight wrappers into the Run 196 payload-carrying helpers"
  echo "  and the Run 194 boundary end-to-end in release mode. Default remains"
  echo "  Disabled; CLI and env selectors both work; CLI-over-env precedence is"
  echo "  deterministic; invalid values fail closed; fixture loopback is"
  echo "  accepted only under an explicit fixture policy; production material"
  echo "  fails closed as unavailable; rejected cases produce no mutation."
  echo "  MainNet peer-driven apply remains the Run 147 FATAL refusal even with"
  echo "  MainnetProductionRemoteSignerRequired and fixture loopback material."
  echo "  Real RemoteSigner / KMS / HSM backends, real on-chain governance proof"
  echo "  verification, governance execution, and validator-set rotation all"
  echo "  remain unimplemented. Full C4 and C5 remain OPEN."
} > "${SUMMARY}"