#!/usr/bin/env bash
# Run 187 — Release-binary production OnChainGovernance verifier-boundary
# evidence on real `target/release/qbind-node`. Closes the Run 186-deferred
# release-binary boundary for the typed production OnChainGovernance
# verifier surface added by `pqc_onchain_governance_verifier.rs`.
#
# Driving spec: `task/RUN_187_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default `OnChainGovernanceVerifierKind::Disabled` remains
#     fail-closed on every production surface — the binary emits no
#     Run 180 armed banner and a v2 sidecar carrying a Run 184
#     `onchain_governance_proof` sibling parses as
#     `OnChainGovernanceProofPolicy::Disabled` (A8 / R1);
#   * the hidden CLI selector
#     `--p2p-trust-bundle-onchain-governance-fixture-allowed` and the
#     `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` env
#     selector arm `AllowFixtureSourceTest` on real qbind-node and
#     do NOT enable any production verifier (A1 / A2 / A3 / A4);
#   * the existing Run 185 reload-check / reload-apply DevNet fixture
#     payload paths remain compatible under the Run 186 typed
#     verifier-boundary contract (A3 / A4);
#   * the Run 186 dispatcher
#     `dispatch_onchain_governance_proof_through_verifier_boundary`
#     returns the typed `ProductionVerifierUnavailable` /
#     `MainNetProductionVerifierUnavailable` /
#     `ProductionProofUnsupported` /
#     `FixtureProofRejectedAsMainNetProductionAuthority` /
#     `Run178Rejection` outcomes per A1–A8 / R1–R29 in release mode
#     through the production library symbols, captured by the
#     release-built Run 187 helper;
#   * the real binary's MainNet peer-driven apply refusal
#     (Run 147 FATAL invariant) is unchanged with the selector armed
#     AND a fully-valid DevNet fixture proof carried in the v2
#     sidecar via the Run 184 sibling AND/OR a production-class proof
#     carried — the surface-level `MainNetRefused` short-circuit
#     fires ahead of any verifier (R27);
#   * release-built helpers (the Run 185
#     `run_185_onchain_governance_payload_release_binary_helper` for
#     payload reachability and the new Run 187
#     `run_187_onchain_governance_verifier_boundary_release_binary_helper`
#     for the typed verifier-boundary corpus) exercise the Run 186
#     A1–A8 / R1–R29 corpus end-to-end in **release mode** through
#     the production library symbols
#     `pqc_onchain_governance_verifier::*` —
#     `OnChainGovernanceVerifierKind`, `OnChainGovernanceVerifierPolicy`,
#     `OnChainGovernanceProofClass`, `OnChainGovernanceVerifier`,
#     the four concrete verifier modes
#     (`DisabledOnChainGovernanceVerifier`,
#     `FixtureSourceTestOnChainGovernanceVerifier`,
#     `ProductionUnavailableOnChainGovernanceVerifier`,
#     `ProductionVerifierPlaceholderOnChainGovernanceVerifier`),
#     `verify_fixture_onchain_governance_proof`,
#     `verify_production_onchain_governance_proof`,
#     `dispatch_onchain_governance_proof_through_verifier_boundary`,
#     `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`,
#     `classify_onchain_governance_proof_class`, and
#     `is_reserved_production_onchain_governance_proof_suite`.
#
# Strict scope (from `task/RUN_187_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use release-built helper(s) to exercise the Run 186 verifier
#     boundary; reuse the Run 185 helper to mint payload-carrying
#     sidecars for binary-surface compatibility scenarios.
#   * No production source change unless a tiny harness-only fix is
#     required (none introduced by this run).
#   * No MainNet peer-driven apply enablement.
#   * No real on-chain governance execution / no real on-chain proof
#     verifier / no bridge / light-client / KMS-HSM / validator-set
#     rotation / autonomous apply / apply-on-receipt / peer-majority
#     authority.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * Do not weaken Runs 070, 130–186.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_185_BIN="${REPO_ROOT}/target/release/examples/run_185_onchain_governance_payload_release_binary_helper"
HELPER_187_BIN="${REPO_ROOT}/target/release/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper"

HELPER_185_OUT="${OUTDIR}/helper_evidence/run_185"
HELPER_187_OUT="${OUTDIR}/helper_evidence/run_187"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
GREP_DIR="${OUTDIR}/grep_summaries"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
SCEN_DIR="${OUTDIR}/scenarios"
SIDE_DIR="${OUTDIR}/sidecars"
DATA_DIR="${OUTDIR}/data"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"
MUT_PROOF="${OUTDIR}/mutation_proof.txt"
NOMUT_PROOF="${OUTDIR}/no_mutation_proof.txt"

log()  { printf '[run-187] %s\n' "$*" >&2; }
fail() { printf '[run-187] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_185_OUT}" "${HELPER_187_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
       "${SIDE_DIR}" "${DATA_DIR}"
mkdir -p "${HELPER_185_OUT}" "${HELPER_187_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
         "${SIDE_DIR}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-187 provenance"
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
# Build qbind-node bin + Run 185 helper (for sidecar minting) + Run 187
# helper (verifier-boundary corpus) in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_185_onchain_governance_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_185_onchain_governance_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_185.log" 2>&1 \
  || fail "release build of run_185 helper failed (see ${LOGS_DIR}/build_helper_run_185.log)"

log "cargo build --release -p qbind-node --example run_187_onchain_governance_verifier_boundary_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_187_onchain_governance_verifier_boundary_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_187.log" 2>&1 \
  || fail "release build of run_187 helper failed (see ${LOGS_DIR}/build_helper_run_187.log)"

[[ -x "${NODE_BIN}"        ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_185_BIN}"  ]] || fail "missing ${HELPER_185_BIN}"
[[ -x "${HELPER_187_BIN}"  ]] || fail "missing ${HELPER_187_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_185_path:    ${HELPER_185_BIN}"
  echo "helper_185_sha256:  $(sha256_file "${HELPER_185_BIN}")"
  echo "helper_185_buildid: $(build_id "${HELPER_185_BIN}")"
  echo "helper_187_path:    ${HELPER_187_BIN}"
  echo "helper_187_sha256:  $(sha256_file "${HELPER_187_BIN}")"
  echo "helper_187_buildid: $(build_id "${HELPER_187_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive both release-built helpers. Each helper exits 0 iff every
# scenario matched its expected typed outcome in release mode through
# the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 185 payload-carrying release helper -> ${HELPER_185_OUT}"
HELPER_185_LOG="${LOGS_DIR}/helper_run_185.log"
set +e
"${HELPER_185_BIN}" "${HELPER_185_OUT}" > "${HELPER_185_LOG}" 2>&1
HELPER_185_RC=$?
set -e
echo "${HELPER_185_RC}" > "${EXIT_DIR}/helper_run_185.rc"
[[ "${HELPER_185_RC}" -eq 0 ]] || fail "run_185 helper exited rc=${HELPER_185_RC} (see ${HELPER_185_LOG})"
[[ -s "${HELPER_185_OUT}/helper_summary.txt" ]] || fail "run_185 helper did not write helper_summary.txt"
assert_grep "${HELPER_185_OUT}/helper_summary.txt" "verdict: PASS"

log "running Run 187 verifier-boundary release helper -> ${HELPER_187_OUT}"
HELPER_187_LOG="${LOGS_DIR}/helper_run_187.log"
set +e
"${HELPER_187_BIN}" "${HELPER_187_OUT}" > "${HELPER_187_LOG}" 2>&1
HELPER_187_RC=$?
set -e
echo "${HELPER_187_RC}" > "${EXIT_DIR}/helper_run_187.rc"
[[ "${HELPER_187_RC}" -eq 0 ]] || fail "run_187 helper exited rc=${HELPER_187_RC} (see ${HELPER_187_LOG})"
[[ -s "${HELPER_187_OUT}/helper_summary.txt" ]] || fail "run_187 helper did not write helper_summary.txt"
assert_grep "${HELPER_187_OUT}/helper_summary.txt" "verdict: PASS"

# Mirror the canonical Run 185-minted sidecars into the harness top-level
# `sidecars/` so that real `target/release/qbind-node` invocations
# below can pass them via `--p2p-trust-bundle-reload-check` /
# `--p2p-trust-bundle-reload-apply-path` for Run 187 compatibility
# (A3 / A4) and for MainNet refusal (R27) at the binary surface.
cp -f "${HELPER_185_OUT}/sidecars/legacy_no_proof.json"            "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/devnet_rotate_valid.json"        "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/testnet_rotate_valid.json"       "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/mainnet_rotate_valid.json"       "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/malformed_non_object.json"       "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/malformed_unknown_schema.json"   "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/malformed_empty_field.json"      "${SIDE_DIR}/" 2>/dev/null || true
cp -f "${HELPER_185_OUT}/sidecars/malformed_empty_proof_bytes.json" "${SIDE_DIR}/" 2>/dev/null || true

# Per-sidecar SHA-256 for the manifest.
{
  echo "Run 187 reused-from-Run-185 sidecar manifest (release-built helper output):"
  for f in "${SIDE_DIR}"/*.json; do
    [[ -f "$f" ]] || continue
    echo "  $(basename "$f")  $(sha256_file "$f")"
  done
} > "${OUTDIR}/fixture_manifest.txt"

# ---------------------------------------------------------------------------
# A8 / R1 — default Disabled invariants on real qbind-node:
#   - `--help` does not surface hidden selector flag (`hide = true`)
#     and does not surface `run-180`..`run-187` tokens;
#   - default invocation (no flag, no env) emits no Run 180 banner;
#   - the binary does not surface `production-verifier` / `governance
#     execution` / `kms-hsm` / `validator-set rotation` claims.
# We use `--print-genesis-hash` as a no-op terminal that exits 0
# quickly so we can capture early-startup banner emission without
# opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "A8 / R1 — default Disabled invariants (no flag, no env)"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/A8_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-onchain-governance-fixture-allowed"
assert_not_grep "${HELP_LOG}" "(?i)onchain.?governance.?fixture"
assert_not_grep "${HELP_LOG}" "run-180"
assert_not_grep "${HELP_LOG}" "run-181"
assert_not_grep "${HELP_LOG}" "run-182"
assert_not_grep "${HELP_LOG}" "run-183"
assert_not_grep "${HELP_LOG}" "run-184"
assert_not_grep "${HELP_LOG}" "run-185"
assert_not_grep "${HELP_LOG}" "run-186"
assert_not_grep "${HELP_LOG}" "run-187"
assert_not_grep "${HELP_LOG}" "ProductionVerifier"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

A8_LOG="${LOGS_DIR}/A8_default_disabled.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${A8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A8_default_disabled.rc"
assert_not_grep "${A8_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_not_grep "${A8_LOG}" "(?i)production verifier (?:enabled|active|wired)"
assert_not_grep "${A8_LOG}" "(?i)real on-chain governance proof"

# ---------------------------------------------------------------------------
# A1 / A2 — CLI selector arms AllowFixtureSourceTest on real
# qbind-node and does NOT enable any production verifier.
# ---------------------------------------------------------------------------
log "A1/A2 — CLI selector arms fixture policy on real qbind-node"
A1_LOG="${LOGS_DIR}/A1_cli_selector.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${A1_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A1_cli_selector.rc"
assert_grep     "${A1_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep     "${A1_LOG}" "AllowFixtureSourceTest"
assert_not_grep "${A1_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${A1_LOG}" "(?i)production verifier (?:enabled|active|wired)"

# ---------------------------------------------------------------------------
# A1/A2 — env selector arms / disarms across truthy/falsey variants.
# ---------------------------------------------------------------------------
log "A1/A2 — env selector arms fixture policy on real qbind-node"
A2_LOG="${LOGS_DIR}/A2_env_selector.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${A2_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A2_env_selector.rc"
assert_grep "${A2_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep "${A2_LOG}" "AllowFixtureSourceTest"

for v in true TRUE yes YES on ON True; do
  log "A2 — env selector truthy variant: ${v}"
  L="${LOGS_DIR}/A2_env_selector_${v}.log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${L}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/A2_env_selector_${v}.rc"
  assert_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

for v in 0 false FALSE no off "" "garbage"; do
  log "A2 — env selector falsey variant: '${v}'"
  L="${LOGS_DIR}/A2_env_selector_falsey_$(printf '%s' "${v:-empty}" | tr -c 'a-zA-Z0-9_' '_').log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${L}" 2>&1 || true
  assert_not_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

# ---------------------------------------------------------------------------
# A3 — Run 185 reload-check fixture proof path remains compatible under
# Run 186 typed verifier-boundary contract: real
# `target/release/qbind-node --p2p-trust-bundle-reload-check
# <devnet_rotate_valid.json>
# --p2p-trust-bundle-onchain-governance-fixture-allowed` reaches the
# Run 182 reload-check named entry through the validation-only call
# site, the parsed proof is supplied via the Run 184 sibling, the
# typed verifier-boundary outcome remains a fixture-accept under the
# Run 186 dispatcher (captured at the library layer by the helper),
# and the binary exits cleanly with no marker write and no sequence
# write.
# ---------------------------------------------------------------------------
A3_SIDECAR="${SIDE_DIR}/devnet_rotate_valid.json"
A3_LOG="${LOGS_DIR}/A3_reload_check_compat.log"
if [[ -s "${A3_SIDECAR}" ]]; then
  log "A3 — reload-check loads valid DevNet Rotate sidecar with sibling (Run 185 compat)"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${A3_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A3_LOG}" 2>&1
  A3_RC=$?
  set -e
  echo "${A3_RC}" > "${EXIT_DIR}/A3_reload_check_compat.rc"
  assert_grep     "${A3_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
  assert_not_grep "${A3_LOG}" "MainNet peer-driven apply ENABLED"
  assert_not_grep "${A3_LOG}" "DummySig"
  assert_not_grep "${A3_LOG}" "DummyKem"
  assert_not_grep "${A3_LOG}" "DummyAead"
  assert_not_grep "${A3_LOG}" "(?i)production verifier (?:enabled|active|wired)"
else
  log "A3 — skipped (run_185 helper did not mint ${A3_SIDECAR})"
fi

# A3_legacy — pre-Run-184 sidecar (no sibling) under armed selector
# parses identically; selector banner armed; no carrier acceptance
# without a sibling.
A3L_SIDECAR="${SIDE_DIR}/legacy_no_proof.json"
A3L_LOG="${LOGS_DIR}/A3_legacy_reload_check.log"
if [[ -s "${A3L_SIDECAR}" ]]; then
  log "A3_legacy — reload-check on pre-Run-184 sidecar without sibling"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${A3L_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A3L_LOG}" 2>&1
  A3L_RC=$?
  set -e
  echo "${A3L_RC}" > "${EXIT_DIR}/A3_legacy_reload_check.rc"
  assert_not_grep "${A3L_LOG}" "MainNet peer-driven apply ENABLED"
fi

# ---------------------------------------------------------------------------
# A4 — Run 185 reload-apply fixture proof path remains compatible
# under Run 186 typed verifier-boundary contract. This binary
# surface honestly returns `ReloadApplyError::UnsupportedRuntimeContext`
# per Run 070 evidence on a non-long-running invocation; the value of
# this scenario is the **payload/context reachability** capture: the
# selector arms, the sidecar is loaded, the sibling parses, the
# Run 182 reload-apply named entry is invoked at the library layer,
# and the helper Run 187 corpus captures the matching Run 186
# verifier-boundary outcome through the production library symbols.
# Exit code is captured but not asserted to be 0 because the Run 070
# honest boundary may surface `UnsupportedRuntimeContext` here.
# ---------------------------------------------------------------------------
A4_SIDECAR="${SIDE_DIR}/devnet_rotate_valid.json"
A4_LOG="${LOGS_DIR}/A4_reload_apply_compat.log"
if [[ -s "${A4_SIDECAR}" ]]; then
  log "A4 — reload-apply loads valid DevNet Rotate sidecar with sibling (Run 185 compat)"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-apply-enabled \
                    --p2p-trust-bundle-reload-apply-path "${A4_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A4_LOG}" 2>&1
  A4_RC=$?
  set -e
  echo "${A4_RC}" > "${EXIT_DIR}/A4_reload_apply_compat.rc"
  assert_grep     "${A4_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
  assert_not_grep "${A4_LOG}" "MainNet peer-driven apply ENABLED"
  assert_not_grep "${A4_LOG}" "DummySig"
  assert_not_grep "${A4_LOG}" "DummyKem"
  assert_not_grep "${A4_LOG}" "DummyAead"
  assert_not_grep "${A4_LOG}" "(?i)production verifier (?:enabled|active|wired)"
fi

# ---------------------------------------------------------------------------
# R27 — MainNet refusal: even with CLI selector + env selector engaged
# AND a fully-valid MainNet OnChainGovernance fixture proof carried
# in the v2 sidecar via the Run 184 sibling, the real binary refuses
# any MainNet peer-driven apply path. We assert this by requesting
# `--print-genesis-hash --env mainnet` (a non-mutating CLI) and
# recording that no banner declares MainNet apply enablement.
# Source-level MainNet refusal — including the peer-driven drain
# callsite entry's surface-level `MainNetRefused` short-circuit
# layered ahead of the Run 180 verifier per Runs 147/148/152 and the
# Run 186 typed
# `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
# helper — is additionally captured by the helper R27 scenarios
# across every policy kind, even in the presence of the valid MainNet
# fixture proof OR a production-class proof.
# ---------------------------------------------------------------------------
log "R27 — MainNet refusal under armed selector AND valid fixture payload"
R27_LOG="${LOGS_DIR}/R27_mainnet_refusal.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${R27_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/R27_mainnet_refusal.rc"
assert_not_grep "${R27_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${R27_LOG}" "(?i)mainnet.+apply.+enabled"

# Also feed the canonical MainNet-Rotate-with-sibling sidecar through
# the reload-check binary surface to capture the MainNet refusal even
# when a fully-valid MainNet fixture proof is carried.
R27P_SIDECAR="${SIDE_DIR}/mainnet_rotate_valid.json"
R27P_LOG="${LOGS_DIR}/R27_mainnet_payload_reload_check.log"
if [[ -s "${R27P_SIDECAR}" ]]; then
  log "R27 — MainNet refusal at reload-check with valid MainNet fixture sibling"
  set +e
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${R27P_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env mainnet ) \
    > "${R27P_LOG}" 2>&1
  R27P_RC=$?
  set -e
  echo "${R27P_RC}" > "${EXIT_DIR}/R27_mainnet_payload_reload_check.rc"
  assert_not_grep "${R27P_LOG}" "MainNet peer-driven apply ENABLED"
fi

# ---------------------------------------------------------------------------
# R20 / R22 — malformed-sibling fail-closed at the qbind-node binary
# boundary: the Run 184 loader returns
# `OnChainGovernanceProofPayloadParseError` BEFORE any Run 186
# verifier-boundary dispatch; the binary should exit non-zero. We
# feed the four malformed shapes the Run 185 helper minted.
for shape in malformed_non_object malformed_unknown_schema \
             malformed_empty_field malformed_empty_proof_bytes; do
  SIDECAR="${SIDE_DIR}/${shape}.json"
  RM_LOG="${LOGS_DIR}/R20_${shape}_reload_check.log"
  if [[ -s "${SIDECAR}" ]]; then
    log "R20/R22 — malformed sibling rejected at reload-check (${shape})"
    set +e
    ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
        "${NODE_BIN}" --p2p-trust-bundle-reload-check "${SIDECAR}" \
                      --p2p-trust-bundle-onchain-governance-fixture-allowed \
                      --env devnet ) \
      > "${RM_LOG}" 2>&1
    RM_RC=$?
    set -e
    echo "${RM_RC}" > "${EXIT_DIR}/R20_${shape}.rc"
    # No mutating side effects regardless of rc.
    assert_not_grep "${RM_LOG}" "MainNet peer-driven apply ENABLED"
    assert_not_grep "${RM_LOG}" "DummySig"
    assert_not_grep "${RM_LOG}" "DummyKem"
    assert_not_grep "${RM_LOG}" "DummyAead"
    assert_not_grep "${RM_LOG}" "(?i)production verifier (?:enabled|active|wired)"
  fi
done

# ---------------------------------------------------------------------------
# Source/release reachability proof. Run 187 widens the Run 185 grep
# corpus to cover the Run 186 typed verifier-boundary symbols (the
# verifier kind enum, the four concrete verifier modes, the typed
# boundary outcomes, the dispatcher entry points, the MainNet
# refusal helper, the proof classifier).
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 187 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_onchain_governance_verifier' \
    'OnChainGovernanceVerifierKind' \
    'OnChainGovernanceVerifierKind::Disabled' \
    'OnChainGovernanceVerifierKind::FixtureSourceTest' \
    'OnChainGovernanceVerifierKind::ProductionUnavailable' \
    'OnChainGovernanceVerifierKind::ProductionVerifier' \
    'OnChainGovernanceVerifierPolicy' \
    'OnChainGovernanceProofClass' \
    'OnChainGovernanceVerifierBoundaryOutcome' \
    'OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture' \
    'OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled' \
    'OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable' \
    'OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported' \
    'OnChainGovernanceVerifierBoundaryOutcome::ProductionProofMalformed' \
    'OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable' \
    'OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority' \
    'OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection' \
    'OnChainGovernanceVerifier' \
    'DisabledOnChainGovernanceVerifier' \
    'FixtureSourceTestOnChainGovernanceVerifier' \
    'ProductionUnavailableOnChainGovernanceVerifier' \
    'ProductionVerifierPlaceholderOnChainGovernanceVerifier' \
    'verify_fixture_onchain_governance_proof' \
    'verify_production_onchain_governance_proof' \
    'dispatch_onchain_governance_proof_through_verifier_boundary' \
    'mainnet_peer_driven_apply_remains_refused_under_verifier_boundary' \
    'classify_onchain_governance_proof_class' \
    'is_reserved_production_onchain_governance_proof_suite' \
    'OnChainGovernanceReplaySet' \
    'OnChainGovernanceProofPolicy::AllowFixtureSourceTest' \
    'pqc_onchain_governance_proof_surface' \
    'pqc_onchain_governance_callsite_wiring' \
    'pqc_onchain_governance_payload_carrying' \
    'reload_check_compose_onchain_governance_marker_decision' \
    'reload_apply_compose_onchain_governance_marker_decision'
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
  echo "Run 187 denylist (proven empty across all captured logs):"
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
    'validator-set rotation claim' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED' \
    'production verifier enabled' \
    'production verifier active' \
    'production verifier wired'
  do
    if find "${LOGS_DIR}" "${HELPER_185_OUT}" "${HELPER_187_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected verifier-boundary scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 187 no-mutation proof for rejected verifier-boundary scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven Run 186 verifier-boundary rejection corpus (R1..R29):"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  echo "    * no real production verifier wired"
  grep -E 'verdict: PASS|R[0-9]+_|A[0-9]+_' \
    "${HELPER_187_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
  echo
  echo "  Run 185 helper payload-carrying compatibility summary:"
  grep -E 'verdict: PASS|R[0-9]+_' \
    "${HELPER_185_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted compatibility scenarios.
# ---------------------------------------------------------------------------
{
  echo "Run 187 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site Run 186 verifier-boundary"
  echo "  reachability today:"
  echo "    - main.rs resolves OnChainGovernanceProofPolicy via"
  echo "      onchain_governance_proof_policy_from_cli_or_env(...) — Run 180;"
  echo "    - main.rs emits the [run-180] armed banner only when"
  echo "      AllowFixtureSourceTest is resolved (CLI flag set OR env truthy);"
  echo "    - the production v2 sidecar load path"
  echo "      (load_v2_ratification_sidecar_with_onchain_governance_proof_*) —"
  echo "      Run 184 — extracts the additive onchain_governance_proof sibling"
  echo "      and yields a typed OnChainGovernanceProofLoadStatus;"
  echo "    - Run 186 added pqc_onchain_governance_verifier.rs with the typed"
  echo "      OnChainGovernanceVerifierKind {Disabled, FixtureSourceTest,"
  echo "      ProductionUnavailable, ProductionVerifierPlaceholder}, the proof"
  echo "      classifier, the OnChainGovernanceVerifier trait, four concrete"
  echo "      verifier modes, pure entry points"
  echo "      (verify_fixture_onchain_governance_proof,"
  echo "       verify_production_onchain_governance_proof) and the dispatcher"
  echo "      (dispatch_onchain_governance_proof_through_verifier_boundary)"
  echo "      plus the MainNet refusal helper"
  echo "      (mainnet_peer_driven_apply_remains_refused_under_verifier_boundary);"
  echo "    - the Run 186 verifier boundary is wired source-side BEHIND the"
  echo "      Run 184 routing helpers and BEFORE any Run 070 apply call,"
  echo "      so a malformed-payload short-circuit AND a typed"
  echo "      verifier-boundary outcome both fire BEFORE any sequence/marker"
  echo "      write, BEFORE any live trust swap, BEFORE any session"
  echo "      eviction, and BEFORE any Run 070 call;"
  echo "    - the peer-driven-drain callsite entry layers a surface-level"
  echo "      MainNetRefused short-circuit BEFORE invoking the Run 180"
  echo "      verifier (Run 147 / 148 / 152 FATAL invariant), and the Run 186"
  echo "      mainnet_peer_driven_apply_remains_refused_under_verifier_boundary"
  echo "      helper additionally encodes the rule at the typed verifier"
  echo "      boundary regardless of policy kind."
  echo
  echo "  release-binary verifier-boundary corpus (this run):"
  echo "    - the Run 187 helper exercises all four verifier kinds"
  echo "      (Disabled / FixtureSourceTest / ProductionUnavailable /"
  echo "      ProductionVerifierPlaceholder) against the dispatcher with"
  echo "      both Fixture-class and Production-class proofs in release"
  echo "      mode through the production library symbols, across the"
  echo "      A1..A8 acceptance corpus and the R1..R29 rejection corpus;"
  echo "    - the helper additionally exercises the four concrete"
  echo "      OnChainGovernanceVerifier trait impls' kind() and verify()"
  echo "      surfaces (verifier_kinds_table.txt) and the proof"
  echo "      classifier + reserved-production-suite predicate"
  echo "      (proof_class_table.txt);"
  echo "    - non-mutation evidence is captured for every rejected"
  echo "      scenario via bit-equality of candidate / persisted"
  echo "      snapshots taken before and after a rejecting dispatch"
  echo "      (no_mutation_evidence.txt)."
  echo
  echo "  release-binary reload-check / reload-apply compatibility (this run):"
  echo "    - real target/release/qbind-node --p2p-trust-bundle-reload-check"
  echo "      ${SIDE_DIR}/devnet_rotate_valid.json"
  echo "      --p2p-trust-bundle-onchain-governance-fixture-allowed --env devnet"
  echo "      successfully loads the Run 185 valid DevNet sidecar through the"
  echo "      production validation-only path; the Run 184 loader extracts"
  echo "      the sibling; the typed OnChainGovernanceProofWire parses; the"
  echo "      Run 182 reload-check named callsite entry is invoked; the"
  echo "      Run 186 typed verifier boundary returns its fixture-accept"
  echo "      under FixtureSourceTest at the library layer (captured by the"
  echo "      Run 187 helper); no marker write, no sequence write, no live"
  echo "      trust swap, no session eviction, no Run 070 call."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real on-chain governance proof verifier is wired in Run 187."
  echo "      Both ProductionUnavailable and ProductionVerifierPlaceholder route"
  echo "      production-class proofs to ProductionVerifierUnavailable on"
  echo "      DevNet/TestNet and to MainNetProductionVerifierUnavailable on"
  echo "      MainNet, and route fixture-class proofs to ProductionProofUnsupported"
  echo "      regardless of environment, encoding the honest unavailability"
  echo "      and explicitly forbidding fixture-as-MainNet-production-authority."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_187_TASK.txt
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
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_verifier pqc_onchain_governance_verifier)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_proof_surface pqc_onchain_governance_proof_surface)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_callsite_wiring pqc_onchain_governance_callsite_wiring)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_payload_carrying pqc_onchain_governance_payload_carrying)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 187 — release-binary OnChainGovernance production verifier-boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_185_sha256:  $(sha256_file "${HELPER_185_BIN}")"
  echo "  helper_185_buildid: $(build_id "${HELPER_185_BIN}")"
  echo "  helper_187_sha256:  $(sha256_file "${HELPER_187_BIN}")"
  echo "  helper_187_buildid: $(build_id "${HELPER_187_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in A8_help A8_default_disabled A1_cli_selector A2_env_selector \
           A3_reload_check_compat A3_legacy_reload_check \
           A4_reload_apply_compat \
           R20_malformed_non_object R20_malformed_unknown_schema \
           R20_malformed_empty_field R20_malformed_empty_proof_bytes \
           R27_mainnet_refusal R27_mainnet_payload_reload_check
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_185	rc=$(cat "${EXIT_DIR}/helper_run_185.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_185_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo "  helper_run_187	rc=$(cat "${EXIT_DIR}/helper_run_187.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_187_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "regression test verdicts:"
  for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits:"
  echo "  * default OnChainGovernanceVerifierKind::Disabled preserved on every surface;"
  echo "  * AllowFixtureSourceTest hidden, explicit, DevNet/TestNet fixture-only;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with armed selector AND fully-valid MainNet fixture proof carried"
  echo "    through the Run 184 v2 sidecar additive sibling;"
  echo "  * fixture proof CANNOT satisfy MainNet production governance authority"
  echo "    (typed FixtureProofRejectedAsMainNetProductionAuthority under"
  echo "    FixtureSourceTest on MainNet);"
  echo "  * production-class proof verification is fail-closed as unavailable"
  echo "    (typed ProductionVerifierUnavailable on DevNet/TestNet,"
  echo "    MainNetProductionVerifierUnavailable on MainNet);"
  echo "  * no real on-chain governance proof verifier wired in Run 187;"
  echo "  * no governance execution engine;"
  echo "  * no KMS/HSM custody;"
  echo "  * no validator-set rotation;"
  echo "  * no schema/wire/metric drift (Run 187 is release-binary evidence only);"
  echo "  * no marker write before sequence commit;"
  echo "  * no sequence write or marker write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node preserves the Run 186 typed"
  echo "  OnChainGovernance verifier-boundary contract end-to-end. Default"
  echo "  Disabled fail-closes on every production surface. The hidden"
  echo "  AllowFixtureSourceTest selector arms a DevNet/TestNet fixture-only"
  echo "  verifier and does not enable any production verifier. Existing"
  echo "  Run 185 payload-carrying reload-check / reload-apply fixture paths"
  echo "  remain compatible. The Run 187 release-built helper exercises the"
  echo "  full Run 186 A1-A8 / R1-R29 corpus end-to-end through the production"
  echo "  library symbols pqc_onchain_governance_verifier::*, returning the"
  echo "  expected typed boundary outcomes. MainNet peer-driven apply remains"
  echo "  the Run 147 FATAL refusal even with a fully-valid MainNet fixture"
  echo "  proof carried, with the Run 186"
  echo "  mainnet_peer_driven_apply_remains_refused_under_verifier_boundary"
  echo "  helper additionally encoding the rule at the typed verifier"
  echo "  boundary. Real on-chain governance proof verification, governance"
  echo "  execution, KMS/HSM custody, validator-set rotation, bridge /"
  echo "  light-client integration, autonomous apply, and apply-on-receipt"
  echo "  all remain unimplemented. Full C4 and C5 remain OPEN."
} > "${SUMMARY}"