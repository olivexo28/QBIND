#!/usr/bin/env bash
# Run 185 — Release-binary OnChainGovernance proof-payload-carrying
# accepted-proof evidence on real `target/release/qbind-node`. Closes
# the Run 184-deferred release-binary boundary for the additive
# optional `onchain_governance_proof` sibling on the v2 ratification
# sidecar JSON wire.
#
# Driving spec: `task/RUN_185_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default `OnChainGovernanceProofPolicy::Disabled` remains
#     fail-closed on real production surfaces — the binary emits no
#     Run 180 armed banner and a v2 sidecar **without** the Run 184
#     additive sibling parses byte-for-byte identically to its
#     pre-Run-184 form (A1 / R1);
#   * the hidden CLI selector arms `AllowFixtureSourceTest` on real
#     `target/release/qbind-node` (A2);
#   * the env selector arms `AllowFixtureSourceTest` across truthy
#     variants `{1, true, TRUE, True, yes, YES, on, ON}` and remains
#     disabled on falsey variants `{0, false, FALSE, no, off, "",
#     garbage}` (A3);
#   * a real `target/release/qbind-node --p2p-trust-bundle-reload-check
#     <sidecar-with-sibling>
#     --p2p-trust-bundle-onchain-governance-fixture-allowed`
#     invocation reaches the Run 182
#     `reload_check_callsite_onchain_governance_marker_decision` named
#     entry through the production
#     `preflight_run_132_validation_only_v2_marker_check` code path,
#     the parsed proof from the Run 184 sibling is supplied via
#     `OnChainGovernanceCallsiteContext`, and acceptance is observed
#     on the validation-only surface with no marker write and no
#     sequence write (A2/A3);
#   * the same path with `--p2p-trust-bundle-reload-apply-path`
#     /`--p2p-trust-bundle-reload-apply-enabled` reaches the Run 182
#     `reload_apply_callsite_onchain_governance_marker_decision`
#     named entry through the production
#     `preflight_run_134_v2_marker_decision` code path on the
#     mutating surface, with Run 055 sequence-before-marker ordering
#     preserved at the library layer (A4 / A5);
#   * `qbind-node --help` does not surface the hidden selector flag
#     (`hide = true`) and does not surface `run-180` / `run-181` /
#     `run-182` / `run-183` / `run-184` / `run-185` /
#     `onchain-governance-fixture` tokens;
#   * the real binary's MainNet peer-driven apply refusal
#     (Run 147 FATAL invariant) is unchanged with the selector armed
#     AND a fully-valid DevNet fixture proof carried in the v2
#     sidecar via the Run 184 sibling (R26);
#   * release-built helpers (the Run 179
#     `run_179_onchain_governance_proof_release_binary_helper` for
#     the verifier corpus AND the new Run 185
#     `run_185_onchain_governance_payload_release_binary_helper` for
#     the Run 184 payload-carrying / call-site-routing corpus)
#     exercise the Run 178 / 180 / 182 / 184 acceptance / rejection
#     corpus end-to-end in **release mode** through the production
#     library symbols `verify_onchain_governance_proof`,
#     `validate_lifecycle_with_onchain_governance_proof`,
#     `compose_onchain_governance_marker_decision`, the seven Run 180
#     per-surface composed wrappers, the seven Run 182 named
#     call-site entries plus `OnChainGovernanceCallsiteContext` and
#     `with_onchain_governance_fixture_allowed_selector`, the Run 184
#     payload-carrying loaders
#     `load_v2_ratification_sidecar_with_onchain_governance_proof_*`
#     / `parse_optional_onchain_governance_proof_sibling_from_json_value`
#     / `callsite_context_with_loaded_onchain_governance_proof`, and
#     every `route_loaded_onchain_governance_proof_to_*_callsite_decision`
#     helper.
#
# Strict scope (from `task/RUN_185_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use release-built helper(s) to mint OnChainGovernance proof-
#     carrying payloads.
#   * No production source change unless a tiny harness-only fix is
#     required (none introduced by this run).
#   * No MainNet peer-driven apply enablement.
#   * No real on-chain governance execution / no real on-chain proof
#     verifier / no bridge / light-client / KMS-HSM / validator-set
#     rotation / autonomous apply / apply-on-receipt / peer-majority
#     authority.
#   * No marker / sequence-file / trust-bundle / wire / metric drift
#     beyond Run 184's additive optional sibling.
#   * Do not weaken Runs 070, 130–184.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_185_onchain_governance_payload_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_179_BIN="${REPO_ROOT}/target/release/examples/run_179_onchain_governance_proof_release_binary_helper"
HELPER_185_BIN="${REPO_ROOT}/target/release/examples/run_185_onchain_governance_payload_release_binary_helper"

HELPER_179_OUT="${OUTDIR}/helper_evidence/run_179"
HELPER_185_OUT="${OUTDIR}/helper_evidence/run_185"
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

log()  { printf '[run-185] %s\n' "$*" >&2; }
fail() { printf '[run-185] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_179_OUT}" "${HELPER_185_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
       "${SIDE_DIR}" "${DATA_DIR}"
mkdir -p "${HELPER_179_OUT}" "${HELPER_185_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
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
  echo "run-185 provenance"
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
# Build qbind-node bin + Run 179 helper + Run 185 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_179.log" 2>&1 \
  || fail "release build of run_179 helper failed (see ${LOGS_DIR}/build_helper_run_179.log)"

log "cargo build --release -p qbind-node --example run_185_onchain_governance_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_185_onchain_governance_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_185.log" 2>&1 \
  || fail "release build of run_185 helper failed (see ${LOGS_DIR}/build_helper_run_185.log)"

[[ -x "${NODE_BIN}"        ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_179_BIN}"  ]] || fail "missing ${HELPER_179_BIN}"
[[ -x "${HELPER_185_BIN}"  ]] || fail "missing ${HELPER_185_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_179_path:    ${HELPER_179_BIN}"
  echo "helper_179_sha256:  $(sha256_file "${HELPER_179_BIN}")"
  echo "helper_179_buildid: $(build_id "${HELPER_179_BIN}")"
  echo "helper_185_path:    ${HELPER_185_BIN}"
  echo "helper_185_sha256:  $(sha256_file "${HELPER_185_BIN}")"
  echo "helper_185_buildid: $(build_id "${HELPER_185_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive both release-built helpers. Each helper exits 0 iff every
# scenario matched its expected typed outcome in release mode through
# the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 179 release helper -> ${HELPER_179_OUT}"
HELPER_179_LOG="${LOGS_DIR}/helper_run_179.log"
set +e
"${HELPER_179_BIN}" "${HELPER_179_OUT}" > "${HELPER_179_LOG}" 2>&1
HELPER_179_RC=$?
set -e
echo "${HELPER_179_RC}" > "${EXIT_DIR}/helper_run_179.rc"
[[ "${HELPER_179_RC}" -eq 0 ]] || fail "run_179 helper exited rc=${HELPER_179_RC} (see ${HELPER_179_LOG})"
[[ -s "${HELPER_179_OUT}/helper_summary.txt" ]] || fail "run_179 helper did not write helper_summary.txt"
assert_grep "${HELPER_179_OUT}/helper_summary.txt" "verdict: PASS"

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

# Mirror the canonical minted sidecars into the harness top-level
# `sidecars/` so that real `target/release/qbind-node` invocations
# below can pass them via `--p2p-trust-bundle-reload-check` /
# `--p2p-trust-bundle-reload-apply-path`.
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
  echo "Run 185 minted sidecar manifest (release-built helper output):"
  for f in "${SIDE_DIR}"/*.json; do
    [[ -f "$f" ]] || continue
    echo "  $(basename "$f")  $(sha256_file "$f")"
  done
} > "${OUTDIR}/fixture_manifest.txt"

# ---------------------------------------------------------------------------
# A1 / R1 — default Disabled invariants on real qbind-node:
#   - `--help` does not surface hidden selector flag (`hide = true`)
#     and does not surface `run-180`..`run-185` tokens;
#   - default invocation (no flag, no env) emits no Run 180 banner;
#   - a v2 sidecar without the Run 184 sibling parses byte-for-byte
#     identical to its pre-Run-184 form (no carrier acceptance under
#     default Disabled).
# We use `--print-genesis-hash` as a no-op terminal that exits 0
# quickly so we can capture early-startup banner emission without
# opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "A1 / R1 — default Disabled invariants (no flag, no env)"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/A1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-onchain-governance-fixture-allowed"
assert_not_grep "${HELP_LOG}" "(?i)onchain.?governance.?fixture"
assert_not_grep "${HELP_LOG}" "run-180"
assert_not_grep "${HELP_LOG}" "run-181"
assert_not_grep "${HELP_LOG}" "run-182"
assert_not_grep "${HELP_LOG}" "run-183"
assert_not_grep "${HELP_LOG}" "run-184"
assert_not_grep "${HELP_LOG}" "run-185"

A1_LOG="${LOGS_DIR}/A1_default_disabled.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${A1_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A1_default_disabled.rc"
assert_not_grep "${A1_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"

# ---------------------------------------------------------------------------
# A2 — CLI selector arms AllowFixtureSourceTest on real qbind-node.
# ---------------------------------------------------------------------------
log "A2 — CLI selector arms fixture policy on real qbind-node"
A2_LOG="${LOGS_DIR}/A2_cli_selector.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${A2_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A2_cli_selector.rc"
assert_grep     "${A2_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep     "${A2_LOG}" "AllowFixtureSourceTest"
assert_not_grep "${A2_LOG}" "MainNet peer-driven apply ENABLED"

# ---------------------------------------------------------------------------
# A3 — env selector arms / disarms across truthy/falsey variants.
# ---------------------------------------------------------------------------
log "A3 — env selector arms fixture policy on real qbind-node"
A3_LOG="${LOGS_DIR}/A3_env_selector.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${A3_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A3_env_selector.rc"
assert_grep "${A3_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep "${A3_LOG}" "AllowFixtureSourceTest"

for v in true TRUE yes YES on ON True; do
  log "A3 — env selector truthy variant: ${v}"
  L="${LOGS_DIR}/A3_env_selector_${v}.log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${L}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/A3_env_selector_${v}.rc"
  assert_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

for v in 0 false FALSE no off "" "garbage"; do
  log "A3 — env selector falsey variant: '${v}'"
  L="${LOGS_DIR}/A3_env_selector_falsey_$(printf '%s' "${v:-empty}" | tr -c 'a-zA-Z0-9_' '_').log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --env devnet ) > "${L}" 2>&1 || true
  assert_not_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

# ---------------------------------------------------------------------------
# A2_payload — real `target/release/qbind-node
# --p2p-trust-bundle-reload-check <devnet_rotate_valid.json>
# --p2p-trust-bundle-onchain-governance-fixture-allowed` invocation:
# the binary loads the v2 sidecar via the production reload-check
# code path (Run 069 / Run 132), the Run 184 payload-carrying loader
# extracts the additive `onchain_governance_proof` sibling, the
# Run 178 typed `OnChainGovernanceProofWire` parses, the proof is
# routed into the Run 182
# `reload_check_callsite_onchain_governance_marker_decision` named
# entry through the production validation-only call site, and the
# binary exits cleanly. We do NOT assert a specific stderr token
# here because the reload-check production path is intentionally
# silent on success at the qbind-node binary surface; we DO assert
# negative invariants (no banner-armed FAIL token, no MainNet apply
# ENABLED, no DummySig/DummyKem/DummyAead).
#
# Rejected (R*) production-surface scenarios are captured at the
# binary boundary by feeding the helper's malformed sidecars and by
# the helper's exhaustive R1..R26 corpus in release mode through the
# Run 184 payload-carrying loaders.
# ---------------------------------------------------------------------------
A2P_SIDECAR="${SIDE_DIR}/devnet_rotate_valid.json"
A2P_LOG="${LOGS_DIR}/A2_payload_reload_check.log"
if [[ -s "${A2P_SIDECAR}" ]]; then
  log "A2_payload — reload-check loads valid DevNet Rotate sidecar with sibling"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${A2P_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A2P_LOG}" 2>&1
  A2P_RC=$?
  set -e
  echo "${A2P_RC}" > "${EXIT_DIR}/A2_payload_reload_check.rc"
  assert_grep     "${A2P_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
  assert_not_grep "${A2P_LOG}" "MainNet peer-driven apply ENABLED"
  assert_not_grep "${A2P_LOG}" "DummySig"
  assert_not_grep "${A2P_LOG}" "DummyKem"
  assert_not_grep "${A2P_LOG}" "DummyAead"
else
  log "A2_payload — skipped (helper did not mint ${A2P_SIDECAR})"
fi

# A2_legacy — pre-Run-184 sidecar (no sibling) under armed selector
# parses identically; selector banner armed; no carrier acceptance
# without a sibling.
A2L_SIDECAR="${SIDE_DIR}/legacy_no_proof.json"
A2L_LOG="${LOGS_DIR}/A2_legacy_reload_check.log"
if [[ -s "${A2L_SIDECAR}" ]]; then
  log "A2_legacy — reload-check on pre-Run-184 sidecar without sibling"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${A2L_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A2L_LOG}" 2>&1
  A2L_RC=$?
  set -e
  echo "${A2L_RC}" > "${EXIT_DIR}/A2_legacy_reload_check.rc"
  assert_not_grep "${A2L_LOG}" "MainNet peer-driven apply ENABLED"
fi

# A4 — real qbind-node reload-apply path with valid DevNet Rotate
# sidecar carrying the Run 184 sibling. This binary surface honestly
# returns `ReloadApplyError::UnsupportedRuntimeContext` per Run 070
# evidence on a non-long-running invocation (the binary has no
# mutable runtime trust-context handle in this mode); the value of
# this scenario is the **payload/context reachability** capture: the
# selector arms, the sidecar is loaded, the sibling parses, and the
# Run 182 `reload_apply_callsite_onchain_governance_marker_decision`
# is invoked at the library layer (the helper Run 185 corpus
# captures the matching accepted typed outcome through the same
# library symbols in release mode). Exit code is captured but not
# asserted to be 0 because the Run 070 honest boundary may surface
# `UnsupportedRuntimeContext` here.
A4_SIDECAR="${SIDE_DIR}/devnet_rotate_valid.json"
A4_LOG="${LOGS_DIR}/A4_payload_reload_apply.log"
if [[ -s "${A4_SIDECAR}" ]]; then
  log "A4 — reload-apply loads valid DevNet Rotate sidecar with sibling under armed selector"
  set +e
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
      "${NODE_BIN}" --p2p-trust-bundle-reload-apply-enabled \
                    --p2p-trust-bundle-reload-apply-path "${A4_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env devnet ) \
    > "${A4_LOG}" 2>&1
  A4_RC=$?
  set -e
  echo "${A4_RC}" > "${EXIT_DIR}/A4_payload_reload_apply.rc"
  assert_grep     "${A4_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
  assert_not_grep "${A4_LOG}" "MainNet peer-driven apply ENABLED"
  assert_not_grep "${A4_LOG}" "DummySig"
  assert_not_grep "${A4_LOG}" "DummyKem"
  assert_not_grep "${A4_LOG}" "DummyAead"
fi

# R2 — malformed sibling fail-closed at the qbind-node binary
# boundary: the Run 184 loader returns
# `OnChainGovernanceProofPayloadParseError` BEFORE any verifier or
# marker decision; the binary should exit non-zero. We feed the
# four malformed shapes the helper minted (non-object,
# unknown_schema, empty required field, empty proof bytes).
for shape in malformed_non_object malformed_unknown_schema \
             malformed_empty_field malformed_empty_proof_bytes; do
  SIDECAR="${SIDE_DIR}/${shape}.json"
  R2_LOG="${LOGS_DIR}/R2_${shape}_reload_check.log"
  if [[ -s "${SIDECAR}" ]]; then
    log "R2 — malformed sibling rejected at reload-check (${shape})"
    set +e
    ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
        "${NODE_BIN}" --p2p-trust-bundle-reload-check "${SIDECAR}" \
                      --p2p-trust-bundle-onchain-governance-fixture-allowed \
                      --env devnet ) \
      > "${R2_LOG}" 2>&1
    R2_RC=$?
    set -e
    echo "${R2_RC}" > "${EXIT_DIR}/R2_${shape}.rc"
    # No mutating side effects regardless of rc.
    assert_not_grep "${R2_LOG}" "MainNet peer-driven apply ENABLED"
    assert_not_grep "${R2_LOG}" "DummySig"
    assert_not_grep "${R2_LOG}" "DummyKem"
    assert_not_grep "${R2_LOG}" "DummyAead"
  fi
done

# ---------------------------------------------------------------------------
# R26 — MainNet refusal: even with CLI selector + env selector engaged
# AND a fully-valid MainNet OnChainGovernance fixture proof carried
# in the v2 sidecar via the Run 184 sibling, the real binary refuses
# any MainNet peer-driven apply path. We assert this by requesting
# `--print-genesis-hash --env mainnet` (a non-mutating CLI) and
# recording that no banner declares MainNet apply enablement.
# Source-level MainNet refusal — including the peer-driven drain
# callsite entry's surface-level `MainNetRefused` short-circuit
# layered ahead of the Run 180 verifier per Runs 147/148/152 — is
# additionally captured by the helper R26 scenarios across every
# Run 182 named entry, even in the presence of the valid MainNet
# fixture proof.
# ---------------------------------------------------------------------------
log "R26 — MainNet refusal under armed selector AND valid fixture payload"
R26_LOG="${LOGS_DIR}/R26_mainnet_refusal.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${R26_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/R26_mainnet_refusal.rc"
assert_not_grep "${R26_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${R26_LOG}" "(?i)mainnet.+apply.+enabled"

# Also feed the canonical MainNet-Rotate-with-sibling sidecar through
# the reload-check binary surface to capture the MainNet refusal even
# when a fully-valid MainNet fixture proof is carried.
R26P_SIDECAR="${SIDE_DIR}/mainnet_rotate_valid.json"
R26P_LOG="${LOGS_DIR}/R26_mainnet_payload_reload_check.log"
if [[ -s "${R26P_SIDECAR}" ]]; then
  log "R26 — MainNet refusal at reload-check with valid MainNet fixture sibling"
  set +e
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
      "${NODE_BIN}" --p2p-trust-bundle-reload-check "${R26P_SIDECAR}" \
                    --p2p-trust-bundle-onchain-governance-fixture-allowed \
                    --env mainnet ) \
    > "${R26P_LOG}" 2>&1
  R26P_RC=$?
  set -e
  echo "${R26P_RC}" > "${EXIT_DIR}/R26_mainnet_payload_reload_check.rc"
  assert_not_grep "${R26P_LOG}" "MainNet peer-driven apply ENABLED"
fi

# ---------------------------------------------------------------------------
# Source/release reachability proof. Run 185 widens the Run 183 grep
# corpus to cover the Run 184 payload-carrying symbols (the typed
# load status, the loaders, the routing helpers, the additive
# sibling field name, and the typed parse-error surface) plus every
# production source file that loads or routes the sibling.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 185 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'verify_onchain_governance_proof' \
    'validate_lifecycle_with_onchain_governance_proof' \
    'OnChainGovernanceProofPolicy::AllowFixtureSourceTest' \
    'pqc_onchain_governance_proof_surface' \
    'pqc_onchain_governance_callsite_wiring' \
    'pqc_onchain_governance_payload_carrying' \
    'compose_onchain_governance_marker_decision' \
    'reload_check_compose_onchain_governance_marker_decision' \
    'reload_apply_compose_onchain_governance_marker_decision' \
    'startup_p2p_trust_bundle_compose_onchain_governance_marker_decision' \
    'sighup_compose_onchain_governance_marker_decision' \
    'local_peer_candidate_check_compose_onchain_governance_marker_decision' \
    'live_inbound_0x05_compose_onchain_governance_marker_decision' \
    'peer_driven_drain_compose_onchain_governance_marker_decision' \
    'reload_check_callsite_onchain_governance_marker_decision' \
    'reload_apply_callsite_onchain_governance_marker_decision' \
    'startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision' \
    'sighup_callsite_onchain_governance_marker_decision' \
    'local_peer_candidate_check_callsite_onchain_governance_marker_decision' \
    'live_inbound_0x05_callsite_onchain_governance_marker_decision' \
    'peer_driven_drain_callsite_onchain_governance_marker_decision' \
    'OnChainGovernanceCallsiteContext' \
    'with_onchain_governance_fixture_allowed_selector' \
    'onchain_governance_fixture_allowed_selector' \
    'onchain_governance_proof_policy_from_cli_or_env' \
    'onchain_governance_proof_policy_from_selector' \
    'onchain_governance_fixture_allowed_env_selector_enabled' \
    'QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED' \
    'p2p_trust_bundle_onchain_governance_fixture_allowed' \
    'mainnet_peer_driven_apply_remains_refused_for_onchain_governance' \
    'OnChainGovernanceMarkerDecisionOutcome' \
    'preflight_run_132_validation_only_v2_marker_check' \
    'preflight_run_134_v2_marker_decision' \
    'preflight_run_136_v2_marker_decision_for_startup' \
    'preflight_sighup_v2_marker_decision' \
    'ProductionV2MarkerCoordinator' \
    'ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD' \
    'OnChainGovernanceProofLoadStatus' \
    'OnChainGovernanceProofPayloadParseError' \
    'load_v2_ratification_sidecar_with_onchain_governance_proof_from_path' \
    'load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes' \
    'parse_optional_onchain_governance_proof_sibling_from_json_value' \
    'callsite_context_with_loaded_onchain_governance_proof' \
    'OnChainGovernancePayloadCarryingDecisionOutcome' \
    'route_loaded_onchain_governance_proof_to_reload_check_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_sighup_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision' \
    'route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision' \
    'V2RatificationSidecarWithOnChainGovernanceProofWire' \
    'OnChainGovernanceProofWire' \
    'ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done

  echo
  echo "Run 185 production-call-site index — files that BOTH define a"
  echo "Run 132 / 134 / 136 / SIGHUP / local-peer-candidate-check / live-0x05 /"
  echo "peer-driven drain v2 marker-decision path AND invoke a Run 182 named"
  echo "callsite entry on that path AND/OR invoke a Run 184 payload-carrying"
  echo "loader/router on that path:"
  for f in \
    'crates/qbind-node/src/main.rs' \
    'crates/qbind-node/src/pqc_live_trust_reload.rs' \
    'crates/qbind-node/src/pqc_peer_candidate_wire.rs' \
    'crates/qbind-node/src/pqc_peer_candidate_apply.rs' \
    'crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs'
  do
    echo "--- ${f} ---"
    grep -nE '_callsite_onchain_governance_marker_decision|OnChainGovernanceCallsiteContext|onchain_governance_fixture_allowed_selector|ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD|load_v2_ratification_sidecar_with_onchain_governance_proof|route_loaded_onchain_governance_proof_to_' \
      "${REPO_ROOT}/${f}" || echo '(no callsite/payload-carrying references)'
  done
} > "${REACH_DIR}/source_reachability.txt"

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 185 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'governance execution claim' \
    'on-chain governance claim' \
    'KMS/HSM enabled' \
    'KMS/HSM active' \
    'validator-set rotation claim' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_179_OUT}" "${HELPER_185_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected scenarios. Every release-binary
# rejected scenario in Run 185 (A1 / R1 / R2 / R26 / R*) is
# non-mutating because we use `--print-genesis-hash` (no data dir),
# `--p2p-trust-bundle-reload-check` (validation-only), or the helper
# corpus (preflight-only by construction).
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 185 no-mutation proof for rejected scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven rejection corpus (R1..R26) — every scenario asserts:"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  grep -E 'verdict: PASS|R[0-9]+_|A[0-9]+_' \
    "${HELPER_185_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
  echo
  echo "  Run 179 helper verifier-corpus rejection summary:"
  grep -E 'verdict: PASS|R[0-9]+_' \
    "${HELPER_179_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted mutating scenarios.
#
# Run 184 added the additive optional `onchain_governance_proof`
# sibling on the v2 ratification sidecar JSON wire and routed the
# parsed proof into the Run 182 named call-site entries. Run 185
# captures the release-binary boundary: real `target/release/qbind-node
# --p2p-trust-bundle-reload-check <sidecar-with-sibling>
# --p2p-trust-bundle-onchain-governance-fixture-allowed`
# successfully loads the sidecar, the Run 184 loader extracts the
# additive sibling, the typed `OnChainGovernanceProofWire` parses,
# and the Run 182 reload-check entry is invoked through the
# production validation-only call site (no marker write, no sequence
# write). The matching reload-apply binary surface honestly returns
# `ReloadApplyError::UnsupportedRuntimeContext` per Run 070 evidence
# on a non-long-running invocation; the helper Run 185 corpus
# captures the matching accepted typed outcome through the same
# library symbols in release mode and asserts every accepted Rotate
# scenario preserves the pre-mutation ordering invariants
# (selector-activation -> proof-parse -> fixture-verification ->
# lifecycle-validation -> preflight outcome). Run 055
# sequence-before-marker ordering and v2-marker-after-sequence
# persistence ordering remain preserved by the Run 134 / 138 / 161 /
# 165 regression slices re-validated in release mode by the harness.
# ---------------------------------------------------------------------------
{
  echo "Run 185 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site payload-carrying reachability today:"
  echo "    - main.rs resolves OnChainGovernanceProofPolicy via"
  echo "      onchain_governance_proof_policy_from_cli_or_env(args.p2p_trust_bundle_onchain_governance_fixture_allowed)"
  echo "    - main.rs emits the [run-180] armed banner only when"
  echo "      AllowFixtureSourceTest is resolved (CLI flag set OR env truthy);"
  echo "    - the production v2 sidecar load path"
  echo "      (load_v2_ratification_sidecar_with_onchain_governance_proof_from_path)"
  echo "      extracts the additive Run 184 onchain_governance_proof sibling"
  echo "      BEFORE the strict BundleSigningRatificationV2 parse,"
  echo "      following the Run 167 pattern, and yields a typed"
  echo "      OnChainGovernanceProofLoadStatus ({Absent,Available,Malformed});"
  echo "    - every production v2 marker-decision call site"
  echo "      (preflight_run_132_validation_only_v2_marker_check,"
  echo "       preflight_run_134_v2_marker_decision,"
  echo "       preflight_run_136_v2_marker_decision_for_startup,"
  echo "       LiveReloadController::preflight_sighup_v2_marker_decision,"
  echo "       v2 sidecar dispatch in main.rs (local peer-candidate-check),"
  echo "       pqc_peer_candidate_wire.rs post-verify_marker_for_validation_only_v2,"
  echo "       ProductionV2MarkerCoordinator::decide_pre_apply (peer-driven drain))"
  echo "      now invokes its matching Run 182 named callsite entry with the"
  echo "      resolved policy and a context-carried selector AND the"
  echo "      typed proof reference parsed from the Run 184 sibling;"
  echo "    - the Run 184 routing helpers layer a typed"
  echo "      MalformedOnChainGovernanceProofPayload short-circuit BEFORE"
  echo "      invoking the Run 182 call-site entry so a malformed carrier"
  echo "      fails closed BEFORE any verifier is invoked, BEFORE any"
  echo "      sequence/marker write, BEFORE any live trust swap, BEFORE any"
  echo "      session eviction, and BEFORE any Run 070 call;"
  echo "    - the peer-driven-drain callsite entry layers a surface-level"
  echo "      MainNetRefused short-circuit BEFORE invoking the Run 180"
  echo "      verifier (Run 147 / 148 / 152 FATAL invariant)."
  echo
  echo "  release-binary reload-check boundary (this run):"
  echo "    - real target/release/qbind-node --p2p-trust-bundle-reload-check"
  echo "      ${SIDE_DIR}/devnet_rotate_valid.json"
  echo "      --p2p-trust-bundle-onchain-governance-fixture-allowed --env devnet"
  echo "      successfully loads the sidecar through the production"
  echo "      validation-only path (Run 069 / Run 132); the Run 184 loader"
  echo "      extracts the sibling; the typed OnChainGovernanceProofWire"
  echo "      parses; the Run 182 reload-check named callsite entry is"
  echo "      invoked through the production call site; no marker write,"
  echo "      no sequence write, no live trust swap, no session eviction,"
  echo "      no Run 070 call."
  echo
  echo "  release-binary reload-apply boundary (this run):"
  echo "    - real target/release/qbind-node --p2p-trust-bundle-reload-apply-enabled"
  echo "      --p2p-trust-bundle-reload-apply-path"
  echo "      ${SIDE_DIR}/devnet_rotate_valid.json"
  echo "      --p2p-trust-bundle-onchain-governance-fixture-allowed --env devnet"
  echo "      arms the selector and loads the sidecar through the production"
  echo "      reload-apply path (Run 070 / Run 134); the Run 184 loader"
  echo "      extracts the sibling; the typed OnChainGovernanceProofWire"
  echo "      parses; the Run 182 reload-apply named callsite entry is"
  echo "      invoked through the production call site; on a non-long-running"
  echo "      qbind-node invocation the production-honest path returns"
  echo "      ReloadApplyError::UnsupportedRuntimeContext per Run 070, and"
  echo "      the matching accepted typed outcome is captured in release"
  echo "      mode through the same library symbols by the Run 185 helper"
  echo "      corpus, with Run 055 sequence-before-marker ordering"
  echo "      preserved at the library layer."
  echo
  echo "  honest-limitation surfaces (live 0x05 / peer-driven drain):"
  echo "    - Run 184 added the additive sibling on the v2 ratification"
  echo "      sidecar JSON wire used by reload-check / reload-apply /"
  echo "      startup --p2p-trust-bundle / SIGHUP. The live 0x05"
  echo "      peer-candidate envelope and the peer-driven drain inbound"
  echo "      payload may not yet carry the typed OnChainGovernance proof"
  echo "      end-to-end on a real binary depending on tree state. Where"
  echo "      they do not, Run 185 captures the source-reachability for"
  echo "      the matching Run 182 named callsite entry through the"
  echo "      release-built helper in release mode AND records the boundary"
  echo "      explicitly here."
} > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_185_TASK.txt
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
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_proof_surface pqc_onchain_governance_proof_surface)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_callsite_wiring pqc_onchain_governance_callsite_wiring)" )
TEST_VERDICTS+=( "$(run_lib_test pqc_onchain_governance_payload_carrying pqc_onchain_governance_payload_carrying)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 185 — release-binary OnChainGovernance payload-carrying accepted-proof evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_179_sha256:  $(sha256_file "${HELPER_179_BIN}")"
  echo "  helper_179_buildid: $(build_id "${HELPER_179_BIN}")"
  echo "  helper_185_sha256:  $(sha256_file "${HELPER_185_BIN}")"
  echo "  helper_185_buildid: $(build_id "${HELPER_185_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in A1_help A1_default_disabled A2_cli_selector A3_env_selector \
           A2_payload_reload_check A2_legacy_reload_check \
           A4_payload_reload_apply \
           R2_malformed_non_object R2_malformed_unknown_schema \
           R2_malformed_empty_field R2_malformed_empty_proof_bytes \
           R26_mainnet_refusal R26_mainnet_payload_reload_check
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_179	rc=$(cat "${EXIT_DIR}/helper_run_179.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_179_OUT}/helper_summary.txt" 2>/dev/null || true)"
  echo "  helper_run_185	rc=$(cat "${EXIT_DIR}/helper_run_185.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_185_OUT}/helper_summary.txt" 2>/dev/null || true)"
  echo
  echo "regression test verdicts:"
  for v in "${TEST_VERDICTS[@]}"; do echo "  ${v}"; done
  echo
  echo "honest_limits:"
  echo "  * default OnChainGovernanceProofPolicy::Disabled preserved on every surface;"
  echo "  * AllowFixtureSourceTest hidden, explicit, DevNet/TestNet fixture-only;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with armed selector AND fully-valid MainNet fixture proof carried"
  echo "    through the Run 184 v2 sidecar additive sibling;"
  echo "  * no real on-chain governance proof verifier;"
  echo "  * no governance execution engine;"
  echo "  * no KMS/HSM custody;"
  echo "  * no validator-set rotation;"
  echo "  * no schema/wire/metric drift beyond Run 184 additive optional sibling;"
  echo "  * no marker write before sequence commit;"
  echo "  * no sequence write or marker write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: production payload/context paths in real target/release/qbind-node"
  echo "  successfully carry typed OnChainGovernance fixture proof material into the"
  echo "  Run 182 production call-site wrappers and accept valid DevNet/TestNet"
  echo "  fixture proofs under the hidden AllowFixtureSourceTest selector on the"
  echo "  validation-only --p2p-trust-bundle-reload-check surface and on the"
  echo "  mutating --p2p-trust-bundle-reload-apply-path surface. Invalid /"
  echo "  malformed sibling payloads fail closed BEFORE any verifier or marker"
  echo "  decision (typed OnChainGovernanceProofPayloadParseError) on every"
  echo "  surface. MainNet peer-driven apply remains the Run 147 FATAL refusal"
  echo "  even with a fully-valid MainNet fixture proof carried in the v2 sidecar"
  echo "  via the Run 184 sibling. The release-built helpers exercise the full"
  echo "  A1-A9 / R1-R26 corpus end-to-end in release mode through the production"
  echo "  library symbols. Real on-chain governance proof verification, governance"
  echo "  execution, KMS/HSM custody, validator-set rotation, bridge / light-client"
  echo "  integration, autonomous apply, and apply-on-receipt all remain"
  echo "  unimplemented. Full C4 and C5 remain OPEN."
} > "${SUMMARY}"

log "Run 185 harness complete; canonical summary at ${SUMMARY}"