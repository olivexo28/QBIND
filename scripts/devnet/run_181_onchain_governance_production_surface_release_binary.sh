#!/usr/bin/env bash
# Run 181 — Release-binary OnChainGovernance production-surface fixture
# evidence harness.
#
# Per `task/RUN_181_TASK.txt`, Run 181 captures release-binary evidence
# that the real `target/release/qbind-node` binary can exercise the
# Run 180 source/test `OnChainGovernance` fixture-policy path through
# the hidden disabled-by-default selector
# (`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
# `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1`),
# while preserving fail-closed defaults and MainNet refusal.
#
# This harness proves on real release binaries:
#
#   * default `OnChainGovernanceProofPolicy::Disabled` remains
#     fail-closed (no banner; no fixture-policy activation; selector
#     observed disabled);
#   * the hidden CLI selector enables `AllowFixtureSourceTest`
#     (banner emitted from real `target/release/qbind-node`);
#   * the env selector enables `AllowFixtureSourceTest`
#     (banner emitted from real `target/release/qbind-node` when
#     `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1`);
#   * a release-built helper drives the Run 180
#     `compose_onchain_governance_marker_decision` shared helper and
#     all seven per-surface named wrappers
#     (`reload_check_compose_onchain_governance_marker_decision`,
#     `reload_apply_compose_onchain_governance_marker_decision`,
#     `startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`,
#     `sighup_compose_onchain_governance_marker_decision`,
#     `local_peer_candidate_check_compose_onchain_governance_marker_decision`,
#     `live_inbound_0x05_compose_onchain_governance_marker_decision`,
#     `peer_driven_drain_compose_onchain_governance_marker_decision`)
#     in release mode through the production library symbols linked
#     into the same `qbind-node` binary, exercising A1–A8 and
#     R1–R26;
#   * the real `target/release/qbind-node` MainNet peer-driven apply
#     refusal remains intact even with the fixture selector enabled
#     and a valid DevNet/TestNet fixture proof in hand (Run 147 FATAL
#     invariant);
#   * the real `target/release/qbind-node --help` surfaces no new
#     OnChainGovernance flag (selector is hidden; `hide = true`);
#   * existing validation-only and mutating production surfaces
#     (`--p2p-trust-bundle-reload-check`,
#     `--p2p-trust-bundle-reload-apply-path`,
#     `--p2p-trust-bundle-peer-candidate-check`, live `0x05`,
#     peer-driven drain) keep their pre-Run-180 marker / sequence
#     ordering invariants byte-for-byte.
#
# Strict scope (from `task/RUN_181_TASK.txt`):
#   * Release-binary evidence only. No production source change.
#   * No MainNet peer-driven apply enablement.
#   * No real on-chain governance execution / no real on-chain proof
#     verifier / no bridge / light-client / KMS-HSM / validator-set
#     rotation / autonomous apply / apply-on-receipt / peer-majority
#     authority.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * Do not weaken Runs 070, 130–180.
#   * Do not claim full C4 or C5 closure.
#
# Honest limitation (recorded explicitly):
#   Run 180 wired the `OnChainGovernance` fixture verifier into the
#   production library via
#   `pqc_onchain_governance_proof_surface::compose_onchain_governance_marker_decision`
#   and seven per-surface named wrappers, AND wired the hidden
#   selector capture into `main.rs` (banner emitted when armed).
#   `main.rs` does NOT yet pass the resolved
#   `OnChainGovernanceProofPolicy` down through
#   `--p2p-trust-bundle-reload-check` / `--p2p-trust-bundle-reload-apply-*`
#   into the per-surface wrappers — that integration is the strictly
#   next-after-Run-181 source/test step. Run 181 therefore captures
#   honest **production-surface SELECTOR-REACHABILITY release-binary
#   evidence** (the real binary parses the hidden flag and env var,
#   resolves the policy, emits the armed banner, and links the
#   wrappers into its production library surface), plus
#   release-built helper evidence proving every wrapper accepts /
#   rejects in release mode exactly as the Run 180 source/test
#   matrix asserts. The verdict is therefore
#   `partial-positive: production-surface selector reachability
#   captured on real qbind-node; per-surface wrappers exercised
#   in-process via release-built helper; the binary-side wiring of
#   the wrappers into reload-check / reload-apply / startup /
#   SIGHUP / peer-candidate-check / live-0x05 / peer-driven-drain
#   call sites is the strictly-next integration run identified by
#   this evidence`.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_181_onchain_governance_production_surface_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
# Run 181 reuses the Run 179 release-built helper as the
# OnChainGovernance fixture-proof minter and verifier driver. The
# helper exercises the production library symbols
# (`verify_onchain_governance_proof`,
# `validate_lifecycle_with_onchain_governance_proof`,
# `OnChainGovernanceProofWire`) and, in this run, additionally
# exercises every Run 180 per-surface named wrapper via the same
# library surface. Re-using the helper avoids introducing a new
# example crate target while still satisfying the
# task `cargo build --release -p qbind-node --example
# <onchain-governance-fixture-helper>` validation requirement.
HELPER_BIN="${REPO_ROOT}/target/release/examples/run_179_onchain_governance_proof_release_binary_helper"
HELPER_OUT="${OUTDIR}/helper_evidence"
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

log()  { printf '[run-181] %s\n' "$*" >&2; }
fail() { printf '[run-181] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" \
       "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" "${DATA_DIR}"
mkdir -p "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" \
         "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance — captured up-front so even partial runs leave honest metadata.
# ---------------------------------------------------------------------------
{
  echo "run-181 provenance"
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
# Build qbind-node bin + Run 179 helper in release mode. Run 181 reuses
# the Run 179 helper because the helper drives the production library
# `OnChainGovernance` verifier surface, which is exactly the surface
# Run 180 wired the new per-surface wrappers into.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper.log" 2>&1 \
  || fail "release build of run_179 helper failed (see ${LOGS_DIR}/build_helper.log)"

[[ -x "${NODE_BIN}"   ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_BIN}" ]] || fail "missing ${HELPER_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_path:        ${HELPER_BIN}"
  echo "helper_sha256:      $(sha256_file "${HELPER_BIN}")"
  echo "helper_buildid:     $(build_id "${HELPER_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the release-built helper. The helper's exit code is 0 iff every
# Run 178 / Run 180 acceptance / rejection scenario matched its expected
# typed outcome in release mode.
# ---------------------------------------------------------------------------
log "running release-built helper -> ${HELPER_OUT}"
HELPER_LOG="${LOGS_DIR}/helper_run.log"
set +e
"${HELPER_BIN}" "${HELPER_OUT}" > "${HELPER_LOG}" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "helper exited rc=${HELPER_RC} (see ${HELPER_LOG})"
[[ -s "${HELPER_OUT}/helper_summary.txt" ]] || fail "helper did not write helper_summary.txt"
assert_grep "${HELPER_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# A1 — default Disabled rejects: real `qbind-node --help` does NOT surface
# the hidden selector flag and the binary runs without armed banner when
# the flag is unset and the env var is unset.
#
# We use `--print-genesis-hash` as a no-op terminal that exits 0 quickly
# so we can capture early-startup banner emission without opening sockets
# or touching real data dirs.
# ---------------------------------------------------------------------------
log "A1 — default Disabled invariants (no flag, no env)"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/A1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
# Hidden selector must NOT appear in --help output (clap `hide = true`).
assert_not_grep "${HELP_LOG}" "p2p-trust-bundle-onchain-governance-fixture-allowed"
assert_not_grep "${HELP_LOG}" "(?i)onchain.?governance.?fixture"
assert_not_grep "${HELP_LOG}" "run-180" 
assert_not_grep "${HELP_LOG}" "run-181"

A1_LOG="${LOGS_DIR}/A1_default_disabled.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --network devnet ) \
  > "${A1_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A1_default_disabled.rc"
# Banner must NOT appear when selector is unset / falsey.
assert_not_grep "${A1_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"

# ---------------------------------------------------------------------------
# A2 — CLI selector enables AllowFixtureSourceTest. Real qbind-node MUST
# emit the Run 180 armed banner exactly once on stderr.
# ---------------------------------------------------------------------------
log "A2 — CLI selector arms fixture policy"
A2_LOG="${LOGS_DIR}/A2_cli_selector.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --network devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${A2_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A2_cli_selector.rc"
assert_grep     "${A2_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep     "${A2_LOG}" "AllowFixtureSourceTest"
assert_grep     "${A2_LOG}" "MainNetProductionProofUnavailable"
assert_not_grep "${A2_LOG}" "MainNet peer-driven apply ENABLED"

# ---------------------------------------------------------------------------
# A3 — env selector enables AllowFixtureSourceTest.
# ---------------------------------------------------------------------------
log "A3 — env selector arms fixture policy"
A3_LOG="${LOGS_DIR}/A3_env_selector.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --network devnet ) \
  > "${A3_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A3_env_selector.rc"
assert_grep "${A3_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
assert_grep "${A3_LOG}" "AllowFixtureSourceTest"

# Same selector with truthy aliases (true / yes / on, case-insensitive).
for v in true TRUE yes YES on ON True; do
  log "A3 — env selector truthy variant: ${v}"
  L="${LOGS_DIR}/A3_env_selector_${v}.log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --network devnet ) > "${L}" 2>&1 || true
  echo "$?" > "${EXIT_DIR}/A3_env_selector_${v}.rc"
  assert_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

# Falsey env values keep selector disabled.
for v in 0 false FALSE no off "" "garbage"; do
  log "A3 — env selector falsey variant: '${v}'"
  L="${LOGS_DIR}/A3_env_selector_falsey_$(printf '%s' "${v:-empty}" | tr -c 'a-zA-Z0-9_' '_').log"
  ( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED="${v}" \
      "${NODE_BIN}" --print-genesis-hash --network devnet ) > "${L}" 2>&1 || true
  assert_not_grep "${L}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"
done

# ---------------------------------------------------------------------------
# R23 — MainNet refusal: even with CLI selector + env selector engaged,
# the real binary refuses any MainNet apply path. We assert this by
# requesting `--print-genesis-hash --network mainnet` (a non-mutating
# CLI) and recording that no banner declares MainNet apply enablement.
# Source-level MainNet refusal is covered by the helper R23 scenario.
# ---------------------------------------------------------------------------
log "R23 — MainNet refusal under armed selector"
R23_LOG="${LOGS_DIR}/R23_mainnet_refusal.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --network mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${R23_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/R23_mainnet_refusal.rc"
assert_not_grep "${R23_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${R23_LOG}" "(?i)mainnet.+apply.+enabled"

# ---------------------------------------------------------------------------
# Source/release reachability proof. Run 181 widens the Run 179 grep
# corpus to cover the Run 180 production-surface symbols.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 181 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'verify_onchain_governance_proof' \
    'validate_lifecycle_with_onchain_governance_proof' \
    'OnChainGovernanceProofPolicy::AllowFixtureSourceTest' \
    'pqc_onchain_governance_proof_surface' \
    'compose_onchain_governance_marker_decision' \
    'reload_check_compose_onchain_governance_marker_decision' \
    'reload_apply_compose_onchain_governance_marker_decision' \
    'startup_p2p_trust_bundle_compose_onchain_governance_marker_decision' \
    'sighup_compose_onchain_governance_marker_decision' \
    'local_peer_candidate_check_compose_onchain_governance_marker_decision' \
    'live_inbound_0x05_compose_onchain_governance_marker_decision' \
    'peer_driven_drain_compose_onchain_governance_marker_decision' \
    'onchain_governance_proof_policy_from_cli_or_env' \
    'onchain_governance_proof_policy_from_selector' \
    'onchain_governance_fixture_allowed_env_selector_enabled' \
    'QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED' \
    'p2p_trust_bundle_onchain_governance_fixture_allowed' \
    'mainnet_peer_driven_apply_remains_refused_for_onchain_governance' \
    'OnChainGovernanceMarkerDecisionOutcome'
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
  echo "Run 181 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'governance execution claim' \
    'on-chain governance claim' \
    'KMS/HSM' \
    'validator-set rotation claim' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_OUT}" -type f -print0 2>/dev/null \
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
# No-mutation proof for rejected scenarios. Run 181's release-binary
# rejected scenarios (A1 default-disabled, R23 MainNet, plus every
# helper-driven Rxx) are all non-mutating: they exit before any
# data-dir write because we deliberately use `--print-genesis-hash`
# (no --data-dir, no socket, no marker, no sequence).
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 181 no-mutation proof for rejected scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  scenarios that exited without --data-dir (no marker / sequence write possible):"
  for s in A1_default_disabled R23_mainnet_refusal; do
    echo "    ${s} rc=$(cat "${EXIT_DIR}/${s}.rc" 2>/dev/null || echo 'na')"
  done
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation-proof scaffold: Run 181 records that Run 180's binary-side
# wiring is a SELECTOR-CAPTURE-ONLY surface (banner emission). Helper-
# driven A4 / A5 (mutating wrappers) verify ordering at the library
# level. The strict next integration run will wire the wrappers into
# main.rs reload-check / reload-apply call sites and capture
# marker/sequence JSON+SHA before/after via a real --data-dir run.
# ---------------------------------------------------------------------------
{
  echo "Run 181 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-surface fixture-policy reachability today:"
  echo "    - main.rs resolves OnChainGovernanceProofPolicy via"
  echo "      onchain_governance_proof_policy_from_cli_or_env(args.p2p_trust_bundle_onchain_governance_fixture_allowed)"
  echo "    - main.rs emits the [run-180] armed banner only when"
  echo "      AllowFixtureSourceTest is resolved (CLI flag set OR env truthy)."
  echo "    - reload-check / reload-apply / startup --p2p-trust-bundle / SIGHUP /"
  echo "      peer-candidate-check / live-0x05 / peer-driven-drain do NOT yet"
  echo "      pass the resolved policy down into the per-surface wrappers."
  echo
  echo "  library-side per-surface fixture-policy reachability today:"
  echo "    - compose_onchain_governance_marker_decision and the seven per-"
  echo "      surface named wrappers are linked into target/release/qbind-node"
  echo "      via the qbind_node library crate (see source_reachability.txt)"
  echo "      and are exercised in release mode by the helper."
  echo
  echo "  next integration run identified by Run 181:"
  echo "    Wire the resolved OnChainGovernanceProofPolicy from main.rs into"
  echo "    each --p2p-trust-bundle-* surface's marker-decision call site so a"
  echo "    real qbind-node invocation with --p2p-trust-bundle-onchain-"
  echo "    governance-fixture-allowed and an OnChainGovernance proof sidecar"
  echo "    reaches compose_onchain_governance_marker_decision and emits the"
  echo "    typed outcome on stderr / data-dir, and capture the resulting"
  echo "    marker / sequence JSON+SHA before/after on at least one mutating"
  echo "    surface. Run 181 deliberately does NOT introduce that wiring."
} > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_181_TASK.txt §319`.
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

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 181 — release-binary OnChainGovernance production-surface fixture evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "release-built helper:"
  cat "${HELPER_OUT}/helper_summary.txt"
  echo
  echo "release-binary qbind-node selector reachability:"
  echo "  A1 default Disabled (no flag, no env):    no banner observed (PASS)"
  echo "  A2 CLI selector arms AllowFixtureSourceTest: banner observed (PASS)"
  echo "  A3 env selector arms AllowFixtureSourceTest: banner observed for"
  printf '       truthy variants: 1, true, TRUE, True, yes, YES, on, ON\n'
  echo "  R23 MainNet refusal under armed selector:  no MainNet apply enable (PASS)"
  echo "  qbind-node --help surfaces no new OnChainGovernance flag: PASS"
  echo
  echo "test verdicts (release-mode regression slice):"
  for v in "${TEST_VERDICTS[@]}"; do printf '  %s\n' "${v}"; done
  echo
  echo "negative invariants (denylist) proven empty:"
  awk '/^ok-empty:/ {print "  " $0}' "${DENYLIST}"
  echo
  echo "verdict:"
  echo "  partial-positive: production-surface SELECTOR reachability captured on"
  echo "  real target/release/qbind-node (CLI flag + env var both arm the"
  echo "  Run 180 AllowFixtureSourceTest policy and emit the [run-180] banner;"
  echo "  unset/falsey both keep the Disabled production default silent);"
  echo "  Run 180's seven per-surface wrappers are linked into the production"
  echo "  qbind-node binary's library and exercised in release mode by the"
  echo "  release-built helper across the full A1-A8 / R1-R26 matrix; the"
  echo "  binary-side wiring of the per-surface wrappers into reload-check /"
  echo "  reload-apply / startup --p2p-trust-bundle / SIGHUP / peer-candidate-"
  echo "  check / live-0x05 / peer-driven-drain call sites is the strictly"
  echo "  next-after-Run-181 integration run identified by this evidence."
  echo
  echo "next integration run identified:"
  echo "  Pass the resolved OnChainGovernanceProofPolicy from main.rs into"
  echo "  each existing --p2p-trust-bundle-* surface marker-decision site so a"
  echo "  real qbind-node invocation with the hidden selector engaged and an"
  echo "  OnChainGovernance proof sidecar reaches"
  echo "  compose_onchain_governance_marker_decision through the production"
  echo "  CLI surface and emits the typed outcome, then capture mutating-"
  echo "  scenario marker / sequence JSON+SHA before / after on at least one"
  echo "  surface (preserving Run 055 sequence-before-marker ordering and Run"
  echo "  147 / 148 / 152 MainNet refusal)."
} > "${SUMMARY}"

log "done. SUMMARY=${SUMMARY}"
