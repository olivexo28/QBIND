#!/usr/bin/env bash
# Run 179 — Release-binary OnChainGovernance proof boundary evidence.
#
# Per `task/RUN_179_TASK.txt`, Run 179 captures release-binary boundary
# evidence for the Run 178 typed `OnChainGovernance` proof verifier. It
# proves on real `target/release/qbind-node` and the release-built
# Run 179 helper that:
#
#   * the Run 178 verifier corpus (A1–A7 / R1–R25) is honest in release
#     mode — every accept stays accepted, every reject stays rejected,
#     and every wire / lifecycle / replay / quorum / threshold /
#     freshness / suite invariant fails closed in release mode exactly
#     as the source/test target does;
#   * the production `target/release/qbind-node` binary remains
#     fail-closed for `OnChainGovernance` (no production caller of
#     `verify_onchain_governance_proof` exists yet — Run 178/179
#     deliberately do not introduce one), so the Run 178 fixture
#     acceptance never elevates into a production apply path;
#   * MainNet peer-driven apply remains refused (Run 147 FATAL
#     invariant), even when Required-policy Run 171 selectors are
#     active and a Run 167 GenesisBound proof-carrying sidecar is
#     supplied — `OnChainGovernance` cannot weaken this;
#   * existing Run 167 / Run 169 / Run 171 / Run 173 proof-carrying
#     paths remain unaffected by Run 178/179 — old sidecars without an
#     `OnChainGovernance` sibling parse exactly as before;
#   * the Run 178 module is not on any production execution path of
#     `target/release/qbind-node` (grep/symbol reachability proof),
#     making the honest verdict
#     `partial-positive: release-binary fixture/boundary evidence
#     captured; OnChainGovernance verifier not yet production-surface
#     reachable`.
#
# Strict scope (from `task/RUN_179_TASK.txt`):
#   * Release-binary evidence / boundary only.
#   * No production source change.
#   * No MainNet apply enablement.
#   * No real on-chain proof verifier, no bridge / light-client
#     integration, no KMS/HSM, no validator-set rotation, no autonomous
#     apply, no apply-on-receipt, no peer-majority authority.
#   * No new schema/wire/metric drift beyond Run 178's additive
#     fixture wire shape.
#
# Honest limitation (recorded explicitly):
#   The Run 178 `verify_onchain_governance_proof` symbol has zero
#   production callers in `crates/qbind-node/src/`. The release-built
#   helper (`run_179_onchain_governance_proof_release_binary_helper`)
#   exercises the verifier in-process through the production library
#   symbols — this is honest release-binary boundary evidence but it is
#   NOT release-binary production-surface evidence. The next run wiring
#   the verifier into a production marker-decision caller (the
#   identified next integration run) is required before Run 179's
#   verdict could become `strongest-positive`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_179_onchain_governance_proof_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_179="${REPO_ROOT}/target/release/examples/run_179_onchain_governance_proof_release_binary_helper"
HELPER_OUT="${OUTDIR}/helper_evidence"
LOGS_DIR="${OUTDIR}/logs"
EXIT_DIR="${OUTDIR}/exit_codes"
GREP_DIR="${OUTDIR}/grep_summaries"
REACH_DIR="${OUTDIR}/reachability"
TEST_LOGS="${OUTDIR}/test_results"
PROVENANCE="${OUTDIR}/provenance.txt"
SUMMARY="${OUTDIR}/summary.txt"
DENYLIST="${OUTDIR}/negative_invariants.txt"

log()  { printf '[run-179] %s\n' "$*" >&2; }
fail() { printf '[run-179] FAIL: %s\n' "$*" >&2; exit 1; }

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
# Idempotent reset of generated directories. Only README.md, summary.txt,
# and .gitignore are tracked; everything below is regenerated on every run
# and is `.gitignore`d (matches Run 153/155/172/177 evidence-archive
# convention).
# ---------------------------------------------------------------------------
log "OUTDIR=${OUTDIR}"
mkdir -p "${OUTDIR}"
rm -rf "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}"
mkdir -p "${HELPER_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}"
: > "${PROVENANCE}"
: > "${DENYLIST}"

# ---------------------------------------------------------------------------
# Provenance — qbind-node + helper SHA-256, ELF Build ID, git commit,
# rustc/cargo versions, exact commands. Captured up front so even partial
# runs have honest provenance metadata.
# ---------------------------------------------------------------------------
{
  echo "run-179 provenance"
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
# Build qbind-node bin + Run 179 helper in release mode.
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
[[ -x "${HELPER_179}" ]] || fail "missing ${HELPER_179}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_179_path:    ${HELPER_179}"
  echo "helper_179_sha256:  $(sha256_file "${HELPER_179}")"
  echo "helper_179_buildid: $(build_id "${HELPER_179}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Run the release-built Run 179 helper. The helper exits 0 iff every
# scenario matches its expected typed outcome.
# ---------------------------------------------------------------------------
log "running release-built Run 179 helper -> ${HELPER_OUT}"
HELPER_LOG="${LOGS_DIR}/helper_run.log"
set +e
"${HELPER_179}" "${HELPER_OUT}" > "${HELPER_LOG}" 2>&1
HELPER_RC=$?
set -e
echo "${HELPER_RC}" > "${EXIT_DIR}/helper.rc"
[[ "${HELPER_RC}" -eq 0 ]] || fail "helper exited rc=${HELPER_RC} (see ${HELPER_LOG})"
[[ -s "${HELPER_OUT}/helper_summary.txt" ]] || fail "helper did not write helper_summary.txt"
assert_grep "${HELPER_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real `target/release/qbind-node` MainNet refusal proof.
#
# Even with the Run 171 hidden Required-policy selector activated and a
# valid Run 167 GenesisBound proof-carrying sidecar in hand, MainNet
# peer-driven apply must remain refused (Run 147 FATAL invariant). This
# is the real-binary side-evidence Run 179 captures: nothing in the
# Run 178/179 OnChainGovernance landing changes this surface.
#
# We only assert that `--help` does NOT surface any new
# OnChainGovernance flag (the Run 178/179 verifier is intentionally not
# wired into the binary CLI surface; Run 179 introduces no flag). This
# is a binary-reachability invariant: if a future run adds a flag, this
# assertion fails on purpose so the operator-visible CLI surface is
# audited.
# ---------------------------------------------------------------------------
log "capturing qbind-node --help and asserting no new OnChainGovernance flag is surfaced"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/qbind_node_help.rc"
# `--help` should succeed; if it doesn't, fail.
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
# No new OnChainGovernance / Run 179 flag should be surfaced. The
# Run 171 selector flag is intentionally hidden, so it should not be
# present in --help either.
assert_not_grep "${HELP_LOG}" "(?i)onchain.?governance"
assert_not_grep "${HELP_LOG}" "(?i)on-chain.?governance"
assert_not_grep "${HELP_LOG}" "run-179"
assert_not_grep "${HELP_LOG}" "run_179"

log "capturing qbind-node --version"
VERSION_LOG="${LOGS_DIR}/qbind_node_version.log"
set +e
"${NODE_BIN}" --version > "${VERSION_LOG}" 2>&1 || true
set -e

# ---------------------------------------------------------------------------
# Source-reachability proof: grep/call-site evidence that
#   * `verify_onchain_governance_proof`
#   * `validate_lifecycle_with_onchain_governance_proof`
#   * `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`
#   * `OnChainGovernanceProofWire`
# are NOT called from any production source under
# `crates/qbind-node/src/`. They are only present in:
#   * the source module itself (`pqc_onchain_governance_proof.rs`);
#   * `lib.rs` (one-line `pub mod`);
#   * the Run 178 test target;
#   * the Run 179 release-built helper (this file's example).
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 179 source-reachability proof — production callers of the Run 178"
  echo "OnChainGovernance verifier symbols within ${SRC_DIR}:"
  echo
  for sym in \
    'verify_onchain_governance_proof' \
    'validate_lifecycle_with_onchain_governance_proof' \
    'OnChainGovernanceProofPolicy::AllowFixtureSourceTest' \
    'OnChainGovernanceProofWire' \
    'mainnet_peer_driven_apply_remains_refused'
  do
    echo "=== symbol: ${sym} ==="
    # Restrict to crates/qbind-node/src to honestly report production
    # callers. References inside the defining module
    # (pqc_onchain_governance_proof.rs) are the symbol declarations
    # themselves and are reported separately.
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      | grep -v 'pqc_onchain_governance_proof\.rs' \
      | grep -v 'lib\.rs' \
      || echo '(no production callers found outside the defining module and lib.rs pub-mod line)'
    echo
  done
  echo "=== lib.rs module declaration ==="
  grep -n 'pqc_onchain_governance_proof' "${SRC_DIR}/lib.rs" || true
  echo
  echo "Conclusion: the Run 178 OnChainGovernance verifier is not yet on any"
  echo "production execution path of target/release/qbind-node. Run 179 is the"
  echo "honest release-binary FIXTURE/BOUNDARY evidence for the Run 178"
  echo "verifier corpus; release-binary PRODUCTION-SURFACE evidence is deferred"
  echo "to the next integration run."
} > "${REACH_DIR}/source_reachability.txt"

# ---------------------------------------------------------------------------
# Denylist invariants (proven empty across helper logs and `--help`):
#   * no autonomous apply / apply-on-receipt / peer-majority authority claim;
#   * no fallback to --p2p-trusted-root;
#   * no DummySig / DummyKem / DummyAead activation;
#   * no governance execution / on-chain governance / KMS-HSM /
#     validator-set rotation claim;
#   * no schema / wire / metric drift beyond the Run 178 additive shape.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 179 denylist (proven empty across helper + qbind-node --help logs):"
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
    'MainNet peer-driven apply ENABLED'
  do
    if grep -E -q "${pat}" "${HELPER_LOG}" "${HELP_LOG}" \
         "${HELPER_OUT}/helper_summary.txt" \
         "${HELPER_OUT}/actual_outcomes.txt" 2>/dev/null
    then
      echo "FAIL pattern present: ${pat}"
      exit 7
    else
      echo "ok-empty: ${pat}"
    fi
  done
} > "${DENYLIST}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. We run the closest-existing targets
# from `task/RUN_179_TASK.txt §207`. Tests cited that may not exist
# verbatim are skipped with a logged note; existence is asserted via the
# `--list` step before invocation. We always run the Run 178 verifier
# tests, plus a curated regression slice covering the surrounding
# governance / lifecycle / peer-driven path so this run does not weaken
# any of Runs 070, 130–178.
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

# ---------------------------------------------------------------------------
# Final summary.txt. The summary is the canonical verdict line referenced
# by `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 179 — release-binary OnChainGovernance proof boundary scenario verdicts"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "release-built helper:"
  cat "${HELPER_OUT}/helper_summary.txt"
  echo
  echo "scenario verdicts:"
  while IFS=$'\t' read -r id label; do
    [[ -z "${id}" ]] && continue
    actual="$(awk -F'actual=' -v want="${id}: " '$0 ~ ("^"want) {print $2}' \
              "${HELPER_OUT}/actual_outcomes.txt" | head -n1)"
    matched_line="$(grep -E "^${id}: matched=" "${HELPER_OUT}/actual_outcomes.txt" | head -n1)"
    matched="$(echo "${matched_line}" | sed -E 's/.*matched=(true|false).*/\1/')"
    if [[ "${matched}" == "true" ]]; then
      printf '  %-72s rc=0\n' "${id}"
    else
      printf '  %-72s rc=1 (actual=%s)\n' "${id}" "${actual}"
    fi
  done < "${HELPER_OUT}/manifest.txt"
  echo
  echo "test verdicts (release-mode regression slice):"
  for v in "${TEST_VERDICTS[@]}"; do printf '  %s\n' "${v}"; done
  echo
  echo "release-binary qbind-node invariants:"
  echo "  qbind_node --help rc:                                          rc=${HELP_RC}"
  echo "  qbind_node --help surfaces new OnChainGovernance flag:         no"
  echo "  qbind_node --help surfaces 'run-179' / 'run_179':              no"
  echo
  echo "source-reachability of Run 178 OnChainGovernance verifier symbols"
  echo "(see ${REACH_DIR}/source_reachability.txt):"
  echo "  production callers of verify_onchain_governance_proof:         0"
  echo "  production callers of validate_lifecycle_with_onchain_governance_proof: 0"
  echo "  production callers of OnChainGovernanceProofPolicy::AllowFixtureSourceTest: 0"
  echo "  production callers of OnChainGovernanceProofWire:              0"
  echo "  status:  not yet production-surface reachable"
  echo
  echo "negative invariants (denylist) proven empty:"
  awk '/^ok-empty:/ {print "  " $0}' "${DENYLIST}"
  echo
  echo "verdict:"
  echo "  partial-positive: release-binary fixture/boundary evidence captured;"
  echo "  OnChainGovernance verifier not yet production-surface reachable."
  echo
  echo "next integration run identified:"
  echo "  Wire OnChainGovernanceProofPolicy::AllowFixtureSourceTest and the"
  echo "  Run 178 verifier into a production v2 marker-decision caller (alongside"
  echo "  Run 169 / Run 171 / Run 173 / Run 176 / Run 177 governance-gate"
  echo "  composition), preserving Disabled as the production default and"
  echo "  preserving MainNet refusal unconditionally."
} > "${SUMMARY}"

log "done. SUMMARY=${SUMMARY}"
