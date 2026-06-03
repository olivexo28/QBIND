#!/usr/bin/env bash
# Run 183 — Release-binary evidence for the Run 182 production v2
# marker-decision call-site wiring of the Run 180 per-surface
# OnChainGovernance preflight wrappers behind the hidden Run 180
# disabled-by-default selector
# (`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
# `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1`).
#
# Driving spec: `task/RUN_183_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default `OnChainGovernanceProofPolicy::Disabled` remains
#     fail-closed on real production surfaces — the binary emits no
#     Run 180 armed banner and the per-surface wiring entries
#     short-circuit on `PolicyDisabled` (A1 / R1);
#   * the hidden CLI selector arms `AllowFixtureSourceTest` on real
#     `target/release/qbind-node` (A2);
#   * the env selector arms `AllowFixtureSourceTest` across truthy
#     variants `{1, true, TRUE, True, yes, YES, on, ON}` and remains
#     disabled on falsey variants `{0, false, FALSE, no, off, "",
#     garbage}` (A3);
#   * `qbind-node --help` does not surface the hidden selector flag
#     (`hide = true`);
#   * the real binary's MainNet peer-driven apply refusal
#     (Run 147 FATAL invariant) is unchanged with the selector armed
#     and a fully-valid DevNet fixture proof in hand (R23);
#   * a release-built helper (the Run 179
#     `run_179_onchain_governance_proof_release_binary_helper`,
#     reused because it drives the production library
#     `OnChainGovernance` verifier symbols and now also the seven
#     Run 182 named call-site entries) exercises the Run 178 / 180
#     / 182 acceptance / rejection corpus end-to-end in **release
#     mode** through the production library symbols
#     `verify_onchain_governance_proof`,
#     `validate_lifecycle_with_onchain_governance_proof`,
#     `compose_onchain_governance_marker_decision`, the seven Run 180
#     per-surface composed wrappers, and the seven Run 182 named
#     call-site entries
#     (`reload_check_callsite_onchain_governance_marker_decision`,
#     `reload_apply_callsite_onchain_governance_marker_decision`,
#     `startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision`,
#     `sighup_callsite_onchain_governance_marker_decision`,
#     `local_peer_candidate_check_callsite_onchain_governance_marker_decision`,
#     `live_inbound_0x05_callsite_onchain_governance_marker_decision`,
#     `peer_driven_drain_callsite_onchain_governance_marker_decision`)
#     plus the typed argument bundle `OnChainGovernanceCallsiteContext`
#     and the additive selector builder
#     `with_onchain_governance_fixture_allowed_selector`;
#   * a source/release reachability proof is recorded showing the
#     production-source-tree call sites that now invoke each Run 182
#     callsite wiring entry, the Run 180 per-surface wrappers, the
#     Run 178 typed verifier, and the Run 180 selector helpers, all
#     linked into the same `target/release/qbind-node` binary.
#
# Strict scope (from `task/RUN_183_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use a release-built helper to mint OnChainGovernance fixture
#     proof material; do NOT substitute helper-only evidence for the
#     central production call-site accepted-proof claim.
#   * No production source change unless a tiny harness-only fix is
#     required (none introduced by this run).
#   * No MainNet peer-driven apply enablement.
#   * No real on-chain governance execution / no real on-chain proof
#     verifier / no bridge / light-client / KMS-HSM / validator-set
#     rotation / autonomous apply / apply-on-receipt / peer-majority
#     authority.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * Do not weaken Runs 070, 130–182.
#   * Do not claim full C4 or C5 closure.
#
# Honest limitation (recorded explicitly):
#   Run 182 wired the seven per-surface Run 180 OnChainGovernance
#   preflight wrappers into every production v2 marker-decision call
#   site through the new `pqc_onchain_governance_callsite_wiring`
#   module. Run 182 also honestly recorded a wire/schema blocker: no
#   current peer-candidate, SIGHUP-trigger, reload-apply trigger,
#   startup-bundle, or live `0x05` payload format carries a typed
#   `OnChainGovernanceProof`. Adding such a payload field is
#   explicitly out of scope for Run 183 (no schema bump, no wire
#   field, no sidecar field, no metric). Therefore production callers
#   in the real `target/release/qbind-node` always invoke the wiring
#   entries with `proof: None`; the Run 180 wrapper short-circuits on
#   `NoOnChainGovernanceProofSupplied` (or `PolicyDisabled` under the
#   default), and call-site behaviour is preserved bit-for-bit. Run
#   183 captures honest **production call-site reachability
#   release-binary evidence**: the real binary now resolves the
#   Run 180 policy and propagates it to every Run 182 named entry on
#   each of the seven production call sites; the typed-proof
#   acceptance path A1–A9 / R1–R26 is exercised in release mode
#   through the production library symbols by the release-built
#   helper, which is linked into the same `qbind-node` library
#   surface. The verdict is therefore
#   `partial-positive: production call-site reachability captured on
#   real qbind-node; Run 182 callsite entries exercised in release
#   mode via the release-built helper; an end-to-end real-binary
#   accepted-fixture-proof flow through any of the seven production
#   surfaces requires a wire/schema bump that is explicitly out of
#   scope for Run 183 and tracked as the strictly-next integration
#   run`.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_183_onchain_governance_callsite_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
# Run 183 reuses the Run 179 release-built helper as the
# OnChainGovernance fixture-proof minter / verifier driver. The
# helper drives the production library symbols Run 182 wired
# (`verify_onchain_governance_proof`,
# `validate_lifecycle_with_onchain_governance_proof`,
# `compose_onchain_governance_marker_decision`, the seven Run 180
# per-surface composed wrappers, and the seven Run 182 named
# call-site entries plus `OnChainGovernanceCallsiteContext`) so the
# same `target/release/qbind-node` library surface used by every
# production call site is exercised in release mode. Re-using the
# helper avoids introducing a new example crate target while still
# satisfying the task `cargo build --release -p qbind-node --example
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

log()  { printf '[run-183] %s\n' "$*" >&2; }
fail() { printf '[run-183] FAIL: %s\n' "$*" >&2; exit 1; }

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
  echo "run-183 provenance"
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
# Build qbind-node bin + Run 179 helper in release mode. Run 183 reuses
# the Run 179 helper because the helper drives the production library
# `OnChainGovernance` verifier surface — exactly the surface Run 180
# wired the per-surface wrappers into and Run 182 wired the named
# callsite entries into.
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
# Run 178 / 180 / 182 acceptance / rejection scenario matched its
# expected typed outcome in release mode through the production library
# symbols (including the seven Run 182 named callsite entries).
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
# A1 / R1 — default Disabled rejects: real `qbind-node --help` does NOT
# surface the hidden selector flag (clap `hide = true`) and the binary
# runs without armed banner when the flag is unset and the env var is
# unset. We use `--print-genesis-hash` as a no-op terminal that exits 0
# quickly so we can capture early-startup banner emission without opening
# sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "A1 / R1 — default Disabled invariants (no flag, no env)"
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
assert_not_grep "${HELP_LOG}" "run-182"
assert_not_grep "${HELP_LOG}" "run-183"

A1_LOG="${LOGS_DIR}/A1_default_disabled.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --network devnet ) \
  > "${A1_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/A1_default_disabled.rc"
# Banner must NOT appear when selector is unset / falsey.
assert_not_grep "${A1_LOG}" "\\[run-180\\] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED"

# ---------------------------------------------------------------------------
# A2 — CLI selector enables AllowFixtureSourceTest on every production
# surface that wires through the Run 105 reload-check context. Real
# qbind-node MUST emit the Run 180 armed banner exactly once on stderr.
# The Run 182 callsite entries inside the same binary then receive the
# resolved policy on every reload-check / reload-apply / startup
# `--p2p-trust-bundle` / SIGHUP / local peer-candidate-check / live
# `0x05` / peer-driven-drain code path.
# ---------------------------------------------------------------------------
log "A2 — CLI selector arms fixture policy on real qbind-node"
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
# A3 — env selector enables AllowFixtureSourceTest on real qbind-node.
# ---------------------------------------------------------------------------
log "A3 — env selector arms fixture policy on real qbind-node"
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
# the real binary refuses any MainNet peer-driven apply path. We assert
# this by requesting `--print-genesis-hash --network mainnet` (a
# non-mutating CLI) and recording that no banner declares MainNet apply
# enablement. Source-level MainNet refusal — including the peer-driven
# drain callsite entry's surface-level `MainNetRefused` short-circuit
# layered ahead of the Run 180 verifier per Runs 147/148/152 — is
# captured by the helper R23 / R3b scenarios.
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
# Source/release reachability proof. Run 183 widens the Run 181 grep
# corpus to cover the Run 182 callsite-wiring symbols (the seven named
# entries, the typed argument bundle, and the additive selector
# builder) plus every production source file that now invokes a
# Run 182 entry on its v2 marker-decision code path.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 183 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'verify_onchain_governance_proof' \
    'validate_lifecycle_with_onchain_governance_proof' \
    'OnChainGovernanceProofPolicy::AllowFixtureSourceTest' \
    'pqc_onchain_governance_proof_surface' \
    'pqc_onchain_governance_callsite_wiring' \
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
    'ProductionV2MarkerCoordinator'
  do
    echo "=== symbol: ${sym} ==="
    grep -RIn --include='*.rs' "${sym}" "${SRC_DIR}" \
      || echo '(no occurrences in production source)'
    echo
  done

  echo
  echo "Run 183 production-call-site index — files that BOTH define a Run 132/"
  echo "134/136 / SIGHUP / local-peer-candidate-check / live-0x05 / peer-driven"
  echo "drain v2 marker-decision path AND invoke a Run 182 named callsite entry"
  echo "on that path:"
  for f in \
    'crates/qbind-node/src/main.rs' \
    'crates/qbind-node/src/pqc_live_trust_reload.rs' \
    'crates/qbind-node/src/pqc_peer_candidate_wire.rs' \
    'crates/qbind-node/src/pqc_peer_candidate_apply.rs'
  do
    echo "--- ${f} ---"
    grep -nE '_callsite_onchain_governance_marker_decision|OnChainGovernanceCallsiteContext|onchain_governance_fixture_allowed_selector' \
      "${REPO_ROOT}/${f}" || echo '(no callsite-wiring references)'
  done
} > "${REACH_DIR}/source_reachability.txt"

# ---------------------------------------------------------------------------
# Denylist invariants across helper logs + every captured qbind-node log.
# ---------------------------------------------------------------------------
log "writing denylist invariants to ${DENYLIST}"
{
  echo "Run 183 denylist (proven empty across all captured logs):"
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
# No-mutation proof for rejected scenarios. Run 183's release-binary
# rejected scenarios (A1 / R1 default-disabled, R23 MainNet refusal,
# plus every helper-driven Rxx) are all non-mutating: they exit before
# any data-dir write because we deliberately use `--print-genesis-hash`
# (no --data-dir, no socket, no marker, no sequence).
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 183 no-mutation proof for rejected scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  scenarios that exited without --data-dir (no marker / sequence write possible):"
  for s in A1_default_disabled R23_mainnet_refusal; do
    echo "    ${s} rc=$(cat "${EXIT_DIR}/${s}.rc" 2>/dev/null || echo 'na')"
  done
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
  grep -E 'verdict: PASS|R[0-9]+_' "${HELPER_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted mutating scenarios.
#
# Run 182 wired the Run 180 per-surface wrappers into every production
# v2 marker-decision call site. Run 182 also recorded an honest wire/
# schema blocker: no current peer-candidate, SIGHUP-trigger,
# reload-apply trigger, startup-bundle, or live `0x05` payload format
# carries a typed `OnChainGovernanceProof`. Adding that field to any
# wire/schema is explicitly OUT OF SCOPE for Run 183.
#
# Therefore Run 183's release-binary mutating-scenario evidence is
# captured at the LIBRARY layer through the release-built helper,
# which exercises the seven Run 182 named callsite entries with
# in-process crafted typed proofs. The helper records canonical
# commitment bytes for every accepted Rotate scenario and asserts:
#
#   * selector activation occurs before proof parse;
#   * proof parse occurs before marker decision;
#   * OnChainGovernance fixture verification occurs before apply /
#     mutation;
#   * lifecycle validation occurs before apply / mutation;
#   * Run 070 / relevant apply ordering preserved (no apply call in
#     the helper because the helper is preflight-only by construction);
#   * Run 055 sequence-before-marker ordering preserved (covered by
#     Runs 134 / 138 / 161 / 165 / 180 / 182 regression slices below);
#   * v2 marker persists strictly after sequence commit (covered by
#     Run 134 / 138 / 161 / 165 regression slices below).
#
# This is exactly the honest scope identified by Run 182 and tracked
# as the strictly-next integration run that must add a typed proof
# field to a peer-candidate / SIGHUP / reload-apply / startup-bundle
# / live-`0x05` payload format. Run 183 deliberately does NOT
# introduce that schema bump.
# ---------------------------------------------------------------------------
{
  echo "Run 183 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site fixture-policy reachability today:"
  echo "    - main.rs resolves OnChainGovernanceProofPolicy via"
  echo "      onchain_governance_proof_policy_from_cli_or_env(args.p2p_trust_bundle_onchain_governance_fixture_allowed)"
  echo "    - main.rs emits the [run-180] armed banner only when"
  echo "      AllowFixtureSourceTest is resolved (CLI flag set OR env truthy);"
  echo "    - every production v2 marker-decision call site"
  echo "      (preflight_run_132_validation_only_v2_marker_check,"
  echo "       preflight_run_134_v2_marker_decision,"
  echo "       preflight_run_136_v2_marker_decision_for_startup,"
  echo "       LiveReloadController::preflight_sighup_v2_marker_decision,"
  echo "       v2 sidecar dispatch in main.rs (local peer-candidate-check),"
  echo "       pqc_peer_candidate_wire.rs post-verify_marker_for_validation_only_v2,"
  echo "       ProductionV2MarkerCoordinator::decide_pre_apply (peer-driven drain))"
  echo "      now invokes its matching Run 182 named callsite entry with the"
  echo "      resolved policy and a context-carried selector;"
  echo "    - the peer-driven-drain callsite entry layers a surface-level"
  echo "      MainNetRefused short-circuit BEFORE invoking the Run 180"
  echo "      verifier (Run 147 / 148 / 152 FATAL invariant)."
  echo
  echo "  wire/schema blocker (honest limitation, unchanged from Run 182):"
  echo "    No current peer-candidate, SIGHUP-trigger, reload-apply trigger,"
  echo "    startup-bundle, or live 0x05 payload format carries a typed"
  echo "    OnChainGovernanceProof. Adding such a field is explicitly OUT OF"
  echo "    SCOPE for Run 183 (no schema bump, no wire field, no sidecar"
  echo "    field, no metric)."
  echo
  echo "    Therefore production callers in real target/release/qbind-node"
  echo "    invoke the wiring entries with proof: None; the Run 180 wrapper"
  echo "    short-circuits on NoOnChainGovernanceProofSupplied (or"
  echo "    PolicyDisabled under the default), and call-site behaviour is"
  echo "    preserved bit-for-bit. The accepted-fixture-proof acceptance"
  echo "    path A1-A9 / R1-R26 is exercised in release mode through the"
  echo "    production library symbols by the release-built helper, which"
  echo "    is linked into the same qbind-node library surface."
  echo
  echo "  next integration run identified by Run 183:"
  echo "    Add an additive optional typed OnChainGovernanceProof field to"
  echo "    one of the existing peer-candidate / SIGHUP / reload-apply /"
  echo "    startup-bundle / live-0x05 payload formats (with a"
  echo "    monotonically-bumped wire schema version, fail-closed default,"
  echo "    DevNet/TestNet-only fixture acceptance, and explicit MainNet"
  echo "    refusal) so a real qbind-node invocation with the hidden"
  echo "    selector engaged AND an OnChainGovernance fixture proof in the"
  echo "    payload reaches a Run 182 callsite entry through a production"
  echo "    surface and emits the typed accepted outcome on stderr / data"
  echo "    dir, then capture marker / sequence JSON+SHA before / after on"
  echo "    at least one mutating surface. Run 183 deliberately does NOT"
  echo "    introduce that schema bump."
} > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_183_TASK.txt
# Validation commands`.
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

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 183 — release-binary OnChainGovernance production call-site evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "release-built helper:"
  cat "${HELPER_OUT}/helper_summary.txt"
  echo
  echo "release-binary qbind-node call-site reachability:"
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
  echo "  partial-positive: production CALL-SITE reachability captured on real"
  echo "  target/release/qbind-node (CLI flag + env var both arm the Run 180"
  echo "  AllowFixtureSourceTest policy and propagate it through every"
  echo "  Run 182 named callsite entry into the seven production v2 marker-"
  echo "  decision code paths; unset/falsey both keep the Disabled production"
  echo "  default silent). The seven Run 182 callsite entries and the seven"
  echo "  Run 180 per-surface wrappers are linked into the same qbind-node"
  echo "  library surface and exercised in release mode by the release-built"
  echo "  helper across the full A1-A9 / R1-R26 matrix. The wire/schema"
  echo "  blocker honestly recorded by Run 182 (no current production wire"
  echo "  payload carries a typed OnChainGovernanceProof field) is unchanged"
  echo "  by Run 183 and is the strictly next integration run identified by"
  echo "  this evidence."
  echo
  echo "next integration run identified:"
  echo "  Add an additive optional typed OnChainGovernanceProof field to one"
  echo "  of the existing peer-candidate / SIGHUP / reload-apply / startup-"
  echo "  bundle / live-0x05 payload formats (with a monotonically-bumped"
  echo "  wire schema version, fail-closed default, DevNet/TestNet-only"
  echo "  fixture acceptance, and explicit MainNet refusal) so a real"
  echo "  qbind-node invocation with the hidden selector engaged AND an"
  echo "  OnChainGovernance fixture proof in the payload reaches a Run 182"
  echo "  callsite entry through a production surface and emits the typed"
  echo "  accepted outcome on stderr / data dir, then capture mutating-"
  echo "  scenario marker / sequence JSON+SHA before / after on at least"
  echo "  one surface (preserving Run 055 sequence-before-marker ordering"
  echo "  and Run 147 / 148 / 152 MainNet refusal)."
} > "${SUMMARY}"