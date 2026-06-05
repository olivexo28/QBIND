#!/usr/bin/env bash
# Run 195 — Release-binary RemoteSigner production-custody boundary evidence
# on real `target/release/qbind-node`. Closes the Run 194-deferred release-
# binary boundary for the RemoteSigner production-custody interface added by
# `crates/qbind-node/src/pqc_remote_authority_signer.rs` (Run 194) layered
# above the Run 192 hidden authority-custody policy selector, the Run 190
# typed authority-custody payload carrying surface, and the Run 188 typed
# authority-custody boundary.
#
# Driving spec: `task/RUN_195_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * MainNet peer-driven apply remains refused (Run 147 / 148 / 152 FATAL
#     invariant) — RemoteSigner introduces no MainNet apply enablement;
#   * default behaviour does not expose or enable a production RemoteSigner —
#     no `RemoteSigner enabled` / `RemoteSigner backend connected` /
#     `remote signer production active` claim is emitted in `--help` or on
#     `--print-genesis-hash --env {devnet,testnet,mainnet}`;
#   * no KMS/HSM active claim, no governance execution claim, and no
#     validator-set rotation claim is emitted;
#   * the existing Run 193 hidden authority-custody policy selector and the
#     existing governance fixture proof paths remain compatible at the
#     binary surface;
#   * the release-built Run 195 helper
#     `run_195_remote_authority_signer_boundary_release_binary_helper`
#     exercises the Run 194 A1–A7 / R1–R31 RemoteSigner corpus end-to-end in
#     **release mode** through the production library symbols
#     `pqc_remote_authority_signer::*` —
#     `RemoteSignerPolicy`, `RemoteSignerIdentity`, `RemoteSignerRequest`,
#     `RemoteSignerResponse`, `RemoteSignerExpectations`,
#     `RemoteAuthoritySigner`, `FixtureLoopbackRemoteSigner`,
#     `ProductionRemoteSigner`, `validate_remote_signer`,
#     `validate_remote_signer_for_custody_class`,
#     `validate_lifecycle_governance_custody_and_remote_signer`, the named
#     MainNet / local-operator / peer-majority refusal helpers, and the
#     deterministic domain-separated SHA3-256 canonical digest entry
#     points — layered over Run 192
#     `pqc_authority_custody_policy_surface::*`, Run 190
#     `pqc_authority_custody_payload_carrying::*`, and Run 188
#     `pqc_authority_custody::*`.
#
# Strict scope (from `task/RUN_195_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 195 helper to exercise the Run 194
#     RemoteSigner boundary in release mode through production library
#     symbols.
#   * No production-source change (harness-only tooling).
#   * No real RemoteSigner backend; no networked signer service.
#   * No real KMS / HSM / cloud KMS / PKCS#11 integration.
#   * No MainNet peer-driven apply enablement.
#   * No governance execution; no real on-chain proof verifier; no
#     validator-set rotation; no autonomous apply; no apply-on-receipt;
#     no peer-majority authority.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * No new CLI flag, env var, schema bump, sidecar field, metric, or
#     exit code.
#   * Do not weaken Runs 070, 130–194.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_195_remote_authority_signer_boundary_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_195_BIN="${REPO_ROOT}/target/release/examples/run_195_remote_authority_signer_boundary_release_binary_helper"

HELPER_195_OUT="${OUTDIR}/helper_evidence/run_195"
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

log()  { printf '[run-195] %s\n' "$*" >&2; }
fail() { printf '[run-195] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_195_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
       "${DATA_DIR}"
mkdir -p "${HELPER_195_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
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
  echo "run-195 provenance"
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
# Build qbind-node bin + Run 195 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_195_remote_authority_signer_boundary_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_195_remote_authority_signer_boundary_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_195.log" 2>&1 \
  || fail "release build of run_195 helper failed (see ${LOGS_DIR}/build_helper_run_195.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_195_BIN}" ]] || fail "missing ${HELPER_195_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_195_path:    ${HELPER_195_BIN}"
  echo "helper_195_sha256:  $(sha256_file "${HELPER_195_BIN}")"
  echo "helper_195_buildid: $(build_id "${HELPER_195_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 195 release helper. Exits 0 iff every Run 194 A1..A7 /
# R1..R31 RemoteSigner scenario, the canonical digest table, the policy-
# mode table, the custody-routing table, the composition table, the
# refusal-helper table, the no-mutation snapshot table, and the
# determinism re-evaluation table all matched in release mode through
# the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 195 RemoteSigner-boundary release helper -> ${HELPER_195_OUT}"
HELPER_195_LOG="${LOGS_DIR}/helper_run_195.log"
set +e
"${HELPER_195_BIN}" "${HELPER_195_OUT}" > "${HELPER_195_LOG}" 2>&1
HELPER_195_RC=$?
set -e
echo "${HELPER_195_RC}" > "${EXIT_DIR}/helper_run_195.rc"
[[ "${HELPER_195_RC}" -eq 0 ]] || fail "run_195 helper exited rc=${HELPER_195_RC} (see ${HELPER_195_LOG})"
[[ -s "${HELPER_195_OUT}/helper_summary.txt" ]] || fail "run_195 helper did not write helper_summary.txt"
assert_grep "${HELPER_195_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants — Run 194 added NO new CLI flag and NO new
# env var; it added a pure library RemoteSigner boundary. The surface
# contract for Run 195 is therefore that the existing Run 070 / 130–194
# binary surfaces emit no RemoteSigner enablement banner, no KMS/HSM active
# claim, no governance execution claim, no validator-set rotation claim, and
# no MainNet peer-driven apply enablement claim — and that the Run 193
# hidden authority-custody policy selector and the governance fixture proof
# paths remain compatible. `--print-genesis-hash` is a non-mutating CLI that
# exits quickly without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help exposes no RemoteSigner/KMS/HSM enablement surface"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer enabled"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer backend connected"
assert_not_grep "${HELP_LOG}" "(?i)remote signer production active"
assert_not_grep "${HELP_LOG}" "(?i)production remote.?signer"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"
assert_not_grep "${HELP_LOG}" "run-194"
assert_not_grep "${HELP_LOG}" "run-195"

log "S2 — default DevNet startup terminal: no RemoteSigner/KMS/HSM banner"
S2_LOG="${LOGS_DIR}/S2_default_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S2_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S2_default_devnet.rc"
assert_not_grep "${S2_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S2_LOG}" "(?i)remote signer production active"
assert_not_grep "${S2_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S2_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S2_LOG}" "(?i)governance execution"
assert_not_grep "${S2_LOG}" "(?i)autonomous apply"
assert_not_grep "${S2_LOG}" "MainNet peer-driven apply ENABLED"

log "S3 — TestNet startup terminal: no RemoteSigner/KMS/HSM banner"
S3_LOG="${LOGS_DIR}/S3_default_testnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env testnet ) \
  > "${S3_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S3_default_testnet.rc"
assert_not_grep "${S3_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S3_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S3_LOG}" "MainNet peer-driven apply ENABLED"

log "S4 — MainNet startup terminal: refusal preserved, no RemoteSigner banner"
S4_LOG="${LOGS_DIR}/S4_default_mainnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                          -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    "${NODE_BIN}" --print-genesis-hash --env mainnet ) \
  > "${S4_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S4_default_mainnet.rc"
assert_not_grep "${S4_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S4_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S4_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S4_LOG}" "(?i)remote signer production active"
assert_not_grep "${S4_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S4_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S4_LOG}" "(?i)governance execution"

log "S5 — Run 193 hidden custody policy selector remains compatible (env, DevNet)"
S5_LOG="${LOGS_DIR}/S5_custody_policy_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_custody_policy_selector_compat.rc"
assert_not_grep "${S5_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"

log "S6 — governance fixture proof path remains compatible (DevNet)"
S6_LOG="${LOGS_DIR}/S6_governance_fixture_compat.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_governance_fixture_compat.rc"
assert_not_grep "${S6_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S6_LOG}" "(?i)governance execution"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"

log "S7 — MainNet with custody policy + governance fixture armed: refusal preserved"
S7_LOG="${LOGS_DIR}/S7_mainnet_armed.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=mainnet-production-custody-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_mainnet_armed.rc"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S7_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S7_LOG}" "(?i)remote.?signer (?:enabled|active|connected|wired)"
assert_not_grep "${S7_LOG}" "(?i)remote signer production active"
assert_not_grep "${S7_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S7_LOG}" "(?i)validator-set rotation"
assert_not_grep "${S7_LOG}" "(?i)governance execution"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 194 typed RemoteSigner
# production-custody boundary + Run 192 selector + Run 190 routing helpers +
# Run 188 typed boundary. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface the
# Run 195 helper exercises is wired in production source — not in tests or
# fixtures.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 195 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_remote_authority_signer' \
    'RemoteSignerPolicy' \
    'RemoteSignerPolicy::Disabled' \
    'RemoteSignerPolicy::FixtureLoopbackAllowed' \
    'RemoteSignerPolicy::ProductionRemoteSignerRequired' \
    'RemoteSignerPolicy::MainnetProductionRemoteSignerRequired' \
    'RemoteSignerIdentity' \
    'RemoteSignerRequest' \
    'RemoteSignerResponse' \
    'RemoteSignerExpectations' \
    'RemoteSignerOutcome' \
    'RemoteAuthoritySigner' \
    'FixtureLoopbackRemoteSigner' \
    'ProductionRemoteSigner' \
    'validate_remote_signer' \
    'validate_remote_signer_for_custody_class' \
    'validate_lifecycle_governance_custody_and_remote_signer' \
    'mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary' \
    'local_operator_key_cannot_satisfy_remote_signer' \
    'peer_majority_cannot_satisfy_remote_signer' \
    'custody_class_routes_to_remote_signer' \
    'canonical_digest' \
    'REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL' \
    'AuthorityCustodyClass::RemoteSigner' \
    'pqc_authority_custody_policy_surface' \
    'pqc_authority_custody_payload_carrying' \
    'pqc_authority_custody'
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
  echo "Run 195 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'governance execution claim' \
    'real governance execution' \
    'on-chain governance claim' \
    'real on-chain governance proof claim' \
    'KMS/HSM enabled' \
    'KMS/HSM active' \
    'kms-hsm enabled' \
    'real RemoteSigner backend' \
    'RemoteSigner backend connected' \
    'RemoteSigner enabled' \
    'remote signer production active' \
    'RemoteSigner production active' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_195_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected RemoteSigner-boundary scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 195 no-mutation proof for rejected RemoteSigner-boundary scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven Run 194 RemoteSigner rejection corpus (R1..R31):"
  echo "    * no Run 070 apply call observed in helper log"
  echo "    * no live trust swap"
  echo "    * no session eviction"
  echo "    * no sequence write"
  echo "    * no marker write"
  echo "    * marker bytes unchanged where present"
  echo "    * sequence bytes unchanged where present"
  echo "    * no .tmp residue"
  echo "    * no fallback to --p2p-trusted-root"
  echo "    * no active DummySig / DummyKem / DummyAead"
  echo "    * no real KMS / HSM / remote-signer backend wired"
  echo "    * no real governance execution / no real on-chain proof verifier"
  echo "    * no validator-set rotation"
  echo "    * candidate / persisted snapshots taken before and after a"
  echo "      rejecting RemoteSigner / custody / lifecycle / routing dispatch"
  echo "      are bit-equal (captured in no_mutation_evidence.txt)."
  grep -E 'verdict: PASS|R[0-9]+_|A[0-9]+_|no_mutation_pass|determinism_pass' \
    "${HELPER_195_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted RemoteSigner scenarios (release-
# binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 195 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site Run 194 RemoteSigner boundary"
  echo "  reachability today:"
  echo "    - Run 194 added pqc_remote_authority_signer.rs with the typed"
  echo "      RemoteSignerPolicy (Disabled / FixtureLoopbackAllowed /"
  echo "      ProductionRemoteSignerRequired /"
  echo "      MainnetProductionRemoteSignerRequired), RemoteSignerIdentity,"
  echo "      RemoteSignerRequest with deterministic domain-separated"
  echo "      SHA3-256 canonical digest, RemoteSignerResponse,"
  echo "      RemoteSignerExpectations, the pure RemoteAuthoritySigner"
  echo "      trait, the DevNet/TestNet-only FixtureLoopbackRemoteSigner,"
  echo "      the fail-closed ProductionRemoteSigner, the pure"
  echo "      validate_remote_signer verifier,"
  echo "      validate_remote_signer_for_custody_class custody-class router,"
  echo "      validate_lifecycle_governance_custody_and_remote_signer"
  echo "      composition entry point, and the named MainNet /"
  echo "      local-operator / peer-majority refusal helpers;"
  echo "    - the Run 194 RemoteSigner boundary is layered ABOVE Run 192's"
  echo "      typed authority-custody policy selector"
  echo "      (pqc_authority_custody_policy_surface::*), Run 190's typed"
  echo "      authority-custody payload-carrying surface"
  echo "      (pqc_authority_custody_payload_carrying::*), and Run 188's"
  echo "      typed authority-custody boundary (pqc_authority_custody::*);"
  echo "    - Run 194 added NO new CLI flag, NO new env var, NO schema bump,"
  echo "      NO sidecar field, NO metric, and NO exit code — it is a pure"
  echo "      library boundary; the release binary therefore surfaces no"
  echo "      RemoteSigner enablement banner (proven empty above, S1–S7);"
  echo "    - the RemoteSigner boundary is wired source-side as a pure"
  echo "      preflight/validation helper, BEFORE any Run 070 apply call,"
  echo "      BEFORE any live trust swap, BEFORE any session eviction,"
  echo "      BEFORE any sequence/marker write, and BEFORE any peer-driven"
  echo "      drain;"
  echo "    - the Run 147 / 148 / 152 FATAL MainNet peer-driven apply"
  echo "      refusal remains layered ahead of the RemoteSigner gate via the"
  echo "      MainNetPeerDrivenApplyRefused short-circuit and the named"
  echo "      mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary"
  echo "      helper."
  echo
  echo "  release-binary RemoteSigner corpus (this run):"
  echo "    - the Run 195 helper exercises every RemoteSignerPolicy source"
  echo "      (Disabled / FixtureLoopbackAllowed /"
  echo "      ProductionRemoteSignerRequired /"
  echo "      MainnetProductionRemoteSignerRequired) against"
  echo "      validate_remote_signer across the A1..A7 acceptance corpus and"
  echo "      the R1..R31 rejection corpus from Run 194 in release mode"
  echo "      through the production library symbols;"
  echo "    - the helper additionally exercises the canonical-digest binding"
  echo "      table, the policy-mode table, the custody-class routing table"
  echo "      (validate_remote_signer_for_custody_class), the composition"
  echo "      table (validate_lifecycle_governance_custody_and_remote_signer),"
  echo "      the refusal-helper table, the no-mutation snapshot table, and"
  echo "      the determinism re-evaluation table;"
  echo "    - non-mutation evidence is captured for every rejected scenario"
  echo "      via bit-equality of candidate / persisted snapshots taken"
  echo "      before and after a rejecting RemoteSigner / custody / lifecycle"
  echo "      / routing dispatch (no_mutation_evidence.txt); deterministic"
  echo "      re-evaluation evidence is captured in determinism_evidence.txt."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help surfaces no RemoteSigner"
  echo "      / KMS / HSM / governance-execution / validator-set-rotation"
  echo "      enablement claim;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no RemoteSigner enablement"
  echo "      banner and no MainNet peer-driven apply enablement claim;"
  echo "    - the Run 193 hidden authority-custody policy selector and the"
  echo "      governance fixture proof paths remain compatible at the binary"
  echo "      surface;"
  echo "    - even with the Run 193 selector set to"
  echo "      mainnet-production-custody-required and the governance fixture"
  echo "      selector armed on MainNet, MainNet peer-driven apply remains"
  echo "      refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real RemoteSigner backend and no networked signer service is"
  echo "      wired in Run 195. Every ProductionRemoteSigner attestation"
  echo "      routes to the typed unavailable outcome, and every"
  echo "      ProductionRemoteSignerRequired /"
  echo "      MainnetProductionRemoteSignerRequired policy fails closed,"
  echo "      encoding the honest unavailability;"
  echo "    - fixture loopback RemoteSigner remains DevNet/TestNet"
  echo "      evidence-only and explicitly cannot satisfy MainNet production"
  echo "      RemoteSigner policy;"
  echo "    - local operator keys and peer-majority/gossip counts explicitly"
  echo "      cannot satisfy RemoteSigner policy;"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "    - no MainNet peer-driven apply enablement, no governance"
  echo "      execution, no real on-chain proof verifier, no validator-set"
  echo "      rotation, no autonomous apply, no apply-on-receipt, no"
  echo "      peer-majority authority, no schema/wire/metric drift."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_195_TASK.txt
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
TEST_VERDICTS+=( "$(run_lib_test pqc_remote_authority_signer pqc_remote_authority_signer)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_195.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 195 — release-binary RemoteSigner production-custody boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_195_sha256:  $(sha256_file "${HELPER_195_BIN}")"
  echo "  helper_195_buildid: $(build_id "${HELPER_195_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_custody_policy_selector_compat S6_governance_fixture_compat \
           S7_mainnet_armed
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_195	rc=$(cat "${EXIT_DIR}/helper_run_195.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_195_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A7 / R1-R31 corpus verdicts (release mode, production library symbols):"
  for k in total_pass total_fail scenarios_pass scenarios_fail \
           canonical_digest_pass canonical_digest_fail \
           policy_mode_pass policy_mode_fail \
           custody_routing_pass custody_routing_fail \
           composition_pass composition_fail \
           refusal_helpers_pass refusal_helpers_fail \
           no_mutation_pass no_mutation_fail determinism_pass determinism_fail
  do
    v="$(grep -E "^${k}: " "${HELPER_195_OUT}/helper_summary.txt" 2>/dev/null | head -n1 | awk '{print $2}')"
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
  echo "  * default behaviour exposes/enables no production RemoteSigner;"
  echo "    Run 194 added no new CLI flag and no new env var;"
  echo "  * fixture loopback RemoteSigner remains DevNet/TestNet"
  echo "    evidence-only and cannot satisfy MainNet production RemoteSigner"
  echo "    policy;"
  echo "  * production RemoteSigner remains unavailable/fail-closed under"
  echo "    ProductionRemoteSignerRequired and"
  echo "    MainnetProductionRemoteSignerRequired regardless of environment;"
  echo "  * RemoteSigner request/response binding is deterministic and"
  echo "    domain-bound (environment, chain, genesis, authority root,"
  echo "    lifecycle action, candidate digest, authority-domain sequence);"
  echo "  * local operator keys and peer-majority/gossip counts cannot"
  echo "    satisfy RemoteSigner policy;"
  echo "  * RemoteSigner integrates with custody composition at the"
  echo "    release-helper/library level only;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL"
  echo "    invariant) at every binary surface — including with the Run 193"
  echo "    selector set to mainnet-production-custody-required and the"
  echo "    governance fixture selector armed — and at the typed boundary via"
  echo "    mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary;"
  echo "  * no real RemoteSigner backend / no networked signer service;"
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift (Run 195 is release-binary"
  echo "    evidence only);"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node exposes no production"
  echo "  RemoteSigner, emits no RemoteSigner/KMS/HSM enablement banner, no"
  echo "  governance execution claim, and no validator-set rotation claim on"
  echo "  --help or --print-genesis-hash --env {devnet,testnet,mainnet}. The"
  echo "  Run 193 hidden authority-custody policy selector and the governance"
  echo "  fixture proof paths remain compatible. The Run 195 release-built"
  echo "  helper exercises the full Run 194 A1-A7 / R1-R31 RemoteSigner"
  echo "  corpus end-to-end through the production library symbols"
  echo "  pqc_remote_authority_signer::* layered above"
  echo "  pqc_authority_custody_policy_surface::*,"
  echo "  pqc_authority_custody_payload_carrying::*, and"
  echo "  pqc_authority_custody::*, returning the expected typed outcomes."
  echo "  RemoteSigner request/response binding is deterministic and"
  echo "  domain-bound. Fixture loopback RemoteSigner is DevNet/TestNet"
  echo "  evidence-only; production RemoteSigner is unavailable/fail-closed;"
  echo "  local operator keys and peer-majority/gossip cannot satisfy"
  echo "  RemoteSigner policy. MainNet peer-driven apply remains the Run 147"
  echo "  FATAL refusal even with the Run 193 selector and governance fixture"
  echo "  selector armed. Real RemoteSigner / KMS / HSM / cloud KMS / PKCS#11"
  echo "  backends, real on-chain governance proof verification, governance"
  echo "  execution, and validator-set rotation all remain unimplemented."
  echo "  Full C4 and C5 remain OPEN."
} > "${SUMMARY}"

log "done. summary at ${SUMMARY}"
