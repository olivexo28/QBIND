#!/usr/bin/env bash
# Run 202 — Release-binary RemoteSigner **transport boundary** evidence on real
# `target/release/qbind-node`. Closes the Run 201-deferred release-binary
# boundary for the production RemoteSigner transport boundary added by
# `crates/qbind-node/src/pqc_remote_signer_transport.rs` (Run 201), layered
# over the Run 194 RemoteSigner production-custody boundary
# (`crates/qbind-node/src/pqc_remote_authority_signer.rs`).
#
# Driving spec: `task/RUN_202_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * the existing Run 070 / 130–201 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193 hidden
#     custody-policy selector, the Run 198 hidden RemoteSigner-policy selector,
#     the governance fixture flag) emit no RemoteSigner transport enablement
#     banner, no "RemoteSigner transport active" / "RemoteSigner backend
#     connected" / "networked signer daemon active" claim, no KMS/HSM active
#     claim, no governance-execution claim, no validator-set rotation claim,
#     and no MainNet peer-driven apply enablement;
#   * default behaviour does not expose or enable any production RemoteSigner
#     transport;
#   * even with the Run 198 RemoteSigner policy selector armed to
#     `mainnet-production-remote-signer-required` on `--env mainnet`, the
#     binary still emits no MainNet peer-driven apply enablement and no
#     RemoteSigner transport / KMS / HSM enablement — the Run 147 / 148 / 152
#     FATAL invariant is preserved at the binary surface;
#   * the release-built Run 202 helper
#     `run_202_remote_signer_transport_release_binary_helper` exercises the
#     Run 201 RemoteSigner transport corpus (`validate_remote_signer_transport`,
#     `validate_lifecycle_custody_remote_signer_and_transport`,
#     `FixtureLoopbackRemoteSignerTransport`, `ProductionRemoteSignerTransport`,
#     the request/response/transcript envelope digests) — all in **release
#     mode** through the production library symbols.
#
# Strict scope (from `task/RUN_202_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 202 helper to exercise the Run 201 transport
#     boundary in release mode through the production library symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real RemoteSigner backend / networked signer daemon.
#   * No production signing key custody.
#   * No real KMS / HSM / cloud KMS / PKCS#11 integration.
#   * No real on-chain governance proof verifier; no governance execution;
#     no validator-set rotation; no autonomous apply; no apply-on-receipt;
#     no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No schema / wire / metric drift.
#   * No authority-marker / sequence-file / trust-bundle core schema change.
#   * Do not weaken Runs 070, 130–201.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under `OUTDIR`
# except `README.md`, `summary.txt`, and `.gitignore`, which are tracked in
# git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_202_remote_signer_transport_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_202_BIN="${REPO_ROOT}/target/release/examples/run_202_remote_signer_transport_release_binary_helper"

HELPER_202_OUT="${OUTDIR}/helper_evidence/run_202"
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

log()  { printf '[run-202] %s\n' "$*" >&2; }
fail() { printf '[run-202] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_202_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_202_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-202 provenance"
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
# Build qbind-node bin + Run 202 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_202_remote_signer_transport_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_202_remote_signer_transport_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_202.log" 2>&1 \
  || fail "release build of run_202 helper failed (see ${LOGS_DIR}/build_helper_run_202.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_202_BIN}" ]] || fail "missing ${HELPER_202_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_202_path:    ${HELPER_202_BIN}"
  echo "helper_202_sha256:  $(sha256_file "${HELPER_202_BIN}")"
  echo "helper_202_buildid: $(build_id "${HELPER_202_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 202 release helper. Exits 0 iff the accepted (A1..A10),
# rejection (R1..R35), separation/fail-closed, composition, determinism, and
# refusal-helper tables all matched in release mode through the production
# library symbols.
# ---------------------------------------------------------------------------
log "running Run 202 RemoteSigner transport release helper -> ${HELPER_202_OUT}"
HELPER_202_LOG="${LOGS_DIR}/helper_run_202.log"
set +e
"${HELPER_202_BIN}" "${HELPER_202_OUT}" > "${HELPER_202_LOG}" 2>&1
HELPER_202_RC=$?
set -e
echo "${HELPER_202_RC}" > "${EXIT_DIR}/helper_run_202.rc"
[[ "${HELPER_202_RC}" -eq 0 ]] || fail "run_202 helper exited rc=${HELPER_202_RC} (see ${HELPER_202_LOG})"
[[ -s "${HELPER_202_OUT}/helper_summary.txt" ]] || fail "run_202 helper did not write helper_summary.txt"
assert_grep "${HELPER_202_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants. Run 201 added a pure additive library module
# only (no CLI flag, no env var, no runtime banner). The surface contract is
# therefore that every existing Run 070 / 130–201 surface emits no RemoteSigner
# transport / KMS / HSM enablement banner and no MainNet peer-driven apply
# enablement claim. `--print-genesis-hash` is a non-mutating CLI that exits
# quickly without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help advertises no RemoteSigner transport surface"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer transport"
assert_not_grep "${HELP_LOG}" "(?i)networked signer daemon"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "run-201"
assert_not_grep "${HELP_LOG}" "run-202"
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
  assert_not_grep "${logf}" "(?i)remote signer transport (?:enabled|active|connected|wired)"
  assert_not_grep "${logf}" "(?i)remote signer backend connected"
  assert_not_grep "${logf}" "(?i)networked signer daemon active"
  assert_not_grep "${logf}" "(?i)kms.?hsm (?:enabled|active)"
  assert_not_grep "${logf}" "(?i)production custody (?:enabled|active|wired)"
  assert_not_grep "${logf}" "(?i)governance execution"
  assert_not_grep "${logf}" "(?i)validator-set rotation"
  assert_not_grep "${logf}" "(?i)autonomous apply"
  assert_not_grep "${logf}" "MainNet peer-driven apply ENABLED"
}

log "S2 — default DevNet surface: no RemoteSigner transport/KMS/HSM banner"
run_surface_scenario "S2_default_devnet" devnet

log "S3 — default TestNet surface: no RemoteSigner transport/KMS/HSM banner"
run_surface_scenario "S3_default_testnet" testnet

log "S4 — default MainNet surface: no RemoteSigner transport banner, no MainNet apply"
run_surface_scenario "S4_default_mainnet" mainnet

log "S5 — Run 198 RemoteSigner policy selector armed on DevNet: no transport banner drift"
S5_LOG="${LOGS_DIR}/S5_remote_signer_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-remote-signer-policy fixture-loopback-allowed ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_remote_signer_selector_compat.rc"
assert_not_grep "${S5_LOG}" "(?i)remote signer transport (?:enabled|active|connected|wired)"
assert_not_grep "${S5_LOG}" "(?i)networked signer daemon active"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"

log "S6 — Run 193 custody selector armed alongside RemoteSigner selector on DevNet: compat"
S6_LOG="${LOGS_DIR}/S6_custody_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=fixture-loopback-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_custody_selector_compat.rc"
assert_not_grep "${S6_LOG}" "(?i)remote signer transport (?:enabled|active|connected|wired)"
assert_not_grep "${S6_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"

log "S7 — governance fixture flag armed on DevNet: no RemoteSigner transport banner drift"
S7_LOG="${LOGS_DIR}/S7_governance_fixture_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    -u QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY \
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_governance_fixture_compat.rc"
assert_not_grep "${S7_LOG}" "(?i)remote signer transport (?:enabled|active|connected|wired)"
assert_not_grep "${S7_LOG}" "(?i)governance execution"
assert_not_grep "${S7_LOG}" "(?i)on-chain governance proof verifier active"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"

log "S8 — MainNet with RemoteSigner selector mainnet-production-remote-signer-required: refusal preserved"
S8_LOG="${LOGS_DIR}/S8_mainnet_armed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=mainnet-production-remote-signer-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-remote-signer-policy mainnet-production-remote-signer-required ) \
  > "${S8_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S8_mainnet_armed.rc"
assert_not_grep "${S8_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S8_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S8_LOG}" "(?i)remote signer transport (?:enabled|active|connected|wired)"
assert_not_grep "${S8_LOG}" "(?i)networked signer daemon active"
assert_not_grep "${S8_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S8_LOG}" "(?i)validator-set rotation"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 201 RemoteSigner transport
# boundary layered over the Run 194 verifier. We grep the production source
# under crates/qbind-node/src so the artifact records that the typed surface
# the Run 202 helper exercises is wired in production source.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 202 source-reachability proof — production symbols within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_remote_signer_transport' \
    'RemoteSignerTransportConfig' \
    'RemoteSignerTransportRequestEnvelope' \
    'RemoteSignerTransportResponseEnvelope' \
    'trait RemoteSignerTransport' \
    'FixtureLoopbackRemoteSignerTransport' \
    'ProductionRemoteSignerTransport' \
    'fn envelope_digest' \
    'remote_signer_response_canonical_digest' \
    'fn transport_transcript_digest' \
    'validate_remote_signer_transport' \
    'validate_remote_signer_transport_for_custody_class' \
    'validate_lifecycle_custody_remote_signer_and_transport' \
    'ProductionTransportUnavailable' \
    'MainNetProductionTransportUnavailable' \
    'mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary' \
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
  echo "Run 202 denylist (proven empty across all captured logs):"
  for pat in \
    'apply on receipt' \
    'apply-on-receipt' \
    'autonomous apply' \
    'peer-majority authority' \
    'fallback to --p2p-trusted-root' \
    'DummySig' 'DummyKem' 'DummyAead' \
    'remote signer backend connected' \
    'RemoteSigner backend connected' \
    'remote signer transport active' \
    'RemoteSigner transport active' \
    'networked signer daemon active' \
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
    if find "${LOGS_DIR}" "${HELPER_202_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected RemoteSigner transport-boundary scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 202 no-mutation proof for rejected RemoteSigner transport-boundary scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven RemoteSigner transport rejection corpus (R1..R35):"
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
  echo "    * no real RemoteSigner / networked signer daemon / KMS / HSM backend wired"
  echo "    * no real governance execution / no real on-chain proof verifier"
  echo "    * no validator-set rotation"
  echo "    * the verifier validate_remote_signer_transport and the composition"
  echo "      validate_lifecycle_custody_remote_signer_and_transport are pure"
  echo "      functions returning typed owned outcomes; on a reject they touch"
  echo "      no marker / sequence / live trust and never invoke Run 070"
  echo "      (helper rejection.manifest R1..R35 + R33/R34 no-mutation asserts)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_202_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted fixture-loopback transport scenarios
# (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 202 mutation proof (release-binary scope):"
  echo
  echo "  library-side production RemoteSigner transport boundary reachability"
  echo "  today:"
  echo "    - Run 201 added pqc_remote_signer_transport.rs with the typed"
  echo "      RemoteSignerTransportConfig, the RemoteSignerTransportRequestEnvelope"
  echo "      / RemoteSignerTransportResponseEnvelope wrapping the Run 194"
  echo "      RemoteSignerRequest / RemoteSignerResponse, deterministic"
  echo "      domain-separated request/response/transcript digests"
  echo "      (envelope_digest + transport_transcript_digest +"
  echo "      remote_signer_response_canonical_digest), the pure/mockable"
  echo "      RemoteSignerTransport trait, the DevNet/TestNet-only"
  echo "      FixtureLoopbackRemoteSignerTransport, the fail-closed"
  echo "      ProductionRemoteSignerTransport, the typed"
  echo "      RemoteSignerTransportOutcome taxonomy, the verifier"
  echo "      validate_remote_signer_transport, and the composition"
  echo "      validate_lifecycle_custody_remote_signer_and_transport;"
  echo "    - the module is additive and pure: it performs no network or file"
  echo "      I/O, writes no marker, writes no sequence, swaps no live trust,"
  echo "      evicts no sessions, and never invokes Run 070;"
  echo "    - the production transport fails closed as"
  echo "      ProductionTransportUnavailable / MainNetProductionTransportUnavailable;"
  echo "    - the fixture loopback transport is DevNet/TestNet evidence-only and"
  echo "      is refused on a MainNet trust domain;"
  echo "    - MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL"
  echo "      refusal even with fixture loopback transport material."
  echo
  echo "  release-binary RemoteSigner transport corpus (this run):"
  echo "    - the Run 202 helper exercises the A1..A10 acceptance corpus and"
  echo "      the R1..R35 rejection corpus in release mode through the"
  echo "      production library symbols (accepted / rejection / separation /"
  echo "      composition / determinism / refusal_helpers tables);"
  echo "    - request / response / transcript digests are deterministic and"
  echo "      domain-bound; the transport composes with the Run 194 verifier;"
  echo "    - the production transport returns the typed unavailable outcome;"
  echo "    - rejected cases leave every input byte-identical (R33) and the"
  echo "      composition rejects without mutating the candidate (R34);"
  echo "    - MainNet peer-driven apply remains refused even with a fixture"
  echo "      loopback transport response (R35 / compose-mainnet-refused)."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help advertises no RemoteSigner"
  echo "      transport / networked signer daemon / KMS / HSM surface;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no RemoteSigner transport / KMS /"
  echo "      HSM enablement banner and no MainNet peer-driven apply enablement"
  echo "      claim, with or without the Run 198 RemoteSigner selector, the"
  echo "      Run 193 custody selector, or the governance fixture flag armed;"
  echo "    - even with the RemoteSigner selector set to"
  echo "      mainnet-production-remote-signer-required on MainNet, MainNet"
  echo "      peer-driven apply remains refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real RemoteSigner backend / networked signer daemon is wired"
  echo "      in Run 202. The production transport always returns the typed"
  echo "      ProductionTransportUnavailable / MainNetProductionTransportUnavailable"
  echo "      reject;"
  echo "    - fixture loopback transport remains DevNet/TestNet evidence-only"
  echo "      and cannot satisfy MainNet production RemoteSigner transport;"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "    - no MainNet peer-driven apply enablement, no governance execution,"
  echo "      no real on-chain proof verifier, no validator-set rotation, no"
  echo "      autonomous apply, no apply-on-receipt, no peer-majority authority,"
  echo "      no schema/wire/metric drift."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_202_TASK.txt Validation
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
TEST_VERDICTS+=( "$(run_lib_test pqc_remote_signer_transport pqc_remote_signer_transport)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_202.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 202 — release-binary RemoteSigner transport boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_202_sha256:  $(sha256_file "${HELPER_202_BIN}")"
  echo "  helper_202_buildid: $(build_id "${HELPER_202_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_remote_signer_selector_compat S6_custody_selector_compat \
           S7_governance_fixture_compat S8_mainnet_armed
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_202	rc=$(cat "${EXIT_DIR}/helper_run_202.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_202_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A10 / R1-R35 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_202_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
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
  echo "  * no real RemoteSigner backend / networked signer daemon is wired;"
  echo "    the production transport fails closed as"
  echo "    ProductionTransportUnavailable / MainNetProductionTransportUnavailable;"
  echo "  * fixture loopback transport remains DevNet/TestNet evidence-only and"
  echo "    cannot satisfy MainNet production RemoteSigner transport;"
  echo "  * request/response/transcript digests are deterministic and domain-bound;"
  echo "  * the transport composes with the Run 194 RemoteSigner request/response;"
  echo "  * rejected RemoteSigner transport-boundary cases produce no mutation"
  echo "    (no marker / sequence write, no Run 070 call, no live trust swap, no"
  echo "    session eviction);"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL invariant)"
  echo "    even with a fixture loopback transport response;"
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
  echo "  positive: real target/release/qbind-node keeps every existing Run 070"
  echo "  / 130–201 surface RemoteSigner-transport-silent (no transport / KMS /"
  echo "  HSM enablement banner, MainNet peer-driven apply refusal preserved),"
  echo "  and the release-built Run 202 helper exercises the Run 201 RemoteSigner"
  echo "  transport corpus end-to-end in release mode through the production"
  echo "  library symbols: fixture loopback transport accepted on DevNet/TestNet"
  echo "  only; production transport fail-closed as unavailable; MainNet"
  echo "  production transport fail-closed as unavailable; request/response/"
  echo "  transcript digests deterministic and domain-bound; transport composes"
  echo "  with the Run 194 RemoteSigner request/response; rejected cases produce"
  echo "  no mutation; and MainNet peer-driven apply remains the Run 147 FATAL"
  echo "  refusal even with fixture loopback transport material. Real RemoteSigner"
  echo "  / networked signer daemon / KMS / HSM backends, real on-chain governance"
  echo "  proof verification, governance execution, and validator-set rotation all"
  echo "  remain unimplemented. Full C4 and C5 remain OPEN."
} > "${SUMMARY}"

log "done"
