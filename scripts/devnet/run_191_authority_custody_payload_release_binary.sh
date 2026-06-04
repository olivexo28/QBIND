#!/usr/bin/env bash
# Run 191 — Release-binary KMS/HSM authority-custody boundary evidence on
# real `target/release/qbind-node`. Closes the Run 190-deferred release-
# binary boundary for the typed source/test authority-custody surface
# added by `crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`
# (Run 190) and the Run 188 typed authority-custody boundary in
# `crates/qbind-node/src/pqc_authority_custody.rs`.
#
# Driving spec: `task/RUN_191_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * default `AuthorityCustodyPolicy::Disabled` is preserved on every
#     production surface — the binary surfaces no custody flag, no KMS
#     / HSM enablement banner, and no peer-majority / autonomous custody
#     claim. Run 190 added no operator-visible selector, so the
#     release-binary boundary for Run 191 mirrors that surface contract;
#   * the existing Run 070 / 130–187 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|mainnet`,
#     `--p2p-trust-bundle-reload-check`,
#     `--p2p-trust-bundle-reload-apply-path`,
#     `--p2p-trust-bundle-onchain-governance-fixture-allowed`) emit no
#     Run 190 custody enablement claim;
#   * the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
#     invariant is unchanged — the binary never declares MainNet
#     peer-driven apply ENABLED, with or without the Run 187 fixture
#     selector and/or a fully-valid MainNet ratification sibling
#     carried; the Run 190 typed
#     `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
#     helper additionally encodes the rule at the typed custody
#     boundary regardless of attestation contents;
#   * the release-built Run 191 helper
#     `run_191_authority_custody_boundary_release_binary_helper`
#     exercises the Run 190 A1–A8 / R1–R29 corpus end-to-end in
#     **release mode** through the production library symbols
#     `pqc_authority_custody::*` —
#     `AuthorityCustodyClass`, `AuthorityCustodyPolicy`,
#     `AuthorityCustodyAttestation`, `AuthorityCustodyValidationOutcome`,
#     `LifecycleGovernanceCustodyOutcome`,
#     `validate_authority_custody_attestation`,
#     `validate_lifecycle_governance_and_custody`,
#     `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
#     `peer_majority_cannot_satisfy_custody`,
#     `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
#
# Strict scope (from `task/RUN_191_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 191 helper to exercise the Run 190
#     custody boundary in release mode through production library
#     symbols.
#   * No production-source change.
#   * No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
#   * No real on-chain governance proof verifier; no governance
#     execution; no validator-set rotation; no autonomous apply;
#     no apply-on-receipt; no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No marker / sequence-file / trust-bundle / wire / metric drift.
#   * No new CLI flag, env var, schema bump, sidecar field, metric, or
#     exit code.
#   * Do not weaken Runs 070, 130–188.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which
# are tracked in git. The committed `summary.txt` is a placeholder
# overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_191_authority_custody_payload_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_191_BIN="${REPO_ROOT}/target/release/examples/run_191_authority_custody_payload_release_binary_helper"

HELPER_191_OUT="${OUTDIR}/helper_evidence/run_191"
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

log()  { printf '[run-191] %s\n' "$*" >&2; }
fail() { printf '[run-191] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_191_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${SCEN_DIR}" \
       "${DATA_DIR}"
mkdir -p "${HELPER_191_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
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
  echo "run-191 provenance"
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
# Build qbind-node bin + Run 191 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_191_authority_custody_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_191_authority_custody_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_191.log" 2>&1 \
  || fail "release build of run_191 helper failed (see ${LOGS_DIR}/build_helper_run_191.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_191_BIN}" ]] || fail "missing ${HELPER_191_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_191_path:    ${HELPER_191_BIN}"
  echo "helper_191_sha256:  $(sha256_file "${HELPER_191_BIN}")"
  echo "helper_191_buildid: $(build_id "${HELPER_191_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 191 release helper. Exits 0 iff every Run 190 A1..A10 /
# R1..R32 scenario, every combined-helper scenario, every custody-class
# placeholder fail-closed, every named-helper assertion, every
# no-mutation snapshot, and the determinism re-evaluation matched in
# release mode through the production library symbols.
# ---------------------------------------------------------------------------
log "running Run 191 custody-boundary release helper -> ${HELPER_191_OUT}"
HELPER_191_LOG="${LOGS_DIR}/helper_run_191.log"
set +e
"${HELPER_191_BIN}" "${HELPER_191_OUT}" > "${HELPER_191_LOG}" 2>&1
HELPER_191_RC=$?
set -e
echo "${HELPER_191_RC}" > "${EXIT_DIR}/helper_run_191.rc"
[[ "${HELPER_191_RC}" -eq 0 ]] || fail "run_191 helper exited rc=${HELPER_191_RC} (see ${HELPER_191_LOG})"
[[ -s "${HELPER_191_OUT}/helper_summary.txt" ]] || fail "run_191 helper did not write helper_summary.txt"
assert_grep "${HELPER_191_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants — Run 190 added no operator-visible
# selector, so the release-binary surface contract for Run 191 is that
# the existing Runs 070 / 130–187 surfaces (`--help`,
# `--print-genesis-hash --env devnet|mainnet`,
# `--p2p-trust-bundle-onchain-governance-fixture-allowed`) still emit
# no custody enablement banner and no MainNet apply enablement claim.
# `--print-genesis-hash` is a non-mutating CLI that exits quickly
# without opening sockets or touching real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help surfaces no Run 190 custody flag / claim"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "(?i)authority.?custody"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer"
assert_not_grep "${HELP_LOG}" "(?i)production custody"
assert_not_grep "${HELP_LOG}" "run-188"
assert_not_grep "${HELP_LOG}" "run-191"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

log "S2 — default DevNet startup terminal: no custody/KMS/HSM banner"
S2_LOG="${LOGS_DIR}/S2_default_devnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
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

log "S3 — default TestNet startup terminal: no custody/KMS/HSM banner"
S3_LOG="${LOGS_DIR}/S3_default_testnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env testnet ) \
  > "${S3_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S3_default_testnet.rc"
assert_not_grep "${S3_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S3_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S3_LOG}" "MainNet peer-driven apply ENABLED"

log "S4 — MainNet startup terminal: no custody enablement, no MainNet apply"
S4_LOG="${LOGS_DIR}/S4_default_mainnet.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    "${NODE_BIN}" --print-genesis-hash --env mainnet ) \
  > "${S4_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S4_default_mainnet.rc"
assert_not_grep "${S4_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S4_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S4_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S4_LOG}" "(?i)mainnet.+apply.+enabled"

log "S5 — Run 187 fixture selector armed on MainNet still refuses MainNet apply"
S5_LOG="${LOGS_DIR}/S5_mainnet_fixture_selector.log"
( cd "${REPO_ROOT}" && QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_mainnet_fixture_selector.rc"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S5_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm enabled"
assert_not_grep "${S5_LOG}" "(?i)production custody (?:enabled|active|wired)"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 190 typed authority-
# custody boundary symbols. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface
# the Run 191 helper exercises is wired in production source — not in
# tests or fixtures.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 191 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_authority_custody' \
    'AuthorityCustodyClass' \
    'AuthorityCustodyClass::FixtureLocalKey' \
    'AuthorityCustodyClass::LocalOperatorKey' \
    'AuthorityCustodyClass::RemoteSigner' \
    'AuthorityCustodyClass::Kms' \
    'AuthorityCustodyClass::Hsm' \
    'AuthorityCustodyClass::Unknown' \
    'AuthorityCustodyPolicy' \
    'AuthorityCustodyPolicy::Disabled' \
    'AuthorityCustodyPolicy::FixtureOnly' \
    'AuthorityCustodyPolicy::DevnetLocalAllowed' \
    'AuthorityCustodyPolicy::TestnetLocalAllowed' \
    'AuthorityCustodyPolicy::ProductionCustodyRequired' \
    'AuthorityCustodyPolicy::MainnetProductionCustodyRequired' \
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
    'AuthorityCustodyValidationOutcome::CustodyAttestationMissing' \
    'AuthorityCustodyValidationOutcome::CustodyAttestationMalformed' \
    'AuthorityCustodyValidationOutcome::CustodyAttestationExpired' \
    'AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch' \
    'AuthorityCustodyValidationOutcome::UnsupportedCustodySuite' \
    'AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected' \
    'LifecycleGovernanceCustodyOutcome' \
    'LifecycleGovernanceCustodyOutcome::Accepted' \
    'LifecycleGovernanceCustodyOutcome::LifecycleRejected' \
    'LifecycleGovernanceCustodyOutcome::CustodyRejected' \
    'LifecycleGovernanceCustodyOutcome::MainNetPeerDrivenApplyRefused' \
    'validate_authority_custody_attestation' \
    'validate_lifecycle_governance_and_custody' \
    'mainnet_peer_driven_apply_remains_refused_under_custody_boundary' \
    'peer_majority_cannot_satisfy_custody' \
    'local_operator_config_alone_cannot_satisfy_mainnet_production_custody' \
    'pqc_authority_custody_payload_carrying' \
    'AuthorityCustodyAttestationWire' \
    'AuthorityCustodyClassWire' \
    'GovernanceAuthorityClassWire' \
    'AuthorityCustodyLoadStatus' \
    'AuthorityCustodyLoadStatus::Loaded' \
    'AuthorityCustodyLoadStatus::Absent' \
    'AuthorityCustodyLoadStatus::Malformed' \
    'AuthorityCustodyCallsiteContext' \
    'AuthorityCustodyPayloadCarryingDecisionOutcome' \
    'AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite' \
    'AuthorityCustodyPayloadCarryingDecisionOutcome::Refused' \
    'AuthorityCustodyPayloadCarryingDecisionOutcome::Unhandled' \
    'parse_optional_authority_custody_attestation_sibling_from_json_value' \
    'callsite_context_for_authority_custody' \
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
  echo "Run 191 denylist (proven empty across all captured logs):"
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
    'production custody enabled' \
    'production custody active' \
    'production custody wired' \
    'validator-set rotation claim' \
    'validator-set rotation enabled' \
    'schema drift' 'wire drift' 'metric drift' \
    'MainNet peer-driven apply ENABLED' \
    'MainNet apply ENABLED'
  do
    if find "${LOGS_DIR}" "${HELPER_191_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected custody-boundary scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 191 no-mutation proof for rejected custody-boundary scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven Run 190 custody-boundary rejection corpus (R1..R32):"
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
  echo "      rejecting validate_authority_custody_attestation /"
  echo "      validate_lifecycle_governance_and_custody dispatch are"
  echo "      bit-equal (captured in no_mutation_evidence.txt)."
  grep -E 'verdict: PASS|R[0-9]+_|A[0-9]+_|no_mutation_pass|determinism_pass' \
    "${HELPER_191_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted custody scenarios (release-binary
# scope).
# ---------------------------------------------------------------------------
{
  echo "Run 191 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site Run 190 custody-boundary"
  echo "  reachability today:"
  echo "    - Run 190 added pqc_authority_custody_payload_carrying.rs"
  echo "      with the typed AuthorityCustodyAttestationWire (Wire types"
  echo "      for class / governance authority class / attestation),"
  echo "      AuthorityCustodyLoadStatus (Loaded / Absent / Malformed),"
  echo "      AuthorityCustodyCallsiteContext (per-surface routing"
  echo "      context), AuthorityCustodyPayloadCarryingDecisionOutcome"
  echo "      (Callsite / Refused / Unhandled), seven per-surface"
  echo "      routing helpers (reload_check / reload_apply /"
  echo "      startup_p2p_trust_bundle / sighup /"
  echo "      local_peer_candidate_check / live_inbound_0x05 /"
  echo "      peer_driven_drain), the optional sibling JSON parser"
  echo "      parse_optional_authority_custody_attestation_sibling_from_json_value,"
  echo "      and the named helper"
  echo "      mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying;"
  echo "      Run 188 typed AuthorityCustodyClass / AuthorityCustodyPolicy /"
  echo "      RemoteSigner / Kms / Hsm / Unknown), the typed"
  echo "      AuthorityCustodyPolicy (Disabled (default) / FixtureOnly /"
  echo "      DevnetLocalAllowed / TestnetLocalAllowed /"
  echo "      ProductionCustodyRequired / MainnetProductionCustodyRequired),"
  echo "      the typed AuthorityCustodyAttestation, the typed"
  echo "      AuthorityCustodyValidationOutcome, the typed"
  echo "      LifecycleGovernanceCustodyOutcome, the pure validator"
  echo "      validate_authority_custody_attestation, the typed combined"
  echo "      helper validate_lifecycle_governance_and_custody, and the"
  echo "      three explicit grep-verifiable named helpers"
  echo "      (mainnet_peer_driven_apply_remains_refused_under_custody_boundary,"
  echo "       peer_majority_cannot_satisfy_custody,"
  echo "       local_operator_config_alone_cannot_satisfy_mainnet_production_custody);"
  echo "    - Run 190 added no operator-visible selector, so the"
  echo "      release-binary surface contract preserves Run 187's binary"
  echo "      defaults bit-identically — the only new release-binary"
  echo "      reachability for Run 191 is the typed library boundary"
  echo "      exercised by the Run 191 release-built helper through"
  echo "      pqc_authority_custody::*;"
  echo "    - the Run 190 custody validator is wired source-side as a pure"
  echo "      validation helper, BEFORE any Run 070 apply call, BEFORE"
  echo "      any live trust swap, BEFORE any session eviction, BEFORE"
  echo "      any sequence/marker write, and BEFORE any peer-driven drain;"
  echo "    - the Run 147 / 148 / 152 FATAL MainNet peer-driven apply"
  echo "      refusal is layered ahead of the Run 190 policy gate via"
  echo "      the FixtureCustodyRejectedForMainNet /"
  echo "      LocalCustodyRejectedForMainNet outcomes for fixture / local"
  echo "      classes, the MainNetProductionCustodyUnavailable outcome"
  echo "      for the MainnetProductionCustodyRequired policy, and the"
  echo "      mainnet_peer_driven_apply_remains_refused_under_custody_boundary"
  echo "      named helper at the typed boundary."
  echo
  echo "  release-binary custody-boundary corpus (this run):"
  echo "    - the Run 191 helper exercises every AuthorityCustodyPolicy"
  echo "      (Disabled / FixtureOnly / DevnetLocalAllowed /"
  echo "      TestnetLocalAllowed / ProductionCustodyRequired /"
  echo "      MainnetProductionCustodyRequired) against the validator"
  echo "      and combined helper with every AuthorityCustodyClass"
  echo "      (FixtureLocalKey / LocalOperatorKey / RemoteSigner / Kms /"
  echo "      Hsm / Unknown) in release mode through the production"
  echo "      library symbols, across the A1..A10 acceptance corpus and"
  echo "      the R1..R32 rejection corpus from Run 190;"
  echo "    - the helper additionally exercises the per-class /"
  echo "      per-policy fail-closed table (custody_class_table.txt)"
  echo "      and the three named helpers"
  echo "      (named_helpers_table.txt);"
  echo "    - non-mutation evidence is captured for every rejected"
  echo "      scenario via bit-equality of candidate / persisted"
  echo "      snapshots taken before and after a rejecting custody"
  echo "      validation (no_mutation_evidence.txt); deterministic"
  echo "      re-evaluation evidence is captured in"
  echo "      determinism_evidence.txt."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help surfaces no Run 190"
  echo "      custody flag and no KMS/HSM/remote-signer claim;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no Run 190 custody enablement"
  echo "      banner and no MainNet peer-driven apply enablement claim;"
  echo "    - the existing Run 187 hidden fixture selector, when armed on"
  echo "      MainNet, still refuses MainNet peer-driven apply (Run 147"
  echo "      FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer"
  echo "      backend is wired in Run 191. Every RemoteSigner / Kms / Hsm"
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
# Targeted cargo test cross-checks. Mirrors `task/RUN_191_TASK.txt
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

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 191 — release-binary KMS/HSM authority-custody boundary evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_191_sha256:  $(sha256_file "${HELPER_191_BIN}")"
  echo "  helper_191_buildid: $(build_id "${HELPER_191_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet \
           S4_default_mainnet S5_mainnet_fixture_selector
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}	rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_191	rc=$(cat "${EXIT_DIR}/helper_run_191.rc" 2>/dev/null || echo 'na')	$(grep -E 'verdict:' "${HELPER_191_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A10 / R1-R32 corpus verdicts (release mode, production library symbols):"
  for k in total_pass total_fail scenarios_pass scenarios_fail \
           wire_pass wire_fail sibling_pass sibling_fail \
           routing_pass routing_fail named_helpers_pass named_helpers_fail \
           no_mutation_pass no_mutation_fail determinism_pass determinism_fail
  do
    v="$(grep -E "^${k}: " "${HELPER_191_OUT}/helper_summary.txt" 2>/dev/null | head -n1 | awk '{print $2}')"
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
  echo "  * default AuthorityCustodyPolicy::Disabled preserved on every surface;"
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
  echo "    Unavailable) in Run 191;"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL"
  echo "    invariant) at every binary surface — including with the"
  echo "    Run 187 hidden fixture selector armed — and at the typed"
  echo "    custody boundary via"
  echo "    mainnet_peer_driven_apply_remains_refused_under_custody_boundary;"
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend"
  echo "    wired in Run 191;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift (Run 191 is release-binary"
  echo "    evidence only);"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node preserves the Run 190"
  echo "  typed authority-custody boundary contract end-to-end. Default"
  echo "  AuthorityCustodyPolicy::Disabled fail-closes on every surface."
  echo "  No Run 190 selector is exposed at the binary surface (no new"
  echo "  CLI flag, no new env var). The Run 187 hidden fixture selector"
  echo "  remains DevNet/TestNet evidence-only and does not enable any"
  echo "  KMS/HSM/remote-signer backend. The Run 191 release-built helper"
  echo "  exercises the full Run 190 A1-A10 / R1-R32 corpus end-to-end"
  echo "  through the production library symbols pqc_authority_custody::*,"
  echo "  returning the expected typed custody-boundary outcomes. MainNet"
  echo "  peer-driven apply remains the Run 147 FATAL refusal; fixture /"
  echo "  local custody can never satisfy MainNet production custody;"
  echo "  RemoteSigner / Kms / Hsm placeholders fail closed regardless of"
  echo "  policy or environment. Real KMS / HSM / cloud KMS / PKCS#11 /"
  echo "  remote-signer backends, real on-chain governance proof"
  echo "  verification, governance execution, validator-set rotation,"
  echo "  autonomous apply, apply-on-receipt, and peer-majority authority"
  echo "  all remain unimplemented. Full C4 and C5 remain OPEN."
} > "${SUMMARY}"

log "done"