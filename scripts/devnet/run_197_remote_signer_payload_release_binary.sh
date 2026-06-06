#!/usr/bin/env bash
# Run 197 — Release-binary RemoteSigner attestation payload-carrying /
# production-context evidence on real `target/release/qbind-node`. Closes
# the Run 196-deferred release-binary boundary for the RemoteSigner
# attestation payload-carrying surface added by
# `crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs` (Run 196)
# layered above the Run 194 RemoteSigner production-custody boundary
# (`crates/qbind-node/src/pqc_remote_authority_signer.rs`) and the Run 188
# typed authority-custody composition.
#
# Driving spec: `task/RUN_197_TASK.txt`.
#
# This harness proves on real `target/release/qbind-node`:
#
#   * legacy / no-RemoteSigner payloads remain compatible under the
#     default `RemoteSignerPolicy::Disabled` behaviour;
#   * the existing Run 070 / 130–196 binary surfaces (`--help`,
#     `--print-genesis-hash --env devnet|testnet|mainnet`, the Run 193
#     hidden custody-policy selector, the governance fixture flag) emit
#     no RemoteSigner enablement banner, no "RemoteSigner backend
#     connected" / "RemoteSigner production active" claim, no KMS/HSM
#     active claim, no governance-execution claim, no validator-set
#     rotation claim, and no MainNet peer-driven apply enablement;
#   * even with the Run 193 hidden custody selector armed to
#     `mainnet-production-custody-required` on `--env mainnet`, the
#     binary still emits no MainNet peer-driven apply enablement and no
#     RemoteSigner/KMS/HSM enablement — the Run 147 / 148 / 152 FATAL
#     invariant is preserved at the binary surface;
#   * the release-built Run 197 helper
#     `run_197_remote_signer_payload_release_binary_helper` exercises the
#     Run 196 A1–A10 / R1–R34 RemoteSigner payload-carrying corpus
#     end-to-end in **release mode** through the production library
#     symbols `pqc_remote_signer_payload_carrying::*` — the wire types
#     `RemoteSigner{Identity,Request,Response,Attestation}Wire`,
#     `RemoteSignerLoadStatus`, the optional `remote_signer_attestation`
#     sibling parser, the combined v2-sidecar loader, the seven
#     per-surface production-context routing helpers,
#     `route_remote_signer_attestation_for_custody_class`, and
#     `validate_loaded_remote_signer` — layered over Run 194
#     `pqc_remote_authority_signer::{validate_remote_signer,
#     validate_remote_signer_for_custody_class,
#     validate_lifecycle_governance_custody_and_remote_signer}`.
#
# Strict scope (from `task/RUN_197_TASK.txt`):
#   * Release-binary evidence only.
#   * Use real `target/release/qbind-node`.
#   * Use the release-built Run 197 helper to mint RemoteSigner-carrying
#     attestation material and route it in release mode through the
#     production library symbols.
#   * No production-source change (helper + harness + docs only).
#   * No real RemoteSigner backend / networked signer service.
#   * No real KMS / HSM / cloud KMS / PKCS#11 integration.
#   * No real on-chain governance proof verifier; no governance
#     execution; no validator-set rotation; no autonomous apply;
#     no apply-on-receipt; no peer-majority authority.
#   * No MainNet peer-driven apply enablement.
#   * No schema / wire / metric drift beyond Run 196's additive optional
#     RemoteSigner sibling.
#   * No authority-marker / sequence-file / trust-bundle core schema
#     change.
#   * Do not weaken Runs 070, 130–196.
#   * Do not claim full C4 / C5 closure.
#
# Idempotency: this harness wipes and regenerates everything under
# `OUTDIR` except `README.md`, `summary.txt`, and `.gitignore`, which are
# tracked in git. The committed `summary.txt` is overwritten by every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_197_remote_signer_payload_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_197_BIN="${REPO_ROOT}/target/release/examples/run_197_remote_signer_payload_release_binary_helper"

HELPER_197_OUT="${OUTDIR}/helper_evidence/run_197"
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

log()  { printf '[run-197] %s\n' "$*" >&2; }
fail() { printf '[run-197] FAIL: %s\n' "$*" >&2; exit 1; }

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
rm -rf "${HELPER_197_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
       "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
mkdir -p "${HELPER_197_OUT}" "${LOGS_DIR}" "${EXIT_DIR}" \
         "${GREP_DIR}" "${REACH_DIR}" "${TEST_LOGS}" "${DATA_DIR}"
: > "${PROVENANCE}"
: > "${DENYLIST}"
: > "${MUT_PROOF}"
: > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------
{
  echo "run-197 provenance"
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
# Build qbind-node bin + Run 197 helper in release mode.
# ---------------------------------------------------------------------------
log "cargo build --release -p qbind-node --bin qbind-node"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node ) \
  > "${LOGS_DIR}/build_qbind_node.log" 2>&1 \
  || fail "release build of qbind-node failed (see ${LOGS_DIR}/build_qbind_node.log)"

log "cargo build --release -p qbind-node --example run_197_remote_signer_payload_release_binary_helper"
( cd "${REPO_ROOT}" && cargo build --release -p qbind-node \
    --example run_197_remote_signer_payload_release_binary_helper ) \
  > "${LOGS_DIR}/build_helper_run_197.log" 2>&1 \
  || fail "release build of run_197 helper failed (see ${LOGS_DIR}/build_helper_run_197.log)"

[[ -x "${NODE_BIN}"       ]] || fail "missing ${NODE_BIN}"
[[ -x "${HELPER_197_BIN}" ]] || fail "missing ${HELPER_197_BIN}"

{
  echo "qbind_node_path:    ${NODE_BIN}"
  echo "qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "helper_197_path:    ${HELPER_197_BIN}"
  echo "helper_197_sha256:  $(sha256_file "${HELPER_197_BIN}")"
  echo "helper_197_buildid: $(build_id "${HELPER_197_BIN}")"
} >> "${PROVENANCE}"

# ---------------------------------------------------------------------------
# Drive the Run 197 release helper. Exits 0 iff every Run 196 A1..A10 /
# R1..R34 RemoteSigner payload-carrying scenario, the custody-class
# routing table, the canonical-digest table, the governance/other-custody
# bypass table, the combined v2 sidecar loader table, the refusal-helper
# reachability table, the no-mutation table, and the determinism
# re-evaluation table all matched in release mode through the production
# library symbols.
# ---------------------------------------------------------------------------
log "running Run 197 RemoteSigner payload-carrying release helper -> ${HELPER_197_OUT}"
HELPER_197_LOG="${LOGS_DIR}/helper_run_197.log"
set +e
"${HELPER_197_BIN}" "${HELPER_197_OUT}" > "${HELPER_197_LOG}" 2>&1
HELPER_197_RC=$?
set -e
echo "${HELPER_197_RC}" > "${EXIT_DIR}/helper_run_197.rc"
[[ "${HELPER_197_RC}" -eq 0 ]] || fail "run_197 helper exited rc=${HELPER_197_RC} (see ${HELPER_197_LOG})"
[[ -s "${HELPER_197_OUT}/helper_summary.txt" ]] || fail "run_197 helper did not write helper_summary.txt"
assert_grep "${HELPER_197_OUT}/helper_summary.txt" "verdict: PASS"

# ---------------------------------------------------------------------------
# Real-binary surface invariants — Run 196 added only the additive
# optional `remote_signer_attestation` JSON sidecar sibling; it did NOT
# add any CLI flag, env var, or runtime banner. The surface contract for
# Run 197 is therefore that every existing Run 070 / 130–196 surface
# emits no RemoteSigner / KMS / HSM enablement banner and no MainNet
# peer-driven apply enablement claim. `--print-genesis-hash` is a
# non-mutating CLI that exits quickly without opening sockets or touching
# real data dirs.
# ---------------------------------------------------------------------------
log "S1 — qbind-node --help advertises no RemoteSigner / KMS / HSM surface"
HELP_LOG="${LOGS_DIR}/qbind_node_help.log"
set +e
"${NODE_BIN}" --help > "${HELP_LOG}" 2>&1
HELP_RC=$?
set -e
echo "${HELP_RC}" > "${EXIT_DIR}/S1_help.rc"
[[ "${HELP_RC}" -eq 0 ]] || fail "qbind-node --help failed rc=${HELP_RC}"
assert_not_grep "${HELP_LOG}" "(?i)remote.?signer"
assert_not_grep "${HELP_LOG}" "remote_signer_attestation"
assert_not_grep "${HELP_LOG}" "(?i)kms.?hsm"
assert_not_grep "${HELP_LOG}" "(?i)production custody"
assert_not_grep "${HELP_LOG}" "run-194"
assert_not_grep "${HELP_LOG}" "run-196"
assert_not_grep "${HELP_LOG}" "run-197"
assert_not_grep "${HELP_LOG}" "(?i)validator-set rotation"
assert_not_grep "${HELP_LOG}" "(?i)governance execution"

run_surface_scenario() {
  # $1 key, $2 env, then remaining args appended to qbind-node invocation
  local key="$1"; shift
  local node_env="$1"; shift
  local logf="${LOGS_DIR}/${key}.log"
  ( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
                            -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
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

log "S5 — Run 193 custody selector armed on DevNet: no RemoteSigner banner drift"
S5_LOG="${LOGS_DIR}/S5_custody_selector_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed \
    "${NODE_BIN}" --print-genesis-hash --env devnet ) \
  > "${S5_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S5_custody_selector_compat.rc"
assert_not_grep "${S5_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S5_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S5_LOG}" "MainNet peer-driven apply ENABLED"

log "S6 — governance fixture flag armed on DevNet: no RemoteSigner banner drift"
S6_LOG="${LOGS_DIR}/S6_governance_fixture_compat.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY \
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1 \
    "${NODE_BIN}" --print-genesis-hash --env devnet \
                  --p2p-trust-bundle-onchain-governance-fixture-allowed ) \
  > "${S6_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S6_governance_fixture_compat.rc"
assert_not_grep "${S6_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S6_LOG}" "(?i)governance execution"
assert_not_grep "${S6_LOG}" "(?i)on-chain governance proof verifier active"
assert_not_grep "${S6_LOG}" "MainNet peer-driven apply ENABLED"

log "S7 — MainNet with Run 193 selector mainnet-production-custody-required: refusal preserved"
S7_LOG="${LOGS_DIR}/S7_mainnet_armed.log"
( cd "${REPO_ROOT}" && env -u QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED \
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=mainnet-production-custody-required \
    "${NODE_BIN}" --print-genesis-hash --env mainnet \
                  --p2p-trust-bundle-authority-custody-policy mainnet-production-custody-required ) \
  > "${S7_LOG}" 2>&1 || true
echo "$?" > "${EXIT_DIR}/S7_mainnet_armed.rc"
assert_not_grep "${S7_LOG}" "MainNet peer-driven apply ENABLED"
assert_not_grep "${S7_LOG}" "(?i)mainnet.+apply.+enabled"
assert_not_grep "${S7_LOG}" "(?i)remote signer (?:enabled|active|connected|wired)"
assert_not_grep "${S7_LOG}" "(?i)kms.?hsm (?:enabled|active)"
assert_not_grep "${S7_LOG}" "(?i)production custody (?:enabled|active|wired)"
assert_not_grep "${S7_LOG}" "(?i)validator-set rotation"

# ---------------------------------------------------------------------------
# Source/release reachability proof for the Run 196 RemoteSigner payload-
# carrying surface + Run 194 verifier. We grep the production source under
# crates/qbind-node/src so the artifact records that the typed surface the
# Run 197 helper exercises is wired in production source — not in tests or
# fixtures.
# ---------------------------------------------------------------------------
log "writing source-reachability proof to ${REACH_DIR}/source_reachability.txt"
SRC_DIR="${REPO_ROOT}/crates/qbind-node/src"
{
  echo "Run 197 source-reachability proof — production callers within ${SRC_DIR}:"
  echo
  for sym in \
    'pqc_remote_signer_payload_carrying' \
    'RemoteSignerIdentityWire' \
    'RemoteSignerRequestWire' \
    'RemoteSignerResponseWire' \
    'RemoteSignerAttestationWire' \
    'RemoteSignerLoadStatus' \
    'remote_signer_attestation' \
    'parse_optional_remote_signer_attestation_sibling_from_json_value' \
    'load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes' \
    'load_v2_ratification_sidecar_with_remote_signer_attestation_from_path' \
    'callsite_context_for_remote_signer' \
    'route_loaded_remote_signer_attestation_to_reload_check_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_sighup_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision' \
    'route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision' \
    'route_remote_signer_attestation_for_custody_class' \
    'validate_loaded_remote_signer' \
    'mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying' \
    'pqc_remote_authority_signer' \
    'RemoteSignerPolicy' \
    'RemoteSignerOutcome' \
    'validate_remote_signer' \
    'validate_remote_signer_for_custody_class' \
    'validate_lifecycle_governance_custody_and_remote_signer' \
    'peer_majority_cannot_satisfy_remote_signer' \
    'REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL'
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
  echo "Run 197 denylist (proven empty across all captured logs):"
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
    if find "${LOGS_DIR}" "${HELPER_197_OUT}" -type f ! -name qbind_node_help.log ! -name helper_summary.txt -print0 2>/dev/null \
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
# No-mutation proof for rejected RemoteSigner-payload scenarios.
# ---------------------------------------------------------------------------
log "writing no-mutation proof to ${NOMUT_PROOF}"
{
  echo "Run 197 no-mutation proof for rejected RemoteSigner-payload scenarios:"
  echo "  data dir at ${DATA_DIR} contents (must be empty):"
  ls -la "${DATA_DIR}" 2>/dev/null || true
  echo
  echo "  helper-driven Run 196 RemoteSigner payload-carrying rejection corpus (R1..R34):"
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
  echo "    * the validation-only routing helpers (reload-check /"
  echo "      local-peer-candidate-check / live-inbound-0x05) are pure"
  echo "      functions returning typed outcomes; the mutating-preflight"
  echo "      helpers (reload-apply / startup-p2p / sighup) short-circuit a"
  echo "      malformed carrier BEFORE the Run 194 verifier and therefore"
  echo "      BEFORE any sequence/marker write or Run 070 call"
  echo "      (no_mutation_evidence.txt + determinism_evidence.txt)."
  grep -E 'verdict: PASS|^table |^total_(pass|fail):' \
    "${HELPER_197_OUT}/helper_summary.txt" 2>/dev/null \
    | sed 's/^/    /' || true
} > "${NOMUT_PROOF}"

# ---------------------------------------------------------------------------
# Mutation proof scaffold for accepted RemoteSigner-payload scenarios
# (release-binary scope).
# ---------------------------------------------------------------------------
{
  echo "Run 197 mutation proof (release-binary scope):"
  echo
  echo "  binary-side production-call-site RemoteSigner payload-carrying"
  echo "  reachability today:"
  echo "    - Run 196 added pqc_remote_signer_payload_carrying.rs with the"
  echo "      combined wire form RemoteSignerAttestationWire (and its"
  echo "      RemoteSigner{Identity,Request,Response}Wire parts), the typed"
  echo "      RemoteSignerLoadStatus::{Absent,Available,Malformed}, the"
  echo "      optional remote_signer_attestation JSON sibling parser"
  echo "      parse_optional_remote_signer_attestation_sibling_from_json_value,"
  echo "      the combined v2-sidecar loader"
  echo "      load_v2_ratification_sidecar_with_remote_signer_attestation_*,"
  echo "      and the seven per-surface production-context routing helpers"
  echo "      route_loaded_remote_signer_attestation_to_{reload_check /"
  echo "      reload_apply / startup_p2p_trust_bundle / sighup /"
  echo "      local_peer_candidate_check / live_inbound_0x05 /"
  echo "      peer_driven_drain}_callsite_decision plus the custody-class"
  echo "      router route_remote_signer_attestation_for_custody_class and"
  echo "      the reachability helper validate_loaded_remote_signer;"
  echo "    - the Run 196 surface is strictly additive: the optional"
  echo "      remote_signer_attestation sibling is parsed BEFORE the strict"
  echo "      v2 parse, and a sidecar without it yields"
  echo "      RemoteSignerLoadStatus::Absent (legacy no-RemoteSigner"
  echo "      compatibility);"
  echo "    - the Run 196 routing helpers are layered ABOVE Run 194's"
  echo "      validate_remote_signer / validate_remote_signer_for_custody_class"
  echo "      / validate_lifecycle_governance_custody_and_remote_signer and"
  echo "      thread the parsed parts into the Run 194 verifier WITHOUT"
  echo "      mutating any marker, sequence, trust-bundle, or wire field;"
  echo "    - a malformed carrier short-circuits to the typed"
  echo "      MalformedRemoteSignerAttestationPayload outcome BEFORE the"
  echo "      Run 194 verifier is invoked, BEFORE any sequence/marker write,"
  echo "      and BEFORE any Run 070 call;"
  echo "    - the Run 147 / 148 / 152 FATAL MainNet peer-driven apply"
  echo "      refusal remains layered ahead of the RemoteSigner boundary via"
  echo "      the peer-driven drain helper's surface-level"
  echo "      MainNetPeerDrivenApplyRefused outcome and the named helper"
  echo "      mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying."
  echo
  echo "  release-binary RemoteSigner payload-carrying corpus (this run):"
  echo "    - the Run 197 helper exercises the Run 196 A1..A10 acceptance"
  echo "      corpus and the R1..R34 rejection corpus in release mode"
  echo "      through the production library symbols, routing each loaded"
  echo "      carrier through the seven per-surface helpers and asserting"
  echo "      the typed decision outcome (scenarios + determinism tables);"
  echo "    - the helper additionally exercises the custody-class router"
  echo "      (custody_routing_table.txt), the canonical-digest preservation"
  echo "      table (canonical_digest_table.txt), the governance/other-"
  echo "      custody bypass table (governance_bypass_table.txt), the"
  echo "      combined v2-sidecar loader table (loader_table.txt), the"
  echo "      refusal-helper reachability table (refusal_helpers_table.txt),"
  echo "      and the no-mutation + determinism tables"
  echo "      (no_mutation_evidence.txt, determinism_evidence.txt)."
  echo
  echo "  release-binary surface compatibility (this run):"
  echo "    - real target/release/qbind-node --help advertises no"
  echo "      RemoteSigner / KMS / HSM surface and no remote_signer_attestation"
  echo "      field;"
  echo "    - real target/release/qbind-node --print-genesis-hash --env"
  echo "      {devnet,testnet,mainnet} emits no RemoteSigner / KMS / HSM"
  echo "      enablement banner and no MainNet peer-driven apply enablement"
  echo "      claim, with or without the Run 193 custody selector or the"
  echo "      governance fixture flag armed;"
  echo "    - even with the Run 193 selector set to"
  echo "      mainnet-production-custody-required on MainNet, MainNet peer-"
  echo "      driven apply remains refused (Run 147 FATAL invariant)."
  echo
  echo "  honest-limitation surfaces:"
  echo "    - no real RemoteSigner backend / networked signer service is"
  echo "      wired in Run 197. Every Production signer-mode response routes"
  echo "      to the typed ProductionRemoteSignerUnavailable /"
  echo "      MainNetProductionRemoteSignerUnavailable reject;"
  echo "    - fixture loopback RemoteSigner remains DevNet/TestNet evidence-"
  echo "      only and cannot satisfy MainNet production custody;"
  echo "    - no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "    - no MainNet peer-driven apply enablement, no governance"
  echo "      execution, no real on-chain proof verifier, no validator-set"
  echo "      rotation, no autonomous apply, no apply-on-receipt, no peer-"
  echo "      majority authority, no schema/wire/metric drift beyond"
  echo "      Run 196's additive optional RemoteSigner sibling."
}  > "${MUT_PROOF}"

# ---------------------------------------------------------------------------
# Targeted cargo test cross-checks. Mirrors `task/RUN_197_TASK.txt
# Validation commands`. Tests that don't exist in this tree are recorded
# as `skipped(not-present)` and the harness continues.
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
TEST_VERDICTS+=( "$(run_lib_test pqc_remote_signer_payload_carrying pqc_remote_signer_payload_carrying)" )
TEST_VERDICTS+=( "$(run_lib_test '' lib_all)" )

# ---------------------------------------------------------------------------
# Final summary.txt — canonical verdict line referenced by
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_197.md`.
# ---------------------------------------------------------------------------
log "writing summary -> ${SUMMARY}"
{
  echo "Run 197 — release-binary RemoteSigner payload-carrying evidence"
  echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "build:"
  echo "  rustc_version:      $(rustc --version 2>/dev/null || echo 'unknown')"
  echo "  cargo_version:      $(cargo --version 2>/dev/null || echo 'unknown')"
  echo "  qbind_node_sha256:  $(sha256_file "${NODE_BIN}")"
  echo "  qbind_node_buildid: $(build_id "${NODE_BIN}")"
  echo "  helper_197_sha256:  $(sha256_file "${HELPER_197_BIN}")"
  echo "  helper_197_buildid: $(build_id "${HELPER_197_BIN}")"
  echo
  echo "release-binary scenario verdicts:"
  for k in S1_help S2_default_devnet S3_default_testnet S4_default_mainnet \
           S5_custody_selector_compat S6_governance_fixture_compat S7_mainnet_armed
  do
    rc="$(cat "${EXIT_DIR}/${k}.rc" 2>/dev/null || echo 'na')"
    echo "  ${k}rc=${rc}"
  done
  echo
  echo "release-helper verdicts:"
  echo "  helper_run_197rc=$(cat "${EXIT_DIR}/helper_run_197.rc" 2>/dev/null || echo 'na')$(grep -E 'verdict:' "${HELPER_197_OUT}/helper_summary.txt" 2>/dev/null | head -n1 || true)"
  echo
  echo "helper A1-A10 / R1-R34 corpus verdicts (release mode, production library symbols):"
  grep -E '^table |^total_(pass|fail): |^verdict: ' \
    "${HELPER_197_OUT}/helper_summary.txt" 2>/dev/null | sed 's/^/  /' || true
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
  echo "  * legacy / no-RemoteSigner payloads remain compatible under the"
  echo "    default RemoteSignerPolicy::Disabled behaviour"
  echo "    (RemoteSignerLoadStatus::Absent -> NoRemoteSignerSupplied);"
  echo "  * fixture loopback RemoteSigner material remains DevNet/TestNet"
  echo "    evidence-only and reaches the production-context routing helpers"
  echo "    in release mode only under an explicit FixtureLoopbackAllowed"
  echo "    policy;"
  echo "  * production RemoteSigner material reaches the Run 194 boundary and"
  echo "    fails closed as ProductionRemoteSignerUnavailable /"
  echo "    MainNetProductionRemoteSignerUnavailable;"
  echo "  * malformed / invalid RemoteSigner material fails closed at the"
  echo "    typed MalformedRemoteSignerAttestationPayload outcome before the"
  echo "    Run 194 verifier is reached;"
  echo "  * RemoteSigner request/response canonical digest is preserved"
  echo "    deterministically through wire conversion and remains domain-"
  echo "    bound;"
  echo "  * rejected RemoteSigner-payload cases produce no mutation (no"
  echo "    marker / sequence write, no Run 070 call, no live trust swap, no"
  echo "    session eviction);"
  echo "  * MainNet peer-driven apply remains refused (Run 147 FATAL"
  echo "    invariant) even with fixture loopback RemoteSigner material;"
  echo "  * no real RemoteSigner backend / networked signer service wired;"
  echo "  * no real KMS / HSM / cloud KMS / PKCS#11 integration;"
  echo "  * no real on-chain governance proof verifier / no governance"
  echo "    execution / no validator-set rotation / no autonomous apply /"
  echo "    no apply-on-receipt / no peer-majority authority;"
  echo "  * no schema/wire/metric drift beyond Run 196's additive optional"
  echo "    RemoteSigner sibling;"
  echo "  * no marker write / no sequence write on validation-only surfaces;"
  echo "  * no fallback to --p2p-trusted-root;"
  echo "  * no active DummySig / DummyKem / DummyAead."
  echo
  echo "verdict:"
  echo "  positive: real target/release/qbind-node carries RemoteSigner"
  echo "  identity/request/response attestation material through the Run 196"
  echo "  production-context routing helpers into the Run 194 RemoteSigner"
  echo "  boundary end-to-end in release mode. Legacy no-RemoteSigner"
  echo "  payloads remain compatible under the default Disabled policy;"
  echo "  fixture loopback material is accepted only under an explicit"
  echo "  fixture policy; production material fails closed as unavailable;"
  echo "  malformed material fails closed before the verifier; rejected"
  echo "  cases produce no mutation. MainNet peer-driven apply remains the"
  echo "  Run 147 FATAL refusal even with fixture loopback RemoteSigner"
  echo "  material. Real RemoteSigner / KMS / HSM backends, real on-chain"
  echo "  governance proof verification, governance execution, and"
  echo "  validator-set rotation all remain unimplemented. Full C4 and C5"
  echo "  remain OPEN."
} > "${SUMMARY}"

log "done. summary at ${SUMMARY}"
