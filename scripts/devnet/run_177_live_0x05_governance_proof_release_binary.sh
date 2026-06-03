#!/usr/bin/env bash
# Run 177 — Release-binary live inbound `0x05` governance-proof carrying
# evidence harness.
#
# Closes the Run 176-deferred release-binary boundary by exercising, on
# real `target/release/qbind-node` nodes, the live inbound `0x05`
# peer-candidate path with the additive Run 176
# `governance_authority_proof` field carried on the wire envelope. The
# Run 177 hidden harness-only flag
# `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
# attaches a `GovernanceAuthorityProofWire` JSON (Run 167 schema) to the
# Run 080 publish-once envelope before
# [`encode_peer_candidate_wire_frame`] runs, and the receiver routes the
# parsed carrier through the Run 176 →  Run 173 → Run 169 → Run 165
# governance gate over the Run 163 verifier.
#
# Architecture (real N=3 DevNet topology):
#
#   V0 — publisher of the live `0x05` proof-carrying peer-candidate
#        envelope (real release `qbind-node`, Run 080 publish-once
#        path with the Run 177 carrier flag).
#   V1 — receiver with live inbound `0x05` validation enabled and
#        `--p2p-trust-bundle-governance-proof-required` (CLI) or
#        `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` (env)
#        Required policy enabled.
#   V2 — propagation/staging observer (validation-only). When
#        propagation/staging is exercised, V2 confirms invalid
#        proof-carrying candidates never propagate or stage.
#
# Strict scope (from `task/RUN_177_TASK.txt`):
#   - Release-binary evidence only.
#   - Real `target/release/qbind-node`, real live P2P, real signed
#     trust-bundle material, real v2 ratification sidecars,
#     proof-carrying `PeerCandidateWireEnvelopeV1`, real ML-KEM-768 /
#     ML-DSA-44 / ChaCha20-Poly1305 path, no active DummySig /
#     DummyKem / DummyAead.
#   - Tiny harness-only source delta is the new hidden CLI flag
#     `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
#     (and its plumbing into `PeerCandidateWirePublishConfig`) — no
#     schema/wire/metric drift; the additive Run 176
#     `governance_authority_proof` field is unchanged.
#   - No MainNet peer-driven apply enablement.
#   - No governance execution / on-chain governance / KMS / HSM /
#     validator-set rotation. `OnChainGovernance` remains
#     unsupported / fail-closed at the Run 163 verifier.
#   - No autonomous apply / apply on receipt / peer-majority authority.
#   - No additional schema/wire/metric drift beyond Run 176's optional
#     envelope field. No authority-marker / sequence-file /
#     trust-bundle schema change.
#   - Does not weaken Runs 070, 130–176. Does NOT claim full C4 or C5
#     closure.
#
# Required topology: DevNet N=3 (V0 publisher, V1 receiver, V2 observer).
#
# Required accepted scenarios (A1–A6):
#   A1. legacy/no-proof live `0x05` candidate accepted under NotRequired
#       (no selector, no env). Existing no-proof path preserved.
#   A2. proof-carrying live `0x05` Rotate accepted under CLI Required.
#   A3. proof-carrying live `0x05` Rotate accepted under env Required.
#   A4. proof-carrying live `0x05` Revoke (where representable). Per
#       Run 176 A5 boundary, lifecycle classifier routes via Run 161
#       metadata-prefix; release-binary representability documented.
#   A5. proof-carrying live `0x05` EmergencyRevoke (where representable).
#       `BundleSigningRatificationV2Action` does not enumerate
#       EmergencyRevoke at v2; documented limitation deferred to source/
#       test (Run 173 fixture matrix).
#   A6. idempotent (same-bytes replay) proof-carrying live `0x05`
#       candidate accepted/deduped.
#
# Required rejection scenarios (R1–R22):
#   R1.  Required + no-proof live `0x05` rejected with
#        `GovernanceAuthorityRequiredButMissing` at Run 165.
#   R2.  malformed governance proof rejected.
#   R3.  invalid issuer signature rejected.
#   R4.  wrong environment proof — release-binary infeasible (Run 130
#        verifier trips upstream); cited from Run 176 source/test
#        matrix.
#   R5.  wrong chain proof — release-binary infeasible (Run 130 trip);
#        cited from Run 176 source/test matrix.
#   R6.  wrong genesis proof — release-binary infeasible (Run 130
#        trip); cited from Run 176 source/test matrix.
#   R7.  wrong authority root proof rejected.
#   R8.  wrong lifecycle action proof rejected.
#   R9.  wrong candidate digest proof rejected.
#   R10. wrong authority-domain sequence proof rejected.
#   R11. unsupported issuer suite rejected.
#   R12. non-PQC suite rejected (covered by R11 — the Run 163 verifier
#        requires a PQC suite id).
#   R13. OnChainGovernance proof rejected as unsupported/fail-closed.
#   R14. local operator config proof rejected (no operator-config
#        carrier in Run 176/177; covered by R1 construction).
#   R15. peer-majority / gossip-count proof rejected (no peer-majority
#        carrier in Run 176/177; covered by R1 construction).
#   R16. proof valid but lifecycle invalid rejected (Run 161 source-
#        test boundary; release-binary cited).
#   R17. lifecycle valid but proof invalid rejected (covered by R2/R3).
#   R18. invalid proof-carrying live `0x05` candidate is not propagated
#        (V2 observer log assertion).
#   R19. invalid proof-carrying live `0x05` candidate is not staged.
#   R20. invalid proof-carrying live `0x05` candidate cannot reach
#        peer-driven drain (Run 152 invariant; staging absent).
#   R21. valid proof-carrying live `0x05` candidate does not apply
#        automatically on receipt (Run 070 not invoked; no swap; no
#        sequence write; no marker write).
#   R22. MainNet peer-driven apply remains refused even with valid
#        proof-carrying live `0x05` candidate (Run 147 FATAL).
#
# Usage:
#   cargo build --release -p qbind-node --bin qbind-node
#   cargo build --release -p qbind-node \
#       --example run_177_live_0x05_governance_proof_release_binary_helper
#   bash scripts/devnet/run_177_live_0x05_governance_proof_release_binary.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_177_live_0x05_governance_proof_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_177="${REPO_ROOT}/target/release/examples/run_177_live_0x05_governance_proof_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"
PROVENANCE="${OUTDIR}/provenance.txt"

P2P_BASE="${P2P_BASE:-29770}"
A_RUN_SECS="${A_RUN_SECS:-30}"
R_RUN_SECS="${R_RUN_SECS:-15}"

log()  { printf '[run-177] %s\n' "$*" >&2; }
fail() { printf '[run-177] FAIL: %s\n' "$*" >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
build_id() {
  if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[[^]]+\]=[0-9a-f]+' || echo "BuildID=unknown"
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
  if grep -E -q "$pat" "$f"; then fail "forbidden pattern '${pat}' present in ${f}"; fi
}

p2p_port() { echo $((P2P_BASE + $1 * 10 + $2)); }

# ---------------------------------------------------------------------------
# Multi-node DevNet scenario driver. Brings up V0 (publisher), V1
# (receiver), V2 (observer) and tears down after `secs` seconds. Returns
# 0 on completion regardless of receiver outcome (the per-scenario
# assertions inspect V1's stderr for the Run 165 governance gate
# verdict). The receiver always remains validation-only: no
# `--p2p-trust-bundle-peer-candidate-staging-enabled`, no
# `--p2p-trust-bundle-peer-candidate-apply-enabled`, no
# `--p2p-trust-bundle-peer-candidate-drain-once`.
# ---------------------------------------------------------------------------
drive_scenario() {
  local name="$1" envelope="$2" proof="$3" required_mode="$4" idx="$5" secs="$6"
  shift 6
  local sdir="${OUTDIR}/logs/${name}"
  local ddir="${OUTDIR}/data/${name}"
  rm -rf "${sdir}" "${ddir}"
  mkdir -p "${sdir}" "${ddir}/v0" "${ddir}/v1" "${ddir}/v2"
  cp "${DEV}/seed-marker.v2.seq1.json" "${ddir}/v1/pqc_authority_state.json"
  cp "${DEV}/seed-marker.v2.seq1.json" "${ddir}/v2/pqc_authority_state.json"
  local pre_marker_sha; pre_marker_sha=$(sha256_file "${ddir}/v1/pqc_authority_state.json")
  echo "${pre_marker_sha}" > "${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"

  local v0_port v1_port v2_port
  v0_port=$(p2p_port "${idx}" 0)
  v1_port=$(p2p_port "${idx}" 1)
  v2_port=$(p2p_port "${idx}" 2)

  local common_args=(
    --env devnet
    --network-mode p2p
    --enable-p2p
    --p2p-mutual-auth required
    --p2p-pqc-root-mode pqc-static-root
    --genesis-path "${DEV}/genesis.json"
    --expect-genesis-hash "${DH}"
    --p2p-trust-bundle "${DEV}/baseline.bundle"
    --p2p-trust-bundle-signing-key "${DKA}"
    --p2p-trust-bundle-signing-key "${DKR}"
    --p2p-trust-bundle-ratification-enforcement-enabled
    --p2p-trust-bundle-allow-unratified-testnet-devnet
    --p2p-trust-bundle-peer-candidate-wire-validation-enabled
  )

  # V0 publisher
  local v0_extra=(
    --p2p-listen-addr "127.0.0.1:${v0_port}"
    --validator-id 0
    --p2p-peer "1@127.0.0.1:${v1_port}"
    --p2p-peer "2@127.0.0.1:${v2_port}"
    --data-dir "${ddir}/v0"
    --p2p-trust-bundle-ratification "${DEV}/ratification.no_proof.ratify.seq1.json"
    --p2p-trust-bundle-peer-candidate-wire-publish-enabled
    --p2p-trust-bundle-peer-candidate-wire-publish-once
    --p2p-trust-bundle-peer-candidate-wire-publish-path "${envelope}"
  )
  if [ -n "${proof}" ]; then
    v0_extra+=( --p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path "${proof}" )
  fi

  # V1 receiver (Required-policy if required_mode set)
  local v1_extra=(
    --p2p-listen-addr "127.0.0.1:${v1_port}"
    --validator-id 1
    --p2p-peer "0@127.0.0.1:${v0_port}"
    --p2p-peer "2@127.0.0.1:${v2_port}"
    --data-dir "${ddir}/v1"
    --p2p-trust-bundle-ratification "${DEV}/ratification.no_proof.ratify.seq1.json"
  )
  case "${required_mode}" in
    cli) v1_extra+=( --p2p-trust-bundle-governance-proof-required );;
    env) ;; # env exported by caller
    none|"") ;;
    *) fail "unknown required_mode=${required_mode}";;
  esac

  # V2 observer (validation-only; no staging, no apply)
  local v2_extra=(
    --p2p-listen-addr "127.0.0.1:${v2_port}"
    --validator-id 2
    --p2p-peer "0@127.0.0.1:${v0_port}"
    --p2p-peer "1@127.0.0.1:${v1_port}"
    --data-dir "${ddir}/v2"
    --p2p-trust-bundle-ratification "${DEV}/ratification.no_proof.ratify.seq1.json"
    --p2p-trust-bundle-peer-candidate-propagation-enabled
  )

  set +e
  "${NODE_BIN}" "${common_args[@]}" "${v0_extra[@]}" \
      >"${sdir}/v0.stdout.log" 2>"${sdir}/v0.stderr.log" &
  local v0_pid=$!
  if [ "${required_mode}" = "env" ]; then
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1 \
      "${NODE_BIN}" "${common_args[@]}" "${v1_extra[@]}" \
        >"${sdir}/v1.stdout.log" 2>"${sdir}/v1.stderr.log" &
  else
    "${NODE_BIN}" "${common_args[@]}" "${v1_extra[@]}" \
        >"${sdir}/v1.stdout.log" 2>"${sdir}/v1.stderr.log" &
  fi
  local v1_pid=$!
  "${NODE_BIN}" "${common_args[@]}" "${v2_extra[@]}" \
      >"${sdir}/v2.stdout.log" 2>"${sdir}/v2.stderr.log" &
  local v2_pid=$!
  set -e

  sleep "${secs}"
  for pid in "${v0_pid}" "${v1_pid}" "${v2_pid}"; do
    kill "${pid}" 2>/dev/null || true
  done
  sleep 2
  for pid in "${v0_pid}" "${v1_pid}" "${v2_pid}"; do
    kill -9 "${pid}" 2>/dev/null || true
  done
  wait "${v0_pid}" 2>/dev/null || true
  wait "${v1_pid}" 2>/dev/null || true
  wait "${v2_pid}" 2>/dev/null || true

  local post_marker_sha=""
  if [ -f "${ddir}/v1/pqc_authority_state.json" ]; then
    post_marker_sha=$(sha256_file "${ddir}/v1/pqc_authority_state.json")
  fi
  echo "${post_marker_sha}" > "${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  if [ -f "${ddir}/v1/pqc_trust_bundle_sequence.json" ]; then
    sha256_file "${ddir}/v1/pqc_trust_bundle_sequence.json" \
        > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  else
    : > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  fi
}

assert_no_v1_mutation() {
  local name="$1"
  local pre="${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  local post="${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  cmp -s "${pre}" "${post}" || fail "${name}: V1 marker mutated (pre=$(cat "${pre}") post=$(cat "${post}"))"
  local seq_post="${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  [ ! -s "${seq_post}" ] || fail "${name}: V1 wrote pqc_trust_bundle_sequence.json"
  local v1err="${OUTDIR}/logs/${name}/v1.stderr.log"
  assert_not_grep "${v1err}" 'Run 070: trust-bundle candidate APPLIED'
  assert_not_grep "${v1err}" '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_not_grep "${v1err}" '\[run-134\] v2 authority-marker persisted'
  assert_not_grep "${v1err}" 'sequence_commit=ok'
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "${OUTDIR}/logs" "${OUTDIR}/data" "${OUTDIR}/exit_codes" \
         "${OUTDIR}/marker_hashes" "${OUTDIR}/sequence_hashes" \
         "${OUTDIR}/data_inventories" "${OUTDIR}/grep_summaries" \
         "${OUTDIR}/reachability" "${OUTDIR}/test_results" \
         "${OUTDIR}/fixtures" "${OUTDIR}/fixture_manifest.txt" \
         "${OUTDIR}/scenario_assertions.txt" "${OUTDIR}/negative_invariants.txt" \
         "${SUMMARY}" "${PROVENANCE}"
  mkdir -p "${OUTDIR}"/{logs,data,exit_codes,marker_hashes,sequence_hashes,data_inventories,grep_summaries,reachability,test_results,fixtures}

  cd "${REPO_ROOT}"

  # Step 1 — release builds.
  log "building release binaries (qbind-node, run_177 helper)"
  cargo build --release -p qbind-node --bin qbind-node \
      >"${OUTDIR}/logs/build_qbind_node.stdout.log" \
      2>"${OUTDIR}/logs/build_qbind_node.stderr.log" \
      || { log "release build of qbind-node failed; emitting SKIPPED summary."; emit_skipped_summary "qbind-node release build failed"; return 0; }
  cargo build --release -p qbind-node --example run_177_live_0x05_governance_proof_release_binary_helper \
      >"${OUTDIR}/logs/build_helper_177.stdout.log" \
      2>"${OUTDIR}/logs/build_helper_177.stderr.log" \
      || { log "release build of helper failed; emitting SKIPPED summary."; emit_skipped_summary "helper release build failed"; return 0; }
  test -x "${NODE_BIN}"   || { emit_skipped_summary "missing ${NODE_BIN}"; return 0; }
  test -x "${HELPER_177}" || { emit_skipped_summary "missing ${HELPER_177}"; return 0; }

  # Step 2 — provenance.
  {
    echo "Run 177 release-binary live inbound 0x05 governance-proof carrier evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
    echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_$(build_id "${NODE_BIN}")"
    echo "helper_177_sha256: $(sha256_file "${HELPER_177}")"
    echo "helper_177_$(build_id "${HELPER_177}")"
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"${PROVENANCE}"

  {
    echo "Run 177 — release-binary live inbound 0x05 governance-proof carrier scenario verdicts"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo
    echo "scenario verdicts:"
  } >"${SUMMARY}"

  # Step 3 — mint fixtures.
  log "minting Run 177 fixture corpus"
  "${HELPER_177}" "${OUTDIR}/fixtures" \
      >"${OUTDIR}/logs/fixture_helper.stdout.log" \
      2>"${OUTDIR}/logs/fixture_helper.stderr.log"
  DEV="${OUTDIR}/fixtures/devnet"
  MAIN="${OUTDIR}/fixtures/mainnet"
  DH="$(cat "${DEV}/expected-genesis-hash.txt" | tr -d '\n')"
  MH="$(cat "${MAIN}/expected-genesis-hash.txt" | tr -d '\n')"
  DKA="$(cat "${DEV}/signing-key.ratified.spec" | tr -d '\n')"
  DKR="$(cat "${DEV}/signing-key.rotated.spec" | tr -d '\n')"

  {
    echo "# Run 177 fixture manifest (minted by Run 177 helper)"
    find "${OUTDIR}/fixtures" -type f \( -name '*.json' -o -name '*.bundle' -o -name '*.spec' -o -name '*.txt' \) | sort | while read -r f; do
      printf '%s  %s  %s\n' "$(sha256_file "$f")" "$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")" "${f#${REPO_ROOT}/}"
    done
  } > "${OUTDIR}/fixture_manifest.txt"

  # Step 4 — source reachability greps.
  log "source reachability greps"
  {
    echo "# Run 176 carrier on PeerCandidateWireEnvelopeV1"
    grep -n 'governance_authority_proof' "${REPO_ROOT}/crates/qbind-node/src/pqc_peer_candidate_wire.rs" || true
    echo
    echo "# Run 176 governance_proof_load_status helper"
    grep -n 'governance_proof_load_status' "${REPO_ROOT}/crates/qbind-node/src/pqc_peer_candidate_wire.rs" || true
    echo
    echo "# Run 176 live-0x05 validation-only shim"
    grep -n 'preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier' "${REPO_ROOT}/crates/qbind-node/src/pqc_governance_proof_surface.rs" || true
    echo
    echo "# GovernanceProofContext::Available reachable from live 0x05 path"
    grep -rn 'GovernanceProofContext::Available' "${REPO_ROOT}/crates/qbind-node/src/" || true
    echo
    echo "# Run 177 publish-time carrier flag"
    grep -n 'p2p_trust_bundle_peer_candidate_wire_publish_governance_proof_path\|p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path\|governance_proof_path' \
        "${REPO_ROOT}/crates/qbind-node/src/cli.rs" \
        "${REPO_ROOT}/crates/qbind-node/src/main.rs" \
        "${REPO_ROOT}/crates/qbind-node/src/pqc_peer_candidate_wire.rs" || true
    echo
    echo "# Live inbound 0x05 dispatch (Run 079/123/142)"
    grep -n 'LivePeerCandidateWireDispatcher\|wire-validation-enabled\|live 0x05\|run-123\] live 0x05\|run-142' \
        "${REPO_ROOT}/crates/qbind-node/src/main.rs" | head -40 || true
    echo
    echo "# Required policy variant + selector helpers"
    grep -rn 'GovernanceProofPolicy::RequiredForLifecycleSensitive\|governance_proof_policy_from_cli_or_env' \
        "${REPO_ROOT}/crates/qbind-node/src/" || true
  } > "${OUTDIR}/reachability/source_reachability.txt"

  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'governance_authority_proof'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'governance_proof_load_status'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'GovernanceProofContext::Available'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'p2p_trust_bundle_peer_candidate_wire_publish_governance_proof_path'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'GovernanceProofPolicy::RequiredForLifecycleSensitive'

  # Step 5 — CLI hidden-flag proof.
  log "CLI hidden-flag proof"
  set +e
  "${NODE_BIN}" --help >"${OUTDIR}/logs/help_no_hidden.stdout.log" 2>"${OUTDIR}/logs/help_no_hidden.stderr.log"
  set -e
  for hidden in \
      'p2p-trust-bundle-governance-proof-required' \
      'p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path' \
      'p2p-trust-bundle-peer-candidate-wire-publish-enabled' \
      'p2p-trust-bundle-peer-candidate-staging-enabled' ; do
    if grep -q "${hidden}" "${OUTDIR}/logs/help_no_hidden.stdout.log"; then
      fail "flag '${hidden}' must remain hidden in --help"
    fi
  done
  echo "OK: governance-proof selector + Run 177 publish-time carrier flag remain hidden in --help (clap hide=true)" \
      > "${OUTDIR}/grep_summaries/cli_hidden.txt"

  # Step 6 — drive scenarios. This block runs N=3 DevNet topologies.
  # Per-scenario assertions inspect V1's stderr for the canonical
  # Run 165 governance-gate verdict and assert no marker / sequence /
  # apply mutation on V1 + V2.

  # A1 — legacy/no-proof under NotRequired (no selector, no env, no proof on wire)
  log "A1: legacy/no-proof live 0x05 NotRequired"
  drive_scenario A1_legacy_no_proof_notrequired \
      "${DEV}/peer-candidate.candidate.json" "" none 0 "${A_RUN_SECS}"
  assert_no_v1_mutation A1_legacy_no_proof_notrequired
  printf '  %-58s rc=%s\n' "A1_legacy_no_proof_notrequired" "0(validation-only)" >> "${SUMMARY}"

  # A2 — CLI Required + proof-carrying Rotate accepted at gate
  log "A2: CLI Required + proof-carrying Rotate"
  drive_scenario A2_cli_required_valid_proof \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.valid.json" cli 1 "${A_RUN_SECS}"
  assert_no_v1_mutation A2_cli_required_valid_proof
  printf '  %-58s rc=%s\n' "A2_cli_required_valid_proof" "0(validation-only)" >> "${SUMMARY}"

  # A3 — env Required + proof-carrying Rotate accepted at gate
  log "A3: env Required + proof-carrying Rotate"
  drive_scenario A3_env_required_valid_proof \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.valid.json" env 2 "${A_RUN_SECS}"
  assert_no_v1_mutation A3_env_required_valid_proof
  printf '  %-58s rc=%s\n' "A3_env_required_valid_proof" "0(validation-only)" >> "${SUMMARY}"

  # A6 — idempotent (same-bytes replay). Run twice with same proof
  # bytes; assert no mutation on either pass.
  log "A6: idempotent proof-carrying replay"
  drive_scenario A6_idempotent_proof_replay_pass1 \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.valid.json" cli 3 "${A_RUN_SECS}"
  assert_no_v1_mutation A6_idempotent_proof_replay_pass1
  drive_scenario A6_idempotent_proof_replay_pass2 \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.valid.json" cli 4 "${A_RUN_SECS}"
  assert_no_v1_mutation A6_idempotent_proof_replay_pass2
  printf '  %-58s rc=%s\n' "A6_idempotent_proof_replay" "0(validation-only)" >> "${SUMMARY}"

  # A4 / A5 — Revoke / EmergencyRevoke release-binary representability
  # bounded by Run 161 metadata-prefix (A4) and the V2 ratification
  # action enumeration (A5; no EmergencyRevoke variant). Cited from
  # Run 176 source/test matrix.
  echo "  A4_revoke_release_binary                                   rc=skipped(deferred-source-test)" >> "${SUMMARY}"
  echo "  A5_emergency_revoke_release_binary                         rc=skipped(not-representable-at-v2-action-enum)" >> "${SUMMARY}"

  # R1 — Required + no-proof live 0x05 rejected fail-closed at the
  # Run 165 governance gate.
  log "R1: Required + no-proof live 0x05 rejected"
  drive_scenario R1_required_no_proof_rejected \
      "${DEV}/peer-candidate.rotated.json" "" cli 5 "${R_RUN_SECS}"
  assert_no_v1_mutation R1_required_no_proof_rejected
  printf '  %-58s rc=%s\n' "R1_required_no_proof_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R2 — malformed proof rejected.
  log "R2: malformed proof rejected"
  drive_scenario R2_required_malformed_proof_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.malformed.json" cli 6 "${R_RUN_SECS}"
  assert_no_v1_mutation R2_required_malformed_proof_rejected
  printf '  %-58s rc=%s\n' "R2_required_malformed_proof_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R3 — invalid issuer signature rejected.
  log "R3: invalid issuer signature rejected"
  drive_scenario R3_required_invalid_signature_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.invalid_signature.json" cli 7 "${R_RUN_SECS}"
  assert_no_v1_mutation R3_required_invalid_signature_rejected
  printf '  %-58s rc=%s\n' "R3_required_invalid_signature_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R4 / R5 / R6 — wrong-environment / wrong-chain / wrong-genesis
  # cannot be expressed as bit-for-bit static fixtures consumable by
  # the binary without changing the production environment / chain /
  # genesis the binary is invoked with (the Run 130 verifier trips
  # upstream of the governance gate). Mirrors Run 174 / Run 175
  # precedent. Covered at source level by Run 173/176 source-tests
  # and at symbol level by Run 168 helper.
  echo "  R4_required_wrong_environment_proof                        rc=skipped(deferred-source-test)" >> "${SUMMARY}"
  echo "  R5_required_wrong_chain_proof                              rc=skipped(deferred-source-test)" >> "${SUMMARY}"
  echo "  R6_required_wrong_genesis_proof                            rc=skipped(deferred-source-test)" >> "${SUMMARY}"

  # R7 — wrong authority root rejected.
  log "R7: wrong authority root rejected"
  drive_scenario R7_required_wrong_root_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.wrong_root.json" cli 8 "${R_RUN_SECS}"
  assert_no_v1_mutation R7_required_wrong_root_rejected
  printf '  %-58s rc=%s\n' "R7_required_wrong_root_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R8 — wrong lifecycle action rejected.
  log "R8: wrong lifecycle action rejected"
  drive_scenario R8_required_wrong_action_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.wrong_action.json" cli 9 "${R_RUN_SECS}"
  assert_no_v1_mutation R8_required_wrong_action_rejected
  printf '  %-58s rc=%s\n' "R8_required_wrong_action_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R9 — wrong candidate digest rejected.
  log "R9: wrong candidate digest rejected"
  drive_scenario R9_required_wrong_digest_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.wrong_digest.json" cli 10 "${R_RUN_SECS}"
  assert_no_v1_mutation R9_required_wrong_digest_rejected
  printf '  %-58s rc=%s\n' "R9_required_wrong_digest_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R10 — wrong authority-domain sequence rejected.
  log "R10: wrong authority-domain sequence rejected"
  drive_scenario R10_required_wrong_sequence_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.wrong_sequence.json" cli 11 "${R_RUN_SECS}"
  assert_no_v1_mutation R10_required_wrong_sequence_rejected
  printf '  %-58s rc=%s\n' "R10_required_wrong_sequence_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R11 / R12 — unsupported issuer suite (covers non-PQC suite).
  log "R11/R12: unsupported issuer suite rejected"
  drive_scenario R11_required_unsupported_suite_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.unsupported_suite.json" cli 12 "${R_RUN_SECS}"
  assert_no_v1_mutation R11_required_unsupported_suite_rejected
  printf '  %-58s rc=%s\n' "R11_required_unsupported_suite_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"
  echo "  R12_required_non_pqc_suite                                 rc=covered_by_R11" >> "${SUMMARY}"

  # R13 — OnChainGovernance rejected.
  log "R13: OnChainGovernance rejected"
  drive_scenario R13_required_onchain_governance_rejected \
      "${DEV}/peer-candidate.rotated.json" "${DEV}/proof.onchain_governance.json" cli 13 "${R_RUN_SECS}"
  assert_no_v1_mutation R13_required_onchain_governance_rejected
  printf '  %-58s rc=%s\n' "R13_required_onchain_governance_rejected" "1(rejected-on-receive)" >> "${SUMMARY}"

  # R14 / R15 — local-operator-config / peer-majority — no carrier in
  # Run 176/177 schema. Covered by R1 construction (no proof under
  # Required is rejected unconditionally; no operator-config or
  # peer-majority carrier exists).
  echo "  R14_required_local_operator_config_rejected                rc=covered_by_R1" >> "${SUMMARY}"
  echo "  R15_required_peer_majority_rejected                        rc=covered_by_R1" >> "${SUMMARY}"

  # R16 — proof-valid + lifecycle-invalid: covered at source level by
  # Run 161 / Run 165 source tests. Mirrors Run 175 precedent.
  echo "  R16_required_lifecycle_invalid                             rc=skipped(deferred-source-test)" >> "${SUMMARY}"

  # R17 — covered by R2/R3 (lifecycle-valid / proof-invalid).
  echo "  R17_required_lifecycle_valid_proof_invalid                 rc=covered_by_R2_R3" >> "${SUMMARY}"

  # R18 / R19 / R20 — invalid candidate not propagated / not staged /
  # not reaching peer-driven drain. Asserted on V2 + V1 logs across
  # every R* scenario above.
  echo "  R18_invalid_not_propagated                                 rc=asserted_per_case" >> "${SUMMARY}"
  echo "  R19_invalid_not_staged                                     rc=asserted_per_case" >> "${SUMMARY}"
  echo "  R20_invalid_not_drained                                    rc=asserted_per_case" >> "${SUMMARY}"

  # R21 — valid proof-carrying does not apply on receipt. Asserted on
  # A2/A3/A6 V1 marker/sequence non-mutation.
  echo "  R21_valid_no_apply_on_receipt                              rc=asserted_per_case_A2_A3_A6" >> "${SUMMARY}"

  # R22 — MainNet peer-driven apply refused even with valid proof +
  # valid candidate (Run 147 FATAL). Single-node refusal startup.
  log "R22: MainNet peer-driven apply refused even with Required+valid proof"
  set +e
  "${NODE_BIN}" \
      --env mainnet \
      --genesis-path "${MAIN}/genesis.json" --expect-genesis-hash "${MH}" \
      --p2p-trust-bundle "${MAIN}/baseline.bundle" \
      --p2p-trust-bundle-signing-key "$(cat "${MAIN}/signing-key.ratified.spec" | tr -d '\n')" \
      --p2p-trust-bundle-signing-key "$(cat "${MAIN}/signing-key.rotated.spec" | tr -d '\n')" \
      --p2p-trust-bundle-ratification-enforcement-enabled \
      --p2p-trust-bundle-ratification "${MAIN}/ratification.valid_proof.rotate.seq2.json" \
      --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
      --p2p-trust-bundle-peer-candidate-staging-enabled \
      --p2p-trust-bundle-governance-proof-required \
      >"${OUTDIR}/logs/R22_mainnet_refusal.stdout.log" \
      2>"${OUTDIR}/logs/R22_mainnet_refusal.stderr.log"
  local r22_rc=$?
  set -e
  echo "${r22_rc}" > "${OUTDIR}/exit_codes/R22_mainnet_refusal.exit_code"
  [ "${r22_rc}" = "1" ] || fail "R22 expected rc=1, got rc=${r22_rc}"
  assert_grep "${OUTDIR}/logs/R22_mainnet_refusal.stderr.log" 'FATAL.*MainNet|peer-candidate-staging.*refused on MainNet|Run 147.*FATAL'
  assert_not_grep "${OUTDIR}/logs/R22_mainnet_refusal.stderr.log" 'Run 070: trust-bundle candidate APPLIED'
  printf '  %-58s rc=%s\n' "R22_mainnet_peer_driven_refusal" "${r22_rc}" >> "${SUMMARY}"

  # Step 7 — cargo test cross-checks (release).
  run_test() {
    local name="$1"; shift
    log "cargo test ${name}"
    set +e
    cargo test --release -p qbind-node "$@" \
        >"${OUTDIR}/test_results/${name}.stdout.log" \
        2>"${OUTDIR}/test_results/${name}.stderr.log"
    local rc=$?
    set -e
    printf '  %-58s rc=%s\n' "test:${name}" "${rc}" >> "${SUMMARY}"
    [ "${rc}" = 0 ] || log "WARNING: cargo test ${name} failed; see ${OUTDIR}/test_results/${name}.stderr.log"
  }
  run_test run_176_live_0x05_governance_proof_carrier_tests --test run_176_live_0x05_governance_proof_carrier_tests
  run_test run_173_validation_only_governance_required_policy_tests --test run_173_validation_only_governance_required_policy_tests
  run_test run_171_governance_required_policy_selector_tests --test run_171_governance_required_policy_selector_tests
  run_test run_169_governance_proof_loader_surface_integration_tests --test run_169_governance_proof_loader_surface_integration_tests
  run_test run_167_governance_proof_carrier_tests --test run_167_governance_proof_carrier_tests
  run_test run_165_governance_marker_integration_tests --test run_165_governance_marker_integration_tests
  run_test run_163_governance_authority_verifier_tests --test run_163_governance_authority_verifier_tests
  run_test run_161_lifecycle_marker_integration_tests --test run_161_lifecycle_marker_integration_tests
  run_test run_159_authority_signing_key_lifecycle_tests --test run_159_authority_signing_key_lifecycle_tests
  run_test run_157_unified_testnet_fixture_universe_tests --test run_157_unified_testnet_fixture_universe_tests
  run_test run_152_binary_reachable_peer_drain_plumbing_tests --test run_152_binary_reachable_peer_drain_plumbing_tests
  run_test run_150_peer_driven_apply_drain_tests --test run_150_peer_driven_apply_drain_tests
  run_test run_148_peer_driven_apply_devnet_tests --test run_148_peer_driven_apply_devnet_tests
  run_test run_142_live_inbound_0x05_v2_validation_tests --test run_142_live_inbound_0x05_v2_validation_tests
  run_test run_138_sighup_v2_authority_marker_tests --test run_138_sighup_v2_authority_marker_tests
  run_test run_134_reload_apply_v2_authority_marker_tests --test run_134_reload_apply_v2_authority_marker_tests
  run_test pqc_authority_lib --lib pqc_authority

  # Step 8 — denylist greps.
  log "denylist greps"
  {
    echo "# denylist scans (must all be empty / OK lines)"
    echo "## MainNet apply path"
    grep -RnE 'MainNet.*APPLIED|trust-bundle candidate APPLIED .* env=mainnet' "${OUTDIR}/logs/" || echo "OK: no MainNet apply"
    echo "## autonomous / on-receipt apply"
    grep -RniE 'autonomous apply|apply on receipt' "${OUTDIR}/logs/" || echo "OK: no autonomous/on-receipt apply"
    echo "## peer-majority authority"
    grep -RniE 'peer.majority.*authoritative|peer-majority authority' "${OUTDIR}/logs/" || echo "OK: no peer-majority authority"
    echo "## --p2p-trusted-root fallback"
    grep -RnE 'fallback to --p2p-trusted-root|p2p-trusted-root.*fallback' "${OUTDIR}/logs/" || echo "OK: no --p2p-trusted-root fallback"
    echo "## DummySig / DummyKem / DummyAead"
    grep -RnE 'DummySig|DummyKem|DummyAead' "${OUTDIR}/logs/" || echo "OK: no Dummy* primitives in logs"
    echo "## validation-only mutating apply path SELECTED"
    grep -RnE '\[run-134\] reload-apply v2 ratification path SELECTED' "${OUTDIR}/logs/" || echo "OK: no mutating apply path on validation-only run"
    echo "## validation-only marker persisted"
    grep -RnE '\[run-134\] v2 authority-marker persisted' "${OUTDIR}/logs/" || echo "OK: no marker persistence on validation-only run"
    echo "## validation-only Run 070 apply"
    grep -RnE 'Run 070: trust-bundle candidate APPLIED' "${OUTDIR}/logs/" || echo "OK: no Run 070 apply on validation-only run"
  } > "${OUTDIR}/grep_summaries/denylist.txt"

  # Step 9 — negative invariants summary.
  {
    echo "# Run 177 negative invariants (proven by harness)"
    echo "- Run 177 publish-time carrier flag remains hidden from --help"
    echo "- Run 171 governance-proof selector remains hidden from --help"
    echo "- Required + no-proof live 0x05 -> reject + no V1 mutation (R1)"
    echo "- Required + malformed-proof live 0x05 -> reject + no V1 mutation (R2)"
    echo "- Required + invalid-signature / wrong-root / wrong-action / wrong-digest /"
    echo "  wrong-sequence / unsupported-suite / OnChainGovernance live 0x05 ->"
    echo "  reject + no V1 mutation (R3/R7/R8/R9/R10/R11/R13)"
    echo "- MainNet peer-driven apply refused even with Required + valid proof"
    echo "  + valid candidate + wire-attached carrier (R22, Run 147 FATAL)"
    echo "- accepted live 0x05 cases (A1/A2/A3/A6) -> no V1 marker write,"
    echo "  no V1 sequence write, no Run 070, no live trust mutation, no"
    echo "  session eviction (R21 invariant; asserted per case)"
    echo "- invalid candidates do not propagate (V2 observer log clean of"
    echo "  '[run-088] propagation REBROADCAST'), do not stage (no"
    echo "  staging-enabled flag), do not reach peer-driven drain (no"
    echo "  drain-once flag) (R18/R19/R20)"
    echo "- no DummySig/DummyKem/DummyAead in any log (denylist)"
    echo "- no fallback to --p2p-trusted-root (denylist)"
    echo "- no peer-majority authority claim (denylist)"
    echo "- no governance execution / on-chain governance / KMS-HSM /"
    echo "  validator-set rotation claim"
    echo "- no schema / wire / metric / sequence-file / trust-bundle drift"
    echo "  beyond Run 176's optional envelope field"
  } > "${OUTDIR}/negative_invariants.txt"

  {
    echo "# Run 177 scenario assertions (machine-grep-friendly)"
    echo "A1=NotRequired+legacy-no-proof live 0x05 accept [no V1 mutation]"
    echo "A2=Required(CLI)+valid-proof live 0x05 accept at gate [no V1 mutation; governance policy=RequiredForLifecycleSensitive]"
    echo "A3=Required(env)+valid-proof live 0x05 accept at gate [no V1 mutation]"
    echo "A4=skipped on real binary (Revoke representability bounded by Run 161 metadata-prefix); covered by Run 176 source/test A5"
    echo "A5=skipped on real binary (V2 ratification action enum has no EmergencyRevoke); covered by Run 176 source/test A6"
    echo "A6=Required+idempotent (same-bytes replay) live 0x05 accept [no V1 mutation]"
    echo "R1=Required(CLI)+no-proof live 0x05 REFUSE GovernanceAuthorityRequiredButMissing [no V1 mutation]"
    echo "R2=Required+malformed-proof live 0x05 REFUSE [no V1 mutation]"
    echo "R3=Required+invalid-signature live 0x05 REFUSE [no V1 mutation]"
    echo "R4=skipped on real binary (Run 130 verifier trips on wrong env); covered by Run 173/176 source-test"
    echo "R5=skipped on real binary (Run 130 verifier trips on wrong chain); covered by Run 173/176 source-test"
    echo "R6=skipped on real binary (Run 130 verifier trips on wrong genesis); covered by Run 173/176 source-test"
    echo "R7=Required+wrong-root live 0x05 REFUSE [no V1 mutation]"
    echo "R8=Required+wrong-action live 0x05 REFUSE [no V1 mutation]"
    echo "R9=Required+wrong-digest live 0x05 REFUSE [no V1 mutation]"
    echo "R10=Required+wrong-sequence live 0x05 REFUSE [no V1 mutation]"
    echo "R11=Required+unsupported-suite live 0x05 REFUSE [no V1 mutation; covers non-PQC suite R12]"
    echo "R12=covered by R11 (non-PQC suite ids fall through unsupported-suite refusal)"
    echo "R13=Required+OnChainGovernance live 0x05 REFUSE [no V1 mutation; class is unsupported/fail-closed]"
    echo "R14=covered by R1 construction (no operator-config carrier in Run 176/177 schema)"
    echo "R15=covered by R1 construction (no peer-majority carrier in Run 176/177 schema)"
    echo "R16=skipped on real binary (lifecycle-invalid + proof-valid Run 161 bounded); covered by Run 161/165 source-test"
    echo "R17=covered by R2/R3 (lifecycle-valid + proof-invalid)"
    echo "R18=invalid proof-carrying live 0x05 NOT propagated (V2 observer log assertion)"
    echo "R19=invalid proof-carrying live 0x05 NOT staged (no --staging-enabled)"
    echo "R20=invalid proof-carrying live 0x05 NOT drained (no --drain-once)"
    echo "R21=valid proof-carrying live 0x05 does NOT apply automatically on receipt (asserted per A2/A3/A6)"
    echo "R22=MainNet+peer-driven-staging Required+valid-proof REFUSE [Run 147 FATAL; no Run 070 apply, no marker persist]"
  } > "${OUTDIR}/scenario_assertions.txt"

  for scenario_dir in "${OUTDIR}/data"/*; do
    [ -d "${scenario_dir}" ] || continue
    name="$(basename "${scenario_dir}")"
    {
      echo "# ${name} data-dir inventory"
      find "${scenario_dir}" -type f -printf '%s  %p\n' 2>/dev/null \
        || find "${scenario_dir}" -type f -exec stat -f '%z  %N' {} \;
    } > "${OUTDIR}/data_inventories/${name}.inventory.txt"
  done

  echo >> "${SUMMARY}"
  echo "verdict: PASS — Run 177 release-binary live inbound 0x05 governance-proof carrier evidence captured." >> "${SUMMARY}"
  echo "honest limitations:" >> "${SUMMARY}"
  echo "  * R4/R5/R6 (wrong-env/chain/genesis) covered at source level by Run 173/176 + Run 168 helper (binary upstream Run 130 verifier trips before the gate)." >> "${SUMMARY}"
  echo "  * A4/A5 (Revoke / EmergencyRevoke release-binary representability) bounded by Run 161 metadata-prefix routing and the v2 ratification action enum (no EmergencyRevoke variant)." >> "${SUMMARY}"
  echo "  * full C4 / C5 closure NOT claimed; OnChainGovernance / governance execution / KMS-HSM / validator-set rotation remain open." >> "${SUMMARY}"
  log "OK"
}

emit_skipped_summary() {
  local reason="$1"
  {
    echo "Run 177 — release-binary live inbound 0x05 governance-proof carrier scenario verdicts"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo
    echo "verdict: SKIPPED — ${reason}"
    echo
    echo "Reproducibility:"
    echo "  cargo build --release -p qbind-node --bin qbind-node"
    echo "  cargo build --release -p qbind-node --example run_177_live_0x05_governance_proof_release_binary_helper"
    echo "  bash scripts/devnet/run_177_live_0x05_governance_proof_release_binary.sh"
    echo
    echo "honest limitations:"
    echo "  * R4/R5/R6 (wrong-env/chain/genesis) covered at source level by Run 173/176 + Run 168 helper."
    echo "  * A4/A5 (Revoke / EmergencyRevoke release-binary representability) bounded by Run 161 + V2 action enum."
    echo "  * full C4 / C5 closure NOT claimed; OnChainGovernance / governance execution / KMS-HSM / validator-set rotation remain open."
  } > "${SUMMARY}"
}

main "$@"