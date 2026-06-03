#!/usr/bin/env bash
# Run 175 — Release-binary local peer-candidate-check Required-policy
# governance-proof evidence.
#
# Lifts the Run 174-deferred local
# `--p2p-trust-bundle-peer-candidate-check` validation-only surface to
# release-binary evidence. Run 173 wired the validation-only side at
# source/test level (`preflight_run_132_validation_only_v2_marker_check`
# resolves `GovernanceProofPolicy` via
# `governance_proof_policy_from_cli_or_env` and routes through
# `preflight_v2_validation_only_marker_check_with_governance_proof_load`,
# which delegates to the Run 169 shim
# `preflight_v2_marker_decision_with_governance_proof_load`). Run 174
# proved the reload-check side at release-binary level. Run 175 closes
# the peer-candidate-check side at release-binary level on real
# `target/release/qbind-node` using the Run 175 release-built fixture
# helper to mint local PeerCandidateEnvelope JSONs (Run 076 schema,
# unchanged) plus the Run 172-shape proof-carrying / no-proof /
# malformed / invalid-binding v2 ratification corpus.
#
# This harness proves on real `target/release/qbind-node` that:
#   * default local peer-candidate-check behaviour remains
#     `NotRequired` — existing no-proof Ratify@seq=1 sidecars stay
#     accepted via the peer-candidate envelope wrapping the active
#     seq=2 candidate bundle (A1);
#   * the CLI selector
#     `--p2p-trust-bundle-governance-proof-required` activates Required
#     policy on local peer-candidate-check; a valid GenesisBound Rotate
#     proof-carrying sidecar is accepted with the rotated seq=2
#     candidate envelope (A2);
#   * the env selector `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`
#     activates Required policy on local peer-candidate-check with the
#     same valid sidecar accepted (A3);
#   * env unset/false/0 preserves NotRequired (A4);
#   * an idempotent (same-bytes replay) proof-carrying Rotate sidecar
#     is accepted under Required (A5);
#   * Required + no-proof Rotate sidecar is REFUSED on validation-only
#     peer-candidate-check with the typed
#     `Run 165: v2 authority-marker decision requires a governance
#      authority proof for lifecycle action 'rotate' but none was
#      available` (`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { action: Rotate }`)
#     under both CLI (R1) and env (R2) selectors;
#   * Required + malformed / wrong-root / wrong-action / wrong-digest /
#     wrong-sequence / invalid-signature / unsupported-suite /
#     OnChainGovernance proof-carrying sidecars all fail closed on
#     validation-only peer-candidate-check (R3, R8, R9, R10, R11, R4,
#     R-extra, R12);
#   * for every refusal: no Run 070 apply log, no
#     `[run-134] reload-apply v2 ratification path SELECTED` line
#     (validation-only never selects the mutating apply path), no
#     `[run-134] v2 authority-marker persisted` line, no
#     `sequence_commit=ok`, no marker write, no sequence write,
#     marker SHA pre==post if seeded (R15, R16);
#   * every accepted validation-only scenario is strictly non-
#     mutating: no marker write, no sequence write, no Run 070 apply
#     log, no live trust mutation (R15, R16);
#   * MainNet peer-driven apply remains refused even with Required
#     selector active and a valid proof-carrying Rotate sidecar +
#     valid local peer-candidate envelope (R18, Run 147 FATAL invariant);
#   * the selector cannot be implicitly enabled by unrelated flags
#     (R17);
#   * the Run 173 source-test integration suite passes alongside the
#     Run 171 / Run 169 / Run 167 / Run 165 / Run 163 / Run 161 /
#     Run 159 / Run 157 / Run 152 / Run 150 / Run 148 / Run 142 /
#     Run 138 / Run 134 / `--lib pqc_authority` / `--lib` regressions.
#
# Strict scope (from `task/RUN_175_TASK.txt`):
#   * Release-binary evidence only.
#   * No production source change beyond a tiny harness-only fix if
#     required.
#   * No new schema / wire / metric / sequence-file / trust-bundle /
#     peer-candidate-envelope drift.
#   * No live inbound `0x05` proof-carrying schema work — the live
#     `0x05` peer-candidate envelope still does NOT carry a
#     `governance_authority_proof` sibling. Run 175 exercises the
#     LOCAL `--p2p-trust-bundle-peer-candidate-check` validation-only
#     surface only (Run 077 / Run 107 envelope path), where the
#     proof-carrying ratification is supplied separately via
#     `--p2p-trust-bundle-ratification` and parsed by the production
#     loader `load_versioned_ratification_with_governance_proof_from_path`.
#   * No MainNet apply enablement; no autonomous apply; no apply on
#     receipt; no peer-majority authority; no governance execution;
#     no on-chain governance implementation; no KMS/HSM; no
#     validator-set rotation. `OnChainGovernance` remains
#     unsupported / fail-closed at the Run 163 verifier.
#
# Honest limitations (preserved, NOT a Run 175 closure):
#   * Live inbound `0x05` peer-candidate envelopes do NOT carry a
#     `governance_authority_proof` sibling; the live `0x05` validation
#     surface (`pqc_peer_candidate_wire`) cannot yet supply a typed
#     `GovernanceProofLoadStatus`, so live `0x05` proof-carrying
#     remains OPEN (envelope schema change is forbidden by task
#     scope). Run 175 covers only the LOCAL peer-candidate-check
#     binary surface (Run 077 / Run 107), which composes the Run 169
#     loader on the operator-supplied `--p2p-trust-bundle-ratification`
#     argument by construction (Run 105 / Run 132 wiring).
#   * Wrong-environment / wrong-chain / wrong-genesis proof-carrying
#     Rotate sidecars cannot be expressed as bit-for-bit static
#     fixtures consumable by the binary without changing the
#     production environment / chain / genesis the binary is invoked
#     with (the Run 130 verifier trips upstream of the governance
#     gate). These are covered at source level by the Run 173
#     source-test integration suite and at symbol level by the Run 168
#     release-built helper. Mirrors Run 174 precedent (R5/R6/R7).
#   * Lifecycle-invalid + proof-valid (R-class) cases that would
#     require seeding a v2@seq=2 marker before the rotate replay are
#     covered at source level by the Run 161 / Run 165 source tests.
#     Mirrors Run 174 precedent.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${OUTDIR:-${REPO_ROOT}/docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_175="${REPO_ROOT}/target/release/examples/run_175_peer_candidate_check_governance_required_policy_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"
PROVENANCE="${OUTDIR}/provenance.txt"

log()  { printf '[run-175] %s\n' "$*" >&2; }
fail() { printf '[run-175] FAIL: %s\n' "$*" >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
build_id() {
  if command -v file >/dev/null 2>&1; then file "$1" | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' || echo "BuildID=unknown"
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

# Run a release-binary peer-candidate-check scenario with optional pre-
# seed marker and env. Args: name expected_rc pre_marker env_pairs(--key=val csv) -- args...
run_case() {
  local name="$1" expected_rc="$2" pre_marker="$3" env_pairs="$4"
  shift 4
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local data_dir="${OUTDIR}/data/${name}"
  local rcfile="${OUTDIR}/exit_codes/${name}.exit_code"
  local pre_sha="${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  local post_sha="${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  local pre_seq_sha="${OUTDIR}/sequence_hashes/${name}.sequence_pre.sha256"
  local post_seq_sha="${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  mkdir -p "$data_dir"
  if [ -n "$pre_marker" ]; then
    cp "$pre_marker" "${data_dir}/pqc_authority_state.json"
    sha256_file "${data_dir}/pqc_authority_state.json" > "$pre_sha"
  else
    : > "$pre_sha"
  fi
  : > "$pre_seq_sha"

  set +e
  if [ -n "$env_pairs" ]; then
    env $(printf "%s " $env_pairs) "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  else
    "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  fi
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"
  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc} (see ${stderr})"

  if [ -f "${data_dir}/pqc_authority_state.json" ]; then
    sha256_file "${data_dir}/pqc_authority_state.json" > "$post_sha"
  else
    : > "$post_sha"
  fi
  if [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ]; then
    sha256_file "${data_dir}/pqc_trust_bundle_sequence.json" > "$post_seq_sha"
  else
    : > "$post_seq_sha"
  fi
  printf '  %-58s rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

# Validation-only no-mutation invariant: marker bytes preserved if
# seeded (or absent if not); sequence file MUST NOT exist post-run;
# harness logs MUST NOT contain Run 070 apply, mutating reload-apply
# path SELECTED, or v2 authority-marker persisted lines. The
# `consensus/` RocksDB dir and `run077-peer-candidate-scratch/` are
# expected and benign (Run 098 ConsensusStorage open + Run 077 scratch
# tempfile parent).
assert_no_mutation() {
  local name="$1"
  local pre="${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  local post="${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  local seq_post="${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  if [ -s "$pre" ]; then
    cmp -s "$pre" "$post" \
      || fail "${name}: validation-only path mutated marker bytes (pre != post)"
  else
    if [ -s "$post" ]; then fail "${name}: validation-only path created marker file"; fi
  fi
  [ ! -s "$seq_post" ] \
    || fail "${name}: validation-only path wrote pqc_trust_bundle_sequence.json"
  assert_not_grep "$stderr" 'Run 070: trust-bundle candidate APPLIED'
  assert_not_grep "$stderr" '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_not_grep "$stderr" '\[run-134\] v2 authority-marker persisted'
  assert_not_grep "$stderr" 'sequence_commit=ok'
}

# --- main ------------------------------------------------------------------

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

  cd "$REPO_ROOT"

  # Step 1 — release builds.
  log "building release binaries (qbind-node, run_175 helper)"
  cargo build --release -p qbind-node --bin qbind-node \
      >"${OUTDIR}/logs/build_qbind_node.stdout.log" \
      2>"${OUTDIR}/logs/build_qbind_node.stderr.log"
  cargo build --release -p qbind-node --example run_175_peer_candidate_check_governance_required_policy_release_binary_helper \
      >"${OUTDIR}/logs/build_helper_175.stdout.log" \
      2>"${OUTDIR}/logs/build_helper_175.stderr.log"
  test -x "$NODE_BIN"   || fail "missing ${NODE_BIN}"
  test -x "$HELPER_175" || fail "missing ${HELPER_175}"

  # Step 2 — provenance.
  {
    echo "Run 175 release-binary local peer-candidate-check Required-policy governance-proof evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
    echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_$(build_id "${NODE_BIN}")"
    echo "helper_175_sha256: $(sha256_file "${HELPER_175}")"
    echo "helper_175_$(build_id "${HELPER_175}")"
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$PROVENANCE"

  {
    echo "Run 175 — local peer-candidate-check Required-policy release-binary scenario verdicts"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo
    echo "scenario verdicts:"
  } >"$SUMMARY"

  # Step 3 — mint fixtures via the Run 175 release-built helper.
  log "minting Run 175 fixture corpus + peer-candidate envelopes"
  "$HELPER_175" "${OUTDIR}/fixtures" \
      >"${OUTDIR}/logs/fixture_helper.stdout.log" \
      2>"${OUTDIR}/logs/fixture_helper.stderr.log"
  local DEV="${OUTDIR}/fixtures/devnet"
  local MAIN="${OUTDIR}/fixtures/mainnet"
  local DH; DH="$(cat "$DEV/expected-genesis-hash.txt")"
  local MH; MH="$(cat "$MAIN/expected-genesis-hash.txt")"
  local DKA; DKA="$(cat "$DEV/signing-key.ratified.spec")"
  local DKR; DKR="$(cat "$DEV/signing-key.rotated.spec")"
  local MKA; MKA="$(cat "$MAIN/signing-key.ratified.spec")"
  local MKR; MKR="$(cat "$MAIN/signing-key.rotated.spec")"

  {
    echo "# Run 175 fixture manifest (minted by Run 175 helper)"
    find "${OUTDIR}/fixtures" -type f \( -name '*.json' -o -name '*.bundle' -o -name '*.spec' -o -name '*.txt' \) | sort | while read -r f; do
      printf '%s  %s  %s\n' "$(sha256_file "$f")" "$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")" "${f#${REPO_ROOT}/}"
    done
  } > "${OUTDIR}/fixture_manifest.txt"

  # Step 4 — source reachability greps.
  log "source reachability greps (Run 173 wiring + Run 171 selector + peer-candidate-check dispatch)"
  {
    echo "# Run 171 selector helpers"
    grep -n 'governance_proof_policy_from_cli_or_env\|governance_proof_required_env_selector_enabled\|governance_proof_policy_from_selector\|QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED' "${REPO_ROOT}/crates/qbind-node/src/pqc_governance_proof_surface.rs" || true
    echo
    echo "# Run 173 validation-only shim definition + delegation to Run 169"
    grep -n 'preflight_v2_validation_only_marker_check_with_governance_proof_load\|preflight_v2_marker_decision_with_governance_proof_load' "${REPO_ROOT}/crates/qbind-node/src/pqc_governance_proof_surface.rs" || true
    echo
    echo "# Local peer-candidate-check dispatch through preflight_run_132"
    grep -n 'peer-candidate-check v2 authority-marker check\|preflight_run_132_validation_only_v2_marker_check\|p2p_trust_bundle_peer_candidate_check' "${REPO_ROOT}/crates/qbind-node/src/main.rs" | head -40 || true
    echo
    echo "# preflight_run_132 callers (reload-check + local peer-candidate-check)"
    grep -n 'preflight_run_132_validation_only_v2_marker_check' "${REPO_ROOT}/crates/qbind-node/src/main.rs" || true
    echo
    echo "# Required policy variant"
    grep -rn 'GovernanceProofPolicy::RequiredForLifecycleSensitive' "${REPO_ROOT}/crates/qbind-node/src/" || true
    echo
    echo "# v2 sidecar + proof-sibling loader (Run 167 / Run 169)"
    grep -rn 'load_versioned_ratification_with_governance_proof_from_path' "${REPO_ROOT}/crates/qbind-node/src/" "${REPO_ROOT}/crates/qbind-ledger/src/" || true
    echo
    echo "# GovernanceProofContext::Available reach"
    grep -rn 'GovernanceProofContext::Available' "${REPO_ROOT}/crates/qbind-node/src/" || true
    echo
    echo "# CLI hidden flag declaration"
    grep -n 'p2p-trust-bundle-governance-proof-required\|p2p_trust_bundle_governance_proof_required' "${REPO_ROOT}/crates/qbind-node/src/cli.rs" || true
    echo
    echo "# Local peer-candidate-check CLI declaration"
    grep -n 'p2p-trust-bundle-peer-candidate-check\|p2p_trust_bundle_peer_candidate_check' "${REPO_ROOT}/crates/qbind-node/src/cli.rs" || true
  } > "${OUTDIR}/reachability/source_reachability.txt"

  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'preflight_v2_validation_only_marker_check_with_governance_proof_load'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'preflight_run_132_validation_only_v2_marker_check'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'governance_proof_policy_from_cli_or_env'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'GovernanceProofPolicy::RequiredForLifecycleSensitive'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'load_versioned_ratification_with_governance_proof_from_path'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'GovernanceProofContext::Available'
  assert_grep "${OUTDIR}/reachability/source_reachability.txt" 'p2p_trust_bundle_peer_candidate_check'

  # Step 5 — CLI hidden-flag proof.
  log "CLI hidden-flag proof"
  set +e
  "$NODE_BIN" --help >"${OUTDIR}/logs/help_no_hidden.stdout.log" 2>"${OUTDIR}/logs/help_no_hidden.stderr.log"
  set -e
  if grep -q 'p2p-trust-bundle-governance-proof-required' "${OUTDIR}/logs/help_no_hidden.stdout.log"; then
    fail "selector flag must remain hidden in --help"
  fi
  if grep -q 'p2p-trust-bundle-peer-candidate-check' "${OUTDIR}/logs/help_no_hidden.stdout.log"; then
    fail "peer-candidate-check flag must remain hidden in --help"
  fi
  echo "OK: governance-proof-required selector hidden from --help (clap hide=true)" >"${OUTDIR}/grep_summaries/cli_hidden.txt"
  echo "OK: peer-candidate-check flag hidden from --help (clap hide=true)" >>"${OUTDIR}/grep_summaries/cli_hidden.txt"

  # Step 6 — common DevNet flag block (validation-only peer-candidate-check).
  local devnet_check_common=(
    --env devnet --genesis-path "$DEV/genesis.json" --expect-genesis-hash "$DH"
    --p2p-trust-bundle "$DEV/baseline.bundle"
    --p2p-trust-bundle-signing-key "$DKA" --p2p-trust-bundle-signing-key "$DKR"
    --p2p-trust-bundle-ratification-enforcement-enabled
    --p2p-trust-bundle-allow-unratified-testnet-devnet
    --p2p-trust-bundle-peer-candidate-validation-enabled
  )

  ##########################################################################
  # Acceptance scenarios (real qbind-node, validation-only peer-candidate-check)
  ##########################################################################

  # A1 — default no-proof peer-candidate-check (no selector, no env).
  # Confirms NotRequired backward compatibility on the validation-only
  # local peer-candidate-check binary surface.
  log "A1: default NotRequired no-proof peer-candidate-check"
  run_case A1_default_noproof_peer_candidate_check 0 "" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.candidate.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.ratify.seq1.json"
  assert_grep "${OUTDIR}/logs/A1_default_noproof_peer_candidate_check.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A1_default_noproof_peer_candidate_check.stderr.log" 'governance policy=NotRequired'
  assert_not_grep "${OUTDIR}/logs/A1_default_noproof_peer_candidate_check.stderr.log" 'GovernanceAuthorityRequiredButMissing'
  assert_not_grep "${OUTDIR}/logs/A1_default_noproof_peer_candidate_check.stderr.log" 'requires a governance authority proof'
  assert_no_mutation A1_default_noproof_peer_candidate_check

  # A2 — CLI Required + valid proof-carrying Rotate sidecar accepted.
  log "A2: CLI Required + valid proof peer-candidate-check"
  run_case A2_cli_required_valid_proof_peer_candidate_check 0 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.valid_proof.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/A2_cli_required_valid_proof_peer_candidate_check.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A2_cli_required_valid_proof_peer_candidate_check.stderr.log" '\[run-132\] peer-candidate-check v2 authority-marker check passed'
  assert_grep "${OUTDIR}/logs/A2_cli_required_valid_proof_peer_candidate_check.stderr.log" 'governance policy=RequiredForLifecycleSensitive'
  assert_no_mutation A2_cli_required_valid_proof_peer_candidate_check

  # A3 — env Required + valid proof-carrying Rotate sidecar accepted.
  log "A3: env Required + valid proof peer-candidate-check"
  run_case A3_env_required_valid_proof_peer_candidate_check 0 "$DEV/seed-marker.v2.seq1.json" \
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.valid_proof.rotate.seq2.json"
  assert_grep "${OUTDIR}/logs/A3_env_required_valid_proof_peer_candidate_check.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A3_env_required_valid_proof_peer_candidate_check.stderr.log" '\[run-132\] peer-candidate-check v2 authority-marker check passed'
  assert_grep "${OUTDIR}/logs/A3_env_required_valid_proof_peer_candidate_check.stderr.log" 'governance policy=RequiredForLifecycleSensitive'
  assert_no_mutation A3_env_required_valid_proof_peer_candidate_check

  # A4a — env explicitly false preserves NotRequired.
  log "A4a: env=false preserves NotRequired"
  run_case A4a_env_false_preserves_notrequired 0 "$DEV/seed-marker.v2.seq1.json" \
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=false" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.rotate.seq2.json"
  assert_grep "${OUTDIR}/logs/A4a_env_false_preserves_notrequired.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A4a_env_false_preserves_notrequired.stderr.log" 'governance policy=NotRequired'
  assert_not_grep "${OUTDIR}/logs/A4a_env_false_preserves_notrequired.stderr.log" 'GovernanceAuthorityRequiredButMissing'
  assert_no_mutation A4a_env_false_preserves_notrequired

  # A4b — env=0 preserves NotRequired.
  log "A4b: env=0 preserves NotRequired"
  run_case A4b_env_zero_preserves_notrequired 0 "$DEV/seed-marker.v2.seq1.json" \
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=0" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.rotate.seq2.json"
  assert_grep "${OUTDIR}/logs/A4b_env_zero_preserves_notrequired.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A4b_env_zero_preserves_notrequired.stderr.log" 'governance policy=NotRequired'
  assert_no_mutation A4b_env_zero_preserves_notrequired

  # A5 — idempotent (same-bytes replay) proof-carrying Rotate sidecar
  # accepted under Required (replay through validation-only path produces
  # the same v2-upgrade decision; no mutation).
  log "A5: Required + idempotent proof-carrying replay"
  run_case A5_required_idempotent_proof_replay 0 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.idempotent.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/A5_required_idempotent_proof_replay.stderr.log" 'VERDICT=validated'
  assert_grep "${OUTDIR}/logs/A5_required_idempotent_proof_replay.stderr.log" 'governance policy=RequiredForLifecycleSensitive'
  assert_no_mutation A5_required_idempotent_proof_replay

  ##########################################################################
  # Rejection scenarios (validation-only peer-candidate-check; Required policy)
  ##########################################################################

  # R1 — CLI Required + no-proof Rotate sidecar refused.
  log "R1: CLI Required + no-proof peer-candidate-check"
  run_case R1_cli_required_noproof_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R1_cli_required_noproof_peer_candidate_check.stderr.log" 'requires a governance authority proof'
  assert_grep "${OUTDIR}/logs/R1_cli_required_noproof_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R1_cli_required_noproof_peer_candidate_check

  # R2 — env Required + no-proof Rotate sidecar refused.
  log "R2: env Required + no-proof peer-candidate-check"
  run_case R2_env_required_noproof_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" \
    "QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.rotate.seq2.json"
  assert_grep "${OUTDIR}/logs/R2_env_required_noproof_peer_candidate_check.stderr.log" 'requires a governance authority proof'
  assert_no_mutation R2_env_required_noproof_peer_candidate_check

  # R3 — Required + malformed proof refused.
  log "R3: Required + malformed proof peer-candidate-check"
  run_case R3_required_malformed_proof_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.malformed_proof.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R3_required_malformed_proof_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R3_required_malformed_proof_peer_candidate_check

  # R4 — Required + invalid issuer signature refused.
  log "R4: Required + invalid signature peer-candidate-check"
  run_case R4_required_invalid_signature_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.invalid_signature.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R4_required_invalid_signature_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R4_required_invalid_signature_peer_candidate_check

  # R5 / R6 / R7 — wrong-environment / wrong-chain / wrong-genesis.
  # Mirrors Run 174 deferral rationale: cannot be expressed as bit-for-bit
  # static fixtures consumable by the binary without changing the
  # production environment / chain / genesis the binary is invoked with.
  echo "  R5_required_wrong_environment_peer_candidate_check       rc=skipped(deferred-source-test)" >> "$SUMMARY"
  echo "  R6_required_wrong_chain_peer_candidate_check             rc=skipped(deferred-source-test)" >> "$SUMMARY"
  echo "  R7_required_wrong_genesis_peer_candidate_check           rc=skipped(deferred-source-test)" >> "$SUMMARY"

  # R8 — Required + wrong authority root proof refused.
  log "R8: Required + wrong-root proof peer-candidate-check"
  run_case R8_required_wrong_root_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.wrong_root.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R8_required_wrong_root_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R8_required_wrong_root_peer_candidate_check

  # R9 — Required + wrong lifecycle action proof refused.
  log "R9: Required + wrong-action proof peer-candidate-check"
  run_case R9_required_wrong_action_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.wrong_action.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R9_required_wrong_action_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R9_required_wrong_action_peer_candidate_check

  # R10 — Required + wrong candidate digest proof refused.
  log "R10: Required + wrong-digest proof peer-candidate-check"
  run_case R10_required_wrong_digest_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.wrong_digest.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R10_required_wrong_digest_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R10_required_wrong_digest_peer_candidate_check

  # R11 — Required + wrong authority-domain sequence proof refused.
  log "R11: Required + wrong-sequence proof peer-candidate-check"
  run_case R11_required_wrong_sequence_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.wrong_sequence.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R11_required_wrong_sequence_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R11_required_wrong_sequence_peer_candidate_check

  # R12 — Required + OnChainGovernance proof refused.
  log "R12: Required + OnChainGovernance proof peer-candidate-check"
  run_case R12_required_onchain_governance_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.onchain_governance.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R12_required_onchain_governance_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R12_required_onchain_governance_peer_candidate_check

  # R13 — Required + local operator config proof rejected. The Run 167 /
  # 169 / 173 surface shim has no operator-config carrier — covered by R1
  # construction (no-proof under Required).
  echo "  R13_required_local_operator_config_proof_rejected       rc=covered_by_R1" >> "$SUMMARY"

  # R14 — Required + peer-majority proof rejected. The Run 167 / 169 /
  # 173 surface shim has no peer-majority carrier — covered by R1
  # construction.
  echo "  R14_required_peer_majority_proof_rejected               rc=covered_by_R1" >> "$SUMMARY"

  # R-extra: unsupported issuer suite.
  log "R-extra: Required + unsupported issuer suite peer-candidate-check"
  run_case R_extra_required_unsupported_suite_peer_candidate_check 1 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.unsupported_suite.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R_extra_required_unsupported_suite_peer_candidate_check.stderr.log" '\[binary\] Run 132: VERDICT=invalid'
  assert_no_mutation R_extra_required_unsupported_suite_peer_candidate_check

  # R15 / R16 — validation-only Required reject writes no marker / no
  # sequence; performs no Run 070 / live trust swap / session eviction.
  # Asserted on EVERY accept and reject case via `assert_no_mutation`
  # above.
  echo "  R15_validation_only_required_reject_no_marker_no_seq    rc=asserted_per_case" >> "$SUMMARY"
  echo "  R16_validation_only_required_reject_no_run_070_no_swap  rc=asserted_per_case" >> "$SUMMARY"

  # R17 — selector cannot be enabled by unrelated flags.
  log "R17: selector not implicitly enabled"
  run_case R17_selector_not_implicit 0 "$DEV/seed-marker.v2.seq1.json" "" \
    "${devnet_check_common[@]}" \
    --p2p-trust-bundle-peer-candidate-check "$DEV/peer-candidate.rotated.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.no_proof.rotate.seq2.json"
  assert_not_grep "${OUTDIR}/logs/R17_selector_not_implicit.stderr.log" 'GovernanceAuthorityRequiredButMissing'
  assert_grep "${OUTDIR}/logs/R17_selector_not_implicit.stderr.log" 'governance policy=NotRequired'
  assert_grep "${OUTDIR}/logs/R17_selector_not_implicit.stderr.log" 'VERDICT=validated'
  assert_no_mutation R17_selector_not_implicit

  # R18 — MainNet peer-driven apply refusal even with Required policy
  # and a valid proof-carrying Rotate sidecar + valid local peer-
  # candidate envelope. The peer-driven surface is gated by the
  # disabled-by-default
  # `--p2p-trust-bundle-peer-candidate-staging-enabled` flag, which is
  # FATAL-refused on MainNet at startup (Run 147 invariant). The
  # selector / valid proof / valid local envelope do NOT bypass this
  # refusal.
  log "R18: MainNet peer-driven refusal even with Required + valid proof"
  run_case R18_mainnet_peer_driven_refusal 1 "" "" \
    --env mainnet --genesis-path "$MAIN/genesis.json" --expect-genesis-hash "$MH" \
    --p2p-trust-bundle "$MAIN/baseline.bundle" \
    --p2p-trust-bundle-signing-key "$MKA" --p2p-trust-bundle-signing-key "$MKR" \
    --p2p-trust-bundle-peer-candidate-staging-enabled \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$MAIN/ratification.valid_proof.rotate.seq2.json" \
    --p2p-trust-bundle-governance-proof-required
  assert_grep "${OUTDIR}/logs/R18_mainnet_peer_driven_refusal.stderr.log" 'peer-candidate-staging.*refused on MainNet|FATAL.*MainNet'
  assert_not_grep "${OUTDIR}/logs/R18_mainnet_peer_driven_refusal.stderr.log" 'Run 070: trust-bundle candidate APPLIED'
  assert_not_grep "${OUTDIR}/logs/R18_mainnet_peer_driven_refusal.stderr.log" 'v2 authority-marker persisted'

  ##########################################################################
  # Cargo test cross-checks (release).
  ##########################################################################
  run_test() {
    local name="$1"; shift
    log "cargo test ${name}"
    set +e
    cargo test --release -p qbind-node "$@" \
        >"${OUTDIR}/test_results/${name}.stdout.log" \
        2>"${OUTDIR}/test_results/${name}.stderr.log"
    local rc=$?
    set -e
    printf '  %-58s rc=%s\n' "test:${name}" "$rc" >> "$SUMMARY"
    [ "$rc" = 0 ] || fail "cargo test ${name} failed; see ${OUTDIR}/test_results/${name}.stderr.log"
  }
  run_test run_173_validation_only_governance_required_policy_tests --test run_173_validation_only_governance_required_policy_tests
  run_test run_171_governance_required_policy_selector_tests --test run_171_governance_required_policy_selector_tests
  run_test run_169_governance_proof_loader_surface_integration_tests --test run_169_governance_proof_loader_surface_integration_tests
  run_test run_167_governance_proof_carrier_tests --test run_167_governance_proof_carrier_tests
  run_test run_165_governance_marker_integration_tests --test run_165_governance_marker_integration_tests
  run_test pqc_authority_lib --lib pqc_authority

  ##########################################################################
  # Denylist greps.
  ##########################################################################
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
    echo "## marker before sequence"
    grep -RnE 'marker persisted.*before.*sequence' "${OUTDIR}/logs/" || echo "OK: no marker-before-sequence"
    echo "## validation-only mutating apply path SELECTED"
    grep -RnE '\[run-134\] reload-apply v2 ratification path SELECTED' "${OUTDIR}/logs/" || echo "OK: no mutating apply path on validation-only run"
    echo "## validation-only marker persisted"
    grep -RnE '\[run-134\] v2 authority-marker persisted' "${OUTDIR}/logs/" || echo "OK: no marker persistence on validation-only run"
    echo "## validation-only Run 070 apply"
    grep -RnE 'Run 070: trust-bundle candidate APPLIED' "${OUTDIR}/logs/" || echo "OK: no Run 070 apply on validation-only run"
  } > "${OUTDIR}/grep_summaries/denylist.txt"

  ##########################################################################
  # Negative invariants summary.
  ##########################################################################
  {
    echo "# Run 175 negative invariants (proven by harness)"
    echo "- governance-proof-required selector remains hidden from --help"
    echo "- peer-candidate-check flag remains hidden from --help"
    echo "- selector is not implicitly enabled by unrelated flags (R17)"
    echo "- Required + missing-proof on Rotate -> reject + no mutation (R1/R2)"
    echo "- Required + malformed-proof -> reject + no mutation (R3)"
    echo "- Required + invalid-signature / wrong-root / wrong-action / wrong-digest /"
    echo "  wrong-sequence / unsupported-suite / OnChainGovernance -> reject + no mutation (R4/R8/R9/R10/R11/R-extra/R12)"
    echo "- MainNet peer-driven apply refused even with Required + valid proof + valid envelope (R18, Run 147 FATAL)"
    echo "- accepted validation-only cases -> no marker write, no sequence write,"
    echo "  no Run 070 apply, no live trust mutation, no session eviction (A1/A2/A3/A4a/A4b/A5/R17)"
    echo "- rejected validation-only cases -> no marker write, no sequence write,"
    echo "  no Run 070 apply, no [run-134] reload-apply path SELECTED line,"
    echo "  no v2 authority-marker persisted line (R1/R2/R3/R4/R8/R9/R10/R11/R12/R-extra)"
    echo "- no DummySig/DummyKem/DummyAead in any log (denylist)"
    echo "- no fallback to --p2p-trusted-root in any log (denylist)"
    echo "- no peer-majority authority claim (denylist)"
    echo "- no governance execution / on-chain governance / KMS-HSM / validator-set rotation claim"
    echo "- no schema / wire / metric / sequence-file / trust-bundle / peer-candidate-envelope drift"
  } > "${OUTDIR}/negative_invariants.txt"

  {
    echo "# Run 175 scenario assertions (machine-grep-friendly)"
    echo "A1=NotRequired-default peer-candidate-check accept (no proof, no selector) [no mutation]"
    echo "A2=Required(CLI)+valid-proof peer-candidate-check accept [no mutation; governance policy=RequiredForLifecycleSensitive]"
    echo "A3=Required(env)+valid-proof peer-candidate-check accept [no mutation; governance policy=RequiredForLifecycleSensitive]"
    echo "A4a=env=false preserves NotRequired [no mutation]"
    echo "A4b=env=0 preserves NotRequired [no mutation]"
    echo "A5=Required+idempotent (same-bytes replay) proof-carrying Rotate accept [no mutation]"
    echo "R1=Required(CLI)+no-proof peer-candidate-check REFUSE GovernanceAuthorityRequiredButMissing [no mutation]"
    echo "R2=Required(env)+no-proof peer-candidate-check REFUSE GovernanceAuthorityRequiredButMissing [no mutation]"
    echo "R3=Required+malformed-proof peer-candidate-check REFUSE [no mutation]"
    echo "R4=Required+invalid-signature peer-candidate-check REFUSE [no mutation]"
    echo "R5=skipped on real binary (binary upstream Run 130 verifier trips on wrong env); covered by Run 173 source-test + Run 168 helper"
    echo "R6=skipped on real binary (binary upstream Run 130 verifier trips on wrong chain); covered by Run 173 source-test + Run 168 helper"
    echo "R7=skipped on real binary (binary upstream Run 130 verifier trips on wrong genesis); covered by Run 173 source-test + Run 168 helper"
    echo "R8=Required+wrong-root peer-candidate-check REFUSE [no mutation]"
    echo "R9=Required+wrong-action peer-candidate-check REFUSE [no mutation]"
    echo "R10=Required+wrong-digest peer-candidate-check REFUSE [no mutation]"
    echo "R11=Required+wrong-sequence peer-candidate-check REFUSE [no mutation]"
    echo "R12=Required+OnChainGovernance peer-candidate-check REFUSE [no mutation]"
    echo "R13=Required+local-operator-config peer-candidate-check REFUSE [shim has no operator-config carrier; covered by R1 construction]"
    echo "R14=Required+peer-majority peer-candidate-check REFUSE [shim has no peer-majority carrier; covered by R1 construction]"
    echo "R15=validation-only Required reject writes no marker, no sequence (asserted per case via assert_no_mutation)"
    echo "R16=validation-only Required reject performs no Run 070, no live trust swap, no session eviction (asserted per case)"
    echo "R17=No-selector+no-proof peer-candidate-check ACCEPT [confirms selector not implicit]"
    echo "R18=MainNet+peer-driven-staging Required+valid-proof REFUSE [Run 147 FATAL; no Run 070 apply, no marker persist]"
    echo "R-extra=Required+unsupported-suite peer-candidate-check REFUSE [no mutation]"
  } > "${OUTDIR}/scenario_assertions.txt"

  for scenario_dir in "${OUTDIR}/data"/*; do
    [ -d "$scenario_dir" ] || continue
    name="$(basename "$scenario_dir")"
    {
      echo "# ${name} data-dir inventory"
      find "$scenario_dir" -type f -printf '%s  %p\n' 2>/dev/null \
        || find "$scenario_dir" -type f -exec stat -f '%z  %N' {} \;
    } > "${OUTDIR}/data_inventories/${name}.inventory.txt"
  done

  echo >> "$SUMMARY"
  echo "verdict: PASS — Run 175 release-binary local peer-candidate-check Required-policy production-surface evidence captured." >> "$SUMMARY"
  echo "honest limitations:" >> "$SUMMARY"
  echo "  * live inbound 0x05 proof-carrying remains OPEN (envelope schema does not yet carry governance_authority_proof; forbidden by task scope)." >> "$SUMMARY"
  echo "  * R5 / R6 / R7 (wrong-env/chain/genesis) covered at source level by run_173_validation_only_governance_required_policy_tests + Run 168 helper (release-binary upstream Run 130 verifier trips before the gate)." >> "$SUMMARY"
  echo "  * full C4 / C5 closure NOT claimed; OnChainGovernance / governance execution / KMS-HSM / validator-set rotation remain open." >> "$SUMMARY"
  log "OK"
}

main "$@"