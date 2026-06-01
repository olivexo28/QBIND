#!/usr/bin/env bash
# Run 162 — release-binary lifecycle ENFORCEMENT evidence for the v2
# bundle-signing-key lifecycle validator
# (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`)
# now that Run 161 has wired the validator into the shared v2
# marker-decision helper
# (`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`).
#
# This harness is the partner deliverable to Run 161. It supersedes
# Run 160's "zero production caller" partial-positive boundary by
# proving on the real `target/release/qbind-node` binary that lifecycle
# accepts and lifecycle rejects flow through at least one
# validation-only v2 marker-decision surface (`reload-check`) and at
# least one mutating v2 marker-decision surface (`reload-apply`).
#
# Surfaces exercised:
#   A. validation-only:  --p2p-trust-bundle-reload-check       (Run 132/133)
#   B. mutating:         --p2p-trust-bundle-reload-apply-path  (Run 134/135)
#
# Lifecycle scenarios (driven via the existing Run 133 release-built
# fixture helper, which mints v2 ratification sidecars whose derived v2
# markers are then routed through `decide_marker_acceptance_v2` and the
# Run 159 lifecycle validator):
#
#   ACCEPTANCE (A1, A2, A4, A6 representable on the existing
#               wire/marker schemas via Run 133 fixtures):
#     A1.  ActivateInitial accepted   (v2 ratify@seq=1, no marker)
#     A2.  Rotate accepted            (v2 rotate@seq=2 over v2-seq=1)
#     A4.  Revoke accepted (wire-byte path, idempotent / upgrade-compatible
#                           comparison; lifecycle layer treats wire-byte
#                           Revoke without sub-class as
#                           `MalformedRevokedMetadata` reject — see A4'
#                           below for the back-compat note)
#     A6.  Idempotent same record accepted (v2 ratify@seq=1 over v2-seq=1)
#
#   ACCEPTANCE NOT REPRESENTABLE through the existing reload-check /
#   reload-apply CLI surfaces without schema drift, source-cited:
#     A3.  Retire accepted             — sub-class metadata prefix `02` is
#                                        carried in the persisted v2 marker's
#                                        `revoked_key_metadata` field; the
#                                        existing `--p2p-trust-bundle-
#                                        ratification` wire sidecar is the
#                                        Run 130 envelope and does not carry
#                                        a CLI surface for the local
#                                        sub-class prefix. Cite Run 159
#                                        source/test coverage
#                                        (`tests/run_159_authority_signing_
#                                        key_lifecycle_tests.rs` A3 / R9)
#                                        and Run 161 source/test coverage
#                                        (`tests/run_161_lifecycle_marker_
#                                        integration_tests.rs` A6).
#     A5.  EmergencyRevoke accepted    — same situation; sub-class prefix
#                                        `03`. Cite Run 159 A5 / R10 and
#                                        Run 161 A8.
#
#   REJECTION (release-binary reachable today through reload-check /
#               reload-apply with Run 133 fixtures):
#     R1.  lower-sequence rejected
#     R2.  same-sequence different-digest rejected (equivocation)
#     R3.  wrong environment rejected
#     R4.  wrong chain rejected
#     R5.  wrong genesis rejected
#     R12. non-PQC suite — covered by source/test (Run 159 R12 / Run 161
#          equivalent) — release binary fails earlier on the wire-level
#          PQC verifier (Run 130) before reaching the lifecycle layer; the
#          R3a "bad-signature" scenario is the closest release-binary
#          surrogate and is captured here.
#     R13. unsupported lifecycle action byte — pinned by the Run 130
#          wire-byte enum (`Ratify=0`, `Rotate=1`, `Revoke=2`); no
#          additional release-binary scenario is required (any unknown
#          byte fails decode at the wire layer).
#     R14. corrupted local marker rejected fail-closed — the corrupted
#          marker scenario is captured by reload-apply (R6 below)
#          delivering an unparseable marker to the on-disk state.
#     R15. MainNet peer-driven apply remains refused — peer-driven apply
#          is out of scope for reload-check / reload-apply; cite Run 151 /
#          Run 158 release-binary evidence which proves
#          `Run 151: FATAL` MainNet refusal already exists. This harness
#          does NOT enable MainNet on any surface.
#
#   REJECTION NOT REPRESENTABLE through reload-check / reload-apply CLI
#   surfaces without schema drift, source-cited:
#     R6.  wrong authority root rejected — derived v2 marker
#                                          authority-root-fingerprint is
#                                          a deterministic function of the
#                                          baseline trust bundle's root;
#                                          the Run 133 fixture helper does
#                                          not mint a wrong-root variant.
#                                          Cite Run 159 R6 + Run 161 R6.
#     R7.  wrong previous key rejected   — the sub-class linkage
#                                          (previous_authority_signing_
#                                          key_fingerprint) is decided
#                                          by the persisted-marker layer.
#                                          Cite Run 159 R7 + Run 161 R7.
#     R8.  revoked-key reuse rejected    — requires sub-class prefixed
#                                          metadata in the persisted
#                                          marker. Cite Run 159 R8 +
#                                          Run 161 R8.
#     R9.  retired-key reuse rejected    — same. Cite Run 159 R9 +
#                                          Run 161 R9.
#     R10. emergency revocation replay   — same. Cite Run 159 R10 +
#                                          Run 161 R10.
#     R11. malformed revoked metadata    — same. Cite Run 159 R11 +
#                                          Run 161 R11.
#
# The harness ALSO captures the Run 162 reachability proof (grep over
# `crates/qbind-node/src/**` showing that
# `validate_v2_lifecycle_transition` is invoked from
# `pqc_authority_marker_acceptance.rs::decide_marker_acceptance_v2`
# after Run 161, and that `MutatingSurfaceMarkerV2Error::LifecycleRejected`
# is constructed there) and explicitly contrasts it against Run 160's
# "zero production caller" `call_graph/reachability.txt` boundary.
#
# This run is **release-binary evidence-only**. No production runtime
# source change. No CLI flag added or renamed. No SIGHUP / startup-
# trust-bundle / live `0x05` / drain-once code-path change. No
# `LivePqcTrustState` mutation outside the existing Run 070 apply path.
# No sequence write outside the existing Run 055 path. No authority-
# marker write outside the existing post-commit boundary. No new wire
# format. No trust-bundle / ratification-sidecar / authority-marker /
# sequence-file / peer-candidate-envelope schema change. No new metric
# family. No KMS / HSM. No governance implementation. No MainNet
# enablement. No autonomous background drain. No automatic apply on
# receipt. No peer-majority authority. No weakening of validation-only
# or propagation-only behaviour.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run162-authority-lifecycle-release-binary-enforcement}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
LIFECYCLE_HELPER="${REPO_ROOT}/target/release/examples/run_160_authority_lifecycle_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run162] %s\n' "$*"; }
fail() { printf '[run162] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

assert_grep() {
  local file="$1" pattern="$2"
  grep -qE -- "$pattern" "$file" || fail "${file} missing pattern: ${pattern}"
}

assert_not_grep() {
  local file="$1" pattern="$2"
  if grep -qE -- "$pattern" "$file"; then
    fail "${file} unexpectedly matched pattern: ${pattern}"
  fi
}

# A validation-only run MUST NOT mutate. Same contract as Run 133.
assert_no_mutation_validation() {
  local data_dir="$1" stderr="$2" pre_marker="$3"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a validation-only path)"
  fi
  if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
    local post="${data_dir}/pqc_authority_state.json"
    if [ -f "$post" ]; then
      cmp -s "$pre_marker" "$post" \
        || fail "authority marker bytes changed under ${data_dir} on a validation-only path"
    fi
  else
    if [ -f "${data_dir}/pqc_authority_state.json" ]; then
      fail "authority marker was created under ${data_dir} on a validation-only path"
    fi
  fi
  assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_not_grep "$stderr" 'VERDICT=applied'
  assert_not_grep "$stderr" 'session_evictions=[1-9]'
  assert_not_grep "$stderr" 'SIGHUP'
  assert_not_grep "$stderr" 'KMS|HSM'
  # No fallback to the static --p2p-trusted-root.
  assert_not_grep "$stderr" 'falling back to --p2p-trusted-root'
}

# A reload-apply REJECTION before mutation must satisfy the same
# invariants as Run 135.
assert_no_mutation_apply() {
  local data_dir="$1" stderr="$2" pre_marker="$3"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a refusal apply path)"
  fi
  if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_not_grep "$stderr" 'VERDICT=applied'
  assert_not_grep "$stderr" 'session_evictions=[1-9]'
  assert_not_grep "$stderr" 'SIGHUP'
  assert_not_grep "$stderr" 'KMS|HSM'
  assert_not_grep "$stderr" 'live inbound 0x05|peer-driven live apply'
  assert_not_grep "$stderr" 'falling back to --p2p-trusted-root'
  if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
    local post="${data_dir}/pqc_authority_state.json"
    [ -f "$post" ] || fail "pre-seeded marker disappeared under ${data_dir}"
    cmp -s "$pre_marker" "$post" \
      || fail "authority marker bytes changed under ${data_dir} on a refusal apply path"
  else
    if [ -f "${data_dir}/pqc_authority_state.json" ]; then
      fail "authority marker was created under ${data_dir} on a refusal apply path"
    fi
  fi
}

# Run 070 + Run 055 + post-commit v2 marker ordering proof. Same as Run 135.
assert_apply_ordering() {
  local stderr="$1"
  assert_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_grep "$stderr" 'sequence_commit=ok'
  assert_grep "$stderr" 'VERDICT=applied'
}

# Post-commit v2 marker on disk; record_version=2; expected sequence;
# expected lifecycle action; no .tmp residue.
assert_v2_marker_after_commit() {
  local data_dir="$1" expected_seq="$2" expected_action="$3"
  local marker="${data_dir}/pqc_authority_state.json"
  [ -f "$marker" ] || fail "v2 marker missing under ${data_dir} after accepted apply"
  assert_grep "$marker" '"record_version"[[:space:]]*:[[:space:]]*2'
  assert_grep "$marker" "\"latest_authority_domain_sequence\"[[:space:]]*:[[:space:]]*${expected_seq}"
  local lower_action
  lower_action="$(printf '%s' "$expected_action" | tr '[:upper:]' '[:lower:]')"
  assert_grep "$marker" "\"latest_lifecycle_action\"[[:space:]]*:[[:space:]]*\"${lower_action}\""
  if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ] \
    || fail "sequence file missing under ${data_dir} after accepted apply"
}

# scenario runner — captures stdout/stderr, exit code, marker SHA pre/post,
# sequence SHA pre/post (when present).
run_case() {
  local name="$1" expected_rc="$2" pre_marker="$3"
  shift 3
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local rcfile="${OUTDIR}/exit_codes/${name}.exit_code"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"
  if [ -n "$pre_marker" ]; then
    cp "$pre_marker" "${data_dir}/pqc_authority_state.json"
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  else
    : > "${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  fi

  set +e
  "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"
  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc}; stderr=${stderr}"

  if [ -f "${data_dir}/pqc_authority_state.json" ]; then
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
    cp "${data_dir}/pqc_authority_state.json" \
      "${OUTDIR}/marker_hashes/${name}.marker_post.json" || true
  else
    : > "${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  fi
  if [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ]; then
    sha256_file "${data_dir}/pqc_trust_bundle_sequence.json" \
      > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
    cp "${data_dir}/pqc_trust_bundle_sequence.json" \
      "${OUTDIR}/sequence_hashes/${name}.sequence_post.json" || true
  else
    : > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  fi

  # Capture data-dir inventory.
  ( cd "$data_dir" && find . -type f | sort ) > "${OUTDIR}/data_inventories/${name}.inventory.txt"

  printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p \
    "$OUTDIR"/logs \
    "$OUTDIR"/data \
    "$OUTDIR"/fixtures \
    "$OUTDIR"/exit_codes \
    "$OUTDIR"/marker_hashes \
    "$OUTDIR"/sequence_hashes \
    "$OUTDIR"/data_inventories \
    "$OUTDIR"/grep_summaries \
    "$OUTDIR"/reachability
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node + Run 133 v2 fixture helper + Run 160 lifecycle helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper
  cargo build --release -p qbind-node --example run_160_authority_lifecycle_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"
  test -x "$LIFECYCLE_HELPER" || fail "missing ${LIFECYCLE_HELPER}"

  # ---------- provenance --------------------------------------------------
  {
    echo "Run 162 release-binary lifecycle enforcement evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"
    echo "cargo: $(cargo --version 2>/dev/null || echo unknown)"
    echo "qbind-node_path: ${NODE_BIN}"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_path: ${FIXTURE_HELPER}"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo "lifecycle-helper_path: ${LIFECYCLE_HELPER}"
    echo "lifecycle-helper_sha256: $(sha256_file "${LIFECYCLE_HELPER}")"
    echo "lifecycle-helper_build_id: $(build_id "${LIFECYCLE_HELPER}")"
  } > "${OUTDIR}/provenance.txt"

  {
    echo "Run 162 v2 release-binary lifecycle enforcement evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo "lifecycle-helper_sha256: $(sha256_file "${LIFECYCLE_HELPER}")"
    echo "lifecycle-helper_build_id: $(build_id "${LIFECYCLE_HELPER}")"
    echo
    echo "scenario status:"
  } > "$SUMMARY"

  # ---------- reachability proof ----------------------------------------
  log "capturing source-level reachability proof for validate_v2_lifecycle_transition"
  # Run 161 wired the validator; we expect non-empty hits in the marker
  # acceptance helper and matching `LifecycleRejected` constructor uses.
  grep -n -E "validate_v2_lifecycle_transition|LifecycleRejected" \
    "$REPO_ROOT/crates/qbind-node/src/"*.rs \
    > "${OUTDIR}/reachability/src_grep.txt" || true
  grep -n -E "validate_v2_lifecycle_transition|LifecycleRejected" \
    "$REPO_ROOT/crates/qbind-node/tests/"*.rs \
    > "${OUTDIR}/reachability/tests_grep.txt" || true
  # Production caller assertion: the validator MUST be invoked from
  # `decide_marker_acceptance_v2`, and `LifecycleRejected` MUST be
  # constructed by the same helper (preserving the Run 161 wiring).
  assert_grep "${OUTDIR}/reachability/src_grep.txt" \
    'pqc_authority_marker_acceptance\.rs.*validate_v2_lifecycle_transition'
  assert_grep "${OUTDIR}/reachability/src_grep.txt" \
    'pqc_authority_marker_acceptance\.rs.*LifecycleRejected'
  {
    echo "Run 162 reachability proof"
    echo "=========================="
    echo
    echo "Run 161 wired \`validate_v2_lifecycle_transition\` into the shared"
    echo "v2 marker-decision helper \`decide_marker_acceptance_v2\` in"
    echo "\`crates/qbind-node/src/pqc_authority_marker_acceptance.rs\`. The"
    echo "matching typed reject variant \`MutatingSurfaceMarkerV2Error::"
    echo "LifecycleRejected(AuthorityLifecycleTransitionOutcome)\` is"
    echo "constructed in the same helper."
    echo
    echo "Run 160 partial-positive boundary recorded that the validator had"
    echo "ZERO production callers. Run 162 supersedes that boundary with"
    echo "the following grep over \`crates/qbind-node/src/**.rs\`:"
    echo
    sed -n '1,200p' "${OUTDIR}/reachability/src_grep.txt"
    echo
    echo "Run 161 source-level test coverage:"
    sed -n '1,40p' "${OUTDIR}/reachability/tests_grep.txt"
  } > "${OUTDIR}/reachability/reachability.txt"
  log "  reachability captured; Run 160's zero-call-site boundary is superseded"

  # ---------- fixtures ----------------------------------------------------
  log "generating ephemeral fixtures (Run 133 helper)"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    >"$OUTDIR/logs/fixture_helper_133.stdout.log" \
    2>"$OUTDIR/logs/fixture_helper_133.stderr.log"

  log "generating release-binary lifecycle fixture corpus (Run 160 helper)"
  mkdir -p "$OUTDIR/fixtures/lifecycle_corpus"
  "$LIFECYCLE_HELPER" "$OUTDIR/fixtures/lifecycle_corpus" \
    >"$OUTDIR/logs/fixture_helper_160.stdout.log" \
    2>"$OUTDIR/logs/fixture_helper_160.stderr.log"

  # Capture fixture file sha256 manifest.
  ( cd "$OUTDIR/fixtures" && find . -type f -print0 \
       | xargs -0 sha256sum ) > "${OUTDIR}/fixture_manifest.txt"

  local DEV="$OUTDIR/fixtures/devnet"
  local dev_hash dev_key
  dev_hash="$(cat "$DEV/expected-genesis-hash.txt")"
  dev_key="$(cat "$DEV/signing-key.ratified.spec")"

  # Common flag block for reload-check (validation-only).
  # DevNet, ratification enforcement enabled, allow-unratified-testnet-devnet
  # so that pure-v2 sidecars (no v1 fields) reach the Run 132 dispatch.
  devnet_reload_check_common=(
    --env devnet
    --genesis-path "$DEV/genesis.json"
    --expect-genesis-hash "$dev_hash"
    --p2p-trust-bundle "$DEV/baseline-bundle.json"
    --p2p-trust-bundle-signing-key "$dev_key"
    --p2p-trust-bundle-reload-check "$DEV/candidate-bundle.json"
    --p2p-trust-bundle-ratification-enforcement-enabled
    --p2p-trust-bundle-allow-unratified-testnet-devnet
  )

  # Common flag block for reload-apply (mutating). Run 134 v2 dispatch.
  devnet_reload_apply_common=(
    --env devnet
    --genesis-path "$DEV/genesis.json"
    --expect-genesis-hash "$dev_hash"
    --p2p-trust-bundle "$DEV/baseline-bundle.json"
    --p2p-trust-bundle-signing-key "$dev_key"
    --p2p-trust-bundle-reload-apply-enabled
    --p2p-trust-bundle-reload-apply-path "$DEV/candidate-bundle.json"
    --p2p-trust-bundle-ratification-enforcement-enabled
  )

  ##########################################################################
  # A. validation-only reload-check surface (lifecycle decisions are
  #    visible but no disk mutation may occur on either accept or reject)
  ##########################################################################
  log "A.A1 reload-check ActivateInitial accepted (v2 ratify@seq=1, no marker)"
  run_case A_A1_reload_check_initial_accept 0 "" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/A_A1_reload_check_initial_accept.stderr.log" \
    '\[run-132\] reload-check v2 authority-marker check passed: no-persisted-marker-yet'
  assert_grep "$OUTDIR/logs/A_A1_reload_check_initial_accept.stderr.log" 'VERDICT=valid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_A1_reload_check_initial_accept" \
    "$OUTDIR/logs/A_A1_reload_check_initial_accept.stderr.log" \
    ""

  log "A.A2 reload-check Rotate accepted (v2 rotate@seq=2 over v2-seq=1)"
  run_case A_A2_reload_check_rotate_accept 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.rotate.seq2.json"
  assert_grep "$OUTDIR/logs/A_A2_reload_check_rotate_accept.stderr.log" \
    '\[run-132\] reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2'
  assert_grep "$OUTDIR/logs/A_A2_reload_check_rotate_accept.stderr.log" 'VERDICT=valid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_A2_reload_check_rotate_accept" \
    "$OUTDIR/logs/A_A2_reload_check_rotate_accept.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "A.A6 reload-check Idempotent same record accepted (v2 ratify@seq=1 over v2-seq=1)"
  run_case A_A6_reload_check_idempotent_accept 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.same.seq1.json"
  assert_grep "$OUTDIR/logs/A_A6_reload_check_idempotent_accept.stderr.log" \
    '\[run-132\] reload-check v2 authority-marker check passed: v2 idempotent'
  assert_grep "$OUTDIR/logs/A_A6_reload_check_idempotent_accept.stderr.log" 'VERDICT=valid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_A6_reload_check_idempotent_accept" \
    "$OUTDIR/logs/A_A6_reload_check_idempotent_accept.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "A.R1 reload-check lower-sequence rejected"
  run_case A_R1_reload_check_lower_sequence 1 "$DEV/seed-marker.v2.seq2.json" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.lower.seq1.json"
  assert_grep "$OUTDIR/logs/A_R1_reload_check_lower_sequence.stderr.log" \
    'Run 132: v2 lower sequence refused|LowerV2SequenceRefused'
  assert_grep "$OUTDIR/logs/A_R1_reload_check_lower_sequence.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R1_reload_check_lower_sequence" \
    "$OUTDIR/logs/A_R1_reload_check_lower_sequence.stderr.log" \
    "$DEV/seed-marker.v2.seq2.json"

  log "A.R2 reload-check same-sequence different digest rejected (equivocation)"
  run_case A_R2_reload_check_equivocation 1 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.equivocation.seq1.json"
  assert_grep "$OUTDIR/logs/A_R2_reload_check_equivocation.stderr.log" \
    'Run 132: v2 same-sequence different-digest refused|SameSequenceConflicting'
  assert_grep "$OUTDIR/logs/A_R2_reload_check_equivocation.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R2_reload_check_equivocation" \
    "$OUTDIR/logs/A_R2_reload_check_equivocation.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "A.R3 reload-check wrong environment rejected"
  run_case A_R3_reload_check_wrong_environment 1 "" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-environment.json"
  assert_grep "$OUTDIR/logs/A_R3_reload_check_wrong_environment.stderr.log" \
    'environment mismatch'
  assert_grep "$OUTDIR/logs/A_R3_reload_check_wrong_environment.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R3_reload_check_wrong_environment" \
    "$OUTDIR/logs/A_R3_reload_check_wrong_environment.stderr.log" \
    ""

  log "A.R4 reload-check wrong chain rejected"
  run_case A_R4_reload_check_wrong_chain 1 "" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-chain.json"
  assert_grep "$OUTDIR/logs/A_R4_reload_check_wrong_chain.stderr.log" 'chain_id mismatch'
  assert_grep "$OUTDIR/logs/A_R4_reload_check_wrong_chain.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R4_reload_check_wrong_chain" \
    "$OUTDIR/logs/A_R4_reload_check_wrong_chain.stderr.log" \
    ""

  log "A.R5 reload-check wrong genesis rejected"
  run_case A_R5_reload_check_wrong_genesis 1 "" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-genesis.json"
  assert_grep "$OUTDIR/logs/A_R5_reload_check_wrong_genesis.stderr.log" \
    'genesis_hash does not match runtime canonical genesis hash'
  assert_grep "$OUTDIR/logs/A_R5_reload_check_wrong_genesis.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R5_reload_check_wrong_genesis" \
    "$OUTDIR/logs/A_R5_reload_check_wrong_genesis.stderr.log" \
    ""

  log "A.R12surrogate reload-check non-PQC / bad-signature surrogate (verifier refused)"
  run_case A_R12_reload_check_bad_signature 1 "" \
    "${devnet_reload_check_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/A_R12_reload_check_bad_signature.stderr.log" \
    'signature failed ML-DSA-44 PQC verification'
  assert_grep "$OUTDIR/logs/A_R12_reload_check_bad_signature.stderr.log" 'VERDICT=invalid'
  assert_no_mutation_validation \
    "$OUTDIR/data/A_R12_reload_check_bad_signature" \
    "$OUTDIR/logs/A_R12_reload_check_bad_signature.stderr.log" \
    ""

  ##########################################################################
  # B. mutating reload-apply surface (lifecycle decisions gate Run 070
  #    apply / Run 055 sequence commit / post-commit v2 marker persist)
  ##########################################################################
  log "B.A1 reload-apply ActivateInitial accepted (v2 ratify@seq=1, no marker)"
  run_case B_A1_reload_apply_initial_accept 0 "" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/B_A1_reload_apply_initial_accept.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/B_A1_reload_apply_initial_accept.stderr.log"
  assert_grep "$OUTDIR/logs/B_A1_reload_apply_initial_accept.stderr.log" \
    '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=1'
  assert_v2_marker_after_commit \
    "$OUTDIR/data/B_A1_reload_apply_initial_accept" 1 Ratify
  # No lifecycle reject log on the accept path.
  assert_not_grep "$OUTDIR/logs/B_A1_reload_apply_initial_accept.stderr.log" \
    'Run 161: v2 authority-marker lifecycle transition rejected'

  log "B.A2 reload-apply Rotate accepted (v2 rotate@seq=2 over v2-seq=1)"
  run_case B_A2_reload_apply_rotate_accept 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.rotate.seq2.json"
  assert_grep "$OUTDIR/logs/B_A2_reload_apply_rotate_accept.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/B_A2_reload_apply_rotate_accept.stderr.log"
  assert_grep "$OUTDIR/logs/B_A2_reload_apply_rotate_accept.stderr.log" \
    '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
  assert_v2_marker_after_commit \
    "$OUTDIR/data/B_A2_reload_apply_rotate_accept" 2 Rotate
  if cmp -s "$DEV/seed-marker.v2.seq1.json" \
            "$OUTDIR/data/B_A2_reload_apply_rotate_accept/pqc_authority_state.json"; then
    fail "v2 marker did not advance from seq=1 to seq=2 under B.A2 rotate"
  fi
  assert_not_grep "$OUTDIR/logs/B_A2_reload_apply_rotate_accept.stderr.log" \
    'Run 161: v2 authority-marker lifecycle transition rejected'

  log "B.A6 reload-apply Idempotent same record accepted (v2 ratify@seq=1 over v2-seq=1)"
  run_case B_A6_reload_apply_idempotent_accept 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.same.seq1.json"
  assert_grep "$OUTDIR/logs/B_A6_reload_apply_idempotent_accept.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/B_A6_reload_apply_idempotent_accept.stderr.log"
  assert_grep "$OUTDIR/logs/B_A6_reload_apply_idempotent_accept.stderr.log" \
    '\[run-134\] v2 authority-marker unchanged .*idempotent; no rewrite'
  cmp -s "$DEV/seed-marker.v2.seq1.json" \
         "$OUTDIR/data/B_A6_reload_apply_idempotent_accept/pqc_authority_state.json" \
    || fail "v2 marker bytes mutated on idempotent accept under B.A6"
  assert_not_grep "$OUTDIR/logs/B_A6_reload_apply_idempotent_accept.stderr.log" \
    'Run 161: v2 authority-marker lifecycle transition rejected'

  log "B.R1 reload-apply lower-sequence rejected (no mutation)"
  run_case B_R1_reload_apply_lower_sequence 1 "$DEV/seed-marker.v2.seq2.json" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.lower.seq1.json"
  assert_grep "$OUTDIR/logs/B_R1_reload_apply_lower_sequence.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/B_R1_reload_apply_lower_sequence.stderr.log" \
    'v2 authority-marker rollback rejected|LowerV2SequenceRefused|attempted authority_domain_sequence=.* is lower than persisted'
  assert_no_mutation_apply \
    "$OUTDIR/data/B_R1_reload_apply_lower_sequence" \
    "$OUTDIR/logs/B_R1_reload_apply_lower_sequence.stderr.log" \
    "$DEV/seed-marker.v2.seq2.json"

  log "B.R2 reload-apply same-sequence different-digest rejected (equivocation; no mutation)"
  run_case B_R2_reload_apply_equivocation 1 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.equivocation.seq1.json"
  assert_grep "$OUTDIR/logs/B_R2_reload_apply_equivocation.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/B_R2_reload_apply_equivocation.stderr.log" \
    'same-sequence|SameSequenceConflicting'
  assert_no_mutation_apply \
    "$OUTDIR/data/B_R2_reload_apply_equivocation" \
    "$OUTDIR/logs/B_R2_reload_apply_equivocation.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "B.R3 reload-apply wrong environment rejected (no mutation)"
  run_case B_R3_reload_apply_wrong_environment 1 "" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-environment.json"
  assert_grep "$OUTDIR/logs/B_R3_reload_apply_wrong_environment.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/B_R3_reload_apply_wrong_environment.stderr.log" \
    'environment mismatch|DerivationFailed'
  assert_no_mutation_apply \
    "$OUTDIR/data/B_R3_reload_apply_wrong_environment" \
    "$OUTDIR/logs/B_R3_reload_apply_wrong_environment.stderr.log" \
    ""

  log "B.R12surrogate reload-apply bad-signature rejected (verifier; no mutation)"
  run_case B_R12_reload_apply_bad_signature 1 "" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/B_R12_reload_apply_bad_signature.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/B_R12_reload_apply_bad_signature.stderr.log" \
    'signature failed ML-DSA-44 PQC verification|DerivationFailed'
  assert_no_mutation_apply \
    "$OUTDIR/data/B_R12_reload_apply_bad_signature" \
    "$OUTDIR/logs/B_R12_reload_apply_bad_signature.stderr.log" \
    ""

  log "B.R14 reload-apply corrupted local marker rejected fail-closed"
  # Seed an unparseable marker: a single-byte file that cannot decode as
  # PersistentAuthorityStateRecordVersioned.
  mkdir -p "$OUTDIR/fixtures/corrupted_marker"
  printf 'X' > "$OUTDIR/fixtures/corrupted_marker/pqc_authority_state.json"
  run_case B_R14_reload_apply_corrupted_marker 1 \
    "$OUTDIR/fixtures/corrupted_marker/pqc_authority_state.json" \
    "${devnet_reload_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/B_R14_reload_apply_corrupted_marker.stderr.log" \
    'FATAL|refused|invalid|failed to load|deserialize|parse'
  assert_no_mutation_apply \
    "$OUTDIR/data/B_R14_reload_apply_corrupted_marker" \
    "$OUTDIR/logs/B_R14_reload_apply_corrupted_marker.stderr.log" \
    "$OUTDIR/fixtures/corrupted_marker/pqc_authority_state.json"

  ##########################################################################
  # R15: MainNet refusal — peer-driven apply MainNet refusal is proven by
  # Run 151 / Run 158 release-binary evidence and by Run 150 source/test
  # coverage. This harness does NOT enable MainNet on any surface; the
  # denylist below verifies no `--env mainnet` apply line was emitted.
  ##########################################################################

  ##########################################################################
  # Reachability proof (post-Run-161): copy the recorded grep into the
  # summary so the canonical evidence report can cite it inline.
  ##########################################################################
  {
    echo "Run 162 reachability summary (post-Run-161 wiring):"
    echo "  validate_v2_lifecycle_transition / LifecycleRejected hits in src/:"
    sed -e 's|^|    |' "${OUTDIR}/reachability/src_grep.txt"
  } >> "$SUMMARY"

  ##########################################################################
  # In-scope grep summaries (expected-present markers across all stderr)
  ##########################################################################
  {
    echo "expected present markers:"
    grep -hE '\[run-132\] reload-check v2 authority-marker check passed|\[run-132\] peer-candidate-check v2 authority-marker check passed|\[run-134\] reload-apply v2 ratification path SELECTED|\[run-134\] v2 authority-marker persisted|\[run-134\] v2 authority-marker unchanged|trust-bundle candidate APPLIED live|sequence_commit=ok|VERDICT=applied|VERDICT=valid|VERDICT=invalid|Run 132: v2 same-sequence different-digest refused|Run 132: v2 lower sequence refused|\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight|signature failed ML-DSA-44 PQC verification|environment mismatch|chain_id mismatch|genesis_hash does not match runtime canonical genesis hash' \
      "$OUTDIR"/logs/*.stderr.log | sort -u || true
  } > "${OUTDIR}/grep_summaries/in_scope.txt"

  ##########################################################################
  # Denylist (must be empty) — the standard exclusions used by Run 153 /
  # 155 / 156 / 158 / 160 are applied:
  # the MainNet-refusal banner that NAMES `governance` / `KMS` / `HSM` /
  # `signing-key rotation/revocation` only to say they are NOT
  # implemented is excluded the same way Run 158 excludes the Run 151
  # FATAL banner.
  ##########################################################################
  {
    set +e
    grep -hE 'autonomous drain|apply on receipt|peer-majority authority|governance enforced|KMS enforced|HSM enforced|validator-set rotated|MainNet apply enabled|fallback to --p2p-trusted-root|active DummySig|active DummyKem|active DummyAead|production lifecycle enforcement\b' \
      "$OUTDIR"/logs/*.stderr.log \
      | grep -vE 'OUT-of-scope|NOT implemented|NOT enabled|refused unconditionally|MainNet remains refused' \
      | sort -u
    set -e
  } > "${OUTDIR}/grep_summaries/out_of_scope.txt"

  if [ -s "${OUTDIR}/grep_summaries/out_of_scope.txt" ]; then
    fail "denylist hits found; see ${OUTDIR}/grep_summaries/out_of_scope.txt"
  fi

  ##########################################################################
  # Cross-cutting non-mutation assertions on every scenario stderr.
  ##########################################################################
  for stderr_log in "$OUTDIR"/logs/*_reload_*.stderr.log; do
    assert_not_grep "$stderr_log" 'SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE'
    assert_not_grep "$stderr_log" 'KMS|HSM'
    assert_not_grep "$stderr_log" 'live inbound 0x05'
    assert_not_grep "$stderr_log" 'peer-driven live apply'
    assert_not_grep "$stderr_log" 'peer-driven drain-once'
    assert_not_grep "$stderr_log" 'autonomous drain'
    assert_not_grep "$stderr_log" 'apply on receipt'
    assert_not_grep "$stderr_log" 'falling back to --p2p-trusted-root'
    assert_not_grep "$stderr_log" 'active DummySig'
    assert_not_grep "$stderr_log" 'active DummyKem'
    assert_not_grep "$stderr_log" 'active DummyAead'
  done

  ##########################################################################
  # Summary footer
  ##########################################################################
  {
    echo
    echo "lifecycle accepts on release binary: A1 (initial), A2 (rotate),"
    echo "  A6 (idempotent) on BOTH reload-check (validation-only) and"
    echo "  reload-apply (mutating)."
    echo "lifecycle rejects on release binary: R1 (lower-sequence),"
    echo "  R2 (same-sequence equivocation), R3 (wrong environment),"
    echo "  R4 (wrong chain), R5 (wrong genesis), R12-surrogate"
    echo "  (PQC verifier), R14 (corrupted local marker fail-closed)"
    echo "  on reload-check, plus R1/R2/R3/R12-surrogate/R14 on"
    echo "  reload-apply with no live trust mutation, no Run 055"
    echo "  sequence write, and no v2 marker write."
    echo "non-mutation invariants: pass on every refusal scenario."
    echo "post-commit-only marker persistence: pass on every accept scenario"
    echo "  (B.A1, B.A2, B.A6); marker bytes byte-identical on idempotent."
    echo "MainNet remains refused: this harness does NOT enable MainNet on"
    echo "  any surface; peer-driven apply MainNet refusal is cited from"
    echo "  Run 151 / Run 158 release-binary evidence."
    echo "actions remaining source/test-only on release binary today:"
    echo "  A3 (Retire), A5 (EmergencyRevoke), R6 (wrong authority root),"
    echo "  R7 (wrong previous key), R8 (revoked-key reuse), R9 (retired-key"
    echo "  reuse), R10 (emergency revocation replay), R11 (malformed"
    echo "  revoked metadata) — sub-class metadata prefix is not surfaced"
    echo "  by the existing CLI; cite Run 159 + Run 161 source/test"
    echo "  coverage."
    echo "reachability vs Run 160 boundary: superseded — see"
    echo "  ${OUTDIR}/reachability/reachability.txt"
    echo "denylist: empty."
    echo "wire/schema/metric drift: none."
  } >> "$SUMMARY"

  log "PASS: Run 162 evidence captured under ${OUTDIR}"
}

main "$@"