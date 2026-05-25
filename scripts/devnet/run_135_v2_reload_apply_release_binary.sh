#!/usr/bin/env bash
# Run 135 — release-binary evidence matrix for the v2 (ratification-v2)
# process-start reload-apply MUTATING binary surface (Run 134 wiring).
#
# Evidence-only. This harness does NOT change production runtime code and
# does NOT touch any wire format. It exercises BOTH the v1 sidecar
# fall-through path (regression: Run 112/Run 113/Run 119) and the v2
# sidecar dispatch (Run 134) against ephemeral DevNet fixtures minted by
# `run_133_v2_validation_only_fixture_helper`.
#
# Scenario matrix (DevNet `--p2p-trust-bundle-reload-apply-path`):
#   acceptance:
#     A1.  v2 ratify@seq=1, no marker       → first v2 write succeeds,
#                                              v2 marker persisted after
#                                              `commit_sequence`.
#     A2.  v2 ratify@seq=2, v1 marker       → v2-after-v1 migration
#                                              succeeds, v2 marker
#                                              replaces v1 only after
#                                              `commit_sequence`.
#     A3.  v2 ratify@seq=1, v2-seq=1 marker → idempotent same-digest;
#                                              succeeds; marker bytes
#                                              remain byte-identical.
#     A4.  v2 ratify@seq=2, v2-seq=1 marker → higher-sequence upgrade
#                                              succeeds; marker advances
#                                              ONLY after commit.
#   rejection (must occur BEFORE any mutation):
#     R1.  v2 ratify@seq=1, v2-seq=2 marker → lower-sequence refused.
#     R2.  v2 ratify@seq=1 (rotated target),
#          v2-seq=1 marker (active target)  → same-seq different-digest
#                                              refused (equivocation).
#     R3a. v2 bad-signature                 → verifier refused.
#     R3b. v2 wrong-environment             → verifier refused.
#     R4.  apply failure after preflight    → covered by Run 134 §C.3
#                                              test-only (FakeLiveTrust
#                                              ApplyContext); release
#                                              binary cannot trigger a
#                                              deterministic post-
#                                              preflight apply failure.
#   v1 regression:
#     V1.  v1 valid ratification, no marker → Run 119/Run 112 v1 reload-
#                                              apply succeeds; v1 marker
#                                              persisted; NO v2 marker
#                                              path logs are observed.
#
# For every scenario this harness also asserts:
#   * post-run marker bytes match the EXPECTED state (seeded-and-
#     unchanged on rejection / idempotent; advanced-only-after-commit on
#     accept);
#   * no `.tmp` marker sibling is left behind;
#   * no SIGHUP / live-`0x05` / KMS / HSM / peer-driven-apply markers
#     are emitted on any path.
#
# No SIGHUP, no startup-trust-bundle v2 wiring, no live inbound `0x05`
# v2 wiring, no peer-driven live apply, no signing-key rotation/
# revocation, no KMS/HSM, no governance, no trust-bundle wire format
# change, no peer-candidate wire format change.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run135-v2-reload-apply-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run135] %s\n' "$*"; }
fail() { printf '[run135] FAIL: %s\n' "$*" >&2; exit 1; }
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

# --- common rejection invariants --------------------------------------------
# A reload-apply REJECTION before mutation must satisfy ALL of:
#   * no sequence-persistence file written under the scenario data dir;
#   * no Run 070 canonical APPLIED log line;
#   * no Run 073 VERDICT=applied marker;
#   * no session-eviction marker;
#   * no `.tmp` marker sibling;
#   * pre-seeded marker bytes (if any) are byte-identical post-run;
#   * if no pre-seeded marker existed, no marker is created.
assert_no_mutation() {
  local data_dir="$1" stderr="$2" pre_marker="$3"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a refusal path)"
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
  if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
    local post="${data_dir}/pqc_authority_state.json"
    [ -f "$post" ] || fail "pre-seeded marker disappeared under ${data_dir}"
    cmp -s "$pre_marker" "$post" \
      || fail "authority marker bytes changed under ${data_dir} on a refusal path"
  else
    if [ -f "${data_dir}/pqc_authority_state.json" ]; then
      fail "authority marker was created under ${data_dir} on a refusal path"
    fi
  fi
}

# --- common accept-apply invariants -----------------------------------------
# An accepted v1 OR v2 reload-apply must show the Run 070 canonical applied
# log line AND the Run 073 VERDICT=applied marker together. The two together
# prove `validate → snapshot → swap → evict_sessions → commit_sequence`
# order survived: the canonical line is emitted only by
# `AppliedCandidate::applied_log_line`, which `apply_post_validation` only
# returns after the full four-step pipeline completes (see Run 112 / Run 070
# docs).
assert_apply_ordering() {
  local stderr="$1"
  assert_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_grep "$stderr" 'sequence_commit=ok'
  assert_grep "$stderr" 'VERDICT=applied'
}

# --- v2 marker persistence invariants --------------------------------------
# Assert that after a v2-accepted reload-apply the on-disk marker exists,
# loads back as V2, and contains the expected `latest_authority_domain_
# sequence` and `latest_lifecycle_action`. Run 134 §2.1 documents the
# `record_version=2` discriminator carried by `PersistentAuthorityStateRecord
# V2`. We grep the JSON file directly (the file is a serde-json `_pretty`
# blob with one field per line).
assert_v2_marker_after_commit() {
  local data_dir="$1" expected_seq="$2" expected_action="$3"
  local marker="${data_dir}/pqc_authority_state.json"
  [ -f "$marker" ] || fail "v2 marker missing under ${data_dir} after accepted apply"
  assert_grep "$marker" '"record_version"[[:space:]]*:[[:space:]]*2'
  assert_grep "$marker" "\"latest_authority_domain_sequence\"[[:space:]]*:[[:space:]]*${expected_seq}"
  # latest_lifecycle_action is serialized lowercase (serde rename_all = snake_case).
  local lower_action
  lower_action="$(printf '%s' "$expected_action" | tr '[:upper:]' '[:lower:]')"
  assert_grep "$marker" "\"latest_lifecycle_action\"[[:space:]]*:[[:space:]]*\"${lower_action}\""
  if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  # Sequence file must exist because commit_sequence ran.
  [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ] \
    || fail "sequence file missing under ${data_dir} after accepted apply"
}

assert_v1_marker_after_commit() {
  local data_dir="$1"
  local marker="${data_dir}/pqc_authority_state.json"
  [ -f "$marker" ] || fail "v1 marker missing under ${data_dir} after accepted apply"
  # v1 uses `record_version`/`authority_schema_version` = 1.
  assert_grep "$marker" '"record_version"[[:space:]]*:[[:space:]]*1'
  [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ] \
    || fail "sequence file missing under ${data_dir} after accepted v1 apply"
}

# --- scenario runner -------------------------------------------------------
# pre_marker — path to a marker JSON to copy in before the run (or "").
# expected_marker — path to a file whose bytes should match the
#   pqc_authority_state.json file AFTER the run (or "" for "no marker").
#   For acceptance scenarios that advance the marker, this is left empty
#   and we rely on `assert_v2_marker_after_commit` / individual asserts.
run_case() {
  local name="$1" expected_rc="$2" pre_marker="$3"
  shift 3
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local rcfile="${OUTDIR}/logs/${name}.exit_code"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"
  if [ -n "$pre_marker" ]; then
    cp "$pre_marker" "${data_dir}/pqc_authority_state.json"
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/logs/${name}.marker_pre.sha256"
  else
    : > "${OUTDIR}/logs/${name}.marker_pre.sha256"
  fi

  set +e
  "$NODE_BIN" "$@" --data-dir "$data_dir" >"$stdout" 2>"$stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"
  [ "$rc" = "$expected_rc" ] || fail "${name} expected rc=${expected_rc}, got rc=${rc}; stderr=${stderr}"

  if [ -f "${data_dir}/pqc_authority_state.json" ]; then
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/logs/${name}.marker_post.sha256"
  else
    : > "${OUTDIR}/logs/${name}.marker_post.sha256"
  fi
  printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and Run 133 v2 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 135 v2 reload-apply release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo
    echo "scenario status:"
  } > "$SUMMARY"

  log "generating ephemeral fixtures (Run 133 helper)"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    >"$OUTDIR/logs/fixture_helper.stdout.log" \
    2>"$OUTDIR/logs/fixture_helper.stderr.log"

  local DEV="$OUTDIR/fixtures/devnet"
  local dev_hash dev_key
  dev_hash="$(cat "$DEV/expected-genesis-hash.txt")"
  dev_key="$(cat "$DEV/signing-key.ratified.spec")"

  # Common flag block for reload-apply: DevNet, ratification-enforcement
  # enabled so `gate_decision.should_invoke()` is true and the v1/v2
  # ratification ctx is built. On the apply path the v2 dispatch fires
  # directly from `ctx_data.ratification_v2.is_some()` (Run 134 §2.3) —
  # no v1 enforcer runs ahead of it, so the v1-bypass escape hatch is
  # not needed here (unlike the Run 133 validation-only reload-check
  # path, see scripts/devnet/run_133_v2_validation_only_release_binary.sh
  # comment block).
  devnet_apply_common=(
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
  # Acceptance scenarios
  ##########################################################################
  log "Scenario A1: v2 ratify@seq=1, no marker (first v2 write)"
  run_case scenario_A1_v2_first_write 0 "" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log"
  assert_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=1'
  assert_not_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-119\] authority-marker persisted'
  assert_v2_marker_after_commit \
    "$OUTDIR/data/scenario_A1_v2_first_write" 1 Ratify

  log "Scenario A2: v2 ratify@seq=2, v1 marker (v2-after-v1 migration)"
  run_case scenario_A2_v2_after_v1_migration 0 "$DEV/seed-marker.v1.json" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log"
  assert_grep "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
  assert_v2_marker_after_commit \
    "$OUTDIR/data/scenario_A2_v2_after_v1_migration" 2 Ratify
  # The seed v1 marker must NOT survive — it was replaced by a v2 record.
  if cmp -s "$DEV/seed-marker.v1.json" \
            "$OUTDIR/data/scenario_A2_v2_after_v1_migration/pqc_authority_state.json"; then
    fail "v1 marker was not migrated to v2 under scenario A2"
  fi

  log "Scenario A3: v2 ratify@seq=1 with v2-seq=1 marker (idempotent)"
  run_case scenario_A3_v2_idempotent 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.same.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log"
  assert_grep "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[run-134\] v2 authority-marker unchanged .*idempotent; no rewrite'
  cmp -s "$DEV/seed-marker.v2.seq1.json" \
         "$OUTDIR/data/scenario_A3_v2_idempotent/pqc_authority_state.json" \
    || fail "v2 marker bytes mutated on idempotent path under A3"

  log "Scenario A4: v2 ratify@seq=2 with v2-seq=1 marker (higher-sequence upgrade)"
  run_case scenario_A4_v2_higher_sequence 0 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_apply_ordering "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log"
  assert_grep "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
  assert_v2_marker_after_commit \
    "$OUTDIR/data/scenario_A4_v2_higher_sequence" 2 Ratify
  # Marker must NOT match the seeded seq=1 marker bytes anymore.
  if cmp -s "$DEV/seed-marker.v2.seq1.json" \
            "$OUTDIR/data/scenario_A4_v2_higher_sequence/pqc_authority_state.json"; then
    fail "v2 marker did not advance from seq=1 to seq=2 under A4"
  fi

  ##########################################################################
  # Rejection scenarios — all must reject BEFORE any mutation
  ##########################################################################
  log "Scenario R1: v2 ratify@seq=1 with v2-seq=2 marker (lower-sequence refused)"
  run_case scenario_R1_v2_lower_sequence 1 "$DEV/seed-marker.v2.seq2.json" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.lower.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    'v2 authority-marker rollback rejected|attempted authority_domain_sequence=.* is lower than persisted|LowerV2SequenceRefused'
  assert_no_mutation \
    "$OUTDIR/data/scenario_R1_v2_lower_sequence" \
    "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    "$DEV/seed-marker.v2.seq2.json"

  log "Scenario R2: v2 ratify@seq=1 (rotated target) over v2-seq=1 marker (active target) — equivocation refused"
  run_case scenario_R2_v2_same_seq_different_digest 1 "$DEV/seed-marker.v2.seq1.json" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.equivocation.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    'same-sequence|SameSequenceConflicting'
  assert_no_mutation \
    "$OUTDIR/data/scenario_R2_v2_same_seq_different_digest" \
    "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "Scenario R3a: v2 bad-signature (verifier refused)"
  run_case scenario_R3a_v2_bad_signature 1 "" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    'signature failed ML-DSA-44 PQC verification|DerivationFailed'
  assert_no_mutation \
    "$OUTDIR/data/scenario_R3a_v2_bad_signature" \
    "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    ""

  log "Scenario R3b: v2 wrong-environment (verifier refused)"
  run_case scenario_R3b_v2_wrong_environment 1 "" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-environment.json"
  assert_grep "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    '\[run-134\] FATAL: reload-apply refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    'environment mismatch|DerivationFailed'
  assert_no_mutation \
    "$OUTDIR/data/scenario_R3b_v2_wrong_environment" \
    "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    ""

  ##########################################################################
  # v1 regression
  ##########################################################################
  log "Scenario V1: v1 valid ratification, no marker (v1 reload-apply regression)"
  run_case scenario_V1_v1_regression 0 "" \
    "${devnet_apply_common[@]}" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v1.valid.json"
  assert_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-112\] reload-apply ratification gate INVOKED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log"
  assert_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-119\] authority-marker persisted'
  # v1 path must NOT take the v2 dispatch.
  assert_not_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-134\] reload-apply v2 ratification path SELECTED'
  assert_not_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-134\] v2 authority-marker persisted'
  assert_v1_marker_after_commit "$OUTDIR/data/scenario_V1_v1_regression"

  ##########################################################################
  # Non-scope observability (apply across ALL scenarios)
  ##########################################################################
  for stderr_log in "$OUTDIR"/logs/scenario_*.stderr.log; do
    assert_not_grep "$stderr_log" 'SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE'
    assert_not_grep "$stderr_log" 'KMS|HSM'
    assert_not_grep "$stderr_log" 'live inbound 0x05'
    assert_not_grep "$stderr_log" 'peer-driven live apply'
    assert_not_grep "$stderr_log" 'signing-key (rotation|revocation) lifecycle'
    # Run 134 v2 wiring is mutating-surface only — never the validation-only
    # logs from Run 132.
    assert_not_grep "$stderr_log" '\[run-132\] reload-check v2 authority-marker check'
    assert_not_grep "$stderr_log" '\[run-132\] peer-candidate-check v2 authority-marker check'
  done

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json created under any refusal scenario data dir"
    echo "  no pqc_authority_state.json.tmp sibling left behind under any scenario"
    echo "  pre-seeded marker bytes preserved on every refusal path"
    echo "  no marker file created on refusal scenarios with no pre-seeded marker"
    echo "post-commit persist checks: pass"
    echo "  v2 marker present with record_version=2 + expected sequence/action"
    echo "  on every accepted v2 scenario (A1/A2/A4)"
    echo "  v2 marker bytes byte-identical across idempotent run (A3)"
    echo "  v1 marker present with record_version=1 on the V1 regression scenario"
    echo "wire-format checks: source-only; no trust-bundle, ratification, or"
    echo "  peer-candidate wire format changed by this evidence harness"
    echo "scope non-goal checks: no SIGHUP v2, no startup v2, no live 0x05 v2,"
    echo "  no KMS/HSM, no peer-driven apply, no rotation/revocation lifecycle"
    echo "  observed in stderr of any scenario"
    echo "R4 (apply failure after preflight): covered by Run 134 §C.3 test-only"
    echo "  (FakeLiveTrustApplyContext swap-stage failure); release binary"
    echo "  cannot trigger a deterministic post-preflight apply failure."
  } >> "$SUMMARY"
  log "PASS: Run 135 evidence captured under ${OUTDIR}"
}

main "$@"
