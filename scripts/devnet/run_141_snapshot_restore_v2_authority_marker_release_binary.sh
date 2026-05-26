#!/usr/bin/env bash
# Run 141: release-binary evidence harness for the snapshot/restore v2
# authority-marker parity wiring landed in Run 140.
#
# Evidence-only. Run 141 makes NO production runtime code changes.
# This harness exercises `target/release/qbind-node` with the real
# `--restore-from-snapshot` CLI surface against ephemeral DevNet
# fixtures minted by the Run 141 fixture helper
# (`run_141_v2_snapshot_restore_fixture_helper`). It captures
# stdout/stderr/exit codes, sha256s the local marker bytes before and
# after each run, captures pre/post data-dir inventories, snapshot
# meta.json contents, snapshot state inventory, the presence/absence
# of `RESTORED_FROM_SNAPSHOT.json`, and asserts that:
#
#   * every rejected v2 scenario fails BEFORE materializing any state
#     and BEFORE writing the `RESTORED_FROM_SNAPSHOT.json` B3 audit
#     marker;
#   * the locally persisted `pqc_authority_state.json` bytes are
#     byte-identical on every rejection path (no rewrite / no repair /
#     no delete);
#   * every accepted v2 scenario emits the canonical Run 140 v2
#     authority-marker check log line BEFORE the materialization, the
#     B3 audit marker `RESTORED_FROM_SNAPSHOT.json` is written, and the
#     pre-existing local marker bytes are preserved verbatim;
#   * the v1 / no-v2 regression scenarios continue to take the Run 124
#     v1 dispatch verbatim (no v1 regression).
#
# Required scenario matrix (see task/RUN_141_TASK.txt):
#
#   Accept (v2 path):
#     A1. v2 snapshot into empty data-dir → accept; no local marker
#         fabricated; B3 audit marker + state materialization.
#     A2. v2 snapshot + matching local v2 marker → accept; local v2
#         marker bytes preserved verbatim.
#     A3. v2 snapshot with strictly higher sequence over local v2 →
#         accept; local v2 marker bytes preserved (pure restore — does
#         not persist the higher sequence; that's Run 134's surface).
#     A4. v2 snapshot over local v1 marker (explicit v1→v2 migration) →
#         accept; local v1 marker bytes preserved.
#
#   Reject (Run 140 v2 check refuses BEFORE any materialization):
#     R1. legacy/no-marker snapshot + local v2 marker → reject via the
#         Run 124 v1 dispatch verbatim (because authority_state_v2
#         is None on the snapshot — no v1 regression).
#     R2. lower-sequence v2 snapshot over local v2 → reject
#         (LowerSequenceRejected).
#     R3. same-sequence different-digest v2 snapshot over local v2 →
#         reject (SameSequenceDifferentDigestRejected /
#         equivocation guard).
#     R4. wrong-genesis v2 snapshot → reject
#         (RejectSnapshotMarkerWrongDomain).
#     R5. wrong-environment v2 snapshot → reject
#         (RejectSnapshotMarkerWrongDomain).
#     R6. wrong-chain v2 snapshot → reject (the outer
#         `validate_snapshot_dir` `chain_id` is unchanged so the v2
#         block reaches Run 140 with a mismatching `chain_id_hex`
#         field — RejectSnapshotMarkerWrongDomain).
#     R7. corrupt local marker + valid v2 snapshot → reject
#         (RejectLocalMarkerCorrupt); corrupt bytes preserved verbatim.
#     R8. ambiguous snapshot (BOTH `authority_state` and
#         `authority_state_v2` blocks present) → reject
#         (RejectAmbiguousSnapshotMarkers); no consultation of either
#         block.
#     R9. different-authority-root v2 snapshot over local v2 → reject
#         (WrongAuthorityRootRejected).
#
#   Regressions (no v2 path selected, no v2 marker fabricated):
#     R10. v1-only snapshot + matching local v1 marker → existing
#          Run 124 v1 dispatch → idempotent accept (the v1 marker
#          matches verbatim, restore proceeds; local v1 bytes
#          preserved); no v2 marker written.
#     R11. legacy/no-marker snapshot into empty data-dir → existing
#          Run 124 baseline behaviour → accept; no v2 marker written.
#
# Run 141 does NOT change any wire format, does NOT introduce CLI flag
# changes, does NOT change metric families, does NOT exercise live
# inbound 0x05 v2 apply, does NOT exercise peer-driven live apply, does
# NOT touch signing-key rotation/revocation lifecycle, KMS/HSM,
# governance, or validator-set rotation.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run141-snapshot-restore-v2-authority-marker-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_141_v2_snapshot_restore_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

# How long to let an accept-path binary run before SIGKILL'ing it.
# The binary continues to start LocalMesh consensus after a successful
# restore; for evidence purposes we only need stderr to reach the
# `[restore] OK: ...` line and the materialization side-effects, so a
# few seconds is plenty.
ACCEPT_TIMEOUT_SECS="${RUN_141_ACCEPT_TIMEOUT:-6}"

log()   { printf '[run141] %s\n' "$*"; }
fail()  { printf '[run141] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

assert_grep() {
  local file="$1" pattern="$2"
  grep -qE -- "$pattern" "$file" \
    || fail "${file} missing pattern: ${pattern}"
}

assert_not_grep() {
  local file="$1" pattern="$2"
  if grep -qE -- "$pattern" "$file"; then
    fail "${file} unexpectedly matched pattern: ${pattern}"
  fi
}

# A reject path MUST satisfy all of these invariants verbatim (see
# Required negative invariants in task/RUN_141_TASK.txt):
#   * `[restore] ERROR: ...` line is present on stderr;
#   * `[restore] OK: ...` is NOT present (no acceptance);
#   * no `RESTORED_FROM_SNAPSHOT.json` audit marker under data_dir;
#   * no `state_vm_v0/` directory under data_dir, or it is empty;
#   * no `--p2p-trusted-root` fallback log line was emitted;
#   * no Dummy{Sig,Kem,Aead} path was activated;
#   * exit code is 1 (the binary fail-closes via std::process::exit(1)).
assert_reject() {
  local data_dir="$1" stderr="$2" rc="$3"
  [ "$rc" = "1" ] || fail "expected rc=1 on reject, got rc=${rc} (stderr=${stderr})"
  assert_grep      "$stderr" '\[restore\] ERROR: '
  assert_not_grep  "$stderr" '\[restore\] OK: '
  assert_not_grep  "$stderr" 'falling back to --p2p-trusted-root'
  assert_not_grep  "$stderr" '\bDummySig\b|\bDummyKem\b|\bDummyAead\b'
  if [ -e "${data_dir}/RESTORED_FROM_SNAPSHOT.json" ]; then
    fail "audit marker RESTORED_FROM_SNAPSHOT.json was written on a reject path (${data_dir})"
  fi
  if [ -d "${data_dir}/state_vm_v0" ] && [ "$(ls -A "${data_dir}/state_vm_v0" 2>/dev/null | wc -l)" -gt 0 ]; then
    fail "state_vm_v0/ was materialized on a reject path (${data_dir})"
  fi
  # No .tmp marker residue from the restore surface.
  if find "$data_dir" -maxdepth 2 -name 'pqc_authority_state.json.tmp*' -print 2>/dev/null | grep -q .; then
    fail ".tmp residue found under ${data_dir}"
  fi
}

# An accept path MUST satisfy all of these invariants (see Required
# positive invariants + Ordering proof in task/RUN_141_TASK.txt):
#   * stderr contains `[restore] OK: restored from snapshot height=...`;
#   * the B3 audit marker `RESTORED_FROM_SNAPSHOT.json` exists;
#   * the materialized `state_vm_v0/` directory exists and is non-empty;
#   * no `[restore] FATAL: ...` or `[restore] ERROR: ...` lines appear;
#   * no fallback / Dummy path; no .tmp residue.
# (Exit code is whatever `timeout` returned because the accept-path
# binary continues into consensus; we SIGKILL it after a short window.)
assert_accept() {
  local data_dir="$1" stderr="$2"
  assert_grep     "$stderr" '\[restore\] OK: restored from snapshot height='
  assert_not_grep "$stderr" '\[restore\] FATAL: '
  assert_not_grep "$stderr" '\[restore\] ERROR: '
  assert_not_grep "$stderr" 'falling back to --p2p-trusted-root'
  assert_not_grep "$stderr" '\bDummySig\b|\bDummyKem\b|\bDummyAead\b'
  test -f "${data_dir}/RESTORED_FROM_SNAPSHOT.json" \
    || fail "expected B3 audit marker RESTORED_FROM_SNAPSHOT.json under ${data_dir}"
  test -d "${data_dir}/state_vm_v0" \
    || fail "expected state_vm_v0/ to be materialized under ${data_dir}"
  [ "$(ls -A "${data_dir}/state_vm_v0" 2>/dev/null | wc -l)" -gt 0 ] \
    || fail "state_vm_v0/ is empty after an accept path (${data_dir})"
  if find "$data_dir" -maxdepth 2 -name 'pqc_authority_state.json.tmp*' -print 2>/dev/null | grep -q .; then
    fail ".tmp residue found under ${data_dir}"
  fi
}

# Ordering proof for accepted v2 scenarios:
#   1. snapshot validation occurs;
#   2. Run 140 v2 authority-marker check accepts;
#   3. state checkpoint materialization occurs;
#   4. RESTORED_FROM_SNAPSHOT.json is written.
# We assert this by line-number monotonicity on stderr.
assert_v2_accept_ordering() {
  local stderr="$1"
  local v2_check_line restore_ok_line
  v2_check_line=$(grep -nE '\[restore\] Run 140 v2 authority-marker check: ' "$stderr" | head -n1 | cut -d: -f1 || true)
  restore_ok_line=$(grep -nE '\[restore\] OK: restored from snapshot height=' "$stderr" | head -n1 | cut -d: -f1 || true)
  [ -n "$v2_check_line" ]   || fail "ordering: missing Run 140 v2 authority-marker check line in ${stderr}"
  [ -n "$restore_ok_line" ] || fail "ordering: missing [restore] OK line in ${stderr}"
  [ "$v2_check_line" -lt "$restore_ok_line" ] \
    || fail "ordering: v2 authority-marker check (line ${v2_check_line}) must precede [restore] OK (line ${restore_ok_line}) in ${stderr}"
}

inventory_dir() {
  local dir="$1" out="$2"
  if [ -d "$dir" ]; then
    ( cd "$dir" && find . -mindepth 1 -maxdepth 4 -print 2>/dev/null | LC_ALL=C sort ) > "$out"
  else
    : > "$out"
  fi
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p \
    "$OUTDIR/logs" \
    "$OUTDIR/data" \
    "$OUTDIR/fixtures" \
    "$OUTDIR/inventories" \
    "$OUTDIR/marker_hashes" \
    "$OUTDIR/snapshot_meta" \
    "$OUTDIR/snapshot_state_inventory" \
    "$OUTDIR/exit_codes" \
    "$OUTDIR/grep_summaries"
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node + Run 141 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node \
    > "$OUTDIR/logs/build.qbind-node.stdout.log" \
    2> "$OUTDIR/logs/build.qbind-node.stderr.log"
  cargo build --release -p qbind-node --example run_141_v2_snapshot_restore_fixture_helper \
    > "$OUTDIR/logs/build.fixture-helper.stdout.log" \
    2> "$OUTDIR/logs/build.fixture-helper.stderr.log"

  test -x "$NODE_BIN"        || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER"  || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 141 snapshot/restore v2 authority-marker release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rustc_version: $(rustc --version 2>/dev/null || echo unknown)"
    echo "cargo_version: $(cargo --version 2>/dev/null || echo unknown)"
    echo "qbind-node_path: ${NODE_BIN}"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_path: ${FIXTURE_HELPER}"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo "accept_timeout_secs: ${ACCEPT_TIMEOUT_SECS}"
    echo
    echo "scenario status:"
  } > "$SUMMARY"

  log "generating ephemeral fixtures"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    >  "$OUTDIR/logs/fixture_helper.stdout.log" \
    2> "$OUTDIR/logs/fixture_helper.stderr.log"
  # shellcheck disable=SC1091
  source "$OUTDIR/fixtures/manifest.env"

  # Record the canonical fixture sha256s + snapshot meta + state
  # inventories up front. The harness re-reads these post-run to detect
  # any unexpected mutation by the restore surface against the source
  # fixtures (the harness only mutates per-scenario data_dirs).
  {
    echo "manifest:"
    sed 's/^/  /' "$OUTDIR/fixtures/manifest.env"
    echo
    echo "fixture sha256:"
    echo "  matching-v2-marker-fixture: $(sha256_file "$RUN_141_LOCAL_MARKER_MATCHING_V2")"
    echo "  matching-v1-marker-fixture: $(sha256_file "$RUN_141_LOCAL_MARKER_MATCHING_V1")"
    echo "  corrupt-marker-fixture:     $(sha256_file "$RUN_141_LOCAL_MARKER_CORRUPT")"
    for snap in \
        "$RUN_141_SNAP_V2_ONLY" \
        "$RUN_141_SNAP_V2_HIGHER_SEQ" \
        "$RUN_141_SNAP_V2_LOWER_SEQ" \
        "$RUN_141_SNAP_V2_SAME_SEQ_DIFF_DIGEST" \
        "$RUN_141_SNAP_V2_WRONG_GENESIS" \
        "$RUN_141_SNAP_V2_WRONG_ENVIRONMENT" \
        "$RUN_141_SNAP_V2_WRONG_CHAIN" \
        "$RUN_141_SNAP_V2_WRONG_AUTHORITY_ROOT" \
        "$RUN_141_SNAP_V2_AND_V1_AMBIGUOUS" \
        "$RUN_141_SNAP_V1_ONLY" \
        "$RUN_141_SNAP_LEGACY_NO_MARKER"; do
      base="$(basename "$snap")"
      echo "  ${base}/meta.json sha256: $(sha256_file "$snap/meta.json")"
      cp "$snap/meta.json" "$OUTDIR/snapshot_meta/${base}.meta.json"
      inventory_dir "$snap/state" "$OUTDIR/snapshot_state_inventory/${base}.state.inventory.txt"
    done
  } >> "$SUMMARY"
  echo >> "$SUMMARY"

  # --------------------------------------------------------------
  # run_scenario_reject <name> <snapshot> <seed-marker|none> <expect-grep>
  # --------------------------------------------------------------
  run_scenario_reject() {
    local name="$1" snapshot="$2" seed="$3" expect_pattern="$4"
    local data_dir="$OUTDIR/data/${name}"
    local stdout="$OUTDIR/logs/${name}.stdout.log"
    local stderr="$OUTDIR/logs/${name}.stderr.log"
    local rcfile="$OUTDIR/exit_codes/${name}.exit_code"
    local pre_inv="$OUTDIR/inventories/${name}.data_dir.pre.txt"
    local post_inv="$OUTDIR/inventories/${name}.data_dir.post.txt"
    local pre_sha="$OUTDIR/marker_hashes/${name}.marker_pre.sha256"
    local post_sha="$OUTDIR/marker_hashes/${name}.marker_post.sha256"
    mkdir -p "$data_dir"

    local marker_path="${data_dir}/pqc_authority_state.json"
    local sha_before="<none>"
    if [ "$seed" != "none" ]; then
      cp "$seed" "$marker_path"
      sha_before="$(sha256_file "$marker_path")"
      printf '%s\n' "$sha_before" > "$pre_sha"
    else
      : > "$pre_sha"
    fi
    inventory_dir "$data_dir" "$pre_inv"

    log "Scenario ${name} (reject): snapshot=$(basename "$snapshot") seed=$(basename "$seed" 2>/dev/null || echo none)"
    set +e
    "$NODE_BIN" \
      --env devnet \
      --data-dir "$data_dir" \
      --genesis-path "$RUN_141_GENESIS_PATH" \
      --expect-genesis-hash "$RUN_141_GENESIS_HASH" \
      --restore-from-snapshot "$snapshot" \
      > "$stdout" 2> "$stderr"
    local rc=$?
    set -e
    printf '%s\n' "$rc" > "$rcfile"

    inventory_dir "$data_dir" "$post_inv"
    local sha_after="<none>"
    if [ -e "$marker_path" ]; then
      sha_after="$(sha256_file "$marker_path")"
      printf '%s\n' "$sha_after" > "$post_sha"
    else
      : > "$post_sha"
    fi

    if [ "$seed" != "none" ]; then
      [ "$sha_before" = "$sha_after" ] \
        || fail "${name}: local marker bytes mutated on reject path (before=${sha_before} after=${sha_after})"
    fi
    assert_reject "$data_dir" "$stderr" "$rc"
    assert_grep   "$stderr"   "$expect_pattern"

    {
      printf '  %s: rc=%s sha_before=%s sha_after=%s reject_pattern=%q\n' \
        "$name" "$rc" "$sha_before" "$sha_after" "$expect_pattern"
    } >> "$SUMMARY"
  }

  # --------------------------------------------------------------
  # run_scenario_accept <name> <snapshot> <seed-marker|none> [expect-v2-check]
  # --------------------------------------------------------------
  run_scenario_accept() {
    local name="$1" snapshot="$2" seed="$3" expect_v2_check="${4:-yes}"
    local data_dir="$OUTDIR/data/${name}"
    local stdout="$OUTDIR/logs/${name}.stdout.log"
    local stderr="$OUTDIR/logs/${name}.stderr.log"
    local rcfile="$OUTDIR/exit_codes/${name}.exit_code"
    local pre_inv="$OUTDIR/inventories/${name}.data_dir.pre.txt"
    local post_inv="$OUTDIR/inventories/${name}.data_dir.post.txt"
    local pre_sha="$OUTDIR/marker_hashes/${name}.marker_pre.sha256"
    local post_sha="$OUTDIR/marker_hashes/${name}.marker_post.sha256"
    mkdir -p "$data_dir"

    local marker_path="${data_dir}/pqc_authority_state.json"
    local sha_before="<none>"
    if [ "$seed" != "none" ]; then
      cp "$seed" "$marker_path"
      sha_before="$(sha256_file "$marker_path")"
      printf '%s\n' "$sha_before" > "$pre_sha"
    else
      : > "$pre_sha"
    fi
    inventory_dir "$data_dir" "$pre_inv"

    log "Scenario ${name} (accept): snapshot=$(basename "$snapshot") seed=$(basename "$seed" 2>/dev/null || echo none)"
    set +e
    timeout --signal=KILL "${ACCEPT_TIMEOUT_SECS}" \
      "$NODE_BIN" \
        --env devnet \
        --data-dir "$data_dir" \
        --genesis-path "$RUN_141_GENESIS_PATH" \
        --expect-genesis-hash "$RUN_141_GENESIS_HASH" \
        --restore-from-snapshot "$snapshot" \
      > "$stdout" 2> "$stderr"
    local rc=$?
    set -e
    printf '%s\n' "$rc" > "$rcfile"

    inventory_dir "$data_dir" "$post_inv"
    local sha_after="<none>"
    if [ -e "$marker_path" ]; then
      sha_after="$(sha256_file "$marker_path")"
      printf '%s\n' "$sha_after" > "$post_sha"
    else
      : > "$post_sha"
    fi

    if [ "$seed" != "none" ]; then
      [ "$sha_before" = "$sha_after" ] \
        || fail "${name}: local marker bytes mutated on accept path (before=${sha_before} after=${sha_after}) — Run 141 restore design is pure/no-write."
    else
      [ "$sha_after" = "<none>" ] \
        || fail "${name}: restore surface synthesised a local marker on accept (must not invent marker from snapshot bytes)"
    fi
    assert_accept "$data_dir" "$stderr"

    if [ "$expect_v2_check" = "yes" ]; then
      assert_v2_accept_ordering "$stderr"
    else
      # Regression scenarios MUST NOT route through the v2 dispatch.
      assert_not_grep "$stderr" '\[restore\] Run 140 v2 authority-marker check: '
    fi

    {
      printf '  %s: rc=%s sha_before=%s sha_after=%s expect_v2_check=%s\n' \
        "$name" "$rc" "$sha_before" "$sha_after" "$expect_v2_check"
    } >> "$SUMMARY"
  }

  # ---------------------------------------------------------------
  # A1: v2 snapshot, empty data-dir
  # ---------------------------------------------------------------
  run_scenario_accept A1_v2_snapshot_empty_data_dir \
    "$RUN_141_SNAP_V2_ONLY" none yes

  # ---------------------------------------------------------------
  # A2: v2 snapshot, matching local v2 marker
  # ---------------------------------------------------------------
  run_scenario_accept A2_v2_snapshot_matching_local_v2_marker \
    "$RUN_141_SNAP_V2_ONLY" "$RUN_141_LOCAL_MARKER_MATCHING_V2" yes

  # ---------------------------------------------------------------
  # A3: higher-sequence v2 snapshot over local v2 marker
  # ---------------------------------------------------------------
  run_scenario_accept A3_v2_snapshot_higher_sequence_over_local_v2 \
    "$RUN_141_SNAP_V2_HIGHER_SEQ" "$RUN_141_LOCAL_MARKER_MATCHING_V2" yes

  # ---------------------------------------------------------------
  # A4: v2 snapshot over local v1 marker (explicit v1→v2 migration)
  # ---------------------------------------------------------------
  run_scenario_accept A4_v2_snapshot_over_local_v1_marker \
    "$RUN_141_SNAP_V2_ONLY" "$RUN_141_LOCAL_MARKER_MATCHING_V1" yes

  # ---------------------------------------------------------------
  # R1: legacy snapshot + local v2 marker (Run 124 v1 dispatch refuses)
  # ---------------------------------------------------------------
  run_scenario_reject R1_legacy_snapshot_local_v2_marker \
    "$RUN_141_SNAP_LEGACY_NO_MARKER" \
    "$RUN_141_LOCAL_MARKER_MATCHING_V2" \
    'snapshot carries no authority metadata|RejectMissingSnapshotMarker|Run 124 authority-marker check'

  # ---------------------------------------------------------------
  # R2: lower-sequence v2 snapshot rejected
  # ---------------------------------------------------------------
  run_scenario_reject R2_v2_lower_sequence_rejected \
    "$RUN_141_SNAP_V2_LOWER_SEQ" \
    "$RUN_141_LOCAL_MARKER_MATCHING_V2" \
    'LowerSequenceRejected|Run 140 v2 authority-marker check'

  # ---------------------------------------------------------------
  # R3: same-sequence different-digest v2 snapshot rejected
  # ---------------------------------------------------------------
  run_scenario_reject R3_v2_same_sequence_different_digest_rejected \
    "$RUN_141_SNAP_V2_SAME_SEQ_DIFF_DIGEST" \
    "$RUN_141_LOCAL_MARKER_MATCHING_V2" \
    'SameSequenceDifferentDigestRejected|equivocation|Run 140 v2 authority-marker check'

  # ---------------------------------------------------------------
  # R4: wrong-genesis v2 snapshot rejected
  # ---------------------------------------------------------------
  run_scenario_reject R4_v2_wrong_genesis_rejected \
    "$RUN_141_SNAP_V2_WRONG_GENESIS" \
    none \
    'RejectSnapshotMarkerWrongDomain|wrong[- ]domain|genesis_hash'

  # ---------------------------------------------------------------
  # R5: wrong-environment v2 snapshot rejected
  # ---------------------------------------------------------------
  run_scenario_reject R5_v2_wrong_environment_rejected \
    "$RUN_141_SNAP_V2_WRONG_ENVIRONMENT" \
    none \
    'RejectSnapshotMarkerWrongDomain|wrong[- ]domain|environment'

  # ---------------------------------------------------------------
  # R6: wrong-chain v2 snapshot rejected
  #
  # The Run 141 fixture only varies the v2-block's `chain_id_hex`
  # field; the outer `StateSnapshotMeta::chain_id` still matches the
  # runtime so the snapshot-layer chain_id check passes and the
  # Run 140 v2 dispatch is reached, which rejects via
  # RejectSnapshotMarkerWrongDomain on the (chain_id_hex,
  # environment, genesis_hash_hex) tuple.
  # ---------------------------------------------------------------
  run_scenario_reject R6_v2_wrong_chain_rejected \
    "$RUN_141_SNAP_V2_WRONG_CHAIN" \
    none \
    'RejectSnapshotMarkerWrongDomain|wrong[- ]domain|chain_id'

  # ---------------------------------------------------------------
  # R7: corrupt local marker + valid v2 snapshot → reject (preserve bytes)
  # ---------------------------------------------------------------
  run_scenario_reject R7_corrupt_local_marker_v2_snapshot \
    "$RUN_141_SNAP_V2_ONLY" \
    "$RUN_141_LOCAL_MARKER_CORRUPT" \
    'RejectLocalMarkerCorrupt|malformed|corrupt|fail closed'

  # ---------------------------------------------------------------
  # R8: ambiguous snapshot (both v1 + v2 blocks) → reject
  # ---------------------------------------------------------------
  run_scenario_reject R8_ambiguous_snapshot_v1_and_v2_blocks \
    "$RUN_141_SNAP_V2_AND_V1_AMBIGUOUS" \
    none \
    'RejectAmbiguousSnapshotMarkers|ambiguous|both .*authority_state|both v1 and v2'

  # ---------------------------------------------------------------
  # R9: different-authority-root v2 snapshot rejected
  # ---------------------------------------------------------------
  run_scenario_reject R9_v2_different_authority_root_rejected \
    "$RUN_141_SNAP_V2_WRONG_AUTHORITY_ROOT" \
    "$RUN_141_LOCAL_MARKER_MATCHING_V2" \
    'WrongAuthorityRootRejected|authority[- _]root|Run 140 v2 authority-marker check'

  # ---------------------------------------------------------------
  # R10: v1-only snapshot + matching v1 local → existing Run 124 v1
  #      dispatch behaviour preserved (no v2 path selected).
  # ---------------------------------------------------------------
  run_scenario_accept R10_v1_only_snapshot_matching_v1_local \
    "$RUN_141_SNAP_V1_ONLY" "$RUN_141_LOCAL_MARKER_MATCHING_V1" no

  # ---------------------------------------------------------------
  # R11: legacy/no-marker snapshot into empty data-dir → existing
  #      Run 124 baseline preserved (no v2 path selected).
  # ---------------------------------------------------------------
  run_scenario_accept R11_legacy_snapshot_empty_data_dir \
    "$RUN_141_SNAP_LEGACY_NO_MARKER" none no

  # ---------------------------------------------------------------
  # Out-of-scope / forbidden-marker grep summaries across all stderr
  # logs. Any hit here is a Run 141 harness FAIL.
  # ---------------------------------------------------------------
  {
    echo
    echo "out-of-scope grep summaries (must be empty):"
  } >> "$SUMMARY"
  for pat in \
      'falling back to --p2p-trusted-root' \
      '\bDummySig\b' '\bDummyKem\b' '\bDummyAead\b' \
      'live inbound 0x05' \
      'peer-driven live apply' \
      'signing-key (rotation|revocation) lifecycle' \
      '\bKMS\b' '\bHSM\b'; do
    matches=$(grep -REn -- "$pat" "$OUTDIR/logs" 2>/dev/null | grep -v 'qbind-node.stdout.log\|qbind-node.stderr.log\|fixture-helper.stdout.log\|fixture-helper.stderr.log' || true)
    if [ -n "$matches" ]; then
      printf '%s\n' "$matches" > "$OUTDIR/grep_summaries/forbidden.${pat//[^A-Za-z0-9]/_}.txt"
      printf '  PATTERN=%q matches=%s\n' "$pat" "$(printf '%s\n' "$matches" | wc -l)" >> "$SUMMARY"
      fail "out-of-scope pattern observed in stderr logs: ${pat}"
    else
      printf '  PATTERN=%q matches=0\n' "$pat" >> "$SUMMARY"
    fi
  done

  # ---------------------------------------------------------------
  # In-scope grep summaries: per-scenario reasons + Run 140 / Run 124
  # dispatch lines. These are informational, not assertions.
  # ---------------------------------------------------------------
  {
    echo
    echo "in-scope grep summaries (informational):"
  } >> "$SUMMARY"
  for pat in \
      '\[restore\] Run 140 v2 authority-marker check' \
      '\[restore\] Run 124 authority-marker check' \
      '\[restore\] OK: restored from snapshot' \
      '\[restore\] ERROR:' \
      '\[restore\] FATAL:' \
      'RejectAmbiguousSnapshotMarkers' \
      'RejectLocalMarkerCorrupt' \
      'RejectLocalMarkerWrongDomain' \
      'RejectSnapshotMarkerWrongDomain' \
      'LowerSequenceRejected' \
      'SameSequenceDifferentDigestRejected' \
      'WrongAuthorityRootRejected' \
      'AcceptSnapshotV2MarkerNoLocal' \
      'AcceptMatchingV2Marker' \
      'AcceptHigherV2Sequence' \
      'AcceptV2AfterV1Migration' \
      'authority-marker' \
      'restore' \
      'Run 140' \
      'FATAL' \
      'fallback' \
      'DummySig|DummyKem|DummyAead'; do
    count=$(grep -REc -- "$pat" "$OUTDIR/logs" 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
    printf '  PATTERN=%q total_matches=%s\n' "$pat" "$count" >> "$SUMMARY"
    grep -REn -- "$pat" "$OUTDIR/logs" 2>/dev/null \
      > "$OUTDIR/grep_summaries/observed.${pat//[^A-Za-z0-9]/_}.txt" || true
  done

  log "all scenarios passed"
  echo >> "$SUMMARY"
  echo "VERDICT: strongest-positive (release-binary, Run 140 v2 snapshot/restore parity)" >> "$SUMMARY"
}

main "$@"
