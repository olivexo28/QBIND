#!/usr/bin/env bash
# Run 125: release-binary evidence harness for the snapshot/restore
# authority-marker conflict enforcement wiring landed in Run 124.
#
# Evidence-only. Run 125 prefers NO production runtime code changes.
# This harness exercises `target/release/qbind-node` with
# `--restore-from-snapshot` against ephemeral DevNet fixtures minted
# by `run_125_snapshot_restore_authority_marker_fixture_helper`. It
# captures stdout/stderr/exit codes, sha256s the local marker bytes
# before and after each run, and asserts that:
#
#   * the binary rejects every disallowed restore BEFORE materializing
#     any state and BEFORE writing the `RESTORED_FROM_SNAPSHOT.json`
#     B3 audit marker;
#   * the locally persisted `pqc_authority_state.json` bytes are
#     byte-identical on every rejection path (no rewrite / no repair /
#     no delete);
#   * matching authority metadata is accepted and the local marker
#     bytes are still preserved verbatim (the restore surface never
#     writes the local marker file);
#   * legacy snapshots into a fresh data dir continue to be accepted
#     without inventing a synthetic local marker.
#
# Scenarios (all DevNet, with `--genesis-path` so Run 102 takes the
# Verified branch and the Run 124 helper is invoked):
#
#   1. legacy snapshot + no local marker         → accept (timeout-killed)
#   2. legacy snapshot + matching local marker   → rc=1, RejectMissingSnapshotMarker
#   3. matching snapshot + matching local marker → accept; local bytes byte-identical
#   4. conflicting snapshot + matching local     → rc=1, RejectConflict(SameSequenceConflictingHash)
#   5. corrupt local marker + matching snapshot  → rc=1, RejectLocalMarkerCorrupt
#   6. wrong-domain snapshot + no local marker   → rc=1, RejectSnapshotMarkerWrongDomain
#   7. no `--genesis-path` + local marker        → rc=1, AuthorityContextMissing (legacy no-context path)
#
# Run 125 does NOT change any wire format, does NOT introduce
# `--allow-authority-state-reset`, does NOT implement signing-key
# rotation/revocation, does NOT introduce peer-driven live apply, does
# NOT change KMS/HSM custody, governance, or validator-set rotation.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run125-snapshot-restore-authority-marker-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_125_snapshot_restore_authority_marker_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

# How long to let an accept-path binary run before SIGKILL'ing it.
# The binary continues to start LocalMesh consensus after a successful
# restore; for evidence purposes we only need stderr to reach the
# `[restore] OK: ...` line, so a few seconds is plenty.
ACCEPT_TIMEOUT_SECS="${RUN_125_ACCEPT_TIMEOUT:-6}"

log()   { printf '[run125] %s\n' "$*"; }
fail()  { printf '[run125] FAIL: %s\n' "$*" >&2; exit 1; }
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

# A reject path MUST satisfy all of these invariants verbatim:
#   * `[restore] FATAL: ...` line is present on stderr;
#   * `[restore] ERROR: ...` line is present on stderr;
#   * `[restore] OK: ...` is NOT present (no acceptance);
#   * no `RESTORED_FROM_SNAPSHOT.json` audit marker under data_dir;
#   * no `state_vm_v0/` directory under data_dir, or it is empty;
#   * exit code is 1 (the binary fail-closes via std::process::exit(1)).
assert_reject() {
  local data_dir="$1" stderr="$2" rc="$3"
  [ "$rc" = "1" ] || fail "expected rc=1 on reject, got rc=${rc} (stderr=${stderr})"
  # `[restore] ERROR:` is emitted by main.rs on every restore failure;
  # `[restore] FATAL:` is only emitted by the Run 124 check wrapper
  # (`restore_from_snapshot_with_authority_marker_check`) and not by
  # the legacy no-context entry point's `AuthorityContextMissing`
  # fail-closed branch, so we only require the ERROR line here.
  assert_grep      "$stderr" '\[restore\] ERROR: '
  assert_not_grep  "$stderr" '\[restore\] OK: '
  if [ -e "${data_dir}/RESTORED_FROM_SNAPSHOT.json" ]; then
    fail "audit marker RESTORED_FROM_SNAPSHOT.json was written on a reject path (${data_dir})"
  fi
  if [ -d "${data_dir}/state_vm_v0" ] && [ "$(ls -A "${data_dir}/state_vm_v0" 2>/dev/null | wc -l)" -gt 0 ]; then
    fail "state_vm_v0/ was materialized on a reject path (${data_dir})"
  fi
}

# An accept path MUST satisfy all of these invariants:
#   * stderr contains `[restore] OK: restored from snapshot height=...`;
#   * the B3 audit marker `RESTORED_FROM_SNAPSHOT.json` exists;
#   * the materialized `state_vm_v0/` directory exists and is non-empty;
#   * no `[restore] FATAL: ...` or `[restore] ERROR: ...` lines appear.
# (Exit code is whatever `timeout` returned because the accept-path
# binary continues into consensus; we SIGKILL it after a short window.)
assert_accept() {
  local data_dir="$1" stderr="$2"
  assert_grep     "$stderr" '\[restore\] OK: restored from snapshot height='
  assert_not_grep "$stderr" '\[restore\] FATAL: '
  assert_not_grep "$stderr" '\[restore\] ERROR: '
  test -f "${data_dir}/RESTORED_FROM_SNAPSHOT.json" \
    || fail "expected B3 audit marker RESTORED_FROM_SNAPSHOT.json under ${data_dir}"
  test -d "${data_dir}/state_vm_v0" \
    || fail "expected state_vm_v0/ to be materialized under ${data_dir}"
  [ "$(ls -A "${data_dir}/state_vm_v0" 2>/dev/null | wc -l)" -gt 0 ] \
    || fail "state_vm_v0/ is empty after an accept path (${data_dir})"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR/logs" "$OUTDIR/data" "$OUTDIR/fixtures"
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node + Run 125 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node \
    > "$OUTDIR/logs/build.qbind-node.stdout.log" \
    2> "$OUTDIR/logs/build.qbind-node.stderr.log"
  cargo build --release -p qbind-node --example run_125_snapshot_restore_authority_marker_fixture_helper \
    > "$OUTDIR/logs/build.fixture-helper.stdout.log" \
    2> "$OUTDIR/logs/build.fixture-helper.stderr.log"

  test -x "$NODE_BIN"        || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER"  || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 125 snapshot/restore authority marker release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
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

  # Record the canonical fixture sha256s so any later mutation in
  # data dirs can be cross-referenced against the source-of-truth.
  {
    echo "manifest:"
    sed 's/^/  /' "$OUTDIR/fixtures/manifest.env"
    echo
    echo "fixture sha256:"
    echo "  matching-marker-fixture: $(sha256_file "$RUN_125_LOCAL_MARKER_MATCHING")"
    echo "  corrupt-marker-fixture:  $(sha256_file "$RUN_125_LOCAL_MARKER_CORRUPT")"
    for snap in "$RUN_125_SNAP_LEGACY" "$RUN_125_SNAP_MATCHING" "$RUN_125_SNAP_CONFLICTING" "$RUN_125_SNAP_WRONG_DOMAIN"; do
      echo "  $(basename "$snap")/meta.json: $(sha256_file "$snap/meta.json")"
    done
  } >> "$SUMMARY"
  echo >> "$SUMMARY"

  # --------------------------------------------------------------
  # run_reject_scenario <name> <snapshot> <seed-marker|none> <expect-grep>
  #
  # Sets up a fresh data dir, optionally seeds the local
  # `pqc_authority_state.json` marker from a fixture path, captures
  # the marker sha256 before invocation, runs the release binary
  # with the standard Run 102 verified-genesis flag block + the
  # given `--restore-from-snapshot`, records the sha256 after, and
  # then asserts the reject invariants.
  # --------------------------------------------------------------
  run_reject_scenario() {
    local name="$1" snapshot="$2" seed="$3" expect_pattern="$4"
    local data_dir="$OUTDIR/data/${name}"
    local stdout="$OUTDIR/logs/${name}.stdout.log"
    local stderr="$OUTDIR/logs/${name}.stderr.log"
    local rcfile="$OUTDIR/logs/${name}.exit_code"
    mkdir -p "$data_dir"

    local marker_path="${data_dir}/pqc_authority_state.json"
    local sha_before="<none>"
    if [ "$seed" != "none" ]; then
      cp "$seed" "$marker_path"
      sha_before="$(sha256_file "$marker_path")"
    fi

    log "Scenario ${name}: snapshot=$(basename "$snapshot") seed=$(basename "$seed" 2>/dev/null || echo none)"
    set +e
    "$NODE_BIN" \
      --env devnet \
      --data-dir "$data_dir" \
      --genesis-path "$RUN_125_GENESIS_PATH" \
      --expect-genesis-hash "$RUN_125_GENESIS_HASH" \
      --restore-from-snapshot "$snapshot" \
      > "$stdout" 2> "$stderr"
    local rc=$?
    set -e
    printf '%s\n' "$rc" > "$rcfile"

    local sha_after="<none>"
    if [ -e "$marker_path" ]; then
      sha_after="$(sha256_file "$marker_path")"
    fi

    if [ "$seed" != "none" ]; then
      [ "$sha_before" = "$sha_after" ] \
        || fail "${name}: local marker bytes mutated on reject path (before=${sha_before} after=${sha_after})"
    fi
    assert_reject "$data_dir" "$stderr" "$rc"
    assert_grep   "$stderr"   "$expect_pattern"

    {
      printf '  %s: rc=%s sha_before=%s sha_after=%s\n' \
        "$name" "$rc" "$sha_before" "$sha_after"
    } >> "$SUMMARY"
  }

  # --------------------------------------------------------------
  # run_accept_scenario <name> <snapshot> <seed-marker|none>
  #
  # Sets up a fresh data dir, optionally seeds the local marker,
  # captures the marker sha256 before invocation, runs the binary
  # under `timeout ${ACCEPT_TIMEOUT_SECS}` (the binary continues
  # into consensus after a successful restore — we only need the
  # `[restore] OK:` line and the audit/state side-effects), and
  # asserts the accept invariants. On accept we also assert that
  # the local marker bytes are byte-identical post-run (the restore
  # surface never writes the local marker file).
  # --------------------------------------------------------------
  run_accept_scenario() {
    local name="$1" snapshot="$2" seed="$3"
    local data_dir="$OUTDIR/data/${name}"
    local stdout="$OUTDIR/logs/${name}.stdout.log"
    local stderr="$OUTDIR/logs/${name}.stderr.log"
    local rcfile="$OUTDIR/logs/${name}.exit_code"
    mkdir -p "$data_dir"

    local marker_path="${data_dir}/pqc_authority_state.json"
    local sha_before="<none>"
    if [ "$seed" != "none" ]; then
      cp "$seed" "$marker_path"
      sha_before="$(sha256_file "$marker_path")"
    fi

    log "Scenario ${name} (accept): snapshot=$(basename "$snapshot") seed=$(basename "$seed" 2>/dev/null || echo none)"
    set +e
    timeout --signal=KILL "${ACCEPT_TIMEOUT_SECS}" \
      "$NODE_BIN" \
        --env devnet \
        --data-dir "$data_dir" \
        --genesis-path "$RUN_125_GENESIS_PATH" \
        --expect-genesis-hash "$RUN_125_GENESIS_HASH" \
        --restore-from-snapshot "$snapshot" \
      > "$stdout" 2> "$stderr"
    local rc=$?
    set -e
    printf '%s\n' "$rc" > "$rcfile"

    local sha_after="<none>"
    if [ -e "$marker_path" ]; then
      sha_after="$(sha256_file "$marker_path")"
    fi

    if [ "$seed" != "none" ]; then
      [ "$sha_before" = "$sha_after" ] \
        || fail "${name}: local marker bytes mutated on accept path (before=${sha_before} after=${sha_after})"
    else
      [ "$sha_after" = "<none>" ] \
        || fail "${name}: restore surface synthesised a local marker on accept (must not invent marker from snapshot bytes)"
    fi
    assert_accept "$data_dir" "$stderr"

    {
      printf '  %s: rc=%s sha_before=%s sha_after=%s\n' \
        "$name" "$rc" "$sha_before" "$sha_after"
    } >> "$SUMMARY"
  }

  # ---------------------------------------------------------------
  # Scenario 1 — Legacy snapshot + no local marker → ACCEPT.
  # Proves: legacy parsing compatibility preserved, no synthetic
  # local marker invented, Run 097 epoch behaviour intact (snapshot
  # carries no epoch and the binary logs `Run 097 ... epoch=None`).
  # ---------------------------------------------------------------
  run_accept_scenario scenario_1_legacy_snapshot_no_local_marker \
    "$RUN_125_SNAP_LEGACY" \
    none

  # ---------------------------------------------------------------
  # Scenario 2 — Legacy snapshot + matching local marker → REJECT.
  # Proves: accepting would silently shadow or erase the local
  # persisted authority state; the binary refuses fail-closed BEFORE
  # any state copy or audit-marker write, bytes preserved verbatim.
  # ---------------------------------------------------------------
  run_reject_scenario scenario_2_legacy_snapshot_local_marker_present \
    "$RUN_125_SNAP_LEGACY" \
    "$RUN_125_LOCAL_MARKER_MATCHING" \
    'snapshot carries no authority metadata'

  # ---------------------------------------------------------------
  # Scenario 3 — Matching snapshot + matching local marker → ACCEPT.
  # Proves: matching authority metadata restores; local marker bytes
  # are byte-identical post-run (the restore surface never writes
  # the local marker file, even when the snapshot block matches it).
  # ---------------------------------------------------------------
  run_accept_scenario scenario_3_matching_snapshot_and_local_marker \
    "$RUN_125_SNAP_MATCHING" \
    "$RUN_125_LOCAL_MARKER_MATCHING"

  # ---------------------------------------------------------------
  # Scenario 4 — Conflicting snapshot (same authority_sequence,
  # different ratification_object_hash) + matching local marker
  # → REJECT (`RejectConflict(SameSequenceConflictingHash)`).
  # Proves: equivocation at the same authority_sequence is refused
  # BEFORE materialization; the Run 117 "two distinct ratifications
  # cannot share the same authority_sequence" rule is enforced.
  # ---------------------------------------------------------------
  run_reject_scenario scenario_4_conflicting_snapshot \
    "$RUN_125_SNAP_CONFLICTING" \
    "$RUN_125_LOCAL_MARKER_MATCHING" \
    'same-sequence equivocation|SameSequenceConflictingHash|conflict'

  # ---------------------------------------------------------------
  # Scenario 5 — Corrupt local marker + matching snapshot → REJECT
  # (`RejectLocalMarkerCorrupt`). Proves: fail-closed on corruption;
  # the corrupt bytes are NOT repaired, deleted, or overwritten by
  # the restore surface.
  # ---------------------------------------------------------------
  run_reject_scenario scenario_5_corrupt_local_marker \
    "$RUN_125_SNAP_MATCHING" \
    "$RUN_125_LOCAL_MARKER_CORRUPT" \
    'malformed|corrupt|fail closed'

  # ---------------------------------------------------------------
  # Scenario 6 — Wrong-domain snapshot marker (different genesis
  # hash) + no local marker → REJECT
  # (`RejectSnapshotMarkerWrongDomain`). Proves: a snapshot whose
  # authority block does not bind to this node's canonical Run 101
  # genesis is refused even when there is no local marker to
  # protect.
  # ---------------------------------------------------------------
  run_reject_scenario scenario_6_wrong_domain_snapshot_no_local \
    "$RUN_125_SNAP_WRONG_DOMAIN" \
    none \
    'wrong-domain|genesis_hash|domain'

  # ---------------------------------------------------------------
  # Scenario 7 — No `--genesis-path` (Run 102
  # SkippedNoExternalGenesis branch) + matching local marker
  # → REJECT (`AuthorityContextMissing`). Proves: the legacy
  # no-context entry point itself fails closed whenever a
  # pre-existing local marker is on disk; there is no silent
  # shadowing through the no-context path either.
  # ---------------------------------------------------------------
  log "Scenario scenario_7_no_genesis_context: legacy no-context path + matching local marker"
  data_dir="$OUTDIR/data/scenario_7_no_genesis_context"
  mkdir -p "$data_dir"
  cp "$RUN_125_LOCAL_MARKER_MATCHING" "$data_dir/pqc_authority_state.json"
  sha_before="$(sha256_file "$data_dir/pqc_authority_state.json")"
  set +e
  "$NODE_BIN" \
    --env devnet \
    --data-dir "$data_dir" \
    --restore-from-snapshot "$RUN_125_SNAP_MATCHING" \
    > "$OUTDIR/logs/scenario_7_no_genesis_context.stdout.log" \
    2> "$OUTDIR/logs/scenario_7_no_genesis_context.stderr.log"
  rc=$?
  set -e
  printf '%s\n' "$rc" > "$OUTDIR/logs/scenario_7_no_genesis_context.exit_code"
  sha_after="$(sha256_file "$data_dir/pqc_authority_state.json")"
  [ "$sha_before" = "$sha_after" ] \
    || fail "scenario_7: local marker bytes mutated (before=${sha_before} after=${sha_after})"
  assert_reject "$data_dir" \
    "$OUTDIR/logs/scenario_7_no_genesis_context.stderr.log" "$rc"
  assert_grep "$OUTDIR/logs/scenario_7_no_genesis_context.stderr.log" \
    'AuthorityContextMissing|runtime authority context|no runtime authority context'
  printf '  scenario_7_no_genesis_context: rc=%s sha_before=%s sha_after=%s\n' \
    "$rc" "$sha_before" "$sha_after" >> "$SUMMARY"

  log "all scenarios passed"
  echo >> "$SUMMARY"
  echo "VERDICT: strongest-positive (release-binary)" >> "$SUMMARY"
}

main "$@"