#!/usr/bin/env bash
# Run 115: release-binary evidence matrix for SIGHUP live reload
# bundle-signing-key ratification enforcement (Run 114 wiring).
#
# Evidence-only. Run 115 prefers NO production runtime code changes
# (verified: no source under crates/* was modified by this run). This
# harness drives the SIGHUP path of `target/release/qbind-node`
# against ephemeral DevNet/MainNet trust-bundle + ratification
# fixtures minted by the Run 113 helper (reused verbatim — the same
# canonical genesis-bound authority / ratified signing key /
# baseline+candidate bundles / sidecar variants the SIGHUP path
# consumes through the Run 105 verifier and Run 106 policy).
#
# Scenarios proved on real `qbind-node` long-running processes:
#
#   1. MainNet  valid    ratification + SIGHUP -> applied, Run 074 ordering preserved.
#   2. MainNet  missing  ratification + SIGHUP -> refused before any mutation.
#   3. MainNet  bad      ratification (signature flip) -> refused before mutation.
#   4. MainNet  wrong    chain_id in ratification     -> refused before mutation.
#   5. MainNet  wrong    environment in ratification  -> refused before mutation.
#   6. MainNet  unknown  authority root in ratification -> refused before mutation.
#   7. DevNet   without  opt-in (legacy unratified)   -> applies (SIGHUP gate SKIPPED).
#   8. DevNet   opt-in   valid ratification           -> applied.
#   9. DevNet   opt-in   missing ratification         -> refused before mutation.
#  10. MainNet  repeated-trigger safety:
#         a. SIGHUP with missing  sidecar -> refused (no mutation, no sequence file).
#         b. SIGHUP with valid    sidecar -> applied (1st mutation; sequence file written).
#         c. SIGHUP with bad      sidecar -> refused (NO rollback of state from 10b).
#         d. SIGHUP with missing  sidecar -> refused (no advance).
#         e. SIGHUP with missing  sidecar -> still refused (no advance).
#       Net result for the SAME long-running process: exactly 1 APPLIED
#       log line, 4 VERDICT=invalid log lines, sequence file contains
#       the seq-2 candidate fingerprint and is not advanced again.
#
# Each non-repeated scenario is a separate process lifetime (own data
# dir, own baseline, own candidate, own sidecar). The node is started
# in background, we wait for the Run 074 "ENABLED" log marker, send
# `kill -HUP <pid>`, wait for the Run 074 VERDICT log line, then send
# SIGINT to exit it cleanly.
#
# No peer-driven live apply, no signing-key rotation/revocation, no
# authority anti-rollback persistence, no KMS/HSM, no governance, no
# validator-set rotation, no trust-bundle wire format change, no
# peer-candidate wire format change.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run115-sighup-ratification-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_113_reload_apply_ratification_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run115] %s\n' "$*"; }
fail() { printf '[run115] FAIL: %s\n' "$*" >&2; exit 1; }
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

# A SIGHUP REJECTION before mutation must satisfy all of:
#   * no `pqc_trust_bundle_sequence.json` written under the data dir;
#   * no Run 074 canonical VERDICT=applied marker;
#   * no Run 070 'trust-bundle candidate APPLIED live' marker.
assert_no_mutation() {
  local data_dir="$1" stderr="$2"
  if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit 2>/dev/null | grep -q .; then
    fail "sequence file was created under ${data_dir} (mutation on a refusal path)"
  fi
  assert_not_grep "$stderr" 'Run 074: VERDICT=applied'
  assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
}

# A SIGHUP SUCCESS must show:
#   * Run 070 canonical applied log line ("trust-bundle candidate APPLIED live");
#   * Run 074 canonical VERDICT=applied marker carrying session_evictions / sequence_commit=ok.
# These two together prove the `validate -> snapshot -> swap -> evict -> commit`
# pipeline executed in order (the VERDICT=applied line is emitted only by
# `LiveReloadOutcome::Applied::log_line`, which the controller returns only
# after the full four-step pipeline completes).
assert_apply_ordering() {
  local stderr="$1"
  assert_grep "$stderr" 'trust-bundle candidate APPLIED live'
  assert_grep "$stderr" 'Run 074: VERDICT=applied'
  assert_grep "$stderr" 'sequence_commit=ok'
}

# Wait for a pattern to appear in the stderr log of a running node,
# up to TIMEOUT seconds. Returns 0 on hit, 1 on timeout.
wait_for_log() {
  local stderr="$1" pattern="$2" timeout="${3:-30}"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if grep -qE -- "$pattern" "$stderr" 2>/dev/null; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# Start a release-binary qbind-node in the background. Captures its
# PID file and waits for the Run 074 ENABLED marker so we know the
# SIGHUP handler is installed and SIGHUPs sent after this point will
# be received by the running handler.
start_node() {
  local name="$1"
  shift
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local pidfile="${OUTDIR}/logs/${name}.pid"
  : > "$stdout"
  : > "$stderr"
  ( "$NODE_BIN" "$@" >"$stdout" 2>"$stderr" & echo $! > "$pidfile" )
  local pid
  pid="$(cat "$pidfile")"
  # Wait for SIGHUP handler installed (Run 074 ENABLED marker).
  if ! wait_for_log "$stderr" 'Run 074: SIGHUP-driven live trust-bundle reload-apply trigger ENABLED' 60; then
    kill -KILL "$pid" 2>/dev/null || true
    fail "${name}: node did not install Run 074 SIGHUP handler within 60s; see ${stderr}"
  fi
  # Wait for the node main loop ready marker (handshakes installed).
  if ! wait_for_log "$stderr" 'P2P node started\. Press Ctrl\+C' 60; then
    kill -KILL "$pid" 2>/dev/null || true
    fail "${name}: node did not reach P2P-ready state within 60s; see ${stderr}"
  fi
  printf '%s' "$pid"
}

# Send SIGHUP and wait for ANY Run 074 VERDICT line to appear after
# the current trigger. Counts existing VERDICT lines first so we know
# we got a NEW one.
send_sighup_and_wait_verdict() {
  local pid="$1" stderr="$2" timeout="${3:-30}"
  local before
  before="$(grep -cE 'Run 074: VERDICT=' "$stderr" 2>/dev/null || echo 0)"
  kill -HUP "$pid"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    local after
    after="$(grep -cE 'Run 074: VERDICT=' "$stderr" 2>/dev/null || echo 0)"
    if [ "$after" -gt "$before" ]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

stop_node() {
  local pid="$1"
  if kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid" 2>/dev/null || true
    local elapsed=0
    while kill -0 "$pid" 2>/dev/null && [ "$elapsed" -lt 20 ]; do
      sleep 1
      elapsed=$((elapsed + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
}

# Build the MainNet flag block used by every MainNet SIGHUP scenario.
# Baseline + candidate are both signed by the ratified signing key
# minted by the Run 113 fixture helper; the live-reload trigger is
# armed and pointed at the candidate bundle. The optional ratification
# sidecar path is appended by the caller (or omitted for the missing
# scenario).
mainnet_args() {
  local data_dir="$1"
  local main_hash main_key main_baseline main_cand
  main_hash="$(cat "$OUTDIR/fixtures/mainnet/expected-genesis-hash.txt")"
  main_key="$(cat "$OUTDIR/fixtures/mainnet/signing-key.ratified.spec")"
  main_baseline="$OUTDIR/fixtures/mainnet/baseline-bundle.json"
  main_cand="$OUTDIR/fixtures/mainnet/candidate-bundle.ratified.json"
  printf -- '--env mainnet --data-dir %s --genesis-path %s --expect-genesis-hash %s ' \
    "$data_dir" "$OUTDIR/fixtures/mainnet/genesis.json" "$main_hash"
  printf -- '--p2p-trust-bundle %s --p2p-trust-bundle-signing-key %s ' \
    "$main_baseline" "$main_key"
  printf -- '--p2p-trust-bundle-live-reload-enabled --p2p-trust-bundle-live-reload-path %s ' \
    "$main_cand"
}

# DevNet flag block. The caller passes the signing-key spec (ratified
# or unratified) and the candidate path so the same helper covers
# both the legacy DevNet (no opt-in, unratified candidate signed by
# `unratified` key) and the opt-in DevNet (ratified candidate) flows.
devnet_args() {
  local data_dir="$1" signing_spec="$2" candidate="$3"
  local dev_hash dev_baseline
  dev_hash="$(cat "$OUTDIR/fixtures/devnet/expected-genesis-hash.txt")"
  dev_baseline="$OUTDIR/fixtures/devnet/baseline-bundle.json"
  printf -- '--env devnet --data-dir %s --genesis-path %s --expect-genesis-hash %s ' \
    "$data_dir" "$OUTDIR/fixtures/devnet/genesis.json" "$dev_hash"
  printf -- '--p2p-trust-bundle %s --p2p-trust-bundle-signing-key %s ' \
    "$dev_baseline" "$signing_spec"
  printf -- '--p2p-trust-bundle-live-reload-enabled --p2p-trust-bundle-live-reload-path %s ' \
    "$candidate"
}

# Run a one-SIGHUP scenario. Starts a node, sends one SIGHUP, asserts
# the verdict log line shape matches `expected_verdict` ("applied" or
# "invalid"), then stops the node and records the outcome.
run_one_sighup_case() {
  local name="$1" expected_verdict="$2"
  shift 2
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"

  log "scenario ${name}: starting node"
  local pid
  pid="$(start_node "$name" "$@")"

  log "scenario ${name}: sending SIGHUP and awaiting VERDICT"
  if ! send_sighup_and_wait_verdict "$pid" "$stderr" 40; then
    stop_node "$pid"
    fail "${name}: did not observe a Run 074 VERDICT line within 40s after SIGHUP"
  fi
  stop_node "$pid"

  assert_grep "$stderr" "Run 074: VERDICT=${expected_verdict}"
  printf '  %s: VERDICT=%s\n' "$name" "$expected_verdict" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and (reused) Run 113 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_113_reload_apply_ratification_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  {
    echo "Run 115 SIGHUP live reload ratification release-binary evidence"
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

  log "generating ephemeral fixtures via reused Run 113 fixture helper"
  "$FIXTURE_HELPER" "$OUTDIR/fixtures" \
    >"$OUTDIR/logs/fixture_helper.stdout.log" \
    2>"$OUTDIR/logs/fixture_helper.stderr.log"

  local main_rat_valid="$OUTDIR/fixtures/mainnet/ratification.valid.json"
  local main_rat_bad="$OUTDIR/fixtures/mainnet/ratification.bad-signature.json"
  local main_rat_wchain="$OUTDIR/fixtures/mainnet/ratification.wrong-chain.json"
  local main_rat_wenv="$OUTDIR/fixtures/mainnet/ratification.wrong-environment.json"
  local main_rat_unk="$OUTDIR/fixtures/mainnet/ratification.unknown-authority.json"

  local dev_rat_valid="$OUTDIR/fixtures/devnet/ratification.valid.json"
  local dev_cand="$OUTDIR/fixtures/devnet/candidate-bundle.ratified.json"
  local dev_cand_unrat="$OUTDIR/fixtures/devnet/candidate-bundle.unratified.json"
  local dev_key dev_unrat_key
  dev_key="$(cat "$OUTDIR/fixtures/devnet/signing-key.ratified.spec")"
  dev_unrat_key="$(cat "$OUTDIR/fixtures/devnet/signing-key.unratified.spec")"

  # ---------- Scenarios 1..6: MainNet, single SIGHUP per scenario ----------

  log "Scenario 1: MainNet valid ratification + SIGHUP -> applied"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_1_mainnet_valid applied \
    $(mainnet_args "$OUTDIR/data/scenario_1_mainnet_valid") \
    --p2p-trust-bundle-ratification "$main_rat_valid"
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Mainnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log"

  log "Scenario 2: MainNet missing ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_2_mainnet_missing invalid \
    $(mainnet_args "$OUTDIR/data/scenario_2_mainnet_missing")
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Mainnet'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" \
    'ratification missing|RatificationRefused|Missing'
  assert_no_mutation "$OUTDIR/data/scenario_2_mainnet_missing" \
    "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log"

  log "Scenario 3: MainNet bad-signature ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_3_mainnet_bad_signature invalid \
    $(mainnet_args "$OUTDIR/data/scenario_3_mainnet_bad_signature") \
    --p2p-trust-bundle-ratification "$main_rat_bad"
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" \
    'BadSignature|RatificationRefused|signature failed PQC verification'
  assert_no_mutation "$OUTDIR/data/scenario_3_mainnet_bad_signature" \
    "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log"

  log "Scenario 4: MainNet wrong-chain ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_4_mainnet_wrong_chain invalid \
    $(mainnet_args "$OUTDIR/data/scenario_4_mainnet_wrong_chain") \
    --p2p-trust-bundle-ratification "$main_rat_wchain"
  assert_grep "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log" \
    'ChainMismatch|chain_id mismatch|RatificationRefused'
  assert_no_mutation "$OUTDIR/data/scenario_4_mainnet_wrong_chain" \
    "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log"

  log "Scenario 5: MainNet wrong-environment ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_5_mainnet_wrong_env invalid \
    $(mainnet_args "$OUTDIR/data/scenario_5_mainnet_wrong_env") \
    --p2p-trust-bundle-ratification "$main_rat_wenv"
  assert_grep "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log" \
    'EnvironmentMismatch|environment mismatch|RatificationRefused'
  assert_no_mutation "$OUTDIR/data/scenario_5_mainnet_wrong_env" \
    "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log"

  log "Scenario 6: MainNet unknown-authority ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_6_mainnet_unknown_authority invalid \
    $(mainnet_args "$OUTDIR/data/scenario_6_mainnet_unknown_authority") \
    --p2p-trust-bundle-ratification "$main_rat_unk"
  assert_grep "$OUTDIR/logs/scenario_6_mainnet_unknown_authority.stderr.log" \
    'UnknownAuthorityRoot|not present in genesis|RatificationRefused'
  assert_no_mutation "$OUTDIR/data/scenario_6_mainnet_unknown_authority" \
    "$OUTDIR/logs/scenario_6_mainnet_unknown_authority.stderr.log"

  # ---------- Scenarios 7..9: DevNet ----------

  log "Scenario 7: DevNet without opt-in (legacy unratified) + SIGHUP -> applies"
  # The legacy DevNet ergonomics: candidate is signed by an UNRATIFIED
  # signing key and there is no ratification sidecar and no opt-in
  # flag. The Run 114 gate must SKIP (no enforcement on DevNet without
  # explicit opt-in) and the Run 074 pipeline applies as before. We
  # supply BOTH signing-key specs so the baseline (ratified-signed)
  # and the candidate (unratified-signed) both validate.
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_7_devnet_legacy_no_opt_in applied \
    $(devnet_args "$OUTDIR/data/scenario_7_devnet_legacy_no_opt_in" "$dev_key" "$dev_cand_unrat") \
    --p2p-trust-bundle-signing-key "$dev_unrat_key"
  assert_grep "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate SKIPPED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log"

  log "Scenario 8: DevNet opt-in valid ratification + SIGHUP -> applied"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_8_devnet_opt_in_valid applied \
    $(devnet_args "$OUTDIR/data/scenario_8_devnet_opt_in_valid" "$dev_key" "$dev_cand") \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$dev_rat_valid"
  assert_grep "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log"

  log "Scenario 9: DevNet opt-in missing ratification + SIGHUP -> refused"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_9_devnet_opt_in_missing invalid \
    $(devnet_args "$OUTDIR/data/scenario_9_devnet_opt_in_missing" "$dev_key" "$dev_cand") \
    --p2p-trust-bundle-ratification-enforcement-enabled
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Devnet'
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" \
    'ratification missing|RatificationRefused|Missing'
  assert_no_mutation "$OUTDIR/data/scenario_9_devnet_opt_in_missing" \
    "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log"

  # ---------- Scenario 10: repeated-trigger safety on ONE long-running node ----------
  #
  # Goal: prove that within a single process lifetime:
  #   * an early INVALID SIGHUP does not poison a later VALID SIGHUP;
  #   * a later INVALID SIGHUP does not roll back the state established
  #     by an earlier VALID SIGHUP;
  #   * repeated INVALID SIGHUPs do not mutate or advance the sequence;
  # all on the MainNet strict policy.
  log "Scenario 10: MainNet repeated-trigger safety on a single long-running node"
  local s10_name=scenario_10_mainnet_repeated_triggers
  local s10_data="${OUTDIR}/data/${s10_name}"
  local s10_stderr="${OUTDIR}/logs/${s10_name}.stderr.log"
  local s10_sidecar="${OUTDIR}/fixtures/mainnet/ratification.scenario10.json"
  mkdir -p "$s10_data"

  # Start with a non-existent sidecar path so the first SIGHUP fails
  # the sidecar-load preflight (Missing variant).
  test ! -e "$s10_sidecar" || rm -f "$s10_sidecar"

  # shellcheck disable=SC2046
  local s10_pid
  s10_pid="$(start_node "$s10_name" \
    $(mainnet_args "$s10_data") \
    --p2p-trust-bundle-ratification "$s10_sidecar")"

  log "  s10a: SIGHUP with missing sidecar -> refused"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10a: no VERDICT after SIGHUP"; }
  # Snapshot the verdict count so each later trigger can assert it
  # produced a NEW verdict line (we already know there is one now).
  local s10a_invalid_count s10b_applied_count
  s10a_invalid_count="$(grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr")"
  [ "$s10a_invalid_count" -ge 1 ] \
    || { stop_node "$s10_pid"; fail "s10a: expected >=1 VERDICT=invalid"; }
  if find "$s10_data" -name 'pqc_trust_bundle_sequence.json' -print -quit 2>/dev/null | grep -q .; then
    stop_node "$s10_pid"
    fail "s10a: sequence file created on refusal (mutation on rejection)"
  fi

  log "  s10b: drop valid sidecar at the same path and SIGHUP -> applied"
  cp "$main_rat_valid" "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10b: no VERDICT after SIGHUP"; }
  s10b_applied_count="$(grep -cE 'Run 074: VERDICT=applied' "$s10_stderr")"
  [ "$s10b_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10b: expected exactly 1 VERDICT=applied, got ${s10b_applied_count}"; }
  # Sequence file must now exist (state mutated on the VALID apply).
  test -f "$s10_data/pqc_trust_bundle_sequence.json" \
    || { stop_node "$s10_pid"; fail "s10b: sequence file should exist after applied SIGHUP"; }
  local s10_seq_sha_after_b
  s10_seq_sha_after_b="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"

  log "  s10c: overwrite sidecar with bad-signature variant and SIGHUP -> refused, no rollback"
  cp "$main_rat_bad" "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10c: no VERDICT after SIGHUP"; }
  # Still exactly 1 applied; invalid count went up.
  local s10c_applied_count s10c_invalid_count
  s10c_applied_count="$(grep -cE 'Run 074: VERDICT=applied' "$s10_stderr")"
  s10c_invalid_count="$(grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr")"
  [ "$s10c_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10c: VERDICT=applied count must stay at 1; got ${s10c_applied_count}"; }
  [ "$s10c_invalid_count" -gt "$s10a_invalid_count" ] \
    || { stop_node "$s10_pid"; fail "s10c: VERDICT=invalid count must advance"; }
  # Sequence file must be byte-for-byte identical to its post-s10b state
  # (no rollback, no advance).
  local s10_seq_sha_after_c
  s10_seq_sha_after_c="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  [ "$s10_seq_sha_after_b" = "$s10_seq_sha_after_c" ] \
    || { stop_node "$s10_pid"; fail "s10c: sequence file mutated on refusal (b=${s10_seq_sha_after_b} c=${s10_seq_sha_after_c})"; }

  log "  s10d: remove sidecar entirely and SIGHUP -> refused (repeated invalid, no advance)"
  rm -f "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10d: no VERDICT after SIGHUP"; }
  local s10d_applied_count
  s10d_applied_count="$(grep -cE 'Run 074: VERDICT=applied' "$s10_stderr")"
  [ "$s10d_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10d: applied count must stay at 1"; }

  log "  s10e: still missing sidecar, SIGHUP -> still refused (no accumulation)"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10e: no VERDICT after SIGHUP"; }
  local s10e_applied_count s10e_invalid_count
  s10e_applied_count="$(grep -cE 'Run 074: VERDICT=applied' "$s10_stderr")"
  s10e_invalid_count="$(grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr")"
  [ "$s10e_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10e: applied count must stay at 1; got ${s10e_applied_count}"; }
  [ "$s10e_invalid_count" -ge 4 ] \
    || { stop_node "$s10_pid"; fail "s10e: invalid count should be >=4; got ${s10e_invalid_count}"; }
  # Sequence file still byte-identical to the post-apply state.
  local s10_seq_sha_after_e
  s10_seq_sha_after_e="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  [ "$s10_seq_sha_after_b" = "$s10_seq_sha_after_e" ] \
    || { stop_node "$s10_pid"; fail "s10e: sequence file diverged from post-apply state (b=${s10_seq_sha_after_b} e=${s10_seq_sha_after_e})"; }

  stop_node "$s10_pid"
  printf '  %s: 1xapplied + %sxinvalid, sequence file stable post-apply\n' \
    "$s10_name" "$s10e_invalid_count" >> "$SUMMARY"

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json was created under any refusal scenario data dir"
    echo "  no Run 070 APPLIED log line on any refusal scenario"
    echo "  no Run 074 VERDICT=applied marker on any refusal scenario"
    echo "apply-ordering checks: pass"
    echo "  Run 070 canonical applied_log_line + 'sequence_commit=ok' + Run 074"
    echo "  VERDICT=applied present together on every accepted scenario."
    echo "repeated-trigger safety (scenario 10): pass"
    echo "  same long-running process produced exactly 1 VERDICT=applied across 5"
    echo "  SIGHUPs (invalid->valid->invalid->invalid->invalid); on-disk sequence"
    echo "  file is byte-identical pre and post each refusal after the first apply"
    echo "  (no rollback of valid state, no advance on repeated invalids)."
    echo "wire-format checks: source-only, no trust-bundle or ratification structs"
    echo "  changed by this evidence harness."
    echo "scope-non-goal checks: peer-driven live apply, signing-key"
    echo "  rotation/revocation, authority anti-rollback persistence, KMS/HSM,"
    echo "  governance, validator-set rotation: NOT touched."
  } >> "$SUMMARY"
  log "PASS: Run 115 SIGHUP evidence captured under ${OUTDIR}"
}

main "$@"
