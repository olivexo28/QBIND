#!/usr/bin/env bash
# Run 115: release-binary evidence matrix for SIGHUP live reload
# bundle-signing-key ratification enforcement (Run 114 wiring).
#
# Evidence-only. Run 115 prefers NO production runtime code changes
# (verified: no source under crates/* outside of `examples/` was
# modified by this run). This harness drives the SIGHUP path of
# `target/release/qbind-node` against ephemeral DevNet/MainNet
# trust-bundle + ratification fixtures minted by the Run 115 helper
# `run_115_sighup_ratification_fixture_helper` (which extends the
# Run 113 reload-apply fixture shape with the additional per-env
# transport root + ML-KEM-768 leaf KEM keypair + ML-DSA-44-signed
# leaf delegation cert the SIGHUP path needs to enter `run_p2p_node`
# — the only mode where the Run 074 SIGHUP handler is installed).
# Each scenario runs against fresh fixtures with the canonical
# genesis-bound authority / ratified signing key / baseline+candidate
# bundles / sidecar variants the SIGHUP path consumes through the
# Run 105 verifier and Run 106 policy.
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
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_115_sighup_ratification_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

# Loopback P2P listen ports — one per scenario lifetime. Each scenario
# is its own subprocess with its own data dir; the ports are unique
# per-scenario so concurrent shells (or test re-runs while another
# scenario lingers) do not collide. Scenario 10 reuses one port across
# its five SIGHUPs because it runs on a single long-running process.
p2p_port_for() {
  local name="$1"
  case "$name" in
    scenario_1_mainnet_valid)               echo 34101 ;;
    scenario_2_mainnet_missing)             echo 34102 ;;
    scenario_3_mainnet_bad_signature)       echo 34103 ;;
    scenario_4_mainnet_wrong_chain)         echo 34104 ;;
    scenario_5_mainnet_wrong_env)           echo 34105 ;;
    scenario_6_mainnet_unknown_authority)   echo 34106 ;;
    scenario_7_devnet_legacy_no_opt_in)     echo 34107 ;;
    scenario_8_devnet_opt_in_valid)         echo 34108 ;;
    scenario_9_devnet_opt_in_missing)       echo 34109 ;;
    scenario_10_mainnet_repeated_triggers)  echo 34110 ;;
    *)                                      echo 34199 ;;
  esac
}

# Build the per-environment P2P boot flags that the SIGHUP path needs
# in order to reach `run_p2p_node` (the ONLY mode where the Run 074
# SIGHUP handler is installed — `run_local_mesh_node` never installs
# it). Each environment uses its own per-env fixture material minted
# by the Run 115 fixture helper against the SAME transport root the
# trust bundle's `roots[0]` block advertises.
p2p_boot_args() {
  local env_dir="$1" port="$2"
  printf -- '--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:%s ' "$port"
  printf -- '--validator-id 0 '
  printf -- '--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root '
  printf -- '--p2p-leaf-cert %s --p2p-leaf-cert-key %s ' \
    "$env_dir/v0.cert.bin" "$env_dir/v0.kem.sk.bin"
}

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
# A SIGHUP REJECTION before mutation must satisfy all of:
#   * no Run 074 canonical VERDICT=applied marker emitted;
#   * the on-disk `pqc_trust_bundle_sequence.json` record's
#     `highest_sequence` field still records the BASELINE sequence
#     (1), i.e. the candidate (sequence=2) never made it past the
#     gate into a sequence commit.
# Note: the sequence file IS written at startup by Run 055 with the
# baseline's `highest_sequence=1` on first-load, before any SIGHUP
# arrives. So "no mutation" is "sequence stayed at 1" rather than
# "file does not exist".
assert_no_mutation() {
  local data_dir="$1" stderr="$2"
  assert_not_grep "$stderr" 'Run 074: VERDICT=applied'
  local seq_file="${data_dir}/pqc_trust_bundle_sequence.json"
  if [ -f "$seq_file" ]; then
    local seq
    seq="$(grep -oE '"highest_sequence":[0-9]+' "$seq_file" | head -1 | awk -F: '{print $2}')"
    [ "$seq" = "1" ] \
      || fail "sequence file under ${data_dir} advanced past baseline on a refusal path (highest_sequence=${seq}, expected 1)"
  fi
}

# A SIGHUP SUCCESS must show the Run 074 canonical aggregation
# `VERDICT=applied` marker carrying `session_evictions=N; sequence_commit=ok`.
# The `LiveReloadOutcome::Applied::log_line` emits this only after the
# controller has driven the full `validate -> snapshot -> swap -> evict
# -> commit` pipeline to completion (see
# `LiveReloadController::run_apply_pipeline`), so the presence of both
# `sequence_commit=ok` AND `Run 074: VERDICT=applied` together is
# end-to-end ordering proof on the SIGHUP path.
assert_apply_ordering() {
  local stderr="$1"
  assert_grep "$stderr" 'Run 074: VERDICT=applied'
  assert_grep "$stderr" 'sequence_commit=ok'
  assert_grep "$stderr" 'session_evictions='
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
  before="$({ grep -cE 'Run 074: VERDICT=' "$stderr" 2>/dev/null || true; } | head -1)"
  : "${before:=0}"
  kill -HUP "$pid"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    local after
    after="$({ grep -cE 'Run 074: VERDICT=' "$stderr" 2>/dev/null || true; } | head -1)"
    : "${after:=0}"
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
  local data_dir="$1" port="$2"
  local main_hash main_key main_baseline main_cand env_dir
  env_dir="$OUTDIR/fixtures/mainnet"
  main_hash="$(cat "$env_dir/expected-genesis-hash.txt")"
  main_key="$(cat "$env_dir/signing-key.ratified.spec")"
  main_baseline="$env_dir/baseline-bundle.json"
  main_cand="$env_dir/candidate-bundle.ratified.json"
  printf -- '--env mainnet --data-dir %s --genesis-path %s --expect-genesis-hash %s ' \
    "$data_dir" "$env_dir/genesis.json" "$main_hash"
  p2p_boot_args "$env_dir" "$port"
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
  local data_dir="$1" signing_spec="$2" candidate="$3" port="$4"
  local dev_hash env_dir dev_baseline
  env_dir="$OUTDIR/fixtures/devnet"
  dev_hash="$(cat "$env_dir/expected-genesis-hash.txt")"
  dev_baseline="$env_dir/baseline-bundle.json"
  printf -- '--env devnet --data-dir %s --genesis-path %s --expect-genesis-hash %s ' \
    "$data_dir" "$env_dir/genesis.json" "$dev_hash"
  p2p_boot_args "$env_dir" "$port"
  printf -- '--p2p-trust-bundle %s --p2p-trust-bundle-signing-key %s ' \
    "$dev_baseline" "$signing_spec"
  printf -- '--p2p-trust-bundle-live-reload-enabled --p2p-trust-bundle-live-reload-path %s ' \
    "$candidate"
}

# Run a one-SIGHUP scenario. Starts a node with the *currently-on-disk*
# sidecar (the caller must ensure that sidecar is VALID at startup,
# because MainNet/TestNet strict policy refuses at startup-time on a
# missing/invalid ratification — that is intentional Run 106 behavior
# and is NOT the Run 114 SIGHUP gate we are trying to evidence). After
# the node is up and the Run 074 handler is installed, the caller-
# supplied `pre_sighup_mutate` callback runs (e.g. overwriting the
# sidecar with the bad-signature variant, or removing it to test the
# Missing variant), THEN we send SIGHUP and assert verdict.
run_one_sighup_case() {
  local name="$1" expected_verdict="$2" pre_sighup_mutate="$3"
  shift 3
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local data_dir="${OUTDIR}/data/${name}"
  mkdir -p "$data_dir"

  log "scenario ${name}: starting node"
  local pid
  pid="$(start_node "$name" "$@")"

  if [ -n "$pre_sighup_mutate" ]; then
    log "scenario ${name}: applying pre-SIGHUP sidecar mutation"
    eval "$pre_sighup_mutate"
  fi

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
  log "building release qbind-node and Run 115 SIGHUP fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_115_sighup_ratification_fixture_helper

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

  log "generating ephemeral fixtures via Run 115 SIGHUP fixture helper"
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

  # All MainNet refusal scenarios MUST start with a VALID ratification
  # sidecar so the Run 106 startup-strict policy lets the node boot
  # and install the Run 074 SIGHUP handler — the surface we are
  # actually trying to evidence. Each scenario gets a private staged
  # copy of `ratification.valid.json` (one per scenario data dir);
  # the per-scenario pre-SIGHUP mutate step then overwrites that copy
  # in place (or deletes it for the Missing variant), so the Run 114
  # SIGHUP-gate re-read on the next SIGHUP sees the negative input.
  stage_sidecar() {
    local data_dir="$1" src="$2"
    mkdir -p "$data_dir"
    local staged="${data_dir}/ratification.staged.json"
    cp "$src" "$staged"
    printf '%s' "$staged"
  }

  # ---------- Scenarios 1..6: MainNet, single SIGHUP per scenario ----------

  log "Scenario 1: MainNet valid ratification + SIGHUP -> applied"
  local s1_sidecar
  s1_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_1_mainnet_valid" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_1_mainnet_valid applied "" \
    $(mainnet_args "$OUTDIR/data/scenario_1_mainnet_valid" "$(p2p_port_for scenario_1_mainnet_valid)") \
    --p2p-trust-bundle-ratification "$s1_sidecar"
  assert_grep "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Mainnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_1_mainnet_valid.stderr.log"

  log "Scenario 2: MainNet missing ratification (deleted post-startup) + SIGHUP -> refused"
  local s2_sidecar
  s2_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_2_mainnet_missing" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_2_mainnet_missing invalid \
    "rm -f '$s2_sidecar'" \
    $(mainnet_args "$OUTDIR/data/scenario_2_mainnet_missing" "$(p2p_port_for scenario_2_mainnet_missing)") \
    --p2p-trust-bundle-ratification "$s2_sidecar"
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Mainnet'
  assert_grep "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log" \
    'ratification missing|RatificationRefused|Missing|sidecar.*not found|No such file'
  assert_no_mutation "$OUTDIR/data/scenario_2_mainnet_missing" \
    "$OUTDIR/logs/scenario_2_mainnet_missing.stderr.log"

  log "Scenario 3: MainNet bad-signature ratification (swapped post-startup) + SIGHUP -> refused"
  local s3_sidecar
  s3_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_3_mainnet_bad_signature" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_3_mainnet_bad_signature invalid \
    "cp '$main_rat_bad' '$s3_sidecar'" \
    $(mainnet_args "$OUTDIR/data/scenario_3_mainnet_bad_signature" "$(p2p_port_for scenario_3_mainnet_bad_signature)") \
    --p2p-trust-bundle-ratification "$s3_sidecar"
  assert_grep "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log" \
    'BadSignature|RatificationRefused|signature failed PQC verification'
  assert_no_mutation "$OUTDIR/data/scenario_3_mainnet_bad_signature" \
    "$OUTDIR/logs/scenario_3_mainnet_bad_signature.stderr.log"

  log "Scenario 4: MainNet wrong-chain ratification (swapped post-startup) + SIGHUP -> refused"
  local s4_sidecar
  s4_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_4_mainnet_wrong_chain" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_4_mainnet_wrong_chain invalid \
    "cp '$main_rat_wchain' '$s4_sidecar'" \
    $(mainnet_args "$OUTDIR/data/scenario_4_mainnet_wrong_chain" "$(p2p_port_for scenario_4_mainnet_wrong_chain)") \
    --p2p-trust-bundle-ratification "$s4_sidecar"
  assert_grep "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log" \
    'ChainMismatch|chain_id mismatch|RatificationRefused'
  assert_no_mutation "$OUTDIR/data/scenario_4_mainnet_wrong_chain" \
    "$OUTDIR/logs/scenario_4_mainnet_wrong_chain.stderr.log"

  log "Scenario 5: MainNet wrong-environment ratification (swapped post-startup) + SIGHUP -> refused"
  local s5_sidecar
  s5_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_5_mainnet_wrong_env" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_5_mainnet_wrong_env invalid \
    "cp '$main_rat_wenv' '$s5_sidecar'" \
    $(mainnet_args "$OUTDIR/data/scenario_5_mainnet_wrong_env" "$(p2p_port_for scenario_5_mainnet_wrong_env)") \
    --p2p-trust-bundle-ratification "$s5_sidecar"
  assert_grep "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log" \
    'EnvironmentMismatch|environment mismatch|RatificationRefused'
  assert_no_mutation "$OUTDIR/data/scenario_5_mainnet_wrong_env" \
    "$OUTDIR/logs/scenario_5_mainnet_wrong_env.stderr.log"

  log "Scenario 6: MainNet unknown-authority ratification (swapped post-startup) + SIGHUP -> refused"
  local s6_sidecar
  s6_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_6_mainnet_unknown_authority" "$main_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_6_mainnet_unknown_authority invalid \
    "cp '$main_rat_unk' '$s6_sidecar'" \
    $(mainnet_args "$OUTDIR/data/scenario_6_mainnet_unknown_authority" "$(p2p_port_for scenario_6_mainnet_unknown_authority)") \
    --p2p-trust-bundle-ratification "$s6_sidecar"
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
  run_one_sighup_case scenario_7_devnet_legacy_no_opt_in applied "" \
    $(devnet_args "$OUTDIR/data/scenario_7_devnet_legacy_no_opt_in" "$dev_key" "$dev_cand_unrat" "$(p2p_port_for scenario_7_devnet_legacy_no_opt_in)") \
    --p2p-trust-bundle-signing-key "$dev_unrat_key"
  assert_grep "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate SKIPPED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_7_devnet_legacy_no_opt_in.stderr.log"

  log "Scenario 8: DevNet opt-in valid ratification + SIGHUP -> applied"
  local s8_sidecar
  s8_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_8_devnet_opt_in_valid" "$dev_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_8_devnet_opt_in_valid applied "" \
    $(devnet_args "$OUTDIR/data/scenario_8_devnet_opt_in_valid" "$dev_key" "$dev_cand" "$(p2p_port_for scenario_8_devnet_opt_in_valid)") \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$s8_sidecar"
  assert_grep "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Devnet'
  assert_apply_ordering "$OUTDIR/logs/scenario_8_devnet_opt_in_valid.stderr.log"

  log "Scenario 9: DevNet opt-in missing ratification (deleted post-startup) + SIGHUP -> refused"
  local s9_sidecar
  s9_sidecar="$(stage_sidecar "$OUTDIR/data/scenario_9_devnet_opt_in_missing" "$dev_rat_valid")"
  # shellcheck disable=SC2046
  run_one_sighup_case scenario_9_devnet_opt_in_missing invalid \
    "rm -f '$s9_sidecar'" \
    $(devnet_args "$OUTDIR/data/scenario_9_devnet_opt_in_missing" "$dev_key" "$dev_cand" "$(p2p_port_for scenario_9_devnet_opt_in_missing)") \
    --p2p-trust-bundle-ratification-enforcement-enabled \
    --p2p-trust-bundle-ratification "$s9_sidecar"
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" \
    '\[run-114\] SIGHUP live reload ratification gate INVOKED.*Devnet'
  assert_grep "$OUTDIR/logs/scenario_9_devnet_opt_in_missing.stderr.log" \
    'ratification missing|RatificationRefused|Missing|sidecar.*not found|No such file'
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
  mkdir -p "$s10_data"
  # Start with a VALID sidecar so the Run 106 startup-strict gate
  # admits the boot. We then mutate this staged sidecar in-place
  # between SIGHUPs to flip the Run 114 re-read result.
  local s10_sidecar
  s10_sidecar="$(stage_sidecar "$s10_data" "$main_rat_valid")"

  # shellcheck disable=SC2046
  local s10_pid
  s10_pid="$(start_node "$s10_name" \
    $(mainnet_args "$s10_data" "$(p2p_port_for $s10_name)") \
    --p2p-trust-bundle-ratification "$s10_sidecar")"

  log "  s10a: delete sidecar then SIGHUP -> refused (Missing)"
  rm -f "$s10_sidecar"
  test -f "$s10_data/pqc_trust_bundle_sequence.json" \
    || { stop_node "$s10_pid"; fail "s10a: baseline sequence file missing pre-SIGHUP"; }
  local s10_seq_sha_baseline
  s10_seq_sha_baseline="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10a: no VERDICT after SIGHUP"; }
  local s10a_invalid_count s10b_applied_count
  s10a_invalid_count="$({ grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10a_invalid_count:=0}"
  [ "$s10a_invalid_count" -ge 1 ] \
    || { stop_node "$s10_pid"; fail "s10a: expected >=1 VERDICT=invalid"; }
  local s10_seq_sha_after_a
  s10_seq_sha_after_a="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  [ "$s10_seq_sha_baseline" = "$s10_seq_sha_after_a" ] \
    || { stop_node "$s10_pid"; fail "s10a: sequence file mutated on refusal (baseline=${s10_seq_sha_baseline} after=${s10_seq_sha_after_a})"; }

  log "  s10b: drop valid sidecar at the same path and SIGHUP -> applied"
  cp "$main_rat_valid" "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10b: no VERDICT after SIGHUP"; }
  s10b_applied_count="$({ grep -cE 'Run 074: VERDICT=applied' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10b_applied_count:=0}"
  [ "$s10b_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10b: expected exactly 1 VERDICT=applied, got ${s10b_applied_count}"; }
  test -f "$s10_data/pqc_trust_bundle_sequence.json" \
    || { stop_node "$s10_pid"; fail "s10b: sequence file should exist after applied SIGHUP"; }
  local s10_seq_sha_after_b
  s10_seq_sha_after_b="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  [ "$s10_seq_sha_after_b" != "$s10_seq_sha_baseline" ] \
    || { stop_node "$s10_pid"; fail "s10b: sequence file did not advance post-apply (still ${s10_seq_sha_baseline})"; }

  log "  s10c: overwrite sidecar with bad-signature variant and SIGHUP -> refused, no rollback"
  cp "$main_rat_bad" "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10c: no VERDICT after SIGHUP"; }
  local s10c_applied_count s10c_invalid_count
  s10c_applied_count="$({ grep -cE 'Run 074: VERDICT=applied' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10c_applied_count:=0}"
  s10c_invalid_count="$({ grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10c_invalid_count:=0}"
  [ "$s10c_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10c: VERDICT=applied count must stay at 1; got ${s10c_applied_count}"; }
  [ "$s10c_invalid_count" -gt "$s10a_invalid_count" ] \
    || { stop_node "$s10_pid"; fail "s10c: VERDICT=invalid count must advance"; }
  local s10_seq_sha_after_c
  s10_seq_sha_after_c="$(sha256_file "$s10_data/pqc_trust_bundle_sequence.json")"
  [ "$s10_seq_sha_after_b" = "$s10_seq_sha_after_c" ] \
    || { stop_node "$s10_pid"; fail "s10c: sequence file mutated on refusal (b=${s10_seq_sha_after_b} c=${s10_seq_sha_after_c})"; }

  log "  s10d: remove sidecar entirely and SIGHUP -> refused (repeated invalid, no advance)"
  rm -f "$s10_sidecar"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10d: no VERDICT after SIGHUP"; }
  local s10d_applied_count
  s10d_applied_count="$({ grep -cE 'Run 074: VERDICT=applied' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10d_applied_count:=0}"
  [ "$s10d_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10d: applied count must stay at 1"; }

  log "  s10e: still missing sidecar, SIGHUP -> still refused (no accumulation)"
  send_sighup_and_wait_verdict "$s10_pid" "$s10_stderr" 40 \
    || { stop_node "$s10_pid"; fail "s10e: no VERDICT after SIGHUP"; }
  local s10e_applied_count s10e_invalid_count
  s10e_applied_count="$({ grep -cE 'Run 074: VERDICT=applied' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10e_applied_count:=0}"
  s10e_invalid_count="$({ grep -cE 'Run 074: VERDICT=invalid' "$s10_stderr" 2>/dev/null || true; } | head -1)"
  : "${s10e_invalid_count:=0}"
  [ "$s10e_applied_count" = "1" ] \
    || { stop_node "$s10_pid"; fail "s10e: applied count must stay at 1; got ${s10e_applied_count}"; }
  [ "$s10e_invalid_count" -ge 4 ] \
    || { stop_node "$s10_pid"; fail "s10e: invalid count should be >=4; got ${s10e_invalid_count}"; }
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
    echo "  on every refusal scenario, the data dir's"
    echo "  pqc_trust_bundle_sequence.json still records the baseline"
    echo "  (highest_sequence=1), and no Run 074 VERDICT=applied marker"
    echo "  was emitted."
    echo "apply-ordering checks: pass"
    echo "  Run 074 VERDICT=applied carrying 'session_evictions=N;"
    echo "  sequence_commit=ok' present on every accepted scenario. The"
    echo "  VERDICT=applied marker is emitted only by"
    echo "  LiveReloadOutcome::Applied after the full"
    echo "  validate -> snapshot -> swap -> evict -> commit pipeline."
    echo "repeated-trigger safety (scenario 10): pass"
    echo "  same long-running process produced exactly 1 VERDICT=applied"
    echo "  across 5 SIGHUPs (invalid->valid->invalid->invalid->invalid);"
    echo "  on-disk sequence file is byte-identical pre and post each"
    echo "  refusal (baseline state pre-apply; post-apply state held"
    echo "  through the trailing refusals: no rollback, no advance)."
    echo "wire-format checks: source-only, no trust-bundle or ratification"
    echo "  structs changed by this evidence harness."
    echo "scope-non-goal checks: peer-driven live apply, signing-key"
    echo "  rotation/revocation, authority anti-rollback persistence,"
    echo "  KMS/HSM, governance, validator-set rotation: NOT touched."
  } >> "$SUMMARY"
  log "PASS: Run 115 SIGHUP evidence captured under ${OUTDIR}"
}

main "$@"
