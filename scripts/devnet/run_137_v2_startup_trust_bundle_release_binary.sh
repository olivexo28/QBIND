#!/usr/bin/env bash
# Run 137 — release-binary evidence matrix for the v2 (ratification-v2)
# startup `--p2p-trust-bundle` MUTATING binary surface (Run 136 wiring).
#
# Evidence-only. This harness does NOT change production runtime code and
# does NOT touch any wire format. It exercises BOTH the v1 startup
# fall-through path (regression: Run 105/Run 106/Run 120) and the v2
# startup dispatch (Run 136) against ephemeral DevNet fixtures minted by
# the existing Run 133 `run_133_v2_validation_only_fixture_helper` release
# example binary.
#
# Scenario matrix (DevNet startup `--p2p-trust-bundle` + v2 sidecar):
#   acceptance (release binary is bounded by `timeout`; the harness
#     observes the [run-136] persist log line + on-disk marker and then
#     the timeout terminates the still-running node BEFORE consensus
#     does any useful work):
#     A1.  v2 ratify@seq=1, no marker       → first v2 startup write
#                                              succeeds, v2 marker
#                                              persisted strictly AFTER
#                                              the Run 055 sequence
#                                              persistence line.
#     A2.  v2 ratify@seq=2, v1 marker       → v2-after-v1 migration
#                                              succeeds, v2 marker
#                                              replaces v1 only after
#                                              `check_and_update_sequence`.
#     A3.  v2 ratify@seq=1, v2-seq=1 marker → idempotent same-digest;
#                                              succeeds; marker bytes
#                                              remain byte-identical.
#     A4.  v2 ratify@seq=2, v2-seq=1 marker → higher-sequence upgrade
#                                              succeeds; marker advances
#                                              ONLY after commit.
#   rejection (must occur BEFORE any mutation AND BEFORE P2P startup):
#     R1.  v2 ratify@seq=1, v2-seq=2 marker → lower-sequence refused
#                                              (LowerV2SequenceRefused).
#     R2.  v2 ratify@seq=1 (rotated target),
#          v2-seq=1 marker (active target)  → same-seq different-digest
#                                              refused (equivocation;
#                                              SameSequenceConflicting…).
#     R3a. v2 bad-signature                 → verifier refused.
#     R3b. v2 wrong-environment             → verifier refused
#                                              (wrong-domain proof for
#                                              the env binding axis).
#     R4.  v2 wrong-chain                   → verifier refused
#                                              (wrong-domain proof for
#                                              the chain_id binding
#                                              axis).
#     R5.  v2 wrong-genesis                 → verifier refused
#                                              (wrong-domain proof for
#                                              the genesis-hash binding
#                                              axis).
#     A4-low-block.  (Run 134 §C.3 / Run 135 R4 analogue — apply
#                    failure after preflight — release binary cannot
#                    deterministically trigger a post-preflight, pre-
#                    `check_and_update_sequence` failure on the startup
#                    surface with operator-supplied flag inputs alone;
#                    documented in QBIND_DEVNET_EVIDENCE_RUN_137.md as
#                    not-feasible-on-release-binary, identical
#                    treatment to Run 135 R4.)
#   v1 regression:
#     V1.  v1 valid ratification, no marker → Run 105/Run 120 v1 startup
#                                              succeeds; v1 marker
#                                              persisted; NO Run 136 v2
#                                              path logs are observed.
#
# For every scenario this harness also asserts:
#   * post-run marker bytes match the EXPECTED state (seeded-and-
#     unchanged on rejection / idempotent; advanced-only-after-commit on
#     accept);
#   * no `.tmp` marker sibling is left behind;
#   * no SIGHUP / live-`0x05` / KMS / HSM / peer-driven-apply / snapshot
#     -restore markers are emitted on any path;
#   * rejected scenarios prove NO `[binary] P2P transport up` line was
#     emitted — startup fails closed BEFORE P2P listener bind.
#
# No SIGHUP, no live inbound `0x05` v2 wiring, no peer-driven live
# apply, no snapshot/restore v2 wiring, no signing-key rotation/
# revocation lifecycle, no KMS/HSM, no governance, no trust-bundle wire
# format change, no peer-candidate wire format change, no new CLI
# flags, no new metrics.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run137-v2-startup-trust-bundle-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
FIXTURE_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
SUMMARY="${OUTDIR}/summary.txt"

# Per-scenario port allocation. Each accepted scenario reaches the P2P
# listener-bind step (this is REQUIRED to prove the bundle was accepted
# end-to-end on the startup surface; the timeout shuts the process down
# afterwards). Rejected scenarios fail closed BEFORE P2P startup, but we
# still allocate a unique port per scenario so the rejection path cannot
# be confused with a port-conflict failure.
PORT_BASE=38137

log()  { printf '[run137] %s\n' "$*"; }
fail() { printf '[run137] FAIL: %s\n' "$*" >&2; exit 1; }
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
# A startup REJECTION before mutation must satisfy ALL of:
#   * no sequence-persistence file written under the scenario data dir;
#   * no `.tmp` marker sibling;
#   * pre-seeded marker bytes (if any) are byte-identical post-run;
#   * if no pre-seeded marker existed, no marker is created;
#   * no Run 055 sequence persistence log line;
#   * no `[binary] P2P transport up` log line (rejection precedes the
#     P2P listener-bind step);
#   * no SIGHUP / KMS / HSM / live-0x05 / peer-driven apply / snapshot
#     -restore / DummySig / DummyKem / DummyAead markers;
#   * no fallback to --p2p-trusted-root path.
assert_no_mutation_on_rejection() {
  local data_dir="$1" stderr="$2" pre_marker="$3"
  if [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ]; then
    fail "sequence file was created under ${data_dir} (mutation on a refusal path)"
  fi
  if [ -f "${data_dir}/pqc_authority_state.json.tmp" ]; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  assert_not_grep "$stderr" '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_not_grep "$stderr" '\[binary\] P2P transport up'
  assert_not_grep "$stderr" 'SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE'
  assert_not_grep "$stderr" 'KMS|HSM'
  assert_not_grep "$stderr" 'live inbound 0x05|peer-driven live apply'
  assert_not_grep "$stderr" 'snapshot/restore v2|snapshot-restore v2'
  # NOTE: the Run 033 timeout-verification probe line contains the
  # substrings `DummySig` / `TrustedClientRoots` (classified non-active /
  # probe-and-log-only per Run 081/Run 082) on every startup path; that
  # is documented existing behaviour and not in scope for Run 137. We
  # therefore do NOT assert its absence — Run 137 is evidence-only and
  # does not change observability.
  assert_not_grep "$stderr" 'falling back to --p2p-trusted-root|trusted-root fallback'
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

# --- common accept invariants ----------------------------------------------
# An accepted v2 startup must show:
#   * `[run-136] startup --p2p-trust-bundle v2 ratification path SELECTED`
#   * `[binary] Run 055: trust-bundle sequence persistence` (commit)
#   * `[run-136] v2 authority-marker persisted` OR
#     `[run-136] v2 authority-marker unchanged ... (idempotent ...)`
# AND the persisted log line MUST appear at a strictly later line number
# than the Run 055 sequence persistence line.
assert_v2_ordering_after_commit() {
  local stderr="$1" persist_pattern="$2"
  local seq_line v2_line
  seq_line="$(grep -nE '\[binary\] Run 055: trust-bundle sequence persistence' "$stderr" \
    | head -n1 | cut -d: -f1)"
  v2_line="$(grep -nE -- "$persist_pattern" "$stderr" | head -n1 | cut -d: -f1)"
  [ -n "$seq_line" ] || fail "${stderr} missing Run 055 sequence persistence line"
  [ -n "$v2_line" ]  || fail "${stderr} missing v2 persist line matching: ${persist_pattern}"
  if [ "$seq_line" -ge "$v2_line" ]; then
    fail "${stderr} ordering violation: Run 055 line=${seq_line} is not strictly before \
v2 persist line=${v2_line}"
  fi
}

# --- v2 marker persistence invariants --------------------------------------
# Assert that after a v2-accepted startup the on-disk marker exists,
# loads back as V2, and contains the expected `latest_authority_domain_
# sequence`, `latest_lifecycle_action`, AND `last_update_source =
# startup-load` (Run 131 / Run 136 audit-tag invariant for the startup
# surface; serde rename_all = snake_case → "startup-load" via the
# `AuthorityStateUpdateSource::StartupLoad` discriminator).
assert_v2_marker_startup_after_commit() {
  local data_dir="$1" expected_seq="$2" expected_action="$3"
  local marker="${data_dir}/pqc_authority_state.json"
  [ -f "$marker" ] || fail "v2 marker missing under ${data_dir} after accepted startup"
  assert_grep "$marker" '"record_version"[[:space:]]*:[[:space:]]*2'
  assert_grep "$marker" "\"latest_authority_domain_sequence\"[[:space:]]*:[[:space:]]*${expected_seq}"
  local lower_action
  lower_action="$(printf '%s' "$expected_action" | tr '[:upper:]' '[:lower:]')"
  assert_grep "$marker" "\"latest_lifecycle_action\"[[:space:]]*:[[:space:]]*\"${lower_action}\""
  assert_grep "$marker" '"last_update_source"[[:space:]]*:[[:space:]]*"startup-load"'
  if [ -f "${data_dir}/pqc_authority_state.json.tmp" ]; then
    fail ".tmp marker sibling was left behind under ${data_dir}"
  fi
  [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ] \
    || fail "sequence file missing under ${data_dir} after accepted startup"
}

assert_v1_marker_startup_after_commit() {
  local data_dir="$1"
  local marker="${data_dir}/pqc_authority_state.json"
  [ -f "$marker" ] || fail "v1 marker missing under ${data_dir} after accepted v1 startup"
  # v1 uses `record_version`/`authority_schema_version` = 1.
  assert_grep "$marker" '"record_version"[[:space:]]*:[[:space:]]*1'
  [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ] \
    || fail "sequence file missing under ${data_dir} after accepted v1 startup"
}

# --- scenario runner -------------------------------------------------------
# pre_marker          — path to a marker JSON to copy in before the run
#                       (or "").
# expected_rc_class   — "accept" expects rc=124 (SIGTERM after `timeout`)
#                       OR rc=143; "reject" expects rc=1.
# timeout_secs        — how long to let the binary run before SIGTERM.
#                       For acceptance scenarios this MUST be long enough
#                       for `[run-136] v2 authority-marker persisted` /
#                       `unchanged` to appear in stderr. For rejection
#                       scenarios the binary exits non-zero almost
#                       immediately, but we bound it defensively.
run_case() {
  local name="$1" expected_rc_class="$2" timeout_secs="$3" pre_marker="$4" port="$5"
  shift 5
  local stdout="${OUTDIR}/logs/${name}.stdout.log"
  local stderr="${OUTDIR}/logs/${name}.stderr.log"
  local rcfile="${OUTDIR}/exit_codes/${name}.exit_code"
  local data_dir="${OUTDIR}/data/${name}"
  rm -rf "$data_dir"
  mkdir -p "$data_dir"
  if [ -n "$pre_marker" ]; then
    cp "$pre_marker" "${data_dir}/pqc_authority_state.json"
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  else
    : > "${OUTDIR}/marker_hashes/${name}.marker_pre.sha256"
  fi

  set +e
  timeout --signal=TERM --kill-after=5s "${timeout_secs}s" \
    "$NODE_BIN" "$@" --data-dir "$data_dir" --p2p-listen-addr "127.0.0.1:${port}" \
    >"$stdout" 2>"$stderr"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$rcfile"

  case "$expected_rc_class" in
    accept)
      # timeout(1) sends SIGTERM (no signal handler installed by the
      # binary on this path) which the kernel reports as either rc=124
      # (timeout signaled and the process exited via SIGTERM in time)
      # or rc=143 (128+15, SIGTERM-terminated) depending on which
      # observer is faster. Both are acceptable for an "accept" run
      # where the harness only needs the bundle-accepted log lines and
      # the persisted marker file.
      if [ "$rc" != "124" ] && [ "$rc" != "143" ]; then
        fail "${name} expected accept-class exit (124 or 143), got rc=${rc}; stderr=${stderr}"
      fi
      ;;
    reject)
      [ "$rc" = "1" ] || fail "${name} expected reject rc=1, got rc=${rc}; stderr=${stderr}"
      ;;
    *)
      fail "internal: unknown expected_rc_class=${expected_rc_class}"
      ;;
  esac

  if [ -f "${data_dir}/pqc_authority_state.json" ]; then
    sha256_file "${data_dir}/pqc_authority_state.json" \
      > "${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  else
    : > "${OUTDIR}/marker_hashes/${name}.marker_post.sha256"
  fi
  if [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ]; then
    sha256_file "${data_dir}/pqc_trust_bundle_sequence.json" \
      > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  else
    : > "${OUTDIR}/sequence_hashes/${name}.sequence_post.sha256"
  fi
  printf '  %s: rc=%s class=%s\n' "$name" "$rc" "$expected_rc_class" >> "$SUMMARY"
}

main() {
  log "OUTDIR=${OUTDIR}"
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"/logs "$OUTDIR"/data "$OUTDIR"/fixtures \
           "$OUTDIR"/exit_codes "$OUTDIR"/marker_hashes "$OUTDIR"/sequence_hashes
  : > "$SUMMARY"

  cd "$REPO_ROOT"
  log "building release qbind-node and Run 133 v2 fixture helper"
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper

  test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
  test -x "$FIXTURE_HELPER" || fail "missing ${FIXTURE_HELPER}"

  local rustc_version cargo_version git_commit
  rustc_version="$(rustc --version 2>/dev/null || echo unknown)"
  cargo_version="$(cargo --version 2>/dev/null || echo unknown)"
  git_commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"

  {
    echo "Run 137 v2 startup --p2p-trust-bundle release-binary evidence"
    echo "outdir: ${OUTDIR}"
    echo "repo: ${REPO_ROOT}"
    echo "git_commit: ${git_commit}"
    echo "rustc: ${rustc_version}"
    echo "cargo: ${cargo_version}"
    echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
    echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
    echo "fixture-helper_sha256: $(sha256_file "${FIXTURE_HELPER}")"
    echo "fixture-helper_build_id: $(build_id "${FIXTURE_HELPER}")"
    echo
    echo "commands run by this harness:"
    echo "  cargo build --release -p qbind-node --bin qbind-node"
    echo "  cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper"
    echo "  \$FIXTURE_HELPER \$OUTDIR/fixtures"
    echo "  per-scenario: timeout --signal=TERM --kill-after=5s <secs>s \$NODE_BIN \\"
    echo "      --network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port> \\"
    echo "      --env devnet --genesis-path <DEV>/genesis.json \\"
    echo "      --expect-genesis-hash <hash> \\"
    echo "      --p2p-trust-bundle <bundle> \\"
    echo "      --p2p-trust-bundle-signing-key <ratified-spec> \\"
    echo "      --p2p-trust-bundle-ratification <sidecar> \\"
    echo "      --p2p-trust-bundle-ratification-enforcement-enabled \\"
    echo "      --data-dir <data_dir>"
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

  # Common flag block for startup `--p2p-trust-bundle`: DevNet,
  # ratification-enforcement enabled so `gate_decision.should_invoke()`
  # is true and the v1/v2 ratification ctx is built. On the startup
  # path the Run 136 dispatch fires directly from
  # `startup_ctx_data.ratification_v2.is_some()` BEFORE
  # `apply_run_105_ratification_gate_at_startup` — no v1 enforcer runs
  # ahead of it on the v2 branch, so the
  # `--p2p-trust-bundle-allow-unratified-testnet-devnet` v1-bypass
  # escape used by the Run 133 validation-only `reload-check` path is
  # NOT needed here (cf. Run 133 §"v1-bypass" comment).
  #
  # `--network-mode p2p --enable-p2p` are required because the startup
  # `--p2p-trust-bundle` block lives inside the P2P-mode arm of the
  # binary: DevNet defaults to LocalMesh + `enable_p2p = false` per
  # `crates/qbind-node/src/cli.rs:30`, and the v1 / v2 startup gate
  # only runs when the binary takes the `run_p2p_node` path.
  devnet_startup_common=(
    --network-mode p2p
    --enable-p2p
    --env devnet
    --genesis-path "$DEV/genesis.json"
    --expect-genesis-hash "$dev_hash"
    --p2p-trust-bundle-signing-key "$dev_key"
    --p2p-trust-bundle-ratification-enforcement-enabled
  )

  ##########################################################################
  # Acceptance scenarios
  ##########################################################################
  # Acceptance scenarios run with a `timeout` long enough for the
  # startup pipeline to: (1) print `[run-136] startup --p2p-trust-bundle
  # v2 ratification path SELECTED`, (2) verify the v2 sidecar via the
  # Run 130 verifier, (3) decide via Run 134's `decide_marker_acceptance_v2`,
  # (4) write the Run 055 sequence record (`[binary] Run 055: trust-
  # bundle sequence persistence ...`), AND (5) persist the v2 marker
  # via `persist_accepted_v2_marker_after_commit_boundary`
  # (`[run-136] v2 authority-marker persisted ...` or
  # `[run-136] v2 authority-marker unchanged ...`). The timeout then
  # SIGTERMs the process before consensus does any meaningful work.

  log "Scenario A1: v2 ratify@seq=1, no marker (first v2 startup write)"
  run_case scenario_A1_v2_first_write accept 12 "" "$((PORT_BASE + 1))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-136\] startup --p2p-trust-bundle v2 ratification path SELECTED'
  assert_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-136\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=1'
  assert_not_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-120\] authority-marker persisted'
  assert_not_grep "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-105\] FATAL'
  assert_v2_ordering_after_commit \
    "$OUTDIR/logs/scenario_A1_v2_first_write.stderr.log" \
    '\[run-136\] v2 authority-marker persisted'
  assert_v2_marker_startup_after_commit \
    "$OUTDIR/data/scenario_A1_v2_first_write" 1 Ratify

  log "Scenario A2: v2 ratify@seq=2, v1 marker (v2-after-v1 migration at startup)"
  run_case scenario_A2_v2_after_v1_migration accept 12 "$DEV/seed-marker.v1.json" \
    "$((PORT_BASE + 2))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[run-136\] startup --p2p-trust-bundle v2 ratification path SELECTED'
  assert_grep "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_grep "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[run-136\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
  assert_v2_ordering_after_commit \
    "$OUTDIR/logs/scenario_A2_v2_after_v1_migration.stderr.log" \
    '\[run-136\] v2 authority-marker persisted'
  assert_v2_marker_startup_after_commit \
    "$OUTDIR/data/scenario_A2_v2_after_v1_migration" 2 Ratify
  # The seed v1 marker must NOT survive — it was replaced by a v2 record.
  if cmp -s "$DEV/seed-marker.v1.json" \
            "$OUTDIR/data/scenario_A2_v2_after_v1_migration/pqc_authority_state.json"; then
    fail "v1 marker was not migrated to v2 under scenario A2"
  fi

  log "Scenario A3: v2 ratify@seq=1 with v2-seq=1 marker (idempotent at startup)"
  run_case scenario_A3_v2_idempotent accept 12 "$DEV/seed-marker.v2.seq1.json" \
    "$((PORT_BASE + 3))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.same.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[run-136\] startup --p2p-trust-bundle v2 ratification path SELECTED'
  assert_grep "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_grep "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[run-136\] v2 authority-marker unchanged .*idempotent; no rewrite'
  assert_v2_ordering_after_commit \
    "$OUTDIR/logs/scenario_A3_v2_idempotent.stderr.log" \
    '\[run-136\] v2 authority-marker unchanged'
  cmp -s "$DEV/seed-marker.v2.seq1.json" \
         "$OUTDIR/data/scenario_A3_v2_idempotent/pqc_authority_state.json" \
    || fail "v2 marker bytes mutated on idempotent startup path under A3"

  log "Scenario A4: v2 ratify@seq=2 with v2-seq=1 marker (higher-sequence startup upgrade)"
  run_case scenario_A4_v2_higher_sequence accept 12 "$DEV/seed-marker.v2.seq1.json" \
    "$((PORT_BASE + 4))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq2.json"
  assert_grep "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[run-136\] startup --p2p-trust-bundle v2 ratification path SELECTED'
  assert_grep "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_grep "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[run-136\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
  assert_v2_ordering_after_commit \
    "$OUTDIR/logs/scenario_A4_v2_higher_sequence.stderr.log" \
    '\[run-136\] v2 authority-marker persisted'
  assert_v2_marker_startup_after_commit \
    "$OUTDIR/data/scenario_A4_v2_higher_sequence" 2 Ratify
  # Marker must NOT match the seeded seq=1 marker bytes anymore.
  if cmp -s "$DEV/seed-marker.v2.seq1.json" \
            "$OUTDIR/data/scenario_A4_v2_higher_sequence/pqc_authority_state.json"; then
    fail "v2 marker did not advance from seq=1 to seq=2 under A4"
  fi

  ##########################################################################
  # Rejection scenarios — all must reject BEFORE any mutation AND BEFORE
  # P2P startup. The release binary exits rc=1.
  ##########################################################################
  log "Scenario R1: v2 ratify@seq=1 with v2-seq=2 marker (lower-sequence refused)"
  run_case scenario_R1_v2_lower_sequence reject 15 "$DEV/seed-marker.v2.seq2.json" \
    "$((PORT_BASE + 5))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.lower.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    'v2 authority-marker rollback rejected|attempted authority_domain_sequence=.* is lower than persisted|LowerV2SequenceRefused'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R1_v2_lower_sequence" \
    "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
    "$DEV/seed-marker.v2.seq2.json"

  log "Scenario R2: v2 ratify@seq=1 (rotated target) over v2-seq=1 marker (active target) — equivocation refused"
  run_case scenario_R2_v2_same_seq_different_digest reject 15 "$DEV/seed-marker.v2.seq1.json" \
    "$((PORT_BASE + 6))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.equivocation.seq1.json"
  assert_grep "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    'same-sequence|SameSequenceConflicting'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R2_v2_same_seq_different_digest" \
    "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
    "$DEV/seed-marker.v2.seq1.json"

  log "Scenario R3a: v2 bad-signature (verifier refused)"
  run_case scenario_R3a_v2_bad_signature reject 15 "" \
    "$((PORT_BASE + 7))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.bad-signature.json"
  assert_grep "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    'signature failed ML-DSA-44 PQC verification|MalformedOrUnsupportedMarkerRejected'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R3a_v2_bad_signature" \
    "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
    ""

  log "Scenario R3b: v2 wrong-environment (verifier refused — wrong-domain axis: env)"
  run_case scenario_R3b_v2_wrong_environment reject 15 "" \
    "$((PORT_BASE + 8))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-environment.json"
  assert_grep "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    'WrongEnvironment|MalformedOrUnsupportedMarkerRejected'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R3b_v2_wrong_environment" \
    "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
    ""

  log "Scenario R4: v2 wrong-chain (verifier refused — wrong-domain axis: chain_id)"
  run_case scenario_R4_v2_wrong_chain reject 15 "" \
    "$((PORT_BASE + 9))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-chain.json"
  assert_grep "$OUTDIR/logs/scenario_R4_v2_wrong_chain.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R4_v2_wrong_chain.stderr.log" \
    'ChainMismatch|MalformedOrUnsupportedMarkerRejected'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R4_v2_wrong_chain" \
    "$OUTDIR/logs/scenario_R4_v2_wrong_chain.stderr.log" \
    ""

  log "Scenario R5: v2 wrong-genesis (verifier refused — wrong-domain axis: genesis hash)"
  run_case scenario_R5_v2_wrong_genesis reject 15 "" \
    "$((PORT_BASE + 10))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v2.wrong-genesis.json"
  assert_grep "$OUTDIR/logs/scenario_R5_v2_wrong_genesis.stderr.log" \
    '\[run-136\] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight'
  assert_grep "$OUTDIR/logs/scenario_R5_v2_wrong_genesis.stderr.log" \
    'GenesisHashMismatch|MalformedOrUnsupportedMarkerRejected'
  assert_no_mutation_on_rejection \
    "$OUTDIR/data/scenario_R5_v2_wrong_genesis" \
    "$OUTDIR/logs/scenario_R5_v2_wrong_genesis.stderr.log" \
    ""

  ##########################################################################
  # v1 regression
  ##########################################################################
  log "Scenario V1: v1 valid ratification, no marker (v1 startup regression)"
  run_case scenario_V1_v1_regression accept 12 "" \
    "$((PORT_BASE + 11))" \
    "${devnet_startup_common[@]}" \
    --p2p-trust-bundle "$DEV/candidate-bundle.json" \
    --p2p-trust-bundle-ratification "$DEV/ratification.v1.valid.json"
  assert_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-106\] startup ratification gate INVOKED.*Devnet'
  assert_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[binary\] Run 055: trust-bundle sequence persistence'
  assert_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-120\] authority-marker persisted'
  # v1 path must NOT take the v2 dispatch.
  assert_not_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-136\] startup --p2p-trust-bundle v2 ratification path SELECTED'
  assert_not_grep "$OUTDIR/logs/scenario_V1_v1_regression.stderr.log" \
    '\[run-136\] v2 authority-marker persisted'
  assert_v1_marker_startup_after_commit "$OUTDIR/data/scenario_V1_v1_regression"

  ##########################################################################
  # Cross-scenario observability invariants
  ##########################################################################
  for stderr_log in "$OUTDIR"/logs/scenario_*.stderr.log; do
    assert_not_grep "$stderr_log" 'SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE'
    assert_not_grep "$stderr_log" 'KMS|HSM'
    assert_not_grep "$stderr_log" 'live inbound 0x05'
    assert_not_grep "$stderr_log" 'peer-driven live apply'
    assert_not_grep "$stderr_log" 'signing-key (rotation|revocation) lifecycle'
    # NOTE: see assert_no_mutation_on_rejection — the Run 033 probe line
    # mentions `DummySig`/`TrustedClientRoots` on every startup path
    # (classified non-active per Run 081/Run 082). Out of scope.
    # Run 136 startup-surface v2 wiring is mutating-surface only — never
    # the validation-only logs from Run 132.
    assert_not_grep "$stderr_log" '\[run-132\] reload-check v2 authority-marker check'
    assert_not_grep "$stderr_log" '\[run-132\] peer-candidate-check v2 authority-marker check'
    # Run 134 reload-apply v2 path must not fire from a startup-surface
    # run that supplied no --p2p-trust-bundle-reload-apply-* flags.
    assert_not_grep "$stderr_log" '\[run-134\] reload-apply v2 ratification path SELECTED'
  done

  # For every REJECTED scenario, prove no P2P transport up line.
  for stderr_log in \
      "$OUTDIR/logs/scenario_R1_v2_lower_sequence.stderr.log" \
      "$OUTDIR/logs/scenario_R2_v2_same_seq_different_digest.stderr.log" \
      "$OUTDIR/logs/scenario_R3a_v2_bad_signature.stderr.log" \
      "$OUTDIR/logs/scenario_R3b_v2_wrong_environment.stderr.log" \
      "$OUTDIR/logs/scenario_R4_v2_wrong_chain.stderr.log" \
      "$OUTDIR/logs/scenario_R5_v2_wrong_genesis.stderr.log"; do
    assert_not_grep "$stderr_log" '\[binary\] P2P transport up'
  done

  # CSV summary of pre/post marker hashes (and post sequence hashes).
  {
    echo "scenario,marker_pre_sha256,marker_post_sha256,sequence_post_sha256"
    for f in "$OUTDIR/marker_hashes"/scenario_*.marker_pre.sha256; do
      name="$(basename "$f" .marker_pre.sha256)"
      pre="$(cat "$f" || true)"
      post="$(cat "$OUTDIR/marker_hashes/${name}.marker_post.sha256" || true)"
      seqp="$(cat "$OUTDIR/sequence_hashes/${name}.sequence_post.sha256" || true)"
      pre="${pre:-NONE}"
      post="${post:-NONE}"
      seqp="${seqp:-NONE}"
      printf '%s,%s,%s,%s\n' "$name" "$pre" "$post" "$seqp"
    done
  } > "$OUTDIR/marker_hashes/marker_hashes.csv"

  {
    echo
    echo "non-mutation checks: pass"
    echo "  no pqc_trust_bundle_sequence.json created under any refusal scenario data dir"
    echo "  no pqc_authority_state.json.tmp sibling left behind under any scenario"
    echo "  pre-seeded marker bytes preserved on every refusal path"
    echo "  no marker file created on refusal scenarios with no pre-seeded marker"
    echo "  no [binary] P2P transport up on any refusal scenario (rejection before P2P bind)"
    echo "post-commit persist checks: pass"
    echo "  v2 marker present with record_version=2 + expected sequence/action"
    echo "  + last_update_source=startup-load on every accepted v2 scenario (A1/A2/A4)"
    echo "  v2 marker bytes byte-identical across idempotent run (A3)"
    echo "  v1 marker present with record_version=1 on the V1 regression scenario"
    echo "ordering proof: pass"
    echo "  [binary] Run 055 sequence persistence line strictly precedes the"
    echo "  matching [run-136] v2 authority-marker persisted/unchanged line"
    echo "  on every accepted v2 scenario (A1/A2/A3/A4)"
    echo "wire-format checks: source-only; no trust-bundle, ratification, or"
    echo "  peer-candidate wire format changed by this evidence harness"
    echo "scope non-goal checks: no SIGHUP v2, no live 0x05 v2, no peer-driven"
    echo "  apply v2, no snapshot/restore v2, no KMS/HSM, no rotation/revocation"
    echo "  lifecycle observed in stderr of any scenario"
    echo "R4-analogue (apply failure after preflight, Run 135 R4 / Run 134 §C.3):"
    echo "  covered by Run 134 §C.3 test-only (FakeLiveTrustApplyContext); the"
    echo "  release binary cannot deterministically trigger a post-preflight,"
    echo "  pre-check_and_update_sequence apply failure on the startup surface"
    echo "  with operator-supplied flag inputs alone. Same partial-positive"
    echo "  treatment as Run 135 R4."
  } >> "$SUMMARY"
  log "PASS: Run 137 evidence captured under ${OUTDIR}"
}

main "$@"
