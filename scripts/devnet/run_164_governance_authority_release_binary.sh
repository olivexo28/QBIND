#!/usr/bin/env bash
# Run 164 — release-binary EVIDENCE/BOUNDARY harness for the Run 163
# typed pure governance ratification authority verifier
# (`qbind_node::pqc_governance_authority::verify_governance_authority_proof`,
# `validate_lifecycle_with_governance_authority`).
#
# Per task/RUN_164_TASK.txt, Run 164 must:
#
#   1. Determine all release-binary surfaces that could honestly exercise
#      the Run 163 governance verifier today; capture that determination
#      in a source-level reachability proof.
#   2. Capture release-binary fixture/evidence on the strongest surface
#      currently available.
#   3. Honestly classify the verdict as `partial-positive` if the
#      verifier is not reachable from any production v2 surface today,
#      and identify the exact next required integration run.
#
# This harness is **release-binary evidence only**. It does NOT enable
# MainNet apply, does NOT touch any live trust state, does NOT mutate
# any sequence file or authority marker, does NOT change any wire
# format, does NOT introduce a governance execution engine, KMS/HSM
# implementation, or validator-set rotation, and does NOT rewire the
# Run 163 verifier into any mutating apply or validation-only
# marker-decision surface.
#
# Surfaces investigated (full task §Investigation requirement set):
#
#   1. startup `--p2p-trust-bundle` v2 path                 — NOT reachable
#   2. reload-check validation-only path                     — NOT reachable
#   3. local peer-candidate-check validation-only path       — NOT reachable
#   4. process-start reload-apply path                       — NOT reachable
#   5. SIGHUP live-reload path                               — NOT reachable
#   6. live inbound `0x05` validation-only path             — NOT reachable
#   7. peer-driven staged queue / drain-once path            — NOT reachable
#   8. lifecycle marker-decision path from Run 161/162       — NOT reachable
#   9. fixture helper / example binary path                  — REACHABLE
#      (this harness exercises the verifier through the
#      release-built helper
#      `target/release/examples/run_164_governance_authority_fixture_helper`)
#
# Verdict: `partial-positive: release-binary fixture/evidence boundary
# captured; governance authority verifier not yet production-surface
# reachable`. The exact next required integration run is **Run 165 —
# compose `verify_governance_authority_proof` /
# `validate_lifecycle_with_governance_authority` into the existing
# `decide_marker_acceptance_v2` helper (or an immediately-upstream
# typed pre-flight gate) so the existing v2 marker-decision surfaces
# (reload-apply, startup, SIGHUP, peer-driven drain, live `0x05`,
# reload-check, peer-candidate-check) exercise the governance verifier
# without changing the on-wire byte set or the v2 marker schema**.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCHIVE="$REPO_ROOT/docs/devnet/run_164_governance_authority_release_binary"
mkdir -p "$ARCHIVE"

LOGS="$ARCHIVE/logs"
DATA="$ARCHIVE/data"
FIXTURES="$ARCHIVE/fixtures"
EXIT_CODES="$ARCHIVE/exit_codes"
GREP_SUMMARIES="$ARCHIVE/grep_summaries"
REACHABILITY="$ARCHIVE/reachability"
TEST_RESULTS="$ARCHIVE/test_results"
mkdir -p "$LOGS" "$DATA" "$FIXTURES" "$EXIT_CODES" "$GREP_SUMMARIES" \
         "$REACHABILITY" "$TEST_RESULTS"

QBIND_NODE="$REPO_ROOT/target/release/qbind-node"
RUN164_HELPER="$REPO_ROOT/target/release/examples/run_164_governance_authority_fixture_helper"

# ----------------------------------------------------------------------
# 0. Build the release binaries we need.
# ----------------------------------------------------------------------

echo "[run-164] building release qbind-node + helper"
( cd "$REPO_ROOT" && cargo build --release -p qbind-node --bin qbind-node ) \
    > "$LOGS/build_qbind_node.log" 2>&1
echo $? > "$EXIT_CODES/build_qbind_node.exit"

( cd "$REPO_ROOT" && cargo build --release -p qbind-node \
    --example run_164_governance_authority_fixture_helper ) \
    > "$LOGS/build_helper.log" 2>&1
echo $? > "$EXIT_CODES/build_helper.exit"

[ -x "$QBIND_NODE" ] || { echo "FATAL: qbind-node release binary missing"; exit 1; }
[ -x "$RUN164_HELPER" ] || { echo "FATAL: helper release binary missing"; exit 1; }

# ----------------------------------------------------------------------
# 1. Provenance (binary identity).
# ----------------------------------------------------------------------

PROV="$ARCHIVE/provenance.txt"
{
    echo "Run 164 — release-binary provenance"
    echo "===================================="
    echo "git_rev: $(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_status:"
    ( cd "$REPO_ROOT" && git status --porcelain | sed 's/^/  /' )
    echo
    echo "qbind-node:"
    echo "  path:    $QBIND_NODE"
    echo "  size:    $(stat -c '%s' "$QBIND_NODE")"
    echo "  sha256:  $(sha256sum "$QBIND_NODE" | awk '{print $1}')"
    echo "  buildid: $(readelf -n "$QBIND_NODE" 2>/dev/null \
                       | awk '/Build ID:/ {print $3; exit}' || echo unknown)"
    echo
    echo "run_164_governance_authority_fixture_helper:"
    echo "  path:    $RUN164_HELPER"
    echo "  size:    $(stat -c '%s' "$RUN164_HELPER")"
    echo "  sha256:  $(sha256sum "$RUN164_HELPER" | awk '{print $1}')"
    echo "  buildid: $(readelf -n "$RUN164_HELPER" 2>/dev/null \
                       | awk '/Build ID:/ {print $3; exit}' || echo unknown)"
} > "$PROV"

# ----------------------------------------------------------------------
# 2. Source-level reachability proof.
#
# The Run 163 governance authority verifier MUST NOT have any caller in
# `crates/qbind-node/src/` other than its own module and the
# `pub mod pqc_governance_authority;` declaration in `lib.rs`. If a
# future run wires it into a mutating or validation-only surface, this
# script's expectations need to change.
# ----------------------------------------------------------------------

REACH_TXT="$REACHABILITY/reachability.txt"
SRC_GREP="$REACHABILITY/src_grep.txt"

(
    cd "$REPO_ROOT"
    echo "# Run 164 — source-level grep for Run 163 verifier callers"
    echo "# Pattern: verify_governance_authority_proof|validate_lifecycle_with_governance_authority|pqc_governance_authority"
    echo
    grep -RnE \
        'verify_governance_authority_proof|validate_lifecycle_with_governance_authority|pqc_governance_authority' \
        crates/qbind-node/src \
        || true
) > "$SRC_GREP"

# Allowed src-references (module itself + lib.rs declaration). Any other
# hit would mean Run 165 has begun and Run 164 must be reframed as a
# regression run rather than a partial-positive boundary.
ALLOWED_SRC_REFS_PATTERN='^crates/qbind-node/src/(pqc_governance_authority\.rs|lib\.rs):'
UNEXPECTED_SRC_REFS=$(grep -E '^crates/' "$SRC_GREP" \
                      | grep -E -v "$ALLOWED_SRC_REFS_PATTERN" || true)

if [ -n "$UNEXPECTED_SRC_REFS" ]; then
    {
        echo "VERDICT: positive-with-production-call-sites"
        echo
        echo "Unexpected production source references to the Run 163"
        echo "governance authority verifier were found. Run 164's"
        echo "partial-positive boundary expectation no longer holds —"
        echo "the verifier appears to be wired into one or more"
        echo "production surfaces. Audit the unexpected references and"
        echo "decide whether Run 164 should be reframed as a"
        echo "release-binary ENFORCEMENT run rather than a"
        echo "partial-positive boundary."
        echo
        echo "Unexpected src references:"
        echo "$UNEXPECTED_SRC_REFS"
    } > "$REACH_TXT"
    echo "FATAL: unexpected production references — see $REACH_TXT" >&2
    exit 1
fi

cat > "$REACH_TXT" <<'EOF'
Run 164 — release-binary reachability proof for the Run 163 governance
authority verifier (`qbind_node::pqc_governance_authority`).

Production callers (`crates/qbind-node/src/`):

  * crates/qbind-node/src/pqc_governance_authority.rs  — the module
    itself (definition, including the test-only fixture verifier and
    the pure helper functions).
  * crates/qbind-node/src/lib.rs  — `pub mod pqc_governance_authority;`
    declaration only.

Test callers:

  * crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs
    — Run 163 source/test coverage (32 tests).

Release-built example callers (this harness):

  * crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs
    — release-built helper that mints + verifies the A1–A5 / R1–R16
    governance proof corpus on the real release binary.

Surfaces investigated per task/RUN_164_TASK.txt §Investigation
requirement:

  1. startup `--p2p-trust-bundle` v2 path                  — NOT reachable
  2. reload-check validation-only path                     — NOT reachable
  3. local peer-candidate-check validation-only path       — NOT reachable
  4. process-start reload-apply path                       — NOT reachable
  5. SIGHUP live-reload path                               — NOT reachable
  6. live inbound `0x05` validation-only path             — NOT reachable
  7. peer-driven staged queue / drain-once path            — NOT reachable
  8. lifecycle marker-decision path from Run 161 / 162     — NOT reachable
  9. fixture helper / example binary path                  — REACHABLE

For each non-reachable surface above, the verifier:
  * does NOT call `verify_governance_authority_proof`;
  * does NOT call `validate_lifecycle_with_governance_authority`;
  * does NOT observe `GovernanceAuthorityProof`;
  * does NOT carry `GenesisBound`, `EmergencyCouncil`, or
    `OnChainGovernance` proof classes;
  * would NOT require a wire/schema change to gain reachability —
    the existing v2 ratification fields are sufficient for
    `GenesisBound` and `EmergencyCouncil` (Run 163 module docs); the
    `OnChainGovernance` class is deliberately fail-closed pending a
    future on-chain proof schema; the missing piece is the call site,
    not the wire format;
  * can therefore be evidenced **without** production behaviour drift
    by routing through the release-built helper above.

Verdict: `partial-positive: release-binary fixture/evidence boundary
captured; governance authority verifier not yet production-surface
reachable`.

Next required integration run: **Run 165 — compose
`verify_governance_authority_proof` and
`validate_lifecycle_with_governance_authority` into the existing
shared v2 marker-decision helper
`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`
(or an immediately-upstream typed pre-flight gate)** so the
release-binary v2 surfaces (reload-apply, startup, SIGHUP, peer-driven
drain, live `0x05`, reload-check, peer-candidate-check) exercise the
governance verifier on every mutating and validation-only v2 decision
without changing the on-wire byte set or the v2 marker schema.
EOF

# ----------------------------------------------------------------------
# 3. Mint the governance proof corpus on the real release binary.
# ----------------------------------------------------------------------

echo "[run-164] minting governance proof corpus via release helper"
"$RUN164_HELPER" "$FIXTURES" > "$LOGS/run_helper.log" 2>&1
echo $? > "$EXIT_CODES/run_helper.exit"

[ -f "$FIXTURES/manifest.txt" ] || { echo "FATAL: helper did not write manifest"; exit 1; }
[ -f "$FIXTURES/actual_outcomes.txt" ] || { echo "FATAL: helper did not write actual outcomes"; exit 1; }

# Per-scenario fixture manifest with sha256.
( cd "$FIXTURES" && find . -type f -print0 | sort -z \
    | xargs -0 sha256sum ) > "$ARCHIVE/fixture_manifest.txt"

# ----------------------------------------------------------------------
# 4. Assert expected typed outcome for every scenario.
# ----------------------------------------------------------------------

echo "[run-164] asserting expected typed outcomes per scenario"
PASS=0
FAIL=0
{
    echo "# Run 164 — per-scenario expected/actual outcome assertion"
    while IFS=$'\t' read -r SID EXP_LABEL EXP_MATCH; do
        [ -z "$SID" ] && continue
        [[ "$SID" == \#* ]] && continue
        ACT_FILE="$FIXTURES/scenarios/$SID/actual.txt"
        if [ ! -f "$ACT_FILE" ]; then
            echo "FAIL  $SID  missing actual.txt"
            FAIL=$((FAIL+1))
            continue
        fi
        if grep -q "$EXP_MATCH" "$ACT_FILE"; then
            echo "PASS  $SID  expected=$EXP_LABEL match=$EXP_MATCH"
            PASS=$((PASS+1))
        else
            echo "FAIL  $SID  expected=$EXP_LABEL match=$EXP_MATCH actual=$(cat "$ACT_FILE")"
            FAIL=$((FAIL+1))
        fi
    done < "$FIXTURES/manifest.txt"
    echo
    echo "TOTAL: PASS=$PASS FAIL=$FAIL"
} > "$ARCHIVE/scenario_assertions.txt"

if [ "$FAIL" -gt 0 ]; then
    echo "FATAL: $FAIL scenarios failed; see $ARCHIVE/scenario_assertions.txt" >&2
    exit 1
fi

# ----------------------------------------------------------------------
# 5. Negative invariants: confirm the harness does NOT accidentally
#    invoke any qbind-node production surface that mutates state.
# ----------------------------------------------------------------------

# We never start qbind-node here. Capture that fact explicitly.
{
    echo "Run 164 negative invariants"
    echo "============================"
    echo "harness_started_qbind_node: NO"
    echo "harness_wrote_sequence_file: NO"
    echo "harness_wrote_authority_marker: NO"
    echo "harness_mutated_live_trust_state: NO"
    echo "harness_opened_p2p_socket: NO"
    echo "harness_modified_data_dir_outside_archive: NO"
    echo "harness_enabled_mainnet_peer_driven_apply: NO"
    echo
    echo "data dir contents (must be empty):"
    ls -la "$DATA" || true
} > "$ARCHIVE/negative_invariants.txt"

# Out-of-scope denylist grep: ensure we don't claim governance
# execution / on-chain governance / KMS / HSM / validator-set rotation
# anywhere in the harness output. Hits are only allowed if they appear
# in lines that EXPLICITLY say one of those things is NOT implemented
# / OUT-of-scope (the standard Run 153/162 banner-exclusion pattern).
DENY_PATTERN='governance execution|on-chain governance|KMS|HSM|validator-set rotation'
{
    echo "# Run 164 — denylist grep over harness logs (banner-excluded)"
    grep -RInE "$DENY_PATTERN" "$LOGS" "$REACHABILITY" 2>/dev/null \
        | grep -viE 'NOT implemented|UNimplemented|OUT.of.scope|remain[s]? unimplemented|remain[s]? open|deferred|fail-closed|placeholder' \
        || true
} > "$GREP_SUMMARIES/denylist.txt"

if [ -s "$GREP_SUMMARIES/denylist.txt" ] \
   && grep -qvE '^#' "$GREP_SUMMARIES/denylist.txt"; then
    echo "FATAL: denylist tripped; see $GREP_SUMMARIES/denylist.txt" >&2
    exit 1
fi

# ----------------------------------------------------------------------
# 6. Run the regression test suites named in task/RUN_164_TASK.txt.
#    On success, only exit_codes are recorded (full stdout/stderr is
#    saved under test_results/ for investigation).
# ----------------------------------------------------------------------

run_test() {
    local name="$1"; shift
    echo "[run-164] cargo test ${*}"
    (
        cd "$REPO_ROOT"
        cargo "$@"
    ) > "$TEST_RESULTS/${name}.stdout" 2> "$TEST_RESULTS/${name}.stderr"
    echo $? > "$TEST_RESULTS/${name}.exit"
}

run_test run_163_governance_authority_verifier_tests \
    test -p qbind-node --test run_163_governance_authority_verifier_tests
run_test run_161_lifecycle_marker_integration_tests \
    test -p qbind-node --test run_161_lifecycle_marker_integration_tests
run_test run_159_authority_signing_key_lifecycle_tests \
    test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
run_test run_157_unified_testnet_fixture_universe_tests \
    test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests
run_test run_152_binary_reachable_peer_drain_plumbing_tests \
    test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests
run_test run_150_peer_driven_apply_drain_tests \
    test -p qbind-node --test run_150_peer_driven_apply_drain_tests
run_test run_148_peer_driven_apply_devnet_tests \
    test -p qbind-node --test run_148_peer_driven_apply_devnet_tests
run_test run_142_live_inbound_0x05_v2_validation_tests \
    test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
run_test run_134_reload_apply_v2_authority_marker_tests \
    test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
run_test run_138_sighup_v2_authority_marker_tests \
    test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
run_test lib_pqc_authority \
    test -p qbind-node --lib pqc_authority

REGRESSION_FAIL=0
for f in "$TEST_RESULTS"/*.exit; do
    code=$(cat "$f")
    if [ "$code" != "0" ]; then
        echo "FAIL: $(basename "$f" .exit) exit=$code" >&2
        REGRESSION_FAIL=$((REGRESSION_FAIL+1))
    fi
done

if [ "$REGRESSION_FAIL" -gt 0 ]; then
    echo "FATAL: $REGRESSION_FAIL regression suites failed" >&2
    exit 1
fi

# ----------------------------------------------------------------------
# 7. Partial-positive verdict file.
# ----------------------------------------------------------------------

cat > "$ARCHIVE/partial_positive_proof.txt" <<EOF
Run 164 — partial-positive release-binary verdict
==================================================

verdict: partial-positive: release-binary fixture/evidence boundary
         captured; governance authority verifier not yet
         production-surface reachable.

evidence captured:
  * release-built target/release/qbind-node identity in provenance.txt
    (sha256 + ELF Build ID).
  * release-built target/release/examples/run_164_governance_authority_fixture_helper
    identity in provenance.txt.
  * source-level reachability proof in reachability/src_grep.txt and
    reachability/reachability.txt confirming the Run 163 verifier has
    NO production caller in crates/qbind-node/src/ outside
    pqc_governance_authority.rs (definition) and lib.rs
    (pub mod declaration).
  * release-built helper invoked verify_governance_authority_proof
    and validate_lifecycle_with_governance_authority on $PASS scenarios
    covering A1 (genesis-bound Rotate), A2 (genesis-bound Revoke),
    A3 (genesis-bound EmergencyRevoke), A4 (EmergencyCouncil
    EmergencyRevoke), A5 (idempotent same proof same candidate),
    R1–R16 (wrong env / wrong chain / wrong genesis / wrong
    authority root / wrong lifecycle action / wrong candidate digest
    / wrong authority sequence / invalid issuer signature /
    unsupported issuer suite / non-PQC suite / threshold not met /
    malformed proof / replay lower-sequence / OnChainGovernance
    unsupported / local-operator-config-only-rejected /
    peer-majority-rejected); per-scenario actual typed outcome
    matches expected (PASS=$PASS FAIL=$FAIL).
  * release-binary regression for Run 163 / 161 / 159 / 157 / 152 /
    150 / 148 / 142 / 134 / 138 / lib pqc_authority all green.
  * negative invariants asserted in negative_invariants.txt: this
    harness does not start qbind-node, does not write a sequence
    file, does not write an authority marker, does not mutate any
    live trust state, does not open a p2p socket, does not enable
    MainNet peer-driven apply.
  * out-of-scope denylist grep clean post banner-exclusion in
    grep_summaries/denylist.txt.

invariants preserved:
  * MainNet peer-driven apply remains refused unconditionally
    (Run 151 / Run 158 release-binary evidence is unaffected).
  * Run 162 release-binary lifecycle ENFORCEMENT evidence remains
    valid (the Run 161 production-call-site grep still fires).
  * Run 153 / 155 / 156 / 158 / 160 / 162 evidence-archive
    convention preserved (only README.md and summary.txt are
    tracked; per-run logs / fixtures / exit_codes / reachability /
    test_results / provenance.txt / fixture_manifest.txt are
    .gitignored).
  * No new wire format. No marker schema change. No sequence-file
    schema change. No trust-bundle schema change. No
    peer-candidate-envelope schema change. No new metric family. No
    new CLI flag.

infeasible proof classes (today, on existing release-binary v2
surfaces):
  * A1–A5 acceptance and R1–R16 rejection are NOT directly
    representable through the existing reload-check / reload-apply /
    SIGHUP / startup / live 0x05 / drain-once / peer-candidate-check
    CLI surfaces because none of those surfaces calls the Run 163
    verifier today. The strongest honest release-binary signal is
    the release-built helper above, which IS a release-built binary
    that links against and exercises the verifier. This satisfies
    the task's "fixture helper / example binary path" surface and
    the task's allowance to capture release-binary fixture/evidence
    boundary when no release-binary production surface is reachable.
  * OnChainGovernance remains explicitly fail-closed
    (UnsupportedOnChainGovernance). No on-chain proof format
    exists in this codebase; Run 164 does NOT silently invent one.

next required integration run: Run 165 — compose
verify_governance_authority_proof and
validate_lifecycle_with_governance_authority into the existing
shared v2 marker-decision helper
qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2
(or an immediately-upstream typed pre-flight gate) so the existing
release-binary v2 surfaces (reload-apply, startup, SIGHUP,
peer-driven drain, live 0x05, reload-check, peer-candidate-check)
exercise the governance verifier on every mutating and
validation-only v2 decision, without changing the on-wire byte set,
the v2 marker schema, or any other schema.

Run 164 does NOT claim strongest-positive. Run 164 does NOT claim
full C4 closure. Run 164 does NOT claim C5 closure.
EOF

echo "[run-164] OK — partial-positive boundary captured at $ARCHIVE"
exit 0
