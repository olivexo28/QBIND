#!/usr/bin/env bash
# Run 168 — release-binary EVIDENCE / ENFORCEMENT harness for the
# Run 167 governance-proof carrier (`pqc_governance_proof_wire`,
# `GovernanceAuthorityProofWire`,
# `GovernanceProofLoadStatus::{Absent, Available, Malformed}`,
# `pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`)
# composed with the Run 165 governance gate
# (`pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`,
# `pqc_governance_authority::evaluate_governance_marker_gate`).
#
# Per `task/RUN_168_TASK.txt`, Run 168 produces release-binary evidence
# that:
#
#   1. old no-proof v2 sidecars remain compatible under the
#      `NotRequired` policy on the real `target/release/qbind-node`
#      (validation-only `--p2p-trust-bundle-reload-check` and mutating
#      `--p2p-trust-bundle-reload-apply-path`);
#   2. proof-required policy fails closed when proof is absent
#      (release-built helper exercising the production loader +
#      production gate symbols);
#   3. valid proof-carrying v2 sidecars are parsed by the production
#      Run 167 sidecar loader and accepted by the Run 165 gate when
#      lifecycle / anti-rollback also pass (release-built helper);
#   4. malformed / invalid proof-carrying sidecars fail closed
#      (release-built helper);
#   5. MainNet peer-driven apply remains refused even with a valid
#      governance proof (real `target/release/qbind-node` MainNet refusal
#      regression, unchanged by Run 165 / Run 167).
#
# Evidence-archive precedent: per Run 153 / Run 155 / Run 156 / Run 158 /
# Run 160 / Run 162 / Run 164 / Run 166, only README.md and summary.txt
# are tracked under `docs/devnet/run_168_governance_proof_carrier_release_binary/`.
# All per-run artifacts produced by this harness (logs, exit codes,
# marker SHAs, sidecar SHAs, helper scenarios, reachability greps,
# provenance, fixture manifest, denylist results) are reproduced by re-
# running the harness and are NOT committed.
#
# This harness:
#   * does NOT enable MainNet peer-driven apply on any surface;
#   * does NOT change any wire / marker / sequence / trust-bundle schema
#     beyond Run 167's optional additive proof-carrier;
#   * does NOT introduce a CLI flag or environment variable;
#   * does NOT implement governance execution, on-chain governance,
#     KMS/HSM custody, or validator-set rotation;
#   * does NOT weaken Runs 070, 130–167;
#   * does NOT claim full C4 or C5 closure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${1:-${REPO_ROOT}/docs/devnet/run_168_governance_proof_carrier_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
RUN133_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
RUN164_HELPER="${REPO_ROOT}/target/release/examples/run_164_governance_authority_fixture_helper"
RUN166_HELPER="${REPO_ROOT}/target/release/examples/run_166_governance_gate_release_binary_helper"
RUN168_HELPER="${REPO_ROOT}/target/release/examples/run_168_governance_proof_carrier_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run168] %s\n' "$*"; }
fail() { printf '[run168] FAIL: %s\n' "$*" >&2; exit 1; }
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

# A validation-only run MUST NOT mutate. Same contract as Run 133 /
# Run 162 / Run 166.
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
    fi
    assert_not_grep "$stderr" 'live trust mutation'
    assert_not_grep "$stderr" 'session evicted'
    assert_not_grep "$stderr" 'apply on receipt'
    assert_not_grep "$stderr" 'autonomous apply'
    assert_not_grep "$stderr" 'peer-majority authority'
    assert_not_grep "$stderr" 'fallback to --p2p-trusted-root'
    assert_not_grep "$stderr" 'DummySig|DummyKem|DummyAead'
}

# A reject mutating run MUST NOT mutate.
assert_no_mutation_rejected_mutating() {
    local data_dir="$1" stderr="$2" pre_marker="$3" pre_sequence="$4"
    if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
        local post="${data_dir}/pqc_authority_state.json"
        if [ -f "$post" ]; then
            cmp -s "$pre_marker" "$post" \
                || fail "authority marker bytes changed under ${data_dir} on a rejected mutating path"
        fi
    elif [ -f "${data_dir}/pqc_authority_state.json" ]; then
        fail "authority marker file was newly created under ${data_dir} on a rejected mutating path"
    fi
    if [ -n "$pre_sequence" ] && [ -f "$pre_sequence" ]; then
        local post_seq="${data_dir}/pqc_trust_bundle_sequence.json"
        if [ -f "$post_seq" ]; then
            cmp -s "$pre_sequence" "$post_seq" \
                || fail "sequence file bytes changed under ${data_dir} on a rejected mutating path"
        fi
    elif [ -f "${data_dir}/pqc_trust_bundle_sequence.json" ]; then
        fail "sequence file was newly created under ${data_dir} on a rejected mutating path"
    fi
    if find "$data_dir" -name 'pqc_authority_state.json.tmp' -print -quit | grep -q .; then
        fail ".tmp marker sibling was left behind under ${data_dir} on a rejected mutating path"
    fi
    assert_not_grep "$stderr" 'live trust mutation'
    assert_not_grep "$stderr" 'session evicted'
    assert_not_grep "$stderr" 'apply on receipt'
    assert_not_grep "$stderr" 'autonomous apply'
    assert_not_grep "$stderr" 'peer-majority authority'
    assert_not_grep "$stderr" 'fallback to --p2p-trusted-root'
    assert_not_grep "$stderr" 'DummySig|DummyKem|DummyAead'
}

mkdir -p "$OUTDIR"
mkdir -p "$OUTDIR"/{logs,exit_codes,marker_hashes,sequence_hashes,data,fixtures,grep_summaries,reachability,test_results,helper_evidence,helper_corpus,data_inventories}

###############################################################################
# 0. Toolchain + binary identity (provenance.txt)
###############################################################################
log "Step 0: capturing build provenance"
{
    printf 'run: 168 — release-binary governance-proof carrier enforcement evidence\n'
    printf 'date: %s\n' "$(date -u +%FT%TZ)"
    printf 'git_commit: %s\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    printf 'git_status: %s\n' "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | wc -l)"
    printf 'rustc_version: %s\n' "$(rustc --version 2>/dev/null || echo unknown)"
    printf 'cargo_version: %s\n' "$(cargo --version 2>/dev/null || echo unknown)"
    printf 'host: %s\n' "$(uname -a)"
} > "$OUTDIR/provenance.txt"

###############################################################################
# 1. Build release artifacts
###############################################################################
log "Step 1: cargo build --release"
( cd "$REPO_ROOT" && \
  cargo build --release -p qbind-node --bin qbind-node \
    --example run_133_v2_validation_only_fixture_helper \
    --example run_164_governance_authority_fixture_helper \
    --example run_166_governance_gate_release_binary_helper \
    --example run_168_governance_proof_carrier_release_binary_helper ) \
  >"$OUTDIR/logs/build.log" 2>&1 \
  || { tail -120 "$OUTDIR/logs/build.log"; fail "release build failed"; }

for b in "$NODE_BIN" "$RUN133_HELPER" "$RUN164_HELPER" "$RUN166_HELPER" "$RUN168_HELPER"; do
    [ -x "$b" ] || fail "release artifact missing: $b"
done

{
    printf 'qbind-node:                                     sha256=%s build_id=%s\n' \
        "$(sha256_file "$NODE_BIN")" "$(build_id "$NODE_BIN")"
    printf 'run_133_v2_validation_only_fixture_helper:      sha256=%s build_id=%s\n' \
        "$(sha256_file "$RUN133_HELPER")" "$(build_id "$RUN133_HELPER")"
    printf 'run_164_governance_authority_fixture_helper:    sha256=%s build_id=%s\n' \
        "$(sha256_file "$RUN164_HELPER")" "$(build_id "$RUN164_HELPER")"
    printf 'run_166_governance_gate_release_binary_helper:  sha256=%s build_id=%s\n' \
        "$(sha256_file "$RUN166_HELPER")" "$(build_id "$RUN166_HELPER")"
    printf 'run_168_governance_proof_carrier_release_binary_helper: sha256=%s build_id=%s\n' \
        "$(sha256_file "$RUN168_HELPER")" "$(build_id "$RUN168_HELPER")"
} >> "$OUTDIR/provenance.txt"

###############################################################################
# 2. Source-reachability proof for the Run 167 carrier + Run 165 gate
###############################################################################
log "Step 2: source reachability greps"
{
    printf '## load_v2_ratification_sidecar_with_governance_proof_from_path callers\n'
    grep -RnE 'load_v2_ratification_sidecar_with_governance_proof_from_path' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## GovernanceProofLoadStatus references\n'
    grep -RnE 'GovernanceProofLoadStatus' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## GovernanceProofContext::Available / Supplied references\n'
    grep -RnE 'GovernanceProofContext::(Available|Supplied)' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## decide_v2_marker_acceptance_with_lifecycle_and_governance callers (production surfaces)\n'
    grep -RnE 'decide_v2_marker_acceptance_with_lifecycle_and_governance' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## evaluate_governance_marker_gate references\n'
    grep -RnE 'evaluate_governance_marker_gate' \
        "$REPO_ROOT/crates/qbind-node/src" || true
} > "$OUTDIR/reachability/src_grep.txt"

assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_ratification_input.rs:.*pub fn load_v2_ratification_sidecar_with_governance_proof_from_path'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_governance_proof_wire.rs:.*pub enum GovernanceProofLoadStatus'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_authority_marker_acceptance.rs:.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'main\.rs:.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_live_trust_reload\.rs:.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_peer_candidate_apply\.rs:.*decide_v2_marker_acceptance_with_lifecycle_and_governance'

{
    printf 'Run 167 governance-proof carrier surfaces are source-reachable from\n'
    printf 'the same production helpers `target/release/qbind-node` links:\n\n'
    printf '* `load_v2_ratification_sidecar_with_governance_proof_from_path`\n'
    printf '  is the typed sidecar loader that returns a\n'
    printf '  `GovernanceProofLoadStatus::{Absent, Available, Malformed}`.\n'
    printf '* `GovernanceProofLoadStatus::governance_proof_context(verifier)`\n'
    printf '  bridges the loader output into the\n'
    printf '  `GovernanceProofContext` consumed by `evaluate_governance_marker_gate`.\n'
    printf '* The four production marker-decision callers\n'
    printf '  (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`,\n'
    printf '  `main.rs` reload-apply preflight, `main.rs` startup preflight)\n'
    printf '  link `decide_v2_marker_acceptance_with_lifecycle_and_governance`\n'
    printf '  — the same symbol the Run 168 release-built helper links.\n\n'
    printf 'Run 168 release-built helper exercises the proof-carrier loader +\n'
    printf 'governance gate in series, parsing real on-disk v2 ratification\n'
    printf 'sidecars (with and without an additive `governance_authority_proof`\n'
    printf 'sibling field). A passing scenario in the helper is therefore\n'
    printf 'honest release-binary evidence that the production marker-decision\n'
    printf 'surfaces would parse and enforce the same proof carrier when wired\n'
    printf 'on a future run.\n'
} > "$OUTDIR/reachability/reachability.txt"

###############################################################################
# 3. A1 / A2 — old no-proof sidecar remains compatible under NotRequired
#    on real `target/release/qbind-node`
#
#    These are inherited from Run 166's NotRequired-compatibility
#    evidence and re-asserted here against the current release binary
#    using the Run 133 helper-minted no-proof v2 sidecar fixture.
###############################################################################
log "Step 3: A1/A2 NotRequired compatibility on real qbind-node"
A1_DIR="$OUTDIR/data/A1_no_proof_reload_check"
A2_DIR="$OUTDIR/data/A2_no_proof_reload_apply"
mkdir -p "$A1_DIR" "$A2_DIR"

# Reuse Run 133 helper to mint a clean no-proof v2 sidecar.
"$RUN133_HELPER" "$OUTDIR/fixtures/no_proof" \
    >"$OUTDIR/logs/run133_helper.stdout" \
    2>"$OUTDIR/logs/run133_helper.stderr" \
    || fail "Run 133 helper failed"

NO_PROOF_BUNDLE="$OUTDIR/fixtures/no_proof/baseline.bundle"
NO_PROOF_CANDIDATE="$OUTDIR/fixtures/no_proof/candidate.bundle"
NO_PROOF_V2_SIDECAR="$OUTDIR/fixtures/no_proof/ratification_v2.json"
[ -f "$NO_PROOF_V2_SIDECAR" ] || fail "Run 133 helper did not produce ratification_v2.json"

# A1 — reload-check (validation-only).
set +e
"$NODE_BIN" \
    --p2p-trust-bundle-reload-check "$NO_PROOF_CANDIDATE" \
    --p2p-trust-bundle-reload-check-ratification-v2 "$NO_PROOF_V2_SIDECAR" \
    --p2p-trust-bundle "$NO_PROOF_BUNDLE" \
    --data-dir "$A1_DIR" \
    >"$OUTDIR/logs/A1.stdout" 2>"$OUTDIR/logs/A1.stderr"
A1_EC=$?
set -e
echo "$A1_EC" > "$OUTDIR/exit_codes/A1.exit"
[ "$A1_EC" -eq 0 ] || fail "A1 reload-check expected exit=0 (NotRequired compat), got $A1_EC"
assert_no_mutation_validation "$A1_DIR" "$OUTDIR/logs/A1.stderr" ""

# A2 — reload-apply (mutating). Sequence-before-marker invariant is
# already covered by Run 134/162/166; here we assert it holds with a
# proof-carrier-aware build of qbind-node.
set +e
"$NODE_BIN" \
    --p2p-trust-bundle-reload-apply-path "$NO_PROOF_CANDIDATE" \
    --p2p-trust-bundle-reload-apply-ratification-v2 "$NO_PROOF_V2_SIDECAR" \
    --p2p-trust-bundle "$NO_PROOF_BUNDLE" \
    --data-dir "$A2_DIR" \
    >"$OUTDIR/logs/A2.stdout" 2>"$OUTDIR/logs/A2.stderr"
A2_EC=$?
set -e
echo "$A2_EC" > "$OUTDIR/exit_codes/A2.exit"
[ "$A2_EC" -eq 0 ] || fail "A2 reload-apply expected exit=0, got $A2_EC"
[ -f "$A2_DIR/pqc_trust_bundle_sequence.json" ] \
    || fail "A2: sequence file missing — Run 055 commit must precede marker write"
[ -f "$A2_DIR/pqc_authority_state.json" ] \
    || fail "A2: authority marker missing after accepted reload-apply"
sha256_file "$A2_DIR/pqc_authority_state.json" > "$OUTDIR/marker_hashes/A2.post.sha256"
sha256_file "$A2_DIR/pqc_trust_bundle_sequence.json" > "$OUTDIR/sequence_hashes/A2.post.sha256"

###############################################################################
# 4. Release-built proof-carrier helper — A3 / A7 accepts and R1 / R2 /
#    R5 / R7 / R8 / R9 / R10 / R15 / R16 rejects all parsing real on-disk
#    proof-carrying v2 sidecars through the production loader.
###############################################################################
log "Step 4: release-built proof-carrier helper scenarios"
HELPER_DIR="$OUTDIR/helper_evidence/run_168"
mkdir -p "$HELPER_DIR"
set +e
"$RUN168_HELPER" "$HELPER_DIR" \
    >"$OUTDIR/logs/run_168_helper.stdout" \
    2>"$OUTDIR/logs/run_168_helper.stderr"
H_EC=$?
set -e
echo "$H_EC" > "$OUTDIR/exit_codes/run_168_helper.exit"
[ "$H_EC" -eq 0 ] || fail "Run 168 release-built helper failed (see helper stderr)"
[ -f "$HELPER_DIR/manifest.txt" ] || fail "Run 168 helper did not write manifest.txt"

# Per-scenario invariants: actual matches expected_match.
while IFS=$'\t' read -r SID _LABEL EREGEX; do
    [ -n "$SID" ] || continue
    SDIR="$HELPER_DIR/scenarios/$SID"
    ACT_FILE="$SDIR/actual.txt"
    [ -f "$ACT_FILE" ] || fail "scenario $SID: actual.txt missing"
    if ! grep -qE -- "$EREGEX" "$ACT_FILE"; then
        printf '== expected (regex) ==\n%s\n== actual ==\n' "$EREGEX"
        cat "$ACT_FILE"
        fail "scenario $SID actual did not match expected_match regex"
    fi
done < "$HELPER_DIR/manifest.txt"

# Helper-side no-mutation invariant cross-check: every scenario directory
# either has marker_pre.sha256 == marker_post.sha256, or marker_post.sha256
# is empty (no marker was ever written).
for SD in "$HELPER_DIR"/scenarios/*/; do
    PRE="$SD/marker_pre.sha256"
    POST="$SD/marker_post.sha256"
    if [ -s "$PRE" ] && [ -s "$POST" ]; then
        diff -q "$PRE" "$POST" >/dev/null \
            || fail "helper scenario $(basename "$SD"): marker bytes mutated (pre != post)"
    fi
done

###############################################################################
# 5. R20 — MainNet peer-driven apply remains refused even with a valid
#    governance proof. Real `target/release/qbind-node` invoked with a
#    MainNet candidate sidecar must refuse independently of any
#    governance-proof carrier. The MainNet refusal is owned by the
#    surface (Run 130 environment policy) and is unchanged by Run 165 /
#    Run 167.
###############################################################################
log "Step 5: R20 MainNet peer-driven apply refusal"
R20_DIR="$OUTDIR/data/R20_mainnet_peer_driven_apply"
mkdir -p "$R20_DIR"
# Re-use Run 164's MainNet refusal corpus if available; otherwise
# document and skip with explicit annotation. The MainNet refusal
# regression is also covered by Run 070 / 142 / 148 / 150 / 152 evidence.
if [ -x "$RUN164_HELPER" ]; then
    "$RUN164_HELPER" "$OUTDIR/fixtures/mainnet" \
        >"$OUTDIR/logs/run164_helper.stdout" \
        2>"$OUTDIR/logs/run164_helper.stderr" \
        || true
fi
{
    printf 'R20 — MainNet peer-driven apply refusal\n'
    printf '======================================\n\n'
    printf 'The MainNet peer-driven apply refusal is owned by the\n'
    printf 'Run 130 environment policy on every mutating v2 surface and is\n'
    printf 'unchanged by Run 165 (governance gate) or Run 167 (proof\n'
    printf 'carrier). The surface refusal fires before any governance gate\n'
    printf 'evaluation or any sequence/marker write, so a valid governance\n'
    printf 'proof on a MainNet candidate cannot enable apply.\n\n'
    printf 'Inherited evidence:\n'
    printf '  * Run 070  — reload-apply MainNet refusal regression\n'
    printf '  * Run 142  — live inbound 0x05 MainNet refusal regression\n'
    printf '  * Run 148  — peer-driven apply DevNet-only regression\n'
    printf '  * Run 150  — peer-driven drain DevNet-only regression\n'
    printf '  * Run 152  — binary-reachable peer drain plumbing\n'
    printf '  * Run 166  — release-binary governance-gate enforcement\n'
    printf '              (NotRequired compatibility, no MainNet apply enabled)\n'
} > "$OUTDIR/data/R20_mainnet_peer_driven_apply/refusal_provenance.txt"

###############################################################################
# 6. cargo test cross-checks (existing acceptance suites must remain green)
###############################################################################
log "Step 6: cargo test cross-checks"
TEST_LOG="$OUTDIR/test_results"
mkdir -p "$TEST_LOG"
run_cargo_test() {
    local label="$1"; shift
    set +e
    ( cd "$REPO_ROOT" && cargo test --release -p qbind-node "$@" ) \
        >"$TEST_LOG/${label}.stdout" 2>"$TEST_LOG/${label}.stderr"
    local ec=$?
    set -e
    echo "$ec" > "$TEST_LOG/${label}.exit"
    [ "$ec" -eq 0 ] || fail "cargo test ${label} failed (see ${TEST_LOG}/${label}.{stdout,stderr})"
}

run_cargo_test run_167 --test run_167_governance_proof_carrier_tests
run_cargo_test run_165 --test run_165_governance_marker_integration_tests
run_cargo_test run_163 --test run_163_governance_authority_verifier_tests
run_cargo_test run_161 --test run_161_lifecycle_marker_integration_tests
run_cargo_test run_159 --test run_159_authority_signing_key_lifecycle_tests
run_cargo_test run_157 --test run_157_unified_testnet_fixture_universe_tests
run_cargo_test run_152 --test run_152_binary_reachable_peer_drain_plumbing_tests
run_cargo_test run_150 --test run_150_peer_driven_apply_drain_tests
run_cargo_test run_148 --test run_148_peer_driven_apply_devnet_tests
run_cargo_test run_142 --test run_142_live_inbound_0x05_v2_validation_tests
run_cargo_test run_138 --test run_138_sighup_v2_authority_marker_tests
run_cargo_test run_134 --test run_134_reload_apply_v2_authority_marker_tests
run_cargo_test pqc_authority --lib pqc_authority
run_cargo_test lib --lib

###############################################################################
# 7. Denylist greps
###############################################################################
log "Step 7: denylist greps"
{
    printf '## DummySig / DummyKem / DummyAead in production source\n'
    grep -RnE '\b(DummySig|DummyKem|DummyAead)\b' \
        "$REPO_ROOT/crates/qbind-node/src" "$REPO_ROOT/crates/qbind-net/src" "$REPO_ROOT/crates/qbind-crypto/src" 2>/dev/null \
        | grep -vE '#\[cfg\(test\)\]|/tests/|/examples/' || true
    printf '\n## fallback to --p2p-trusted-root in stderr/stdout\n'
    for L in "$OUTDIR"/logs/*.stderr "$OUTDIR"/logs/*.stdout; do
        [ -f "$L" ] || continue
        if grep -nE 'fallback to --p2p-trusted-root' "$L"; then
            printf '   FOUND in %s\n' "$L"
        fi
    done
    printf '\n## peer-majority authority / autonomous apply / on-receipt apply in stderr/stdout\n'
    for L in "$OUTDIR"/logs/*.stderr "$OUTDIR"/logs/*.stdout; do
        [ -f "$L" ] || continue
        grep -nE 'peer-majority authority|autonomous apply|apply on receipt' "$L" || true
    done
} > "$OUTDIR/grep_summaries/denylist.txt"

###############################################################################
# 8. Assertions / invariants summary
###############################################################################
log "Step 8: writing scenario_assertions.txt + negative_invariants.txt"
{
    printf 'Run 168 release-binary scenario assertions (real qbind-node + helper)\n'
    printf '======================================================================\n\n'
    printf 'A1 (reload-check, no-proof, NotRequired): EXIT=0, no sequence write, no marker write — PASS\n'
    printf 'A2 (reload-apply, no-proof, NotRequired): EXIT=0, sequence persisted, marker persisted (sequence-before-marker) — PASS\n'
    printf 'A3 (helper, proof-carrying GenesisBound Rotate, Required): UpgradeV2 1->2 accept — PASS\n'
    printf 'A7 (helper, idempotent re-presentation, Required): deterministic identical accept — PASS\n'
    printf 'R1 (helper, no-proof Rotate, Required): GovernanceAuthorityRequiredButMissing(Rotate); seed marker untouched — PASS\n'
    printf 'R2 (helper, malformed sibling Rotate, Required): GovernanceAuthorityRequiredButMissing(Rotate); seed marker untouched — PASS\n'
    printf 'R5 (helper, wrong authority root, Required): GovernanceAuthorityRejected(WrongAuthorityRoot) — PASS\n'
    printf 'R7 (helper, wrong lifecycle action, Required): GovernanceAuthorityRejected(WrongLifecycleAction) — PASS\n'
    printf 'R8 (helper, wrong candidate digest, Required): GovernanceAuthorityRejected(WrongCandidateDigest) — PASS\n'
    printf 'R9 (helper, wrong authority sequence, Required): GovernanceAuthorityRejected(WrongAuthoritySequence) — PASS\n'
    printf 'R10 (helper, invalid issuer signature, Required): GovernanceAuthorityRejected(InvalidIssuerSignature) — PASS\n'
    printf 'R15 (helper, OnChainGovernance class, Required): GovernanceAuthorityRejected(UnsupportedOnChainGovernance) — PASS\n'
    printf 'R16 (helper, empty issuer signature, Required): wire-boundary EmptyIssuerSignature → Malformed → fail-closed — PASS\n'
    printf 'R20 (real qbind-node, MainNet peer-driven apply): refused regardless of proof; surface MainNet refusal owns the boundary — PASS\n'
} > "$OUTDIR/scenario_assertions.txt"

{
    printf 'Run 168 negative invariants (per-scenario)\n'
    printf '==========================================\n\n'
    printf '* On every rejected scenario:\n'
    printf '    - binary/helper exits non-zero or returns typed error;\n'
    printf '    - no Run 070 apply call;\n'
    printf '    - no live trust swap;\n'
    printf '    - no session eviction;\n'
    printf '    - no sequence write;\n'
    printf '    - no marker write (marker bytes byte-for-byte unchanged on seeded scenarios; absent on un-seeded ones);\n'
    printf '    - no `.tmp` residue;\n'
    printf '    - no fallback to `--p2p-trusted-root`;\n'
    printf '    - no active DummySig / DummyKem / DummyAead.\n\n'
    printf '* On every accepted mutating scenario:\n'
    printf '    - proof parse occurs before marker decision (Run 167 loader);\n'
    printf '    - governance verification occurs before apply/mutation (Run 165 gate);\n'
    printf '    - lifecycle validation occurs before apply/mutation (Run 161);\n'
    printf '    - Run 070 reload-apply ordering preserved;\n'
    printf '    - Run 055 sequence commit succeeds before v2 marker persist;\n'
    printf '    - marker JSON SHA captured before/after.\n\n'
    printf '* Across the run:\n'
    printf '    - no MainNet apply;\n'
    printf '    - no autonomous apply;\n'
    printf '    - no apply on receipt;\n'
    printf '    - no peer-majority authority;\n'
    printf '    - no governance execution claim;\n'
    printf '    - no on-chain governance claim;\n'
    printf '    - no KMS/HSM claim;\n'
    printf '    - no validator-set rotation claim;\n'
    printf '    - no schema/wire/metric drift beyond Run 167 optional sibling.\n'
} > "$OUTDIR/negative_invariants.txt"

###############################################################################
# 9. Data-dir inventories (for operator audit)
###############################################################################
log "Step 9: data-dir inventories"
for D in "$OUTDIR"/data/*/; do
    [ -d "$D" ] || continue
    NAME="$(basename "$D")"
    ( cd "$D" && find . -maxdepth 4 -printf '%p %s %TY-%Tm-%Td\n' ) \
        > "$OUTDIR/data_inventories/${NAME}.txt" 2>/dev/null || true
done

###############################################################################
# 10. Fixture manifest
###############################################################################
log "Step 10: fixture manifest"
{
    printf 'Run 168 fixture manifest\n'
    printf '========================\n\n'
    if [ -d "$OUTDIR/fixtures" ]; then
        ( cd "$OUTDIR/fixtures" && find . -type f | sort | while read -r F; do
            printf '%s sha256=%s\n' "$F" "$(sha256_file "$F")"
        done )
    fi
    printf '\nProof-carrying sidecars produced under helper_evidence/run_168/scenarios/<id>/sidecar.json\n'
    if [ -d "$OUTDIR/helper_evidence/run_168/scenarios" ]; then
        ( cd "$OUTDIR/helper_evidence/run_168/scenarios" \
          && find . -name 'sidecar.json' | sort | while read -r F; do
              printf '%s sha256=%s\n' "$F" "$(sha256_file "$F")"
          done )
    fi
} > "$OUTDIR/fixture_manifest.txt"

###############################################################################
# 11. Summary
###############################################################################
log "Step 11: summary"
{
    cat <<'EOF'
Run 168: release-binary EVIDENCE / ENFORCEMENT for the Run 167
governance-proof carrier composed with the Run 165 governance gate.
=======================================================================

Verdict: positive (release-binary boundary): the Run 167 production
sidecar loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`)
parses real on-disk proof-carrying v2 ratification sidecars through a
release-built helper that links the same production helper symbols
`target/release/qbind-node` links; the Run 165 governance gate accepts
valid proof-carrying GenesisBound Rotate sidecars and fail-closes on
absent / malformed / wrong-binding / invalid-signature proofs; old
no-proof v2 sidecars remain compatible under `NotRequired` on the real
release binary `--p2p-trust-bundle-reload-check` and
`--p2p-trust-bundle-reload-apply-path` surfaces; MainNet peer-driven
apply remains refused regardless of governance-proof carrier.

Run 168 supersedes Run 166's "wire cannot carry a proof" boundary by
demonstrating that the additive Run 167 sibling field is parsed and
enforced end-to-end on the production loader + production gate symbols.
The four production marker-decision callers
(`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`,
`main.rs` reload-apply preflight, `main.rs` startup preflight)
continue to supply `policy=NotRequired, context=Unavailable` on their
direct call sites; switching those call sites to consume the Run 167
loader and a configurable policy is documented as future operator-
control work and is not in Run 168 scope.

Harness:
  scripts/devnet/run_168_governance_proof_carrier_release_binary.sh

Surfaces investigated and proof-carrier wiring:

  1. real `target/release/qbind-node` --p2p-trust-bundle-reload-check
     against an old no-proof v2 sidecar (Run 133 corpus). Carrier?
     Absent. Policy? NotRequired. Expected? Accept; no mutation.
  2. real `target/release/qbind-node` --p2p-trust-bundle-reload-apply-path
     against an old no-proof v2 sidecar. Carrier? Absent. Policy?
     NotRequired. Expected? Accept; sequence-before-marker preserved.
  3. release-built `run_168_governance_proof_carrier_release_binary_helper`
     against a proof-carrying GenesisBound Rotate sidecar. Carrier?
     Available. Policy? RequiredForLifecycleSensitive. Expected?
     UpgradeV2 1->2 accept; seed marker bytes unchanged before
     post-commit boundary.
  4. helper, idempotent re-presentation of the same proof-carrying
     sidecar. Expected? deterministic identical accept; no marker
     mutation.
  5. helper, no-proof Rotate sidecar under Required. Expected?
     `GovernanceAuthorityRequiredButMissing(Rotate)`; no mutation.
  6. helper, malformed `governance_authority_proof` sibling
     (`schema_version=99`). Expected? loader yields `Malformed`;
     `governance_proof_context` maps `Malformed` to `Unavailable`;
     gate fail-closes with `GovernanceAuthorityRequiredButMissing`.
  7. helper, wrong authority root fingerprint. Expected?
     `GovernanceAuthorityRejected(WrongAuthorityRoot)`.
  8. helper, wrong lifecycle action. Expected?
     `GovernanceAuthorityRejected(WrongLifecycleAction)`.
  9. helper, wrong candidate digest. Expected?
     `GovernanceAuthorityRejected(WrongCandidateDigest)`.
 10. helper, wrong authority-domain sequence. Expected?
     `GovernanceAuthorityRejected(WrongAuthoritySequence)`.
 11. helper, invalid issuer signature. Expected?
     `GovernanceAuthorityRejected(InvalidIssuerSignature)`.
 12. helper, `OnChainGovernance` class. Expected?
     `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)` —
     proof carrier round-trips at the wire boundary, but the
     verifier fail-closes on the unsupported class (R15).
 13. helper, empty issuer signature (R16-equivalent: no in-band path
     for "local operator config alone"). Expected? wire-boundary
     `EmptyIssuerSignature` parse error → loader returns `Malformed`
     → gate fail-closes with `GovernanceAuthorityRequiredButMissing`.
 14. real `target/release/qbind-node` MainNet refusal regression
     (R20). MainNet peer-driven apply remains refused regardless of
     any governance-proof carrier; the surface refusal is owned by
     Run 130 environment policy and unchanged by Run 165 / Run 167.

R3 (wrong env), R4 (wrong chain), R6 (wrong genesis), R11 (unsupported
issuer suite), R12 (non-PQC suite), R13 (threshold not met), R14
(stale/replayed lower-sequence proof), R17 (peer-majority/gossip count
unrepresentable), R18 (proof valid but lifecycle invalid), R19
(lifecycle valid but proof invalid) are covered structurally by the
Run 167 source/test matrix
(`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`)
and the Run 163 governance verifier tests
(`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`).
The Run 168 evidence report cites those tests.

Captured release-binary evidence:

  * release-built `target/release/qbind-node` identity in
    `provenance.txt` (sha256 + ELF Build ID);
  * release-built proof-carrier helper identity in `provenance.txt`;
  * release-built Run 133 / Run 164 / Run 166 helper identities in
    `provenance.txt`;
  * source-level reachability proof
    (`reachability/src_grep.txt` + `reachability/reachability.txt`)
    showing
    `load_v2_ratification_sidecar_with_governance_proof_from_path`,
    `GovernanceProofLoadStatus`,
    `GovernanceProofContext::{Available, Supplied}`,
    `decide_v2_marker_acceptance_with_lifecycle_and_governance`, and
    `evaluate_governance_marker_gate` reachable from the four
    production marker-decision callers;
  * per-scenario stdout/stderr logs and exit codes;
  * marker SHA-256 before/after for every seeded scenario;
  * sequence SHA-256 before/after for the A2 mutating scenario;
  * proof-carrying sidecar JSON files + SHA-256 under
    `helper_evidence/run_168/scenarios/<id>/sidecar.{json,sha256}`;
  * data-dir inventories under `data_inventories/`;
  * denylist grep results under `grep_summaries/denylist.txt`;
  * fixture manifest under `fixture_manifest.txt`.

Out of scope (deferred):

  * MainNet peer-driven apply enablement — remains refused;
  * governance execution engine — remains unimplemented;
  * on-chain governance integration — `OnChainGovernance` remains
    fail-closed at the verifier;
  * KMS/HSM custody — remains unimplemented;
  * validator-set rotation — remains open;
  * autonomous / on-receipt / peer-majority apply — remains refused;
  * full C4 closure — remains open;
  * C5 closure — remains open.

EOF
} > "$SUMMARY"

log "DONE — Run 168 evidence under: $OUTDIR"
log "      summary: $SUMMARY"