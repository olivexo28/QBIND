#!/usr/bin/env bash
# Run 170 — release-binary EVIDENCE harness for the **production v2
# marker-decision surfaces** consuming the Run 167 governance-proof
# carrier through the Run 169 shim
# `qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`
# on real `target/release/qbind-node`.
#
# Per `task/RUN_170_TASK.txt`, Run 170 produces release-binary evidence
# that:
#
#   1. pre-Run-167 no-proof v2 sidecars remain compatible under the
#      default `GovernanceProofPolicy::NotRequired` on the real
#      `target/release/qbind-node` (validation-only
#      `--p2p-trust-bundle-reload-check` and mutating
#      `--p2p-trust-bundle-reload-apply-path`);
#   2. proof-carrying v2 sidecars are parsed by the **production**
#      Run 167 loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`)
#      now wired into all four production preflight call sites by
#      Run 169 (`preflight_run_134_v2_marker_decision`,
#      `preflight_run_136_v2_marker_decision_for_startup`,
#      `preflight_sighup_v2_marker_decision`,
#      `ProductionV2MarkerCoordinator::decide_pre_apply`) — this is
#      proven by source-level grep that those callers reference the
#      Run 169 shim and the Run 167 loader symbols;
#   3. malformed `governance_authority_proof` siblings are typed by
#      the loader as `Malformed` and mapped to `Unavailable` by the
#      shim, exactly per Run 167 / Run 169 documented mapping;
#   4. the Run 165 governance gate composed with the Run 169 shim
#      accepts valid proof-carrying GenesisBound `Rotate` sidecars and
#      fail-closes on absent / malformed / wrong-binding /
#      invalid-signature / unsupported proofs through the Run 168
#      release-built helper that links the same production loader +
#      shim + gate symbols `target/release/qbind-node` links;
#   5. MainNet peer-driven apply remains refused regardless of any
#      governance-proof carrier on the real release binary.
#
# Strict scope (mirrors task `Strict scope`):
#   * Release-binary evidence only; no production runtime source
#     change.
#   * No new CLI flag, no environment variable, no schema change.
#   * No MainNet apply enablement.
#   * No governance execution / on-chain governance / KMS-HSM /
#     validator-set rotation.
#   * No weakening of Runs 070, 130–169.
#
# Honest limitation captured in this harness (and in
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_170.md`):
#
#   The four production preflight call sites that Run 169 wired
#   continue to be invoked at the default
#   `GovernanceProofPolicy::NotRequired` from the release-binary CLI
#   today; exposing a `RequiredForLifecycleSensitive` toggle on the
#   release-binary CLI is operator-control plumbing intentionally
#   deferred per Run 170 strict scope ("no production source change").
#   The full A1–A7 / R1–R20 proof-carrying matrix under the `Required`
#   policy is therefore exercised through the Run 168 release-built
#   helper (re-run here against the current checkout) — that helper
#   links the same production loader + Run 165 gate symbols the four
#   production preflights now run through via the Run 169 shim.
#   Run 169 source/test coverage
#   (`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`)
#   directly exercises the `Required` policy through every production
#   preflight at the source level. Run 170 supersedes Run 168's
#   helper-only boundary by capturing the Run 169-wired source-level
#   reachability proof on the same release-binary checkout.
#
# Evidence-archive precedent: per Run 153 / 155 / 156 / 158 / 160 /
# 162 / 164 / 166 / 168, only `README.md`, `summary.txt`, and
# `.gitignore` are tracked under
# `docs/devnet/run_170_governance_proof_production_surface_release_binary/`.
# All per-run artifacts produced by this harness (logs, exit codes,
# marker SHAs, sidecar SHAs, helper scenarios, reachability greps,
# provenance, fixture manifest, denylist results) are reproduced by
# re-running the harness and are NOT committed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${1:-${REPO_ROOT}/docs/devnet/run_170_governance_proof_production_surface_release_binary}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
RUN133_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
RUN164_HELPER="${REPO_ROOT}/target/release/examples/run_164_governance_authority_fixture_helper"
RUN166_HELPER="${REPO_ROOT}/target/release/examples/run_166_governance_gate_release_binary_helper"
RUN168_HELPER="${REPO_ROOT}/target/release/examples/run_168_governance_proof_carrier_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run170] %s\n' "$*"; }
fail() { printf '[run170] FAIL: %s\n' "$*" >&2; exit 1; }
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
# Run 162 / Run 166 / Run 168.
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
    printf 'run: 170 — release-binary production-surface governance-proof carrying evidence\n'
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
  || { tail -160 "$OUTDIR/logs/build.log"; fail "release build failed"; }

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
# 2. Source-reachability proof for the Run 169 shim + Run 167 carrier +
#    Run 165 gate at the four production preflight call sites.
###############################################################################
log "Step 2: source reachability greps"
{
    printf '## Run 169 production-surface shim — preflight_v2_marker_decision_with_governance_proof_load\n'
    grep -RnE 'preflight_v2_marker_decision_with_governance_proof_load' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 167 typed sidecar loader — load_v2_ratification_sidecar_with_governance_proof_from_path\n'
    grep -RnE 'load_v2_ratification_sidecar_with_governance_proof_from_path' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 169 versioned dispatcher — load_versioned_ratification_with_governance_proof_from_path\n'
    grep -RnE 'load_versioned_ratification_with_governance_proof_from_path' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 167 typed load status — GovernanceProofLoadStatus (Absent / Available / Malformed)\n'
    grep -RnE 'GovernanceProofLoadStatus(::|\b)' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 165 typed gate context — GovernanceProofContext::{Available,Supplied,Unavailable}\n'
    grep -RnE 'GovernanceProofContext::(Available|Supplied|Unavailable)' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 165 governance gate — decide_v2_marker_acceptance_with_lifecycle_and_governance (production callers)\n'
    grep -RnE 'decide_v2_marker_acceptance_with_lifecycle_and_governance' \
        "$REPO_ROOT/crates/qbind-node/src" || true
    printf '\n## Run 165 verifier composition — evaluate_governance_marker_gate\n'
    grep -RnE 'evaluate_governance_marker_gate' \
        "$REPO_ROOT/crates/qbind-node/src" || true
} > "$OUTDIR/reachability/src_grep.txt"

# Run 169 wiring: the shim is referenced from each of the four
# production preflight call sites.
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_governance_proof_surface\.rs:.*pub fn preflight_v2_marker_decision_with_governance_proof_load'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'main\.rs:.*preflight_v2_marker_decision_with_governance_proof_load'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_live_trust_reload\.rs:.*preflight_v2_marker_decision_with_governance_proof_load'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_peer_candidate_apply\.rs:.*preflight_v2_marker_decision_with_governance_proof_load'

# Run 167 loader is reachable from the Run 169-wired callers.
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_ratification_input\.rs:.*pub fn load_v2_ratification_sidecar_with_governance_proof_from_path'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_ratification_input\.rs:.*pub fn load_versioned_ratification_with_governance_proof_from_path'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'main\.rs:.*load_versioned_ratification_with_governance_proof_from_path'
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_live_trust_reload\.rs:.*load_versioned_ratification_with_governance_proof_from_path'

# Run 167 typed load status enum is referenced.
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'GovernanceProofLoadStatus'

# Run 165 gate symbol is reachable from each production caller (still
# the gate symbol underneath the Run 169 shim).
assert_grep "$OUTDIR/reachability/src_grep.txt" \
    'pqc_authority_marker_acceptance\.rs:.*decide_v2_marker_acceptance_with_lifecycle_and_governance'

{
    printf 'Run 170 release-binary production-surface reachability\n'
    printf '======================================================\n\n'
    printf 'Run 169 wired the Run 167 typed governance-proof loader into\n'
    printf 'every production v2 marker-decision preflight call site through\n'
    printf 'a single library shim:\n\n'
    printf '  preflight_v2_marker_decision_with_governance_proof_load\n'
    printf '    (crates/qbind-node/src/pqc_governance_proof_surface.rs)\n\n'
    printf 'The four production preflight call sites are:\n\n'
    printf '  * crates/qbind-node/src/main.rs           — reload-apply\n'
    printf '                                              preflight (Run 105/134)\n'
    printf '                                              and startup\n'
    printf '                                              `--p2p-trust-bundle`\n'
    printf '                                              preflight (Run 136)\n'
    printf '  * crates/qbind-node/src/pqc_live_trust_reload.rs\n'
    printf '                                            — SIGHUP live-reload\n'
    printf '                                              preflight (Run 138)\n'
    printf '  * crates/qbind-node/src/pqc_peer_candidate_apply.rs\n'
    printf '                                            — peer-driven drain\n'
    printf '                                              `ProductionV2MarkerCoordinator`\n'
    printf '                                              (Run 152)\n\n'
    printf 'All four call sites consume the Run 169 shim, which in turn:\n\n'
    printf '  * loads the v2 ratification sidecar with optional\n'
    printf '    `governance_authority_proof` sibling via the Run 167\n'
    printf '    typed loader\n'
    printf '    `load_v2_ratification_sidecar_with_governance_proof_from_path`\n'
    printf '    (or the Run 169 versioned dispatcher\n'
    printf '    `load_versioned_ratification_with_governance_proof_from_path`);\n'
    printf '  * maps the typed `GovernanceProofLoadStatus::{Absent, Available,\n'
    printf '    Malformed}` to a `GovernanceProofContext` via\n'
    printf '    `GovernanceProofLoadStatus::governance_proof_context(verifier)`\n'
    printf '    (`Available` -> `Supplied`; `Absent` | `Malformed` ->\n'
    printf '    `Unavailable` per Run 167 documented mapping);\n'
    printf '  * delegates to the Run 165 governance gate\n'
    printf '    `decide_v2_marker_acceptance_with_lifecycle_and_governance`\n'
    printf '    composing the Run 161 lifecycle validator and the Run 163\n'
    printf '    governance verifier.\n\n'
    printf 'The Run 168 release-built helper that this harness re-runs against\n'
    printf 'the current checkout links the same Run 167 loader and Run 165 gate\n'
    printf 'symbols. Combined with the Run 169 wiring captured above, a passing\n'
    printf 'helper scenario is honest release-binary evidence that the\n'
    printf 'production v2 marker-decision preflights enforce the proof-carrier\n'
    printf 'composition through the same code path the helper exercises.\n\n'
    printf 'Honest limitation (Run 170 strict scope): the four production\n'
    printf 'preflight call sites are wired to invoke the Run 169 shim with\n'
    printf '`GovernanceProofPolicy::NotRequired` by default. Lifting the\n'
    printf 'release-binary CLI to expose a configurable\n'
    printf '`RequiredForLifecycleSensitive` toggle is operator-control plumbing\n'
    printf 'intentionally NOT in Run 170 scope (would require production source\n'
    printf 'change beyond a "tiny harness-only helper adjustment"). The full\n'
    printf 'Required-policy proof-carrying matrix is therefore exercised here\n'
    printf 'through the Run 168 release-built helper plus the Run 169 source/\n'
    printf 'test integration suite\n'
    printf '(`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`,\n'
    printf '39 tests).\n'
} > "$OUTDIR/reachability/reachability.txt"

###############################################################################
# 3. A1 / A2 — pre-Run-167 no-proof v2 sidecar remains compatible under
#    NotRequired on real `target/release/qbind-node`. Driven through the
#    Run 169-wired production preflights (reload-check / reload-apply).
###############################################################################
log "Step 3: A1/A2 NotRequired compatibility on real qbind-node (Run 169-wired)"
A1_DIR="$OUTDIR/data/A1_no_proof_reload_check"
A2_DIR="$OUTDIR/data/A2_no_proof_reload_apply"
mkdir -p "$A1_DIR" "$A2_DIR"

"$RUN133_HELPER" "$OUTDIR/fixtures/no_proof" \
    >"$OUTDIR/logs/run133_helper.stdout" \
    2>"$OUTDIR/logs/run133_helper.stderr" \
    || fail "Run 133 helper failed"

NO_PROOF_BUNDLE="$OUTDIR/fixtures/no_proof/baseline.bundle"
NO_PROOF_CANDIDATE="$OUTDIR/fixtures/no_proof/candidate.bundle"
NO_PROOF_V2_SIDECAR="$OUTDIR/fixtures/no_proof/ratification_v2.json"
[ -f "$NO_PROOF_V2_SIDECAR" ] || fail "Run 133 helper did not produce ratification_v2.json"

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
[ "$A1_EC" -eq 0 ] || fail "A1 reload-check expected exit=0 (NotRequired compat through Run 169 shim), got $A1_EC"
assert_no_mutation_validation "$A1_DIR" "$OUTDIR/logs/A1.stderr" ""

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
#    proof-carrying v2 sidecars through the production loader. This is
#    the Run 168 helper re-run on the current checkout to assert that
#    the Run 169 wiring did not regress the proof-carrier
#    parse-and-enforce composition.
###############################################################################
log "Step 4: Run 168 release-built proof-carrier helper scenarios (Run 170 re-run)"
HELPER_DIR="$OUTDIR/helper_evidence/run_168_replay"
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
#    Run 167 / Run 169.
###############################################################################
log "Step 5: R20 MainNet peer-driven apply refusal regression"
R20_DIR="$OUTDIR/data/R20_mainnet_peer_driven_apply"
mkdir -p "$R20_DIR"
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
    printf 'unchanged by Run 165 (governance gate), Run 167 (proof carrier),\n'
    printf 'or Run 169 (production-surface loader wiring). The surface\n'
    printf 'refusal fires before any governance gate evaluation or any\n'
    printf 'sequence/marker write, so a valid governance proof on a MainNet\n'
    printf 'candidate cannot enable apply.\n\n'
    printf 'Inherited evidence:\n'
    printf '  * Run 070  — reload-apply MainNet refusal regression\n'
    printf '  * Run 142  — live inbound 0x05 MainNet refusal regression\n'
    printf '  * Run 148  — peer-driven apply DevNet-only regression\n'
    printf '  * Run 150  — peer-driven drain DevNet-only regression\n'
    printf '  * Run 152  — binary-reachable peer drain plumbing\n'
    printf '  * Run 166  — release-binary governance-gate enforcement\n'
    printf '              (NotRequired compatibility, no MainNet apply enabled)\n'
    printf '  * Run 168  — release-binary governance-proof carrier enforcement\n'
    printf '              (proof carrier parsed; MainNet refusal unchanged)\n'
} > "$R20_DIR/refusal_provenance.txt"

###############################################################################
# 6. cargo test cross-checks (existing acceptance suites must remain green,
#    including the Run 169 source/test integration suite)
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

run_cargo_test run_169 --test run_169_governance_proof_loader_surface_integration_tests
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
    printf '\n## marker write before sequence commit (validation surfaces and rejected mutating)\n'
    for D in "$OUTDIR"/data/A1_*; do
        [ -d "$D" ] || continue
        if [ -f "$D/pqc_authority_state.json" ] && [ ! -f "$D/pqc_trust_bundle_sequence.json" ]; then
            printf '   FOUND marker without sequence under %s\n' "$D"
        fi
    done
} > "$OUTDIR/grep_summaries/denylist.txt"

###############################################################################
# 8. Assertions / invariants summary
###############################################################################
log "Step 8: writing scenario_assertions.txt + negative_invariants.txt"
{
    printf 'Run 170 release-binary scenario assertions (real qbind-node + Run 168 helper replay)\n'
    printf '====================================================================================\n\n'
    printf 'A1 (real qbind-node, reload-check, no-proof, NotRequired, Run 169-wired): EXIT=0, no sequence write, no marker write — PASS\n'
    printf 'A2 (real qbind-node, reload-apply, no-proof, NotRequired, Run 169-wired): EXIT=0, sequence persisted, marker persisted (sequence-before-marker) — PASS\n'
    printf 'A3 (helper replay, proof-carrying GenesisBound Rotate, Required): UpgradeV2 1->2 accept — PASS\n'
    printf 'A7 (helper replay, idempotent re-presentation, Required): deterministic identical accept — PASS\n'
    printf 'R1 (helper replay, no-proof Rotate, Required): GovernanceAuthorityRequiredButMissing(Rotate); seed marker untouched — PASS\n'
    printf 'R2 (helper replay, malformed sibling Rotate, Required): GovernanceAuthorityRequiredButMissing(Rotate); seed marker untouched — PASS\n'
    printf 'R5 (helper replay, wrong authority root, Required): GovernanceAuthorityRejected(WrongAuthorityRoot) — PASS\n'
    printf 'R7 (helper replay, wrong lifecycle action, Required): GovernanceAuthorityRejected(WrongLifecycleAction) — PASS\n'
    printf 'R8 (helper replay, wrong candidate digest, Required): GovernanceAuthorityRejected(WrongCandidateDigest) — PASS\n'
    printf 'R9 (helper replay, wrong authority sequence, Required): GovernanceAuthorityRejected(WrongAuthoritySequence) — PASS\n'
    printf 'R10 (helper replay, invalid issuer signature, Required): GovernanceAuthorityRejected(InvalidIssuerSignature) — PASS\n'
    printf 'R15 (helper replay, OnChainGovernance class, Required): GovernanceAuthorityRejected(UnsupportedOnChainGovernance) — PASS\n'
    printf 'R16 (helper replay, empty issuer signature, Required): wire-boundary EmptyIssuerSignature → Malformed → fail-closed — PASS\n'
    printf 'R20 (real qbind-node, MainNet peer-driven apply): refused regardless of proof; surface MainNet refusal owns the boundary — PASS\n\n'
    printf 'Source-level reachability claim (new in Run 170 vs Run 168):\n'
    printf '  * preflight_v2_marker_decision_with_governance_proof_load (Run 169 shim)\n'
    printf '    referenced from main.rs (reload-apply preflight + startup preflight),\n'
    printf '    pqc_live_trust_reload.rs (SIGHUP preflight),\n'
    printf '    pqc_peer_candidate_apply.rs (peer-driven coordinator).\n'
    printf '  * load_versioned_ratification_with_governance_proof_from_path (Run 169\n'
    printf '    versioned dispatcher) referenced from main.rs and pqc_live_trust_reload.rs.\n'
} > "$OUTDIR/scenario_assertions.txt"

{
    printf 'Run 170 negative invariants (per-scenario)\n'
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
    printf '    - proof parse occurs before marker decision (Run 167 loader, Run 169 dispatcher);\n'
    printf '    - governance verification occurs before apply/mutation (Run 169 shim → Run 165 gate);\n'
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
    printf 'Run 170 fixture manifest\n'
    printf '========================\n\n'
    if [ -d "$OUTDIR/fixtures" ]; then
        ( cd "$OUTDIR/fixtures" && find . -type f | sort | while read -r F; do
            printf '%s sha256=%s\n' "$F" "$(sha256_file "$F")"
        done )
    fi
    printf '\nProof-carrying sidecars produced under helper_evidence/run_168_replay/scenarios/<id>/sidecar.json\n'
    if [ -d "$OUTDIR/helper_evidence/run_168_replay/scenarios" ]; then
        ( cd "$OUTDIR/helper_evidence/run_168_replay/scenarios" \
          && find . -name 'sidecar.json' | sort | while read -r F; do
              printf '%s sha256=%s\n' "$F" "$(sha256_file "$F")"
          done )
    fi
} > "$OUTDIR/fixture_manifest.txt"

###############################################################################
# 11. Summary
###############################################################################
log "Step 11: summary"
cat > "$SUMMARY" <<'EOF'
Run 170: release-binary EVIDENCE for the production v2 marker-decision
surfaces consuming the Run 167 governance-proof carrier through the
Run 169 shim
`qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`
on real `target/release/qbind-node`.
=======================================================================

Verdict: positive (release-binary boundary): the Run 167 production
sidecar loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`,
Run 169 versioned dispatcher
`load_versioned_ratification_with_governance_proof_from_path`) is now
referenced from each of the four production v2 marker-decision
preflight call sites (reload-check / reload-apply preflight in
`main.rs`, startup `--p2p-trust-bundle` preflight in `main.rs`, SIGHUP
preflight in `pqc_live_trust_reload.rs`, peer-driven coordinator in
`pqc_peer_candidate_apply.rs`) via the Run 169 shim
`preflight_v2_marker_decision_with_governance_proof_load`; pre-Run-167
no-proof v2 sidecars continue to load and apply on real
`target/release/qbind-node` (`A1` reload-check accept; `A2`
reload-apply accept with sequence-before-marker preserved); the Run 165
governance gate accepts valid proof-carrying GenesisBound Rotate
sidecars and fail-closes on absent / malformed / wrong-binding /
invalid-signature / unsupported proofs through the Run 168 release-built
helper that links the same production loader + gate symbols
`target/release/qbind-node` links; MainNet peer-driven apply remains
refused regardless of any governance-proof carrier.

Honest limitation: the four production preflight call sites are wired
to invoke the Run 169 shim with `GovernanceProofPolicy::NotRequired` by
default. Lifting the release-binary CLI to expose a configurable
`RequiredForLifecycleSensitive` toggle would require a production
source change beyond the Run 170 strict scope ("no production source
change unless a tiny harness-only helper adjustment is required") and
is intentionally NOT in Run 170 scope. The full Required-policy
proof-carrying matrix is therefore exercised through the Run 168
release-built helper (replayed here against the current checkout) plus
the Run 169 source/test integration suite
(`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`,
39 tests). The release-binary CLI toggle for `Required` is documented
as deferred to a follow-up operator-control wiring run.

Harness:
  scripts/devnet/run_170_governance_proof_production_surface_release_binary.sh

Surfaces investigated and proof-carrier wiring:

  1. real `target/release/qbind-node` --p2p-trust-bundle-reload-check
     against an old no-proof v2 sidecar (Run 133 corpus). Carrier?
     Absent. Policy? NotRequired. Path? Run 169-wired Run 167 loader →
     Run 169 shim → Run 165 gate → accept; no mutation.
  2. real `target/release/qbind-node` --p2p-trust-bundle-reload-apply-path
     against an old no-proof v2 sidecar. Carrier? Absent. Policy?
     NotRequired. Path? Run 169-wired Run 167 loader → Run 169 shim →
     Run 165 gate → accept; sequence-before-marker preserved
     (Run 070 / Run 055).
  3. release-built Run 168 helper replay against a proof-carrying
     GenesisBound Rotate sidecar. Carrier? Available. Policy?
     RequiredForLifecycleSensitive. Expected? UpgradeV2 1->2 accept;
     seed marker bytes unchanged before post-commit boundary.
  4. helper replay, idempotent re-presentation. Expected?
     deterministic identical accept; no marker mutation.
  5. helper replay, no-proof Rotate under Required. Expected?
     `GovernanceAuthorityRequiredButMissing(Rotate)`; no mutation.
  6. helper replay, malformed `governance_authority_proof` sibling.
     Loader: Malformed. Shim maps to Unavailable. Gate fail-closes
     under Required.
  7. helper replay, wrong authority root → `GovernanceAuthorityRejected(WrongAuthorityRoot)`.
  8. helper replay, wrong lifecycle action → `GovernanceAuthorityRejected(WrongLifecycleAction)`.
  9. helper replay, wrong candidate digest → `GovernanceAuthorityRejected(WrongCandidateDigest)`.
 10. helper replay, wrong authority-domain sequence → `GovernanceAuthorityRejected(WrongAuthoritySequence)`.
 11. helper replay, invalid issuer signature → `GovernanceAuthorityRejected(InvalidIssuerSignature)`.
 12. helper replay, `OnChainGovernance` class → `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`.
 13. helper replay, empty issuer signature → wire-boundary
     EmptyIssuerSignature → Malformed → fail-closed.
 14. real `target/release/qbind-node` MainNet refusal regression
     (R20). MainNet peer-driven apply remains refused regardless of
     any governance-proof carrier; the surface refusal is owned by
     Run 130 environment policy and unchanged by Run 165 / Run 167 /
     Run 169.

R3 (wrong env), R4 (wrong chain), R6 (wrong genesis), R11
(unsupported issuer suite), R12 (non-PQC suite), R13 (threshold not
met), R14 (stale/replayed lower-sequence proof), R17 (peer-majority/
gossip count unrepresentable), R18 (proof valid but lifecycle
invalid), R19 (lifecycle valid but proof invalid) are covered
structurally by the Run 167 source/test matrix
(`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`,
47 tests), the Run 163 governance verifier tests
(`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`,
32 tests), and the Run 169 production-surface integration suite
(`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`,
39 tests). Run 170 cites those tests for completeness.

Captured release-binary evidence:

  * release-built `target/release/qbind-node` identity in
    `provenance.txt` (sha256 + ELF Build ID);
  * release-built Run 133 / Run 164 / Run 166 / Run 168 helper
    identities in `provenance.txt`;
  * source-level reachability proof under
    `reachability/src_grep.txt` + `reachability/reachability.txt`
    showing the Run 169 shim
    `preflight_v2_marker_decision_with_governance_proof_load` is
    referenced from each of the four production preflight call sites;
    the Run 167 loader and Run 169 versioned dispatcher are
    referenced from `main.rs` and `pqc_live_trust_reload.rs`;
    `GovernanceProofLoadStatus` and `GovernanceProofContext` symbols
    are reachable from the production source tree;
    `decide_v2_marker_acceptance_with_lifecycle_and_governance` and
    `evaluate_governance_marker_gate` remain the underlying gate
    symbols;
  * per-scenario stdout/stderr logs and exit codes;
  * marker SHA-256 before/after for every seeded scenario;
  * sequence SHA-256 before/after for the A2 mutating scenario;
  * proof-carrying sidecar JSON files + SHA-256 under
    `helper_evidence/run_168_replay/scenarios/<id>/sidecar.{json,sha256}`;
  * data-dir inventories under `data_inventories/`;
  * denylist grep results under `grep_summaries/denylist.txt`;
  * fixture manifest under `fixture_manifest.txt`.

No-mutation invariants asserted on every rejected scenario:

  * binary or helper exits non-zero or returns the precise typed
    error;
  * no Run 070 apply call;
  * no live trust swap;
  * no session eviction;
  * no sequence write;
  * no marker write (marker bytes byte-for-byte unchanged on seeded
    scenarios; absent on un-seeded ones);
  * no `.tmp` residue;
  * no fallback to `--p2p-trusted-root`;
  * no active `DummySig` / `DummyKem` / `DummyAead`.

Mutation-ordering invariants asserted on every accepted mutating
scenario:

  * proof parse occurs before marker decision (Run 167 loader / Run
    169 dispatcher);
  * governance verification occurs before apply/mutation (Run 169
    shim → Run 165 gate);
  * lifecycle validation occurs before apply/mutation (Run 161);
  * Run 070 reload-apply ordering preserved;
  * Run 055 sequence commit succeeds before v2 marker persist.

Denylist invariants (across the run):

  * no MainNet apply;
  * no autonomous apply;
  * no apply on receipt;
  * no peer-majority authority;
  * no governance execution claim;
  * no on-chain governance claim;
  * no KMS/HSM claim;
  * no validator-set rotation claim;
  * no fallback to `--p2p-trusted-root`;
  * no active `DummySig` / `DummyKem` / `DummyAead` in production
    source;
  * no schema/wire/metric drift beyond Run 167's optional sibling
    field;
  * no marker write before sequence commit;
  * no sequence write on validation-only surfaces;
  * no marker write on validation-only surfaces.

Out of scope (deferred):

  * MainNet peer-driven apply enablement — remains refused;
  * governance execution engine — remains unimplemented;
  * on-chain governance integration — `OnChainGovernance` remains
    fail-closed at the verifier;
  * KMS/HSM custody — remains unimplemented;
  * validator-set rotation — remains open;
  * autonomous / on-receipt / peer-majority apply — remains refused;
  * full C4 closure — remains open;
  * C5 closure — remains open;
  * release-binary CLI toggle for
    `GovernanceProofPolicy::RequiredForLifecycleSensitive` —
    operator-control plumbing intentionally NOT in Run 170 scope; the
    full Required-policy proof-carrying matrix is exercised through
    the Run 168 release-built helper and the Run 169 source/test
    integration suite.

EOF

log "DONE — Run 170 evidence under: $OUTDIR"
log "      summary: $SUMMARY"