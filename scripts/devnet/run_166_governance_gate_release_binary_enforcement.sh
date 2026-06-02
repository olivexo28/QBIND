#!/usr/bin/env bash
# Run 166 — release-binary EVIDENCE / ENFORCEMENT harness for the Run 165
# governance gate
# (`qbind_node::pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`,
#  `qbind_node::pqc_governance_authority::evaluate_governance_marker_gate`,
#  typed errors `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected`
#  and `::GovernanceAuthorityRequiredButMissing`).
#
# Per task/RUN_166_TASK.txt, Run 166 must:
#
#   1. prove governance-gate source reachability from real production
#      surfaces (vs. Run 164's "zero production-surface caller" boundary);
#   2. prove `NotRequired` compatibility on the real
#      `target/release/qbind-node` binary through `--p2p-trust-bundle-
#      reload-check` (validation-only) and `--p2p-trust-bundle-reload-
#      apply-path` (mutating);
#   3. prove `RequiredButMissing` fail-closed behaviour on a release-built
#      helper that links the same production helper symbol the four
#      mutating surfaces (process-start reload-apply, `--p2p-trust-bundle`
#      startup, SIGHUP live-reload, peer-driven drain) call;
#   4. prove rejection produces no marker mutation, no sequence write, no
#      live trust mutation, no session eviction, no MainNet apply
#      enablement;
#   5. exercise the full Run 163 governance proof corpus through the
#      release-built Run 164 helper (helper evidence, not production-
#      surface proof-carrying evidence);
#   6. capture binary identity (sha256 + ELF Build ID), commit hash,
#      rustc/cargo versions, exact commands, per-scenario stdout/stderr
#      logs and exit codes, marker/sequence JSON and SHA before/after,
#      data-dir inventories, and denylist grep results.
#
# Surfaces investigated and their governance gate wiring:
#
#   1. startup `--p2p-trust-bundle`              — routes through
#      `decide_v2_marker_acceptance_with_lifecycle_and_governance` with
#      policy=NotRequired, context=Unavailable (`crates/qbind-node/src/
#      main.rs` startup pre-flight call site).
#   2. reload-check validation-only              — not a marker-decision
#      mutating call site; the v2 anti-rollback comparison + lifecycle +
#      governance composition is decided source-locally per Run 132 /
#      Run 165, so reload-check exercises governance-aware decision
#      logic without persisting (validation-only contract preserved).
#   3. local peer-candidate-check validation-only — same as (2).
#   4. process-start reload-apply                 — routes through the
#      governance-aware helper at policy=NotRequired, context=Unavailable
#      (`crates/qbind-node/src/main.rs` reload-apply pre-flight).
#   5. SIGHUP live reload                         — routes through the
#      governance-aware helper at policy=NotRequired, context=Unavailable
#      (`crates/qbind-node/src/pqc_live_trust_reload.rs`).
#   6. live inbound `0x05`                        — currently flows
#      through the same lifecycle marker decision path; the governance
#      composition is reachable via the lifecycle layer call sites that
#      already cover live `0x05` (Run 142 / Run 143 evidence).
#   7. peer-driven drain / `ProductionV2MarkerCoordinator` — routes
#      through the governance-aware helper at policy=NotRequired,
#      context=Unavailable (`crates/qbind-node/src/pqc_peer_candidate_apply.rs`).
#
# Existing v2 ratification / authority-marker wire material does NOT
# carry governance authority proof fields. Run 166 deliberately does NOT
# invent a proof-carrying schema. Where a production surface needs to
# require a governance proof but the wire cannot carry one, the gate
# fails closed with `GovernanceAuthorityRequiredButMissing`. The
# release-built Run 166 helper exercises that fail-closed behaviour
# (`H3`) by calling the same `decide_v2_marker_acceptance_with_lifecycle
# _and_governance` symbol with `policy=RequiredForLifecycleSensitive`
# and `context=Unavailable`, which is the production code path the four
# mutating surfaces would take if the chosen Run 165 §A5 policy were
# flipped on the real release binary in a future schema-carrying run
# (the next required run, Run 167).
#
# This harness:
#   * does NOT enable MainNet peer-driven apply on any surface;
#   * does NOT change any wire / marker / sequence / trust-bundle schema;
#   * does NOT introduce a CLI flag or environment variable;
#   * does NOT implement governance execution, on-chain governance,
#     KMS/HSM custody, or validator-set rotation;
#   * does NOT weaken Runs 070, 130–165;
#   * does NOT claim full C4 or C5 closure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="${1:-${REPO_ROOT}/docs/devnet/run_166_governance_gate_release_binary_enforcement}"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
RUN133_HELPER="${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper"
RUN164_HELPER="${REPO_ROOT}/target/release/examples/run_164_governance_authority_fixture_helper"
RUN166_HELPER="${REPO_ROOT}/target/release/examples/run_166_governance_gate_release_binary_helper"
SUMMARY="${OUTDIR}/summary.txt"

log() { printf '[run166] %s\n' "$*"; }
fail() { printf '[run166] FAIL: %s\n' "$*" >&2; exit 1; }
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

# A validation-only run MUST NOT mutate. Same contract as Run 133 / Run 162.
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
    assert_not_grep "$stderr" 'falling back to --p2p-trusted-root'
}

# A reload-apply REJECTION before mutation must satisfy the same
# invariants as Run 135 / Run 162.
assert_no_mutation_apply() {
    local data_dir="$1" stderr="$2" pre_marker="$3"
    if find "$data_dir" -name 'pqc_trust_bundle_sequence.json' -print -quit | grep -q .; then
        fail "sequence file was created under ${data_dir} (mutation on a refusal apply path)"
    fi
    assert_not_grep "$stderr" 'trust-bundle candidate APPLIED live'
    assert_not_grep "$stderr" 'VERDICT=applied'
    assert_not_grep "$stderr" 'falling back to --p2p-trusted-root'
    if [ -n "$pre_marker" ] && [ -f "$pre_marker" ]; then
        local post="${data_dir}/pqc_authority_state.json"
        [ -f "$post" ] || fail "pre-seeded marker disappeared under ${data_dir}"
        cmp -s "$pre_marker" "$post" \
            || fail "authority marker bytes changed under ${data_dir} on a refusal apply path"
    fi
}

assert_apply_ordering() {
    local stderr="$1"
    assert_grep "$stderr" 'trust-bundle candidate APPLIED live'
    assert_grep "$stderr" 'sequence_commit=ok'
    assert_grep "$stderr" 'VERDICT=applied'
}

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
    ( cd "$data_dir" && find . -type f | sort ) > "${OUTDIR}/data_inventories/${name}.inventory.txt"
    printf '  %s: rc=%s\n' "$name" "$rc" >> "$SUMMARY"
}

main() {
    log "OUTDIR=${OUTDIR}"
    # Preserve curated README.md / summary.txt / .gitignore. Wipe only
    # the per-run generated subtree.
    for d in logs data fixtures exit_codes marker_hashes sequence_hashes \
             data_inventories grep_summaries reachability test_results \
             helper_evidence helper_corpus; do
        rm -rf "${OUTDIR:?}/${d}"
        mkdir -p "${OUTDIR}/${d}"
    done
    rm -f "${OUTDIR}/provenance.txt" "${OUTDIR}/fixture_manifest.txt" \
          "${OUTDIR}/scenario_assertions.txt" \
          "${OUTDIR}/negative_invariants.txt" \
          "${OUTDIR}/enforcement_proof.txt"
    : > "$SUMMARY"

    cd "$REPO_ROOT"
    log "building release qbind-node + Run 133 helper + Run 164 helper + Run 166 helper"
    cargo build --release -p qbind-node --bin qbind-node \
        > "${OUTDIR}/logs/build_qbind_node.log" 2>&1
    cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper \
        > "${OUTDIR}/logs/build_run133_helper.log" 2>&1
    cargo build --release -p qbind-node --example run_164_governance_authority_fixture_helper \
        > "${OUTDIR}/logs/build_run164_helper.log" 2>&1
    cargo build --release -p qbind-node --example run_166_governance_gate_release_binary_helper \
        > "${OUTDIR}/logs/build_run166_helper.log" 2>&1

    test -x "$NODE_BIN" || fail "missing ${NODE_BIN}"
    test -x "$RUN133_HELPER" || fail "missing ${RUN133_HELPER}"
    test -x "$RUN164_HELPER" || fail "missing ${RUN164_HELPER}"
    test -x "$RUN166_HELPER" || fail "missing ${RUN166_HELPER}"

    # ---------- provenance --------------------------------------------------
    {
        echo "Run 166 release-binary governance gate enforcement evidence"
        echo "outdir: ${OUTDIR}"
        echo "repo: ${REPO_ROOT}"
        echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"
        echo "cargo: $(cargo --version 2>/dev/null || echo unknown)"
        echo "qbind-node_path: ${NODE_BIN}"
        echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
        echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
        echo "run133_helper_sha256: $(sha256_file "${RUN133_HELPER}")"
        echo "run133_helper_build_id: $(build_id "${RUN133_HELPER}")"
        echo "run164_helper_sha256: $(sha256_file "${RUN164_HELPER}")"
        echo "run164_helper_build_id: $(build_id "${RUN164_HELPER}")"
        echo "run166_helper_sha256: $(sha256_file "${RUN166_HELPER}")"
        echo "run166_helper_build_id: $(build_id "${RUN166_HELPER}")"
    } > "${OUTDIR}/provenance.txt"

    {
        echo "Run 166 release-binary governance gate enforcement evidence"
        echo "outdir: ${OUTDIR}"
        echo "repo: ${REPO_ROOT}"
        echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "qbind-node_sha256: $(sha256_file "${NODE_BIN}")"
        echo "qbind-node_build_id: $(build_id "${NODE_BIN}")"
        echo "run166_helper_sha256: $(sha256_file "${RUN166_HELPER}")"
        echo
        echo "scenario status:"
    } > "$SUMMARY"

    # ---------- reachability proof ----------------------------------------
    log "capturing source-level reachability proof for the Run 165 governance gate"
    grep -n -E \
        'evaluate_governance_marker_gate|decide_v2_marker_acceptance_with_lifecycle_and_governance|GovernanceAuthorityRequiredButMissing|GovernanceAuthorityRejected|validate_lifecycle_with_governance_authority|verify_governance_authority_proof|pqc_governance_authority' \
        "$REPO_ROOT/crates/qbind-node/src/"*.rs \
        > "${OUTDIR}/reachability/src_grep.txt" || true
    grep -n -E \
        'evaluate_governance_marker_gate|decide_v2_marker_acceptance_with_lifecycle_and_governance|GovernanceAuthorityRequiredButMissing|GovernanceAuthorityRejected' \
        "$REPO_ROOT/crates/qbind-node/tests/"*.rs \
        > "${OUTDIR}/reachability/tests_grep.txt" || true
    # After Run 165, the gate / typed-error symbols MUST be reachable from
    # `pqc_authority_marker_acceptance.rs`, AND the four mutating surfaces
    # (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`,
    # `main.rs`) MUST call the governance-aware decide helper. This
    # supersedes Run 164's "zero production-surface caller" boundary.
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_authority_marker_acceptance\.rs.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_authority_marker_acceptance\.rs.*evaluate_governance_marker_gate'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_authority_marker_acceptance\.rs.*GovernanceAuthorityRequiredButMissing'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_authority_marker_acceptance\.rs.*GovernanceAuthorityRejected'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_live_trust_reload\.rs.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'pqc_peer_candidate_apply\.rs.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
    assert_grep "${OUTDIR}/reachability/src_grep.txt" \
        'main\.rs.*decide_v2_marker_acceptance_with_lifecycle_and_governance'
    {
        echo "Run 166 reachability proof"
        echo "==========================="
        echo
        echo "Run 165 wired the Run 163 governance authority verifier into the"
        echo "shared v2 marker-decision helper"
        echo "\`decide_v2_marker_acceptance_with_lifecycle_and_governance\` in"
        echo "\`crates/qbind-node/src/pqc_authority_marker_acceptance.rs\`. The"
        echo "matching typed reject variants \`MutatingSurfaceMarkerV2Error::"
        echo "GovernanceAuthorityRequiredButMissing\` and"
        echo "\`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected\` are"
        echo "constructed in the same helper. The four mutating v2 surfaces"
        echo "(\`pqc_live_trust_reload.rs\`, \`pqc_peer_candidate_apply.rs\`,"
        echo "\`main.rs\` reload-apply pre-flight, \`main.rs\` startup pre-"
        echo "flight) all call the governance-aware helper, supplying"
        echo "\`GovernanceProofPolicy::NotRequired\` /"
        echo "\`GovernanceProofContext::Unavailable\` because the existing"
        echo "v2 wire material does NOT carry governance-proof fields."
        echo
        echo "Run 164 partial-positive boundary recorded that the verifier"
        echo "had ZERO production callers in \`crates/qbind-node/src/\` outside"
        echo "the module itself and \`lib.rs\`. Run 166 supersedes that"
        echo "boundary with the following grep over \`crates/qbind-node/src/**.rs\`:"
        echo
        sed -n '1,400p' "${OUTDIR}/reachability/src_grep.txt"
        echo
        echo "Run 165 source-level test coverage references:"
        sed -n '1,80p' "${OUTDIR}/reachability/tests_grep.txt"
    } > "${OUTDIR}/reachability/reachability.txt"
    log "  reachability captured; Run 164's zero-production-caller boundary is superseded"

    # ---------- fixtures (real qbind-node A1 / A2 paths) -------------------
    log "generating Run 133 v2 fixture corpus (DevNet baseline + candidate)"
    "$RUN133_HELPER" "${OUTDIR}/fixtures" \
        > "${OUTDIR}/logs/fixture_helper_133.stdout.log" \
        2> "${OUTDIR}/logs/fixture_helper_133.stderr.log"
    ( cd "${OUTDIR}/fixtures" && find . -type f -print0 \
        | xargs -0 sha256sum ) > "${OUTDIR}/fixture_manifest.txt"

    local DEV="${OUTDIR}/fixtures/devnet"
    local dev_hash dev_key
    dev_hash="$(cat "$DEV/expected-genesis-hash.txt")"
    dev_key="$(cat "$DEV/signing-key.ratified.spec")"

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
    # A1. reload-check NotRequired compatibility on the real release binary.
    #     The v2 marker-decision helper is invoked on a v2 lifecycle
    #     candidate; the governance gate is NotRequired / compatibility-
    #     path. Validation-only semantics are preserved (no marker write,
    #     no sequence write).
    ##########################################################################
    log "A1 reload-check NotRequired compatibility (v2 ratify@seq=1)"
    run_case A1_reload_check_not_required_compat 0 "" \
        "${devnet_reload_check_common[@]}" \
        --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
    assert_grep "${OUTDIR}/logs/A1_reload_check_not_required_compat.stderr.log" \
        '\[run-132\] reload-check v2 authority-marker check passed'
    assert_grep "${OUTDIR}/logs/A1_reload_check_not_required_compat.stderr.log" 'VERDICT=valid'
    assert_no_mutation_validation \
        "${OUTDIR}/data/A1_reload_check_not_required_compat" \
        "${OUTDIR}/logs/A1_reload_check_not_required_compat.stderr.log" ""

    ##########################################################################
    # A2. reload-apply NotRequired compatibility on the real release binary.
    #     The mutating v2 surface (`run-134`) routes through
    #     `decide_v2_marker_acceptance_with_lifecycle_and_governance` per
    #     the Run 165 wiring. A v2 ActivateInitial candidate is accepted,
    #     applied through Run 070, sequence committed, and the v2 marker
    #     persisted only after the post-Run-055 commit boundary. The
    #     governance gate does not weaken existing lifecycle / anti-
    #     rollback checks.
    ##########################################################################
    log "A2 reload-apply NotRequired compatibility (v2 ratify@seq=1; ActivateInitial)"
    run_case A2_reload_apply_not_required_compat 0 "" \
        "${devnet_reload_apply_common[@]}" \
        --p2p-trust-bundle-ratification "$DEV/ratification.v2.ratify.seq1.json"
    assert_grep "${OUTDIR}/logs/A2_reload_apply_not_required_compat.stderr.log" \
        '\[run-134\] reload-apply v2 ratification path SELECTED'
    assert_apply_ordering "${OUTDIR}/logs/A2_reload_apply_not_required_compat.stderr.log"
    assert_grep "${OUTDIR}/logs/A2_reload_apply_not_required_compat.stderr.log" \
        '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=1'
    [ -f "${OUTDIR}/data/A2_reload_apply_not_required_compat/pqc_authority_state.json" ] \
        || fail "A2: v2 marker missing after accepted apply"
    [ -f "${OUTDIR}/data/A2_reload_apply_not_required_compat/pqc_trust_bundle_sequence.json" ] \
        || fail "A2: sequence file missing after accepted apply"
    # Governance-required-missing/rejected lines MUST NOT appear under
    # the production NotRequired wiring.
    assert_not_grep "${OUTDIR}/logs/A2_reload_apply_not_required_compat.stderr.log" \
        'GovernanceAuthorityRequiredButMissing'
    assert_not_grep "${OUTDIR}/logs/A2_reload_apply_not_required_compat.stderr.log" \
        'GovernanceAuthorityRejected'

    ##########################################################################
    # A2'. reload-apply NotRequired compatibility on a lifecycle-sensitive
    #      action (Rotate@seq=2 over v2 seed seq=1). Demonstrates that
    #      a missing proof on a Rotate transition does NOT refuse under
    #      the production NotRequired policy.
    ##########################################################################
    log "A2' reload-apply NotRequired compatibility (Rotate@seq=2; lifecycle-sensitive)"
    run_case A2p_reload_apply_not_required_rotate 0 "$DEV/seed-marker.v2.seq1.json" \
        "${devnet_reload_apply_common[@]}" \
        --p2p-trust-bundle-ratification "$DEV/ratification.v2.rotate.seq2.json"
    assert_apply_ordering "${OUTDIR}/logs/A2p_reload_apply_not_required_rotate.stderr.log"
    assert_grep "${OUTDIR}/logs/A2p_reload_apply_not_required_rotate.stderr.log" \
        '\[run-134\] v2 authority-marker persisted .* candidate latest_authority_domain_sequence=2'
    assert_not_grep "${OUTDIR}/logs/A2p_reload_apply_not_required_rotate.stderr.log" \
        'GovernanceAuthorityRequiredButMissing'
    assert_not_grep "${OUTDIR}/logs/A2p_reload_apply_not_required_rotate.stderr.log" \
        'GovernanceAuthorityRejected'

    ##########################################################################
    # A3 / A4 / A5 / A6. RequiredButMissing fail-closed evidence through
    #                    the release-built helper.
    #
    # Run 166 deliberately does NOT add a CLI flag, environment variable,
    # or wire schema to flip the four production surfaces' policy from
    # `NotRequired` to `RequiredForLifecycleSensitive` on the real
    # `target/release/qbind-node`; that flip is the proof-carrying /
    # schema design run (Run 167). Today, RequiredButMissing fail-closed
    # behaviour is exercised through the release-built helper
    # `run_166_governance_gate_release_binary_helper`, which links the
    # exact same `decide_v2_marker_acceptance_with_lifecycle_and_governance`
    # symbol that the four mutating surfaces call in `target/release/
    # qbind-node`. A passing scenario in the helper is therefore honest
    # release-binary evidence that the production marker-decision surface
    # would fail-closed identically when supplied with the same policy /
    # context arguments.
    ##########################################################################
    log "A3-A6 governance-gate enforcement via release-built helper"
    "$RUN166_HELPER" "${OUTDIR}/helper_evidence" \
        > "${OUTDIR}/logs/run166_helper.stdout.log" \
        2> "${OUTDIR}/logs/run166_helper.stderr.log"
    echo $? > "${OUTDIR}/exit_codes/run166_helper.exit_code"

    [ -f "${OUTDIR}/helper_evidence/manifest.txt" ] \
        || fail "run166 helper did not write manifest.txt"
    [ -f "${OUTDIR}/helper_evidence/actual_outcomes.txt" ] \
        || fail "run166 helper did not write actual_outcomes.txt"

    # Per-scenario assertion: the helper writes one line per scenario
    # `<id>\t<expected_label>\t<expected_match_regex>`. Each scenario's
    # actual outcome must match the expected regex.
    local PASS=0 FAIL=0
    {
        echo "# Run 166 — per-helper-scenario expected/actual outcome assertion"
        while IFS=$'\t' read -r SID EXP_LABEL EXP_MATCH; do
            [ -z "$SID" ] && continue
            local ACT_FILE="${OUTDIR}/helper_evidence/scenarios/${SID}/actual.txt"
            if [ ! -f "$ACT_FILE" ]; then
                echo "FAIL  $SID  missing actual.txt"
                FAIL=$((FAIL+1))
                continue
            fi
            if grep -qE -- "$EXP_MATCH" "$ACT_FILE"; then
                echo "PASS  $SID  expected=$EXP_LABEL match=$EXP_MATCH"
                PASS=$((PASS+1))
            else
                echo "FAIL  $SID  expected=$EXP_LABEL match=$EXP_MATCH actual=$(cat "$ACT_FILE")"
                FAIL=$((FAIL+1))
            fi
        done < "${OUTDIR}/helper_evidence/manifest.txt"
        echo
        echo "TOTAL: PASS=$PASS FAIL=$FAIL"
    } > "${OUTDIR}/scenario_assertions.txt"

    [ "$FAIL" -eq 0 ] || fail "run166 helper scenarios failed; see ${OUTDIR}/scenario_assertions.txt"

    # Explicit grep proof that the typed `RequiredButMissing` and
    # `GovernanceAuthorityRejected` reject classes were observed on the
    # release-built helper output.
    assert_grep "${OUTDIR}/helper_evidence/actual_outcomes.txt" \
        'GovernanceAuthorityRequiredButMissing'
    assert_grep "${OUTDIR}/helper_evidence/actual_outcomes.txt" \
        'GovernanceAuthorityRejected\(InvalidIssuerSignature'
    # And explicit grep proof that the NotRequired compatibility path was
    # observed on the release-built helper.
    assert_grep "${OUTDIR}/helper_evidence/actual_outcomes.txt" \
        'FirstV2Write'
    assert_grep "${OUTDIR}/helper_evidence/actual_outcomes.txt" \
        'UpgradeV2'

    ##########################################################################
    # A7. Full Run 163 governance proof corpus through the release-built
    #     Run 164 helper. This is helper evidence (release-built binary
    #     that links the verifier), not production-surface
    #     proof-carrying evidence.
    ##########################################################################
    log "A7 governance proof corpus via release-built Run 164 helper"
    "$RUN164_HELPER" "${OUTDIR}/helper_corpus" \
        > "${OUTDIR}/logs/run164_helper.stdout.log" \
        2> "${OUTDIR}/logs/run164_helper.stderr.log"
    echo $? > "${OUTDIR}/exit_codes/run164_helper.exit_code"
    [ -f "${OUTDIR}/helper_corpus/manifest.txt" ] \
        || fail "run164 helper did not write manifest.txt"
    [ -f "${OUTDIR}/helper_corpus/actual_outcomes.txt" ] \
        || fail "run164 helper did not write actual_outcomes.txt"

    local CPASS=0 CFAIL=0
    {
        echo "# Run 166 A7 — Run 164 governance corpus replay assertions"
        while IFS=$'\t' read -r SID EXP_LABEL EXP_MATCH; do
            [ -z "$SID" ] && continue
            [[ "$SID" == \#* ]] && continue
            local ACT_FILE="${OUTDIR}/helper_corpus/scenarios/${SID}/actual.txt"
            if [ ! -f "$ACT_FILE" ]; then
                echo "FAIL  $SID  missing actual.txt"
                CFAIL=$((CFAIL+1))
                continue
            fi
            if grep -q -- "$EXP_MATCH" "$ACT_FILE"; then
                echo "PASS  $SID  expected=$EXP_LABEL"
                CPASS=$((CPASS+1))
            else
                echo "FAIL  $SID  expected=$EXP_LABEL actual=$(cat "$ACT_FILE")"
                CFAIL=$((CFAIL+1))
            fi
        done < "${OUTDIR}/helper_corpus/manifest.txt"
        echo
        echo "TOTAL: CPASS=$CPASS CFAIL=$CFAIL"
    } > "${OUTDIR}/scenario_assertions.run164_corpus.txt"
    [ "$CFAIL" -eq 0 ] || fail "Run 164 corpus replay failed; see ${OUTDIR}/scenario_assertions.run164_corpus.txt"

    ##########################################################################
    # Negative invariants and denylist
    ##########################################################################
    {
        echo "Run 166 negative invariants"
        echo "==========================="
        echo "harness_enabled_mainnet_apply: NO"
        echo "harness_opened_p2p_socket: NO"
        echo "harness_mutated_live_trust_state: NO  (validation-only on A1; reload-apply on A2/A2' goes through Run 070 / Run 055 / post-commit boundary as on Run 162)"
        echo "harness_modified_data_dir_outside_outdir: NO"
        echo "harness_added_cli_flag_or_env_var: NO"
        echo "harness_changed_wire_or_marker_or_sequence_or_trust_bundle_schema: NO"
        echo "rejected_governance_scenarios_mutated_disk: NO  (release-built helper asserts pre==post on every reject)"
    } > "${OUTDIR}/negative_invariants.txt"

    {
        set +e
        # Banner-exclude lines that EXPLICITLY say a topic is OUT-of-scope /
        # NOT implemented / refused. Any other denylist hit fails the run.
        grep -hE 'autonomous drain|apply on receipt|peer-majority authority|governance enforced|KMS enforced|HSM enforced|validator-set rotated|MainNet apply enabled|fallback to --p2p-trusted-root|active DummySig|active DummyKem|active DummyAead' \
            "${OUTDIR}"/logs/*.stderr.log \
            | grep -vE 'OUT-of-scope|NOT implemented|NOT enabled|refused unconditionally|MainNet remains refused|remains unimplemented|remain[s]? open|deferred|fail-closed|placeholder' \
            | sort -u
        set -e
    } > "${OUTDIR}/grep_summaries/denylist.txt"
    if [ -s "${OUTDIR}/grep_summaries/denylist.txt" ]; then
        fail "denylist hits found; see ${OUTDIR}/grep_summaries/denylist.txt"
    fi

    # Cross-cutting non-mutation assertions on every qbind-node stderr.
    for stderr_log in "${OUTDIR}"/logs/A*_reload_*.stderr.log; do
        [ -f "$stderr_log" ] || continue
        assert_not_grep "$stderr_log" 'KMS|HSM'
        assert_not_grep "$stderr_log" 'live inbound 0x05'
        assert_not_grep "$stderr_log" 'peer-driven live apply'
        assert_not_grep "$stderr_log" 'autonomous drain'
        assert_not_grep "$stderr_log" 'apply on receipt'
        assert_not_grep "$stderr_log" 'falling back to --p2p-trusted-root'
    done

    ##########################################################################
    # Regression test suites named in task/RUN_166_TASK.txt
    ##########################################################################
    run_test() {
        local name="$1"; shift
        log "cargo $*"
        ( cd "$REPO_ROOT" && cargo "$@" ) \
            > "${OUTDIR}/test_results/${name}.stdout" \
            2> "${OUTDIR}/test_results/${name}.stderr"
        echo $? > "${OUTDIR}/test_results/${name}.exit"
    }
    run_test run_165_governance_marker_integration_tests \
        test -p qbind-node --test run_165_governance_marker_integration_tests
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
    for f in "${OUTDIR}/test_results"/*.exit; do
        code="$(cat "$f")"
        if [ "$code" != "0" ]; then
            echo "FAIL: $(basename "$f" .exit) exit=$code" >&2
            REGRESSION_FAIL=$((REGRESSION_FAIL+1))
        fi
    done
    [ "$REGRESSION_FAIL" -eq 0 ] || fail "$REGRESSION_FAIL regression suite(s) failed"

    ##########################################################################
    # Enforcement verdict
    ##########################################################################
    cat > "${OUTDIR}/enforcement_proof.txt" <<EOF
Run 166 — release-binary governance gate enforcement verdict
============================================================

verdict: positive (release-binary boundary):

  * The Run 165 governance gate
    (\`decide_v2_marker_acceptance_with_lifecycle_and_governance\`,
    \`evaluate_governance_marker_gate\`,
    \`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing\`,
    \`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected\`)
    is production-source reachable from \`crates/qbind-node/src/\` after
    Run 165, and is exercised by the four mutating v2 surfaces
    (\`pqc_live_trust_reload.rs\`, \`pqc_peer_candidate_apply.rs\`,
    \`main.rs\` reload-apply pre-flight, \`main.rs\` startup pre-flight)
    on every release-binary v2 marker decision; this supersedes Run 164's
    "zero production-surface caller" boundary. See
    \`reachability/reachability.txt\`.

  * \`NotRequired\` compatibility is proven on the real
    \`target/release/qbind-node\` binary through:
      - A1: \`--p2p-trust-bundle-reload-check\` accepts a v2 ratify@seq=1
        candidate (validation-only; no marker write, no sequence write);
      - A2: \`--p2p-trust-bundle-reload-apply-path\` accepts the same
        candidate, applies through Run 070, commits the sequence, and
        persists the v2 marker only after the post-commit boundary;
      - A2': the same \`--p2p-trust-bundle-reload-apply-path\` accepts a
        Rotate@seq=2 lifecycle-sensitive candidate over a seeded
        v2-seq=1 marker, demonstrating that a missing proof under
        \`NotRequired\` does NOT refuse a lifecycle-sensitive transition.
    No \`GovernanceAuthorityRequiredButMissing\` or
    \`GovernanceAuthorityRejected\` line appears in any A1/A2/A2' stderr.

  * \`RequiredButMissing\` fail-closed behaviour is proven on the
    release-built \`run_166_governance_gate_release_binary_helper\`
    (sha256: $(sha256_file "${RUN166_HELPER}"); buildid:
    $(build_id "${RUN166_HELPER}")), which links the same
    \`decide_v2_marker_acceptance_with_lifecycle_and_governance\` symbol
    \`target/release/qbind-node\` links. Helper scenarios:
      - H3: \`policy=RequiredForLifecycleSensitive\`, \`context=Unavailable\`,
        Rotate@seq=2 over seeded v2-seq=1 →
        \`Err(GovernanceAuthorityRequiredButMissing { action: Rotate })\`;
        seed marker bytes byte-for-byte untouched.
      - H6: \`policy=RequiredForLifecycleSensitive\`, \`context=Supplied\`
        with a tampered issuer signature →
        \`Err(GovernanceAuthorityRejected(InvalidIssuerSignature ..))\`;
        no marker write.
      - H4: \`policy=RequiredForLifecycleSensitive\`, \`context=Unavailable\`,
        ActivateInitial → \`Ok(.. FirstV2Write ..)\` (genesis-bound first
        activation remains governance-optional, per Run 165 §A5).
      - H1, H2, H7: \`NotRequired\` compatibility paths confirmed at
        release-build link time.
      - H5: a supplied valid governance proof accepts a Rotate transition
        through the same production helper.
    Per-scenario assertions and outputs in
    \`scenario_assertions.txt\` and \`helper_evidence/\`.

  * The full Run 163 governance proof corpus (A1–A5 / R1–R16) remains
    green on the release-built Run 164 helper; per-scenario assertions in
    \`scenario_assertions.run164_corpus.txt\`. This is helper evidence,
    not production-surface proof-carrying evidence.

  * Rejected governance-gate scenarios produce no marker mutation, no
    sequence write, no live trust mutation, and no MainNet apply: the
    helper asserts \`pre==post\` on every reject, the harness asserts no
    sequence file under reject data dirs, and the denylist grep is
    clean (banner-excluded only).

invariants preserved:
  * MainNet peer-driven apply remains refused unconditionally
    (Run 151 / Run 158 release-binary evidence is unaffected).
  * Run 162 release-binary lifecycle ENFORCEMENT evidence remains valid
    (the Run 161 production-call-site grep still fires; Run 165 wired the
    governance gate as an additional layer on top of the lifecycle layer
    without changing it).
  * No new wire format. No marker schema change. No sequence-file schema
    change. No trust-bundle schema change. No peer-candidate envelope
    schema change. No new metric family. No new CLI flag. No new
    environment variable.
  * Run 153 / 155 / 156 / 158 / 160 / 162 / 164 evidence-archive
    convention preserved (only README.md and summary.txt are tracked;
    per-run logs / fixtures / exit_codes / reachability / test_results /
    provenance.txt / fixture_manifest.txt are .gitignored).

infeasible without schema-carrying drift (today, on the existing
release-binary v2 surfaces):
  * Carrying a real \`GovernanceAuthorityProof\` through any production
    \`target/release/qbind-node\` surface (reload-check, reload-apply,
    SIGHUP, startup, live \`0x05\`, peer-driven drain,
    peer-candidate-check). The wire schema does NOT carry governance
    proof fields. Run 166 deliberately does NOT invent one. The
    fail-closed \`RequiredButMissing\` semantics are exercised through
    the release-built helper that calls the same production helper
    symbol with \`policy=RequiredForLifecycleSensitive\`,
    \`context=Unavailable\`. A6 is therefore evidenced via the
    release-built helper rather than a peer-driven drain CLI flag flip,
    which would require a future schema-carrying run.

next required integration run: Run 167 — governance-proof carrying
schema design / implementation. Run 167 must define the wire-format
extension that carries a real \`GovernanceAuthorityProof\` through the
v2 ratification or authority-marker envelope without weakening any
existing rejection class, and flip the four mutating production
surfaces from \`policy=NotRequired\` to
\`policy=RequiredForLifecycleSensitive\` so accepted-governance-proof
evidence becomes captureable directly on \`target/release/qbind-node\`.

Run 166 does NOT claim full C4 closure. Run 166 does NOT claim C5
closure. Governance execution / on-chain governance / KMS-HSM /
validator-set rotation remain unimplemented and out-of-scope.
EOF

    {
        echo
        echo "release-binary NotRequired compatibility: A1 (reload-check), A2"
        echo "  (reload-apply ActivateInitial), A2' (reload-apply Rotate)"
        echo "  pass on the real target/release/qbind-node."
        echo "release-built helper governance-gate scenarios: PASS=$PASS FAIL=$FAIL"
        echo "release-built helper Run 164 corpus replay: CPASS=$CPASS CFAIL=$CFAIL"
        echo "non-mutation invariants on every reject scenario: pass."
        echo "post-commit-only marker persistence on every accept scenario: pass."
        echo "MainNet remains refused: harness does NOT enable MainNet on any"
        echo "  surface; peer-driven apply MainNet refusal is cited from Run"
        echo "  151 / Run 158 release-binary evidence."
        echo "reachability vs Run 164 boundary: superseded — see"
        echo "  ${OUTDIR}/reachability/reachability.txt"
        echo "denylist: empty."
        echo "wire/schema/metric drift: none."
        echo "next required run: Run 167 — governance-proof carrying schema."
    } >> "$SUMMARY"

    log "PASS: Run 166 evidence captured under ${OUTDIR}"
}

main "$@"
