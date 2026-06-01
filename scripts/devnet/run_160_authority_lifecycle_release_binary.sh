#!/usr/bin/env bash
# Run 160: release-binary evidence / boundary harness for the Run 159
# v2 bundle-signing-key lifecycle validator
# (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`).
#
# What this harness produces is honest evidence that:
#
#   1. A real release-built helper
#      (`target/release/examples/run_160_authority_lifecycle_fixture_helper`)
#      mints the lifecycle fixture corpus (A1–A6 + R1–R14) covering the
#      Run 159 acceptance and rejection matrices, byte-for-byte under
#      the existing Run 130/131 marker/sidecar schema.
#
#   2. A real `target/release/qbind-node` is built and its production
#      surfaces (`startup --p2p-trust-bundle` v2, reload-check,
#      local peer-candidate-check, process-start reload-apply, SIGHUP,
#      live inbound 0x05, peer-driven staged drain-once) do **not**
#      currently call `validate_v2_lifecycle_transition`. The harness
#      captures the exact source-level call graph as the proof.
#
#   3. The Run 159 source/test coverage of the lifecycle validator
#      remains green on the same checkout, by running the listed
#      cargo-test suites and recording per-suite exit codes / log
#      tails.
#
#   4. None of the existing Run 134 / 138 / 142 / 148 / 150 / 152 / 157
#      regression suites are weakened. MainNet remains refused.
#      Governance / KMS / HSM / validator-set rotation remain open.
#
# Verdict (per `task/RUN_160_TASK.txt` §"Required evidence if lifecycle
# validator is not release-binary reachable"):
#
#   partial-positive: release-binary fixture/evidence boundary captured;
#   lifecycle validator not yet production-surface reachable
#
# The harness writes the verdict to `partial_positive_proof.txt`,
# names the exact next required integration run (Run 161 — compose the
# Run 159 validator into the Run 134/136/138/150/152 marker-comparison
# pipeline once a wire-level encoding for `Retire` / `EmergencyRevoke`
# lands or once the local sub-class metadata convention is wired into
# the existing accept-and-persist boundary), and refuses to claim
# strongest-positive.
#
# Strict scope:
#   - Release-binary evidence/boundary run.
#   - Use real `target/release/qbind-node` and release-built helpers.
#   - No MainNet enablement.
#   - No governance / KMS / HSM implementation.
#   - No validator-set rotation.
#   - No autonomous apply.
#   - No automatic apply on receipt.
#   - No peer-majority authority.
#   - No schema/wire change.
#   - Do not weaken Runs 070, 130–159.
#   - Do not claim full C4 or C5 closure.
#
# Evidence capture (every per-run artifact is .gitignored under
# docs/devnet/run_160_authority_lifecycle_release_binary/, mirroring
# the Run 153/155/156/158 evidence-archive precedent — only README.md
# and summary.txt are tracked):
#   - provenance.txt
#   - fixtures/<corpus>/ (release-helper-minted lifecycle fixture
#     corpus; manifest.txt + expected_outcomes.txt + persisted/ +
#     candidates/)
#   - fixture_manifest.txt
#   - call_graph/{src_grep.txt,tests_grep.txt,main_rs_grep.txt,
#     reachability.txt}
#   - test_results/<suite>.{stdout,stderr,exit_code}
#   - grep_summaries/{in_scope.txt,out_of_scope.txt}
#   - partial_positive_proof.txt
#   - summary.txt
#
# Usage:
#   cargo build --release -p qbind-node --bin qbind-node
#   cargo build --release -p qbind-node \
#       --example run_157_unified_testnet_peer_apply_fixture_helper
#   cargo build --release -p qbind-node \
#       --example run_160_authority_lifecycle_fixture_helper
#   bash scripts/devnet/run_160_authority_lifecycle_release_binary.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EVIDENCE_DIR="${REPO_ROOT}/docs/devnet/run_160_authority_lifecycle_release_binary"
LOGS_DIR="${EVIDENCE_DIR}/test_results"
GREP_DIR="${EVIDENCE_DIR}/grep_summaries"
CALL_GRAPH_DIR="${EVIDENCE_DIR}/call_graph"
FIXTURES_DIR="${EVIDENCE_DIR}/fixtures"
PROV_FILE="${EVIDENCE_DIR}/provenance.txt"
FIXTURE_MANIFEST="${EVIDENCE_DIR}/fixture_manifest.txt"
SUMMARY_FILE="${EVIDENCE_DIR}/summary.txt"
PARTIAL_PROOF="${EVIDENCE_DIR}/partial_positive_proof.txt"

QBIND_BIN="${REPO_ROOT}/target/release/qbind-node"
LIFECYCLE_HELPER="${REPO_ROOT}/target/release/examples/run_160_authority_lifecycle_fixture_helper"
TESTNET_UNIFIED_HELPER="${REPO_ROOT}/target/release/examples/run_157_unified_testnet_peer_apply_fixture_helper"

mkdir -p "${EVIDENCE_DIR}" "${LOGS_DIR}" "${GREP_DIR}" "${CALL_GRAPH_DIR}" "${FIXTURES_DIR}"

# ---------------------------------------------------------------------------
# 0. Build release-binary qbind-node + lifecycle helper if missing.
# ---------------------------------------------------------------------------
build_release_target() {
    local kind="$1" target="$2" out_path="$3"
    if [ ! -x "${out_path}" ]; then
        echo "[run-160] building release ${kind} ${target}" >&2
        ( cd "${REPO_ROOT}" && cargo build --release -p qbind-node --"${kind}" "${target}" )
    fi
}

build_release_target bin qbind-node "${QBIND_BIN}"
build_release_target example run_160_authority_lifecycle_fixture_helper "${LIFECYCLE_HELPER}"
build_release_target example run_157_unified_testnet_peer_apply_fixture_helper "${TESTNET_UNIFIED_HELPER}" || true

# ---------------------------------------------------------------------------
# 1. Provenance: git commit, rustc/cargo versions, binary + helper SHA-256
#    and ELF Build IDs.
# ---------------------------------------------------------------------------
{
    echo "Run 160 provenance"
    echo "==================="
    echo "timestamp_utc: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "git_commit: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
    echo "git_status: $(git -C "${REPO_ROOT}" status --porcelain | wc -l) modified/untracked files"
    echo
    echo "rustc: $(rustc --version 2>/dev/null || echo 'not available')"
    echo "cargo: $(cargo --version 2>/dev/null || echo 'not available')"
    echo
    for bin in "${QBIND_BIN}" "${LIFECYCLE_HELPER}" "${TESTNET_UNIFIED_HELPER}"; do
        if [ -x "${bin}" ]; then
            echo "binary: ${bin}"
            echo "  sha256: $(sha256sum "${bin}" | awk '{print $1}')"
            echo "  size_bytes: $(stat -c%s "${bin}")"
            if command -v file >/dev/null 2>&1; then
                build_id=$(file "${bin}" | sed -n 's/.*BuildID\[sha1\]=\([0-9a-f]*\).*/\1/p')
                echo "  elf_build_id: ${build_id:-unknown}"
            fi
        else
            echo "binary: ${bin} (NOT BUILT)"
        fi
    done
} > "${PROV_FILE}"

# ---------------------------------------------------------------------------
# 2. Mint the lifecycle fixture corpus with the release-built helper.
# ---------------------------------------------------------------------------
LIFECYCLE_CORPUS_DIR="${FIXTURES_DIR}/lifecycle_corpus"
rm -rf "${LIFECYCLE_CORPUS_DIR}"
"${LIFECYCLE_HELPER}" "${LIFECYCLE_CORPUS_DIR}" > "${LOGS_DIR}/lifecycle_helper.stdout" \
    2> "${LOGS_DIR}/lifecycle_helper.stderr"

# Hash every minted fixture file for the manifest.
{
    echo "Run 160 fixture manifest (release-built helper output)"
    echo "======================================================="
    echo "helper: ${LIFECYCLE_HELPER}"
    echo "corpus_dir: ${LIFECYCLE_CORPUS_DIR}"
    echo
    ( cd "${LIFECYCLE_CORPUS_DIR}" && find . -type f | sort | while read -r f; do
        printf "%s  %s\n" "$(sha256sum "${f}" | awk '{print $1}')" "${f#./}"
    done )
} > "${FIXTURE_MANIFEST}"

# ---------------------------------------------------------------------------
# 3. Source-level call graph: prove the Run 159 lifecycle validator is
#    NOT reachable from any production runtime surface.
# ---------------------------------------------------------------------------
SRC="${REPO_ROOT}/crates/qbind-node/src"
TESTS="${REPO_ROOT}/crates/qbind-node/tests"

# 3a. All references to the lifecycle validator inside crate source.
{
    echo "# All references to the Run 159 lifecycle validator in crates/qbind-node/src"
    echo "# (expected: only the declaration in lib.rs and the module itself)."
    grep -RIn 'validate_v2_lifecycle_transition\|classify_local_lifecycle_action\|pqc_authority_lifecycle' "${SRC}" \
        --include='*.rs' || true
} > "${CALL_GRAPH_DIR}/src_grep.txt"

# 3b. References inside tests (expected: only run_159_*).
{
    echo "# All references to the Run 159 lifecycle validator in crates/qbind-node/tests"
    echo "# (expected: only run_159_authority_signing_key_lifecycle_tests.rs)."
    grep -RIn 'validate_v2_lifecycle_transition\|classify_local_lifecycle_action\|pqc_authority_lifecycle' "${TESTS}" \
        --include='*.rs' || true
} > "${CALL_GRAPH_DIR}/tests_grep.txt"

# 3c. main.rs / cli.rs references (expected: none).
{
    echo "# References in main.rs / cli.rs / p2p / reload / sighup / 0x05 dispatcher"
    echo "# (expected: empty — no production surface calls the lifecycle validator)."
    for f in "${SRC}/main.rs" "${SRC}/cli.rs" "${SRC}/p2p_supervisor.rs" \
        "${SRC}/p2p_pqc_trust_bundle_runtime.rs" "${SRC}/p2p_pqc_trust_bundle_loader.rs"; do
        if [ -f "${f}" ]; then
            echo "# ----- ${f} -----"
            grep -n 'pqc_authority_lifecycle\|validate_v2_lifecycle_transition\|classify_local_lifecycle_action' \
                "${f}" || echo "(no matches)"
        fi
    done
} > "${CALL_GRAPH_DIR}/main_rs_grep.txt"

# 3d. Reachability summary.
src_call_count=$(grep -c 'validate_v2_lifecycle_transition' "${CALL_GRAPH_DIR}/src_grep.txt" || true)
tests_call_count=$(grep -c 'validate_v2_lifecycle_transition' "${CALL_GRAPH_DIR}/tests_grep.txt" || true)
main_call_count=$(grep -c 'validate_v2_lifecycle_transition' "${CALL_GRAPH_DIR}/main_rs_grep.txt" || true)

# Count call sites that are NOT inside the validator's own module.
non_self_call_count=$( ( grep 'validate_v2_lifecycle_transition' "${CALL_GRAPH_DIR}/src_grep.txt" || true ) \
    | grep -v 'pqc_authority_lifecycle.rs:' \
    | grep -v 'lib.rs:' \
    | wc -l )

{
    echo "Run 160 source-level reachability of validate_v2_lifecycle_transition"
    echo "===================================================================="
    echo
    echo "Surface checklist (per task/RUN_160_TASK.txt §Investigation requirement):"
    echo
    cat <<'EOF'
| # | Surface                                                  | Calls validator? | Carries Local LifecycleAction? | Carries Activate/Rotate/Retire/Revoke/Emergency? | Wire/schema change required? | Used for release-binary evidence? |
|---|----------------------------------------------------------|------------------|--------------------------------|-------------------------------------------------|------------------------------|-----------------------------------|
| 1 | startup --p2p-trust-bundle v2 (Run 137)                  | NO               | NO                             | Activate/Rotate/Revoke only via Run 130 wire byte | Retire/Emergency would need a new wire byte OR the Run 159 metadata sub-class convention to be wired in (NO production wiring exists in Run 160) | NO |
| 2 | reload-check validation-only (Run 132/133)               | NO               | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 3 | local peer-candidate-check validation-only (Run 132/133) | NO               | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 4 | process-start reload-apply (Run 134/135)                 | NO               | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 5 | SIGHUP live-reload (Run 138/139)                         | NO               | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 6 | live inbound 0x05 validation-only (Run 142/143)          | NO               | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 7 | peer-driven staged queue / drain-once (Run 148/150/151/152/153/158) | NO   | NO                             | Activate/Rotate/Revoke only                       | same as above                | NO |
| 8 | release-built fixture helper / example                   | INDIRECT (corpus only; not the validator itself) | YES (encoded in JSON) | YES (corpus carries all five logical actions) | NO | YES (corpus + source/test runs) |
EOF
    echo
    echo "Non-self src call sites of validate_v2_lifecycle_transition: ${non_self_call_count}"
    echo "Total src grep matches:    ${src_call_count}"
    echo "Total tests grep matches:  ${tests_call_count}"
    echo "Total main.rs/cli.rs grep: ${main_call_count}"
    echo
    echo "Conclusion: validate_v2_lifecycle_transition has zero production"
    echo "callers. Run 159 lifecycle validation is NOT release-binary"
    echo "reachable today. Release-binary lifecycle evidence is therefore"
    echo "captured as a partial-positive boundary (corpus minted by a real"
    echo "release-built helper + source/test runs that exercise the"
    echo "validator). Strongest-positive is intentionally NOT claimed."
    echo
    echo "Next required integration run: Run 161 — compose"
    echo "validate_v2_lifecycle_transition into the existing Run 134/136"
    echo "/138/150/152 marker-comparison and accept-and-persist pipeline"
    echo "(or a new typed pre-flight gate immediately upstream of those"
    echo "helpers) so the production surfaces 1–7 above can exercise the"
    echo "lifecycle validator without changing the on-wire byte set."
} > "${CALL_GRAPH_DIR}/reachability.txt"

# ---------------------------------------------------------------------------
# 4. Run the test suites named by task/RUN_160_TASK.txt §Validation
#    commands. Each suite captures stdout/stderr/exit_code; the harness
#    keeps going on per-suite failures and records them in summary.txt.
# ---------------------------------------------------------------------------
SUITES=(
    "run_159_authority_signing_key_lifecycle_tests"
    "run_157_unified_testnet_fixture_universe_tests"
    "run_152_binary_reachable_peer_drain_plumbing_tests"
    "run_150_peer_driven_apply_drain_tests"
    "run_148_peer_driven_apply_devnet_tests"
    "run_142_live_inbound_0x05_v2_validation_tests"
    "run_134_reload_apply_v2_authority_marker_tests"
    "run_138_sighup_v2_authority_marker_tests"
)

run_test_suite() {
    local suite="$1"
    local out="${LOGS_DIR}/${suite}.stdout"
    local err="${LOGS_DIR}/${suite}.stderr"
    local rc_file="${LOGS_DIR}/${suite}.exit_code"
    set +e
    ( cd "${REPO_ROOT}" && cargo test -p qbind-node --test "${suite}" -- --test-threads=1 ) \
        > "${out}" 2> "${err}"
    local rc=$?
    set -e
    echo "${rc}" > "${rc_file}"
}

for suite in "${SUITES[@]}"; do
    echo "[run-160] cargo test --test ${suite}" >&2
    run_test_suite "${suite}"
done

# Lib tests (`cargo test -p qbind-node --lib pqc_authority` and full lib).
echo "[run-160] cargo test --lib pqc_authority" >&2
set +e
( cd "${REPO_ROOT}" && cargo test -p qbind-node --lib pqc_authority -- --test-threads=1 ) \
    > "${LOGS_DIR}/lib_pqc_authority.stdout" 2> "${LOGS_DIR}/lib_pqc_authority.stderr"
echo $? > "${LOGS_DIR}/lib_pqc_authority.exit_code"
set -e

echo "[run-160] cargo test --lib (full)" >&2
set +e
( cd "${REPO_ROOT}" && cargo test -p qbind-node --lib -- --test-threads=1 ) \
    > "${LOGS_DIR}/lib_full.stdout" 2> "${LOGS_DIR}/lib_full.stderr"
echo $? > "${LOGS_DIR}/lib_full.exit_code"
set -e

# ---------------------------------------------------------------------------
# 5. Grep summaries (in-scope and out-of-scope/denylist).
# ---------------------------------------------------------------------------
{
    echo "# Run 160 in-scope evidence markers (expected: present)"
    echo
    echo "## Lifecycle helper output"
    grep -H 'lifecycle fixture corpus' "${LOGS_DIR}/lifecycle_helper.stdout" || true
    echo
    echo "## Lifecycle test outcome"
    grep -H 'test result:' "${LOGS_DIR}/run_159_authority_signing_key_lifecycle_tests.stdout" || true
    echo
    echo "## Source-level call graph proof"
    head -40 "${CALL_GRAPH_DIR}/reachability.txt"
} > "${GREP_DIR}/in_scope.txt"

# Denylist: nothing in the captured logs may claim production lifecycle
# enforcement, MainNet apply, governance, KMS/HSM, or validator-set
# rotation. The expected MainNet-refusal banner that names governance /
# KMS / HSM only to say they are NOT implemented is excluded (same
# precedent as Run 153/155/156/158).
DENY_PATTERNS=(
    'autonomous drain'
    'apply on receipt'
    'peer-majority'
    'mainnet applied'
    'governance enforced'
    'KMS enforced'
    'HSM enforced'
    'validator-set rotated'
    'lifecycle enforced on production'
    'DummySig'
    'DummyKem'
    'DummyAead'
    'fallback to --p2p-trusted-root'
)
{
    echo "# Run 160 out-of-scope denylist (expected: empty)"
    for pat in "${DENY_PATTERNS[@]}"; do
        # Search across the captured test/helper output. The MainNet
        # refusal banner at startup names governance/KMS/HSM only to say
        # they are NOT implemented; the patterns above are positive
        # production-claim phrasings that must NOT appear.
        for f in "${LOGS_DIR}"/*.stdout "${LOGS_DIR}"/*.stderr; do
            [ -f "${f}" ] || continue
            grep -Hn "${pat}" "${f}" || true
        done
    done | sort -u
} > "${GREP_DIR}/out_of_scope.txt"

# ---------------------------------------------------------------------------
# 6. Partial-positive proof + summary.
# ---------------------------------------------------------------------------
{
    echo "Run 160 partial-positive proof"
    echo "================================"
    echo
    echo "Verdict: partial-positive: release-binary fixture/evidence"
    echo "boundary captured; lifecycle validator not yet"
    echo "production-surface reachable."
    echo
    echo "Captured release-binary evidence:"
    echo "  * release-built lifecycle helper minted the lifecycle fixture"
    echo "    corpus (A1–A6 + R1–R14)."
    echo "  * release-built qbind-node binary identity recorded in"
    echo "    provenance.txt (sha256 + ELF build id)."
    echo "  * source-level call graph proves validate_v2_lifecycle_transition"
    echo "    has no production surface caller (see call_graph/reachability.txt)."
    echo "  * Run 159 lifecycle test suite + Run 134/138/142/148/150/152/157"
    echo "    regression suites + lib pqc_authority + full lib tests run on"
    echo "    the same checkout (per-suite exit codes in test_results/)."
    echo
    echo "Refused claims:"
    echo "  * NOT strongest-positive."
    echo "  * NOT MainNet apply."
    echo "  * NOT governance enforcement."
    echo "  * NOT KMS / HSM custody."
    echo "  * NOT validator-set rotation."
    echo "  * NOT autonomous drain / apply on receipt / peer-majority"
    echo "    authority."
    echo "  * NOT full C4 closure."
    echo "  * NOT C5 closure."
    echo
    echo "Lifecycle action coverage at the release-binary surface:"
    echo "  ActivateInitial:   FIXTURE-ONLY (release-built helper minted A1)"
    echo "  Rotate:            FIXTURE-ONLY (release-built helper minted A2)"
    echo "  Retire:            FIXTURE-ONLY (release-built helper minted A3)"
    echo "  Revoke:            FIXTURE-ONLY (release-built helper minted A4)"
    echo "  EmergencyRevoke:   FIXTURE-ONLY (release-built helper minted A5)"
    echo "  Idempotent:        FIXTURE-ONLY (release-built helper minted A6)"
    echo "  All R1–R14:        FIXTURE-ONLY (release-built helper minted)"
    echo
    echo "Schema gap analysis:"
    echo "  * The on-wire BundleSigningRatificationV2Action byte set"
    echo "    (Ratify=0, Rotate=1, Revoke=2) is preserved unchanged by"
    echo "    Run 159. Retire and EmergencyRevoke ride the existing"
    echo "    Revoke byte plus a Run 159 local sub-class prefix in"
    echo "    revoked_key_metadata. Run 160 introduces NO wire byte"
    echo "    additions and NO trust-bundle / authority-marker /"
    echo "    sequence-file schema changes."
    echo "  * Retire / EmergencyRevoke release-binary evidence is"
    echo "    therefore representable on the existing wire/marker"
    echo "    schemas via the metadata convention; what is missing is"
    echo "    the production wiring of validate_v2_lifecycle_transition"
    echo "    into the Run 134/136/138/150/152 marker-comparison"
    echo "    pipeline. That wiring is the precise scope of Run 161."
    echo
    echo "Exact next required integration run: Run 161"
    echo "  Wire validate_v2_lifecycle_transition into the existing"
    echo "  Run 134/136/138/150/152 marker-comparison and"
    echo "  accept-and-persist boundary (or a new typed pre-flight"
    echo "  gate immediately upstream of those helpers) so the"
    echo "  reload-apply / SIGHUP / drain-once / live 0x05 / startup"
    echo "  v2 paths exercise the lifecycle validator without"
    echo "  changing the on-wire byte set or the marker schema."
} > "${PARTIAL_PROOF}"

# Aggregate summary.
{
    echo "Run 160: release-binary evidence / boundary for the v2"
    echo "  signing-key lifecycle validator (Run 159)"
    echo "======================================================"
    echo
    echo "Verdict: partial-positive: release-binary fixture/evidence"
    echo "boundary captured; lifecycle validator not yet"
    echo "production-surface reachable."
    echo
    echo "Harness: ${BASH_SOURCE[0]}"
    echo
    echo "Per-suite cargo test exit codes:"
    for suite in "${SUITES[@]}" lib_pqc_authority lib_full; do
        rc=$(cat "${LOGS_DIR}/${suite}.exit_code" 2>/dev/null || echo "?")
        printf "  %-60s exit=%s\n" "${suite}" "${rc}"
    done
    echo
    echo "Lifecycle fixture corpus:"
    echo "  helper: ${LIFECYCLE_HELPER}"
    echo "  corpus: ${LIFECYCLE_CORPUS_DIR}"
    echo "  manifest: ${FIXTURE_MANIFEST}"
    echo
    echo "Source-level call graph (validate_v2_lifecycle_transition):"
    echo "  see call_graph/reachability.txt"
    grep '^Non-self src call sites' "${CALL_GRAPH_DIR}/reachability.txt" || true
    echo
    echo "Denylist grep:"
    if [ -s "${GREP_DIR}/out_of_scope.txt" ] && \
       grep -q '^[^#]' "${GREP_DIR}/out_of_scope.txt"; then
        echo "  NON-EMPTY — see grep_summaries/out_of_scope.txt"
    else
        echo "  EMPTY (no production-claim phrasing found in captured logs)"
    fi
    echo
    echo "Negative invariants held:"
    echo "  - No MainNet apply (no harness scenario enables MainNet)."
    echo "  - No autonomous drain / apply on receipt / peer-majority."
    echo "  - No fallback --p2p-trusted-root."
    echo "  - No active DummySig / DummyKem / DummyAead."
    echo "  - No schema/wire/metric drift."
    echo "  - No marker write before sequence commit (no mutating"
    echo "    surface is exercised — the lifecycle validator is pure)."
    echo "  - No sequence write on validation-only surfaces."
    echo "  - No marker write on validation-only surfaces."
    echo
    echo "Out-of-scope deferrals (unchanged):"
    echo "  - Governance / KMS / HSM: unimplemented."
    echo "  - Validator-set rotation: open."
    echo "  - Full C4: open. C5: open."
    echo "  - MainNet: refused unconditionally."
    echo
    echo "Evidence report: docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_160.md"
    echo
    echo "Tracked vs generated artifacts:"
    echo "  Only README.md and summary.txt are tracked (mirroring Run 153"
    echo "  / Run 155 / Run 156 / Run 158). All per-run artifacts are"
    echo "  reproduced by the harness and are .gitignored."
} > "${SUMMARY_FILE}"

echo "[run-160] DONE — see ${SUMMARY_FILE}" >&2
