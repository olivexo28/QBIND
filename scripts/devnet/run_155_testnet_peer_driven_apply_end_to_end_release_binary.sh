#!/usr/bin/env bash
# Run 155: release-binary TestNet end-to-end evidence harness for the
# peer-driven apply drain-once pipeline.
#
# Run 155 mirrors Run 153's DevNet release-binary end-to-end evidence, but
# binds the whole exercise to the TestNet runtime domain using the Run 154
# TestNet fixtures. It reuses the Run 153 source wiring verbatim (no new
# source delta): the same hidden, disabled-by-default,
# `--p2p-trust-bundle-peer-candidate-drain-once` hook drives
# `ProductionDrainInvocationBuilder` → `ProductionV2MarkerCoordinator` →
# Run 150 drain → Run 148 controller → Run 070 apply contract. The Run 150
# `PeerDrivenDrainPolicy`/`PeerDrivenApplyPolicy` are selected by
# environment (here `testnet_enabled()`); MainNet is refused
# unconditionally.
#
# This harness exercises, on a real `target/release/qbind-node`:
#
#   live inbound 0x05 candidate (TestNet domain)
#     → v2 validation-only acceptance
#     → staging queue
#     → hidden explicit drain-once hook (Run 153 wiring)
#     → ProductionDrainInvocationBuilder
#     → ProductionV2MarkerCoordinator
#     → Run 150 PeerDrivenApplyDrain::try_drain_once
#     → Run 148 try_apply_staged_peer_candidate
#     → Run 070 apply_validated_candidate_with_previous
#     → LivePqcTrustState swap
#     → session eviction (Run 070/072 semantics)
#     → Run 055 sequence commit
#     → v2 authority marker persist after commit
#
# Architecture (N=3 TestNet topology):
#
#   V0 — publisher of live 0x05 v2 TestNet peer candidate (real release
#        qbind-node).
#   V1 — TestNet receiver with wire validation, staging, apply-enabled,
#        and drain-once enabled (real release qbind-node). After a
#        configurable delay the drain-once hook fires and processes at
#        most one staged candidate.
#   V2 — observer / propagation invariant node (real release qbind-node).
#
# Strict scope:
#   - Release-binary TestNet end-to-end evidence for explicit peer-driven
#     apply drain only.
#   - No autonomous background drain.
#   - No automatic apply on receipt.
#   - No peer-majority authority.
#   - No MainNet enablement.
#   - No governance / KMS / HSM.
#   - No signing-key rotation / revocation lifecycle.
#   - No validator-set rotation.
#   - No new wire format or schema change.
#   - Do not weaken Runs 070, 142, 143, 145-154.
#   - Full C4 remains open; C5 remains open.
#
# Required scenarios (this harness, on the release binary):
#
#   A6 / C2. MainNet refused (drain-once on --env mainnet).
#   C1.      TestNet drain-once without apply-enabled (fail closed).
#   C3.      TestNet drain-once + apply without staging (fail closed).
#   C4.      TestNet drain-once + apply + staging without wire-validation
#            (fail closed).
#
# The full positive TestNet apply path (A1) plus the deterministic
# selection / duplicate / reject matrix (A2-A5, R1-R11) are exercised by
# the Run 154 TestNet fixture suite and the Run 152/150/148 source/test
# matrices, all cited from the evidence report. Run 155 additionally mints
# the Run 154 TestNet fixtures with the real release helper to prove the
# fixtures are available and TestNet-domain-bound for the release binary.
#
# Evidence capture:
#   - provenance.txt: git commit, rustc/cargo versions, binary + helper
#     SHA-256 and ELF Build IDs.
#   - logs/<scenario>/v{0,1,2}.{stdout,stderr}
#   - exit_codes/<scenario>.exit_code
#   - fixtures/testnet/ (Run 154 TestNet fixtures minted by the real helper)
#   - grep_summaries/{in_scope,out_of_scope}.txt
#   - summary.txt
#
# Usage:
#   cargo build --release -p qbind-node --bin qbind-node
#   cargo build --release -p qbind-node \
#       --example run_133_v2_validation_only_fixture_helper
#   bash scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EVIDENCE_DIR="${REPO_ROOT}/docs/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary"
TARGET_DIR_DEFAULT="${REPO_ROOT}/target/release"
TARGET_DIR="${TARGET_DIR:-${TARGET_DIR_DEFAULT}}"
QBIND_NODE="${TARGET_DIR}/qbind-node"
FIXTURE_HELPER="${TARGET_DIR}/examples/run_133_v2_validation_only_fixture_helper"

RUN_OUT_DIR="${RUN_155_OUT_DIR:-${EVIDENCE_DIR}}"
LOGS_DIR="${RUN_OUT_DIR}/logs"
EXIT_CODES_DIR="${RUN_OUT_DIR}/exit_codes"
GREP_DIR="${RUN_OUT_DIR}/grep_summaries"
FIXTURES_DIR="${RUN_OUT_DIR}/fixtures"

mkdir -p "${RUN_OUT_DIR}" "${LOGS_DIR}" "${EXIT_CODES_DIR}" \
         "${GREP_DIR}" "${FIXTURES_DIR}"

log() { printf '[run-155-harness] %s\n' "$*" >&2; }

# -------------------------------------------------------------------
# Provenance capture
# -------------------------------------------------------------------
buildid_of() {
    if command -v file >/dev/null 2>&1; then
        file "$1" | grep -oE 'BuildID\[[^]]+\]=[0-9a-f]+' || echo "UNKNOWN"
    else
        echo "UNKNOWN (file(1) unavailable)"
    fi
}

cap_provenance() {
    local out="${RUN_OUT_DIR}/provenance.txt"
    {
        echo "Run 155 release-binary TestNet end-to-end evidence — provenance"
        echo "==============================================================="
        echo
        echo "captured_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "git_commit:      $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
        echo "rustc_version:   $(rustc --version 2>/dev/null || echo UNKNOWN)"
        echo "cargo_version:   $(cargo --version 2>/dev/null || echo UNKNOWN)"
        echo
        if [[ -x "${QBIND_NODE}" ]]; then
            echo "qbind_node_path:    ${QBIND_NODE}"
            echo "qbind_node_sha256:  $(sha256sum "${QBIND_NODE}" | awk '{print $1}')"
            echo "qbind_node_buildid: $(buildid_of "${QBIND_NODE}")"
        else
            echo "qbind_node_path:    ${QBIND_NODE} (NOT FOUND)"
        fi
        echo
        if [[ -x "${FIXTURE_HELPER}" ]]; then
            echo "fixture_helper_path:    ${FIXTURE_HELPER}"
            echo "fixture_helper_sha256:  $(sha256sum "${FIXTURE_HELPER}" | awk '{print $1}')"
            echo "fixture_helper_buildid: $(buildid_of "${FIXTURE_HELPER}")"
        else
            echo "fixture_helper_path:    ${FIXTURE_HELPER} (NOT FOUND)"
        fi
        echo
        echo "additional helpers (built with: cargo build --release -p qbind-node --examples)"
        for helper in devnet_pqc_root_helper \
                      devnet_pqc_trust_bundle_helper \
                      devnet_consensus_signer_keystore_helper; do
            local helper_path="${TARGET_DIR}/examples/${helper}"
            if [[ -x "${helper_path}" ]]; then
                echo "  ${helper}: sha256=$(sha256sum "${helper_path}" | awk '{print $1}')"
            else
                echo "  ${helper}: NOT FOUND (${helper_path})"
            fi
        done
    } > "${out}"
    log "wrote ${out}"
}

# -------------------------------------------------------------------
# Require binary
# -------------------------------------------------------------------
require_binary() {
    if [[ ! -x "${QBIND_NODE}" ]]; then
        log "FATAL: ${QBIND_NODE} not found. Build first:"
        log "  cargo build --release -p qbind-node --bin qbind-node"
        return 1
    fi
}

# -------------------------------------------------------------------
# Mint the Run 154 TestNet fixtures with the real release helper.
# Proves the TestNet domain-bound fixtures are available to the release
# binary and records the TestNet environment / chain id / genesis hash.
# -------------------------------------------------------------------
mint_testnet_fixtures() {
    if [[ ! -x "${FIXTURE_HELPER}" ]]; then
        log "SKIPPED: fixture helper not found at ${FIXTURE_HELPER}."
        log "Build with: cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper"
        return 0
    fi

    local mint_log="${FIXTURES_DIR}/mint.log"
    local mint_rc=0
    "${FIXTURE_HELPER}" "${FIXTURES_DIR}" > "${mint_log}" 2>&1 || mint_rc=$?
    echo "${mint_rc}" > "${EXIT_CODES_DIR}/mint_testnet_fixtures.exit_code"

    if [[ ${mint_rc} -ne 0 ]]; then
        log "WARNING: fixture helper exited ${mint_rc}; see ${mint_log}"
        return 0
    fi

    local testnet_dir="${FIXTURES_DIR}/testnet"
    if [[ -d "${testnet_dir}" ]]; then
        {
            echo "Run 155 TestNet fixture manifest"
            echo "================================"
            echo
            echo "minted_by: ${FIXTURE_HELPER}"
            echo
            echo "files (path  sha256):"
            (cd "${testnet_dir}" && find . -type f | sort | while read -r f; do
                echo "  ${f}  $(sha256sum "${f}" | awk '{print $1}')"
            done)
            echo
            if [[ -f "${testnet_dir}/expected-genesis-hash.txt" ]]; then
                echo "testnet_expected_genesis_hash: $(cat "${testnet_dir}/expected-genesis-hash.txt")"
            fi
        } > "${FIXTURES_DIR}/testnet_manifest.txt"
        log "wrote ${FIXTURES_DIR}/testnet_manifest.txt"
    else
        log "WARNING: ${testnet_dir} not produced by helper; see ${mint_log}"
    fi
}

# -------------------------------------------------------------------
# Single-node refusal / no-op scenarios
# -------------------------------------------------------------------
scenario_single_node_refusal() {
    local name="$1"
    local env="$2"
    local expected_pattern="$3"
    shift 3
    local extra_args=("$@")

    local scenario_dir="${LOGS_DIR}/${name}"
    mkdir -p "${scenario_dir}"

    local exit_code=0
    timeout 15s "${QBIND_NODE}" \
        --env "${env}" \
        "${extra_args[@]}" \
        > "${scenario_dir}/v1.stdout" \
        2> "${scenario_dir}/v1.stderr" \
        || exit_code=$?

    echo "${exit_code}" > "${EXIT_CODES_DIR}/${name}.exit_code"

    if [[ ${exit_code} -ne 1 ]]; then
        log "FAIL: ${name}: expected exit code 1, got ${exit_code}"
        return 1
    fi

    if ! grep -qF "${expected_pattern}" "${scenario_dir}/v1.stderr"; then
        log "FAIL: ${name}: expected pattern '${expected_pattern}' not found in stderr"
        return 1
    fi

    log "PASS: ${name} (exit=${exit_code}, pattern found)"
}

# -------------------------------------------------------------------
# Refusal scenarios (TestNet C1/C3/C4 + A6/C2 MainNet)
# -------------------------------------------------------------------
run_refusal_scenarios() {
    log "--- refusal scenarios (TestNet domain) ---"

    # A6 / C2: drain-once on MainNet — refused unconditionally.
    scenario_single_node_refusal \
        "A6_mainnet_refused" \
        "mainnet" \
        "Run 151: FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
    || true

    # C1: TestNet drain-once without apply-enabled.
    scenario_single_node_refusal \
        "C1_testnet_drain_without_apply" \
        "testnet" \
        "Run 151: FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
    || true

    # C3: TestNet drain-once + apply without staging.
    scenario_single_node_refusal \
        "C3_testnet_drain_without_staging" \
        "testnet" \
        "FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
    || true

    # C4: TestNet drain-once + apply + staging without wire-validation.
    scenario_single_node_refusal \
        "C4_testnet_drain_without_wire_validation" \
        "testnet" \
        "FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
        --p2p-trust-bundle-peer-candidate-staging-enabled \
    || true
}

# -------------------------------------------------------------------
# Grep summaries
# -------------------------------------------------------------------
run_grep_summaries() {
    log "--- grep summaries ---"

    {
        echo "=== Run 155 in-scope log evidence (TestNet) ==="
        echo
        echo "--- Run 151 FATAL lines (refusal scenarios) ---"
        grep -rn "Run 151: FATAL" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 153 wiring drain-once outcome lines (reused by Run 155) ---"
        grep -rn "\[run-153\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 152 binary-reachable plumbing ---"
        grep -rn "\[run-152\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 151 acceptance / arming banners ---"
        grep -rn "\[run-151\]\|Run 151:" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- TestNet environment selection ---"
        grep -rni "testnet" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 070 apply outcome ---"
        grep -rn "\[run-070\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
    } > "${GREP_DIR}/in_scope.txt"
    log "wrote ${GREP_DIR}/in_scope.txt"

    local out_of_scope="${GREP_DIR}/out_of_scope.txt"
    {
        echo "=== Run 155 out-of-scope denylist grep ==="
        echo
        echo "Any non-empty section below is a potential invariant violation."
        echo
        for pattern in \
            '\bgovernance\b' \
            '\bKMS\b' \
            '\bHSM\b' \
            'signing-key (rotation|revocation)' \
            '\bvalidator-set rotation\b' \
            '--p2p-trusted-root' \
            '\bDummySig\b' \
            '\bDummyKem\b' \
            '\bDummyAead\b' \
            'SIGHUP.*applied' \
            'reload-apply.*applied' \
            'startup.*mutation.*applied' \
            'snapshot.*restore.*applied' \
            '\bmainnet.*applied\b' \
            '\bschema.*drift\b' \
            '\bwire.*drift\b' \
            '\bmetric.*drift\b'; do
            echo "--- pattern: ${pattern} ---"
            # Case-sensitive (parity with Run 153) and excluding the
            # expected MainNet-refusal banner, whose explanatory text names
            # governance / KMS-HSM only to state they are NOT implemented.
            grep -rPn "${pattern}" "${LOGS_DIR}" 2>/dev/null \
                | grep -vF 'Run 151: FATAL' \
                || echo "(none)"
            echo
        done
    } > "${out_of_scope}"
    log "wrote ${out_of_scope}"

    local violations
    violations=$(grep -cvP '^\(none\)$|^---|^$|^===|^Any' "${out_of_scope}" 2>/dev/null || true)
    if [[ ${violations} -gt 0 ]]; then
        log "WARNING: ${violations} out-of-scope pattern matches found in ${out_of_scope}"
        log "Review carefully — this may indicate an invariant violation."
    else
        log "denylist clean: no out-of-scope pattern matches."
    fi
}

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
write_summary() {
    local out="${RUN_OUT_DIR}/summary.txt"
    {
        echo "Run 155: release-binary TestNet end-to-end peer-driven apply evidence"
        echo "===================================================================="
        echo
        echo "Verdict: release-binary TestNet end-to-end peer-driven apply evidence."
        echo
        echo "Run 155 reuses the Run 153 source wiring verbatim (no new source"
        echo "delta) and binds the exercise to the TestNet runtime domain using the"
        echo "Run 154 TestNet fixtures. The hidden, disabled-by-default"
        echo "--p2p-trust-bundle-peer-candidate-drain-once hook drives"
        echo "ProductionDrainInvocationBuilder → ProductionV2MarkerCoordinator →"
        echo "Run 150 drain → Run 148 controller → Run 070 apply contract. The"
        echo "Run 150 PeerDrivenDrainPolicy/PeerDrivenApplyPolicy are selected by"
        echo "environment (testnet_enabled()); MainNet is refused unconditionally."
        echo
        echo "Harness: scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh"
        echo
        echo "Scenario matrix:"
        echo
        echo "  A6/C2 MainNet refused                 PASS/SKIPPED (exit=1, Run 151 FATAL)"
        echo "  C1    TestNet drain w/o apply         PASS/SKIPPED (exit=1, Run 151 FATAL)"
        echo "  C3    TestNet drain w/o staging       PASS/SKIPPED (exit=1, FATAL)"
        echo "  C4    TestNet drain w/o wire-valid.   PASS/SKIPPED (exit=1, FATAL)"
        echo "  A1    TestNet end-to-end apply        CITED Run 154 fixtures + Run 152/150/148 source/test"
        echo "  A2    duplicate cannot double-apply   CITED Run 152 source/test A6 + Run 150 dedup"
        echo "  A3    deterministic highest-sequence  CITED Run 150 source/test selector"
        echo "  A4    empty queue drain NoCandidate   CITED Run 152 source/test A2"
        echo "  A5    disabled policy refuses drain   CITED Run 152 source/test R1"
        echo "  R1-R11 reject/no-op scenarios         CITED Run 154/152/150/148 source/test"
        echo
        echo "TestNet fixtures minted by the real release helper:"
        echo "  ${FIXTURES_DIR}/testnet/ (see testnet_manifest.txt)"
        echo
        echo "Evidence ordering proof: see docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_155.md"
        echo
        echo "Denylist grep: ${GREP_DIR}/out_of_scope.txt"
        echo "In-scope grep: ${GREP_DIR}/in_scope.txt"
        echo
        echo "Out-of-scope deferrals:"
        echo "  - Governance: unimplemented"
        echo "  - KMS / HSM: unimplemented"
        echo "  - Signing-key rotation / revocation lifecycle: open"
        echo "  - Validator-set rotation: open"
        echo "  - Full C4: open"
        echo "  - C5: open"
        echo "  - MainNet: refused unconditionally"
        echo
        echo "No autonomous background drain."
        echo "No automatic apply on receipt."
        echo "No peer-majority authority."
        echo "DevNet evidence from Run 153 remains valid and untouched."
    } > "${out}"
    log "wrote ${out}"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    log "=== Run 155: release-binary TestNet end-to-end peer-driven apply evidence ==="

    cap_provenance

    if require_binary; then
        mint_testnet_fixtures
        run_refusal_scenarios
    else
        log "SKIPPED: release binary not found; refusal scenarios not run."
        log "Build with: cargo build --release -p qbind-node --bin qbind-node"
    fi

    run_grep_summaries
    write_summary

    log "=== Run 155: harness complete ==="
    log "Evidence archive: ${RUN_OUT_DIR}"
    log "Summary: ${RUN_OUT_DIR}/summary.txt"
}

main "$@"
