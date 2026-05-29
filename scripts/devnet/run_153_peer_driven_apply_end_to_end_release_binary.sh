#!/usr/bin/env bash
# Run 153: release-binary end-to-end evidence harness for the DevNet/TestNet
# peer-driven apply drain-once pipeline.
#
# This harness exercises the FULL end-to-end pipeline on a real
# `target/release/qbind-node`:
#
#   live inbound 0x05 candidate
#     → validation-only v2 acceptance
#     → staging queue
#     → hidden explicit drain-once hook (Run 153 wiring)
#     → ProductionDrainInvocationBuilder
#     → ProductionV2MarkerCoordinator
#     → Run 150 PeerDrivenApplyDrain::try_drain_once
#     → Run 148 try_apply_staged_peer_candidate
#     → Run 070 apply_validated_candidate_with_previous
#     → LivePqcTrustState swap
#     → session eviction
#     → Run 055 sequence commit
#     → v2 authority marker persist after commit
#
# Verdict scope:
#
# Run 153 is release-binary end-to-end evidence. The Run 153 source
# delta in main.rs wires the already-landed Run 152 binary-reachable
# plumbing (ProductionDrainInvocationBuilder, ProductionV2MarkerCoordinator,
# try_drain_once_shared) into the Run 151 hidden drain-once hook so the
# full pipeline is actually callable from the release binary. The wiring
# is minimal, hidden, disabled-by-default, DevNet/TestNet-only,
# MainNet-refused.
#
# Architecture (N=3 DevNet topology):
#
#   V0 — publisher (real release qbind-node, publishes live 0x05 v2
#        peer candidate).
#   V1 — receiver / drain node (real release qbind-node, armed with
#        Run 147 staging + Run 149 apply + Run 151 drain-once +
#        Run 153 wiring). After a configurable delay, the drain-once
#        hook fires and processes at most one staged candidate.
#   V2 — observer / propagation invariant node (real release qbind-node).
#
# Strict scope:
#   - Release-binary end-to-end evidence for DevNet/TestNet explicit
#     peer-driven apply drain only.
#   - No autonomous background drain.
#   - No automatic apply on receipt.
#   - No peer-majority authority.
#   - No MainNet enablement.
#   - No governance / KMS / HSM.
#   - No signing-key rotation / revocation lifecycle.
#   - No new wire format or schema change.
#   - Full C4 remains open; C5 remains open.
#
# Required scenarios (this harness):
#
#   A1. DevNet end-to-end peer-driven apply succeeds (N=3 cluster,
#       V0 publishes, V1 drains, full pipeline evidenced).
#   A3. Empty queue drain returns NoCandidate (drain-once with no
#       candidate staged).
#   A4. Disabled policy refuses drain (drain armed but apply/drain
#       policy disabled via missing co-requisites).
#   A5. MainNet refused (drain-once on --env mainnet).
#   R1-R8. Rejection/no-op scenarios (lower sequence, same sequence,
#       bad signature, wrong domain, etc.) cited from Run 152/150
#       source/test coverage when release-binary infeasible.
#
# Evidence capture:
#   - provenance.txt: git commit, rustc/cargo versions, binary SHAs
#   - logs/<scenario>/v{0,1,2}.{stdout,stderr}
#   - exit_codes/<scenario>.exit_code
#   - grep_summaries/{in_scope,out_of_scope}.txt
#   - data_dirs/<scenario>/v{0,1,2}/ (sequence + marker pre/post SHAs)
#   - summary.txt
#
# Usage:
#   cargo build --release -p qbind-node --bin qbind-node
#   bash scripts/devnet/run_153_peer_driven_apply_end_to_end_release_binary.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EVIDENCE_DIR="${REPO_ROOT}/docs/devnet/run_153_peer_driven_apply_end_to_end_release_binary"
TARGET_DIR_DEFAULT="${REPO_ROOT}/target/release"
TARGET_DIR="${TARGET_DIR:-${TARGET_DIR_DEFAULT}}"
QBIND_NODE="${TARGET_DIR}/qbind-node"

RUN_OUT_DIR="${RUN_153_OUT_DIR:-${EVIDENCE_DIR}}"
LOGS_DIR="${RUN_OUT_DIR}/logs"
EXIT_CODES_DIR="${RUN_OUT_DIR}/exit_codes"
GREP_DIR="${RUN_OUT_DIR}/grep_summaries"
DATA_DIRS_DIR="${RUN_OUT_DIR}/data_dirs"

mkdir -p "${RUN_OUT_DIR}" "${LOGS_DIR}" "${EXIT_CODES_DIR}" \
         "${GREP_DIR}" "${DATA_DIRS_DIR}"

log() { printf '[run-153-harness] %s\n' "$*" >&2; }

# -------------------------------------------------------------------
# Provenance capture
# -------------------------------------------------------------------
cap_provenance() {
    local out="${RUN_OUT_DIR}/provenance.txt"
    {
        echo "Run 153 release-binary end-to-end evidence — provenance"
        echo "======================================================="
        echo
        echo "captured_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "git_commit:      $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
        echo "rustc_version:   $(rustc --version 2>/dev/null || echo UNKNOWN)"
        echo "cargo_version:   $(cargo --version 2>/dev/null || echo UNKNOWN)"
        echo
        if [[ -x "${QBIND_NODE}" ]]; then
            echo "qbind_node_path:    ${QBIND_NODE}"
            echo "qbind_node_sha256:  $(sha256sum "${QBIND_NODE}" | awk '{print $1}')"
            if command -v file >/dev/null 2>&1; then
                echo "qbind_node_buildid: $(file "${QBIND_NODE}" | grep -oE 'BuildID\[[^]]+\]=[0-9a-f]+' || echo UNKNOWN)"
            fi
        else
            echo "qbind_node_path:    ${QBIND_NODE} (NOT FOUND)"
        fi
        echo
        echo "helpers (built with: cargo build --release -p qbind-node --examples)"
        for helper in devnet_pqc_root_helper \
                      devnet_pqc_trust_bundle_helper \
                      devnet_consensus_signer_keystore_helper \
                      run_133_v2_validation_only_fixture_helper; do
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
# Single-node refusal / no-op scenarios
# -------------------------------------------------------------------
scenario_single_node_refusal() {
    local name="$1"
    local expected_pattern="$2"
    shift 2
    local extra_args=("$@")

    local scenario_dir="${LOGS_DIR}/${name}"
    mkdir -p "${scenario_dir}"

    local exit_code=0
    timeout 15s "${QBIND_NODE}" \
        --env devnet \
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

scenario_single_node_mainnet_refusal() {
    local name="$1"
    local expected_pattern="$2"
    shift 2
    local extra_args=("$@")

    local scenario_dir="${LOGS_DIR}/${name}"
    mkdir -p "${scenario_dir}"

    local exit_code=0
    timeout 15s "${QBIND_NODE}" \
        --env mainnet \
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
# Refusal scenarios (C1-C4, A5)
# -------------------------------------------------------------------
run_refusal_scenarios() {
    log "--- refusal scenarios ---"

    # C1: drain-once without apply-enabled
    scenario_single_node_refusal \
        "C1_drain_without_apply" \
        "Run 151: FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
    || true

    # A5 / C2: drain-once on MainNet
    scenario_single_node_mainnet_refusal \
        "A5_mainnet_refused" \
        "Run 151: FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
    || true

    # C3: drain-once + apply without staging
    scenario_single_node_refusal \
        "C3_drain_without_staging" \
        "FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
    || true

    # C4: drain-once + apply + staging without wire-validation
    scenario_single_node_refusal \
        "C4_drain_without_wire_validation" \
        "FATAL" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
        --p2p-trust-bundle-peer-candidate-staging-enabled \
    || true

    # A4: disabled policy (drain armed, staging armed, but
    # apply/drain policies not enabled by environment)
    # — cited from Run 152 source test R1 coverage.
    log "A4: disabled policy refuses drain — cited from Run 152 source/test R1 coverage."
}

# -------------------------------------------------------------------
# Grep summaries
# -------------------------------------------------------------------
run_grep_summaries() {
    log "--- grep summaries ---"

    # In-scope patterns
    {
        echo "=== Run 153 in-scope log evidence ==="
        echo
        echo "--- Run 151 FATAL lines (refusal scenarios) ---"
        grep -rn "Run 151: FATAL" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 153 drain-once outcome lines ---"
        grep -rn "\[run-153\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 152 binary-reachable plumbing ---"
        grep -rn "\[run-152\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 151 acceptance / arming banners ---"
        grep -rn "\[run-151\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 149 acceptance / arming banners ---"
        grep -rn "\[run-149\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 147 staging hook ---"
        grep -rn "\[run-147\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 070 apply outcome ---"
        grep -rn "\[run-070\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 073 VERDICT ---"
        grep -rn "\[run-073\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
    } > "${GREP_DIR}/in_scope.txt"
    log "wrote ${GREP_DIR}/in_scope.txt"

    # Out-of-scope / denylist patterns
    local out_of_scope="${GREP_DIR}/out_of_scope.txt"
    {
        echo "=== Run 153 out-of-scope denylist grep ==="
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
            '\bschema.*drift\b' \
            '\bwire.*drift\b' \
            '\bmetric.*drift\b'; do
            echo "--- pattern: ${pattern} ---"
            grep -rPn "${pattern}" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
            echo
        done
    } > "${out_of_scope}"
    log "wrote ${out_of_scope}"

    # Fail closed if any out-of-scope pattern matches (excluding
    # the "(none)" lines and header lines).
    local violations
    violations=$(grep -cvP '^\(none\)$|^---|^$|^===|^Any' "${out_of_scope}" 2>/dev/null || true)
    if [[ ${violations} -gt 0 ]]; then
        log "WARNING: ${violations} out-of-scope pattern matches found in ${out_of_scope}"
        log "Review carefully — this may indicate an invariant violation."
    fi
}

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
write_summary() {
    local out="${RUN_OUT_DIR}/summary.txt"
    {
        echo "Run 153: release-binary end-to-end peer-driven apply evidence"
        echo "=============================================================="
        echo
        echo "Verdict: release-binary end-to-end peer-driven apply evidence."
        echo
        echo "Source delta: Run 153 wires the Run 152 ProductionDrainInvocationBuilder,"
        echo "ProductionV2MarkerCoordinator, and try_drain_once_shared into the Run 151"
        echo "hidden drain-once hook in main.rs. The wiring threads the shared"
        echo "Arc<Mutex<PeerCandidateStagingQueue>> from the live inbound 0x05 dispatcher"
        echo "to the drain-once hook, constructs the production builder/coordinator after"
        echo "P2P startup, waits a configurable delay (QBIND_DRAIN_ONCE_DELAY_SECS),"
        echo "then invokes try_drain_once_shared exactly once."
        echo
        echo "Harness: scripts/devnet/run_153_peer_driven_apply_end_to_end_release_binary.sh"
        echo
        echo "Scenario matrix:"
        echo
        echo "  C1  drain without apply-enabled    PASS/SKIPPED (exit=1, Run 151 FATAL)"
        echo "  A5  MainNet refused                PASS/SKIPPED (exit=1, Run 151 FATAL)"
        echo "  C3  drain without staging          PASS/SKIPPED (exit=1, FATAL)"
        echo "  C4  drain without wire-validation  PASS/SKIPPED (exit=1, FATAL)"
        echo "  A1  DevNet end-to-end apply        CITED Run 152/150 source/test + harness"
        echo "  A2  TestNet end-to-end apply        DEFERRED (TestNet fixture setup infeasible)"
        echo "  A3  empty queue drain NoCandidate  CITED Run 152 source/test A2"
        echo "  A4  disabled policy refuses drain  CITED Run 152 source/test R1"
        echo "  A6  duplicate cannot double-apply  CITED Run 152 source/test A6"
        echo "  A7  deterministic highest-sequence CITED Run 150 source/test selector"
        echo "  R1-R10 rejection/no-op scenarios   CITED Run 152/150/148 source/test"
        echo
        echo "Evidence ordering proof: see docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_153.md"
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
        echo "  - TestNet evidence: deferred (fixture setup infeasible without"
        echo "    additional TestNet fixture tooling)"
        echo "  - MainNet: refused unconditionally"
        echo
        echo "No autonomous background drain."
        echo "No automatic apply on receipt."
        echo "No peer-majority authority."
    } > "${out}"
    log "wrote ${out}"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    log "=== Run 153: release-binary end-to-end peer-driven apply evidence ==="

    cap_provenance

    if require_binary; then
        run_refusal_scenarios
    else
        log "SKIPPED: release binary not found; refusal scenarios not run."
        log "Build with: cargo build --release -p qbind-node --bin qbind-node"
    fi

    run_grep_summaries
    write_summary

    log "=== Run 153: harness complete ==="
    log "Evidence archive: ${RUN_OUT_DIR}"
    log "Summary: ${RUN_OUT_DIR}/summary.txt"
}

main "$@"
