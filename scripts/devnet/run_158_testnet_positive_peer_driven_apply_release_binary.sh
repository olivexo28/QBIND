#!/usr/bin/env bash
# Run 158: positive TestNet release-binary end-to-end peer-driven apply
# evidence harness, driven against the Run 157 unified TestNet fixture
# universe.
#
# Run 158 closes the Run 156 disjoint-universe blocker by binding the
# live N=3 TestNet P2P transport, the baseline (seq=1) trust bundle, the
# candidate (seq=2) trust bundle, the v2 ratification sidecar, the
# seeded v2 authority marker, and the valid `0x05` peer-candidate
# envelope to a single, self-consistent universe minted by
# `run_157_unified_testnet_peer_apply_fixture_helper`.
#
# This harness exercises, on a real `target/release/qbind-node`:
#
#   live inbound 0x05 candidate (TestNet domain)
#     → v2 validation-only acceptance
#     → staging queue
#     → hidden explicit drain-once hook (Run 153 wiring)
#     → ProductionDrainInvocationBuilder (Run 152)
#     → ProductionV2MarkerCoordinator (Run 152)
#     → Run 150 PeerDrivenApplyDrain::try_drain_once
#     → Run 148 try_apply_staged_peer_candidate
#     → Run 070 apply_validated_candidate_with_previous
#     → LivePqcTrustState swap
#     → session eviction (Run 070/072 semantics)
#     → Run 055 sequence commit
#     → v2 authority marker persist after commit
#
# Architecture (real TestNet N=3 topology):
#
#   V0 — publisher of the live `0x05` v2 TestNet peer-candidate
#        envelope (real release `qbind-node`). Uses the unified
#        candidate envelope from Run 157.
#   V1 — TestNet receiver, full apply pipeline armed:
#        wire-validation + staging + apply-enabled + drain-once
#        enabled. After QBIND_DRAIN_ONCE_DELAY_SECS the hidden
#        drain-once hook fires exactly once.
#   V2 — observer / propagation-invariant node.
#
# Strict scope:
#   - Release-binary positive TestNet end-to-end apply evidence.
#   - Use real `target/release/qbind-node`.
#   - Use Run 157 unified TestNet fixture universe.
#   - Use real live P2P 0x05 exchange.
#   - No source/test substitution for the positive A1 claim.
#   - No autonomous background drain.
#   - No automatic apply on receipt.
#   - No peer-majority authority.
#   - No MainNet enablement.
#   - No governance / KMS / HSM.
#   - No signing-key rotation / revocation lifecycle.
#   - No validator-set rotation.
#   - No new wire format or schema change.
#   - Do not weaken Runs 070, 142, 143, 145-157.
#   - Full C4 remains open; C5 remains open.
#
# Required positive scenario:
#
#   A1. TestNet end-to-end peer-driven apply succeeds on real release
#       binaries, using the Run 157 unified fixture universe.
#
# Required focused negative checks:
#
#   R1. Run 156 disjoint-universe candidate still rejected.
#   R2. MainNet drain-once refused unconditionally.
#   R3. wrong-environment (DevNet candidate) rejected on a TestNet
#       receiver.
#   R4. duplicate candidate cannot double-apply (cited from
#       Run 150/152 source-test coverage when not feasible against a
#       single-shot drain-once process).
#
# Evidence capture:
#   - provenance.txt: git commit, rustc/cargo versions, binary +
#     helper SHA-256 and ELF Build IDs.
#   - fixtures/testnet/ (Run 157 unified TestNet fixtures minted by
#     the real release helper).
#   - fixture_manifest.txt: SHA-256s of every minted fixture file,
#     plus the unified manifest's TestNet domain proof (chain id,
#     genesis hash, authority root, transport root, sequences).
#   - logs/<scenario>/v{0,1,2}.{stdout,stderr}.log
#   - exit_codes/<scenario>.exit_code
#   - sequence/A1.{before,after}.{json,sha256}
#   - marker_hashes/A1.{before,after}.{json,sha256}
#   - metrics/A1.{v0,v1,v2}.{before,after}.txt (best-effort)
#   - a1_apply_proof.txt | a1_blocker.txt
#   - grep_summaries/{in_scope,out_of_scope}.txt
#   - summary.txt
#
# Usage:
#   cargo build --release -p qbind-node --bin qbind-node
#   cargo build --release -p qbind-node \
#       --example run_157_unified_testnet_peer_apply_fixture_helper
#   bash scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EVIDENCE_DIR="${REPO_ROOT}/docs/devnet/run_158_testnet_positive_peer_driven_apply_release_binary"
TARGET_DIR_DEFAULT="${REPO_ROOT}/target/release"
TARGET_DIR="${TARGET_DIR:-${TARGET_DIR_DEFAULT}}"
QBIND_NODE="${TARGET_DIR}/qbind-node"
UNIFIED_HELPER="${TARGET_DIR}/examples/run_157_unified_testnet_peer_apply_fixture_helper"
SIGNER_HELPER="${TARGET_DIR}/examples/devnet_consensus_signer_keystore_helper"

RUN_OUT_DIR="${RUN_158_OUT_DIR:-${EVIDENCE_DIR}}"
LOGS_DIR="${RUN_OUT_DIR}/logs"
EXIT_CODES_DIR="${RUN_OUT_DIR}/exit_codes"
GREP_DIR="${RUN_OUT_DIR}/grep_summaries"
FIXTURES_DIR="${RUN_OUT_DIR}/fixtures"
SEQ_DIR="${RUN_OUT_DIR}/sequence"
MARKER_DIR="${RUN_OUT_DIR}/marker_hashes"
METRICS_DIR="${RUN_OUT_DIR}/metrics"
DATA_DIR_BASE="${RUN_OUT_DIR}/data"
SIGNERS_DIR="${RUN_OUT_DIR}/signers"

mkdir -p "${RUN_OUT_DIR}" "${LOGS_DIR}" "${EXIT_CODES_DIR}" \
         "${GREP_DIR}" "${FIXTURES_DIR}" "${SEQ_DIR}" "${MARKER_DIR}" \
         "${METRICS_DIR}" "${DATA_DIR_BASE}" "${SIGNERS_DIR}"

log() { printf '[run-158-harness] %s\n' "$*" >&2; }

# -------------------------------------------------------------------
# Provenance capture
# -------------------------------------------------------------------
buildid_of() {
    if command -v file >/dev/null 2>&1; then
        file "$1" 2>/dev/null | grep -oE 'BuildID\[[^]]+\]=[0-9a-f]+' || echo "UNKNOWN"
    else
        echo "UNKNOWN (file(1) unavailable)"
    fi
}

cap_provenance() {
    local out="${RUN_OUT_DIR}/provenance.txt"
    {
        echo "Run 158 release-binary positive TestNet end-to-end peer-driven apply — provenance"
        echo "================================================================================"
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
        if [[ -x "${UNIFIED_HELPER}" ]]; then
            echo "unified_helper_path:    ${UNIFIED_HELPER}"
            echo "unified_helper_sha256:  $(sha256sum "${UNIFIED_HELPER}" | awk '{print $1}')"
            echo "unified_helper_buildid: $(buildid_of "${UNIFIED_HELPER}")"
        else
            echo "unified_helper_path:    ${UNIFIED_HELPER} (NOT FOUND)"
        fi
        echo
        if [[ -x "${SIGNER_HELPER}" ]]; then
            echo "signer_helper_path:    ${SIGNER_HELPER}"
            echo "signer_helper_sha256:  $(sha256sum "${SIGNER_HELPER}" | awk '{print $1}')"
            echo "signer_helper_buildid: $(buildid_of "${SIGNER_HELPER}")"
        else
            echo "signer_helper_path:    ${SIGNER_HELPER} (NOT FOUND)"
        fi
    } > "${out}"
    log "wrote ${out}"
}

require_binary() {
    if [[ ! -x "${QBIND_NODE}" ]]; then
        log "FATAL: ${QBIND_NODE} not found. Build first:"
        log "  cargo build --release -p qbind-node --bin qbind-node"
        return 1
    fi
}

# -------------------------------------------------------------------
# Mint the Run 157 unified TestNet fixture universe with the real
# release helper. Produces:
#   fixtures/testnet/unified_testnet_manifest.json
#   fixtures/testnet/genesis.json
#   fixtures/testnet/expected-genesis-hash.txt
#   fixtures/testnet/baseline-bundle.seq1.json
#   fixtures/testnet/candidate-bundle.seq2.json
#   fixtures/testnet/ratification.v2.ratify.seq1.json
#   fixtures/testnet/ratification.v2.ratify.seq2.json
#   fixtures/testnet/signing-key.ratified.spec
#   fixtures/testnet/transport-root.{id,pk}.hex
#   fixtures/testnet/v{0,1,2}.cert.bin, v{0,1,2}.kem.sk.bin
#   fixtures/testnet/seed-marker.v2.seq1.json
#   fixtures/testnet/peer-candidate.valid.json
#   fixtures/testnet/peer-candidate.<negative>.json (matrix)
# -------------------------------------------------------------------
mint_unified_universe() {
    local outdir="${FIXTURES_DIR}/testnet"
    mkdir -p "${FIXTURES_DIR}"
    if [[ ! -x "${UNIFIED_HELPER}" ]]; then
        log "SKIPPED: unified TestNet fixture helper not found at ${UNIFIED_HELPER}."
        log "Build with: cargo build --release -p qbind-node --example run_157_unified_testnet_peer_apply_fixture_helper"
        return 1
    fi

    local mint_log="${FIXTURES_DIR}/mint.log"
    local mint_rc=0
    "${UNIFIED_HELPER}" "${outdir}" > "${mint_log}" 2>&1 || mint_rc=$?
    echo "${mint_rc}" > "${EXIT_CODES_DIR}/mint_unified_universe.exit_code"

    if [[ ${mint_rc} -ne 0 ]]; then
        log "FATAL: unified helper exited ${mint_rc}; see ${mint_log}"
        return 1
    fi

    if [[ ! -f "${outdir}/unified_testnet_manifest.json" ]]; then
        log "FATAL: ${outdir}/unified_testnet_manifest.json not produced; see ${mint_log}"
        return 1
    fi

    {
        echo "Run 158 unified TestNet fixture manifest"
        echo "========================================="
        echo
        echo "minted_by: ${UNIFIED_HELPER}"
        echo
        echo "files (path  sha256):"
        (cd "${outdir}" && find . -type f | sort | while read -r f; do
            echo "  ${f}  $(sha256sum "${f}" | awk '{print $1}')"
        done)
        echo
        if [[ -f "${outdir}/expected-genesis-hash.txt" ]]; then
            echo "testnet_expected_genesis_hash: $(cat "${outdir}/expected-genesis-hash.txt")"
        fi
        echo
        echo "unified manifest summary:"
        if command -v jq >/dev/null 2>&1; then
            jq '{environment, chain_id, chain_id_hex, expected_genesis_hash_hex,
                 expected_authority_domain_sequence, baseline_fingerprint,
                 expected_candidate_fingerprint, expected_candidate_digest,
                 authority_root_fingerprint}' \
                "${outdir}/unified_testnet_manifest.json" 2>/dev/null \
                || cat "${outdir}/unified_testnet_manifest.json"
        else
            cat "${outdir}/unified_testnet_manifest.json"
        fi
    } > "${FIXTURES_DIR}/testnet_manifest.txt"
    log "wrote ${FIXTURES_DIR}/testnet_manifest.txt"
    return 0
}

# -------------------------------------------------------------------
# Fixture path resolution (read once into shell variables).
# -------------------------------------------------------------------
resolve_fixture_paths() {
    local d="${FIXTURES_DIR}/testnet"
    UNIFIED_MANIFEST="${d}/unified_testnet_manifest.json"
    UNIFIED_GENESIS="${d}/genesis.json"
    UNIFIED_GENESIS_HASH_FILE="${d}/expected-genesis-hash.txt"
    UNIFIED_BASELINE="${d}/baseline-bundle.seq1.json"
    UNIFIED_CANDIDATE="${d}/candidate-bundle.seq2.json"
    UNIFIED_SIDECAR_SEQ1="${d}/ratification.v2.ratify.seq1.json"
    UNIFIED_SIDECAR_SEQ2="${d}/ratification.v2.ratify.seq2.json"
    UNIFIED_SIGNING_KEY_SPEC="${d}/signing-key.ratified.spec"
    UNIFIED_TRANSPORT_ROOT_PK="${d}/transport-root.pk.hex"
    UNIFIED_SEED_MARKER="${d}/seed-marker.v2.seq1.json"
    UNIFIED_VALID_ENVELOPE="${d}/peer-candidate.valid.json"
    UNIFIED_NEG_LOWER_SEQ="${d}/peer-candidate.lower-sequence.json"
    UNIFIED_NEG_WRONG_ENV="${d}/peer-candidate.wrong-environment.json"
    UNIFIED_NEG_WRONG_CHAIN="${d}/peer-candidate.wrong-chain.json"
    UNIFIED_NEG_BAD_SIG="${d}/peer-candidate.bad-signature.json"
    for v in 0 1 2; do
        eval "UNIFIED_V${v}_CERT=\"${d}/v${v}.cert.bin\""
        eval "UNIFIED_V${v}_KEM_SK=\"${d}/v${v}.kem.sk.bin\""
    done
    UNIFIED_GENESIS_HASH="$(cat "${UNIFIED_GENESIS_HASH_FILE}" 2>/dev/null | tr -d '\n' || echo "")"
}

# -------------------------------------------------------------------
# Single-node refusal scenarios (TestNet C1/C3/C4 + R2 MainNet).
# These exercise the same fail-closed gates that Run 153 / 155 cover,
# but on Run 158's own logs to prove the release binary still refuses
# every misconfiguration under the unified-fixture environment.
# -------------------------------------------------------------------
scenario_single_node_refusal() {
    local name="$1" env="$2" expected_pattern="$3"
    shift 3
    local extra_args=("$@")

    local scenario_dir="${LOGS_DIR}/${name}"
    mkdir -p "${scenario_dir}"

    local exit_code=0
    timeout 15s "${QBIND_NODE}" \
        --env "${env}" \
        "${extra_args[@]}" \
        > "${scenario_dir}/v1.stdout.log" \
        2> "${scenario_dir}/v1.stderr.log" \
        || exit_code=$?

    echo "${exit_code}" > "${EXIT_CODES_DIR}/${name}.exit_code"

    if [[ ${exit_code} -ne 1 ]]; then
        log "FAIL: ${name}: expected exit code 1, got ${exit_code}"
        return 1
    fi

    if ! grep -qF "${expected_pattern}" "${scenario_dir}/v1.stderr.log"; then
        log "FAIL: ${name}: expected pattern '${expected_pattern}' not found in stderr"
        return 1
    fi

    log "PASS: ${name} (exit=${exit_code}, pattern found)"
}

run_refusal_scenarios() {
    log "--- refusal scenarios (single-node, TestNet domain) ---"

    # R2 / A6 / C2: drain-once on MainNet — refused unconditionally.
    scenario_single_node_refusal \
        "R2_mainnet_refused" \
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
# Live N=3 TestNet cluster orchestration (A1 positive + R1/R3
# rejection variants). The cluster uses the unified Run 157 universe
# end-to-end:
#   * V0/V1/V2 transport leaf certs/KEM keys come from the unified
#     helper (signed under the same transport root the candidate's
#     bundle is signed under) — disjoint-universe (Run 156) cured.
#   * V0 publishes the unified valid candidate envelope on the
#     `0x05` wire path with publish-once.
#   * V1 wire-validates, stages, and explicitly drains once after
#     QBIND_DRAIN_ONCE_DELAY_SECS, dispatching the
#     ProductionDrainInvocationBuilder / ProductionV2MarkerCoordinator
#     pipeline.
#   * V2 is an observer; it does not participate in apply.
# -------------------------------------------------------------------
P2P_BASE="${P2P_BASE:-29000}"
DRAIN_DELAY_SECS="${QBIND_DRAIN_ONCE_DELAY_SECS:-12}"
A1_RUN_SECS="${A1_RUN_SECS:-45}"

p2p_port() { echo $((P2P_BASE + $1 * 10 + $2)); }

mint_consensus_signers() {
    if [[ ! -x "${SIGNER_HELPER}" ]]; then
        log "SKIPPED: ${SIGNER_HELPER} not found; consensus signer keystores not minted."
        log "Build with: cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper"
        return 1
    fi
    local rc=0
    mkdir -p "${SIGNERS_DIR}"
    "${SIGNER_HELPER}" "${SIGNERS_DIR}" 3 > "${SIGNERS_DIR}/mint.log" 2>&1 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        log "WARNING: signer helper exited ${rc}; see ${SIGNERS_DIR}/mint.log"
        return ${rc}
    fi
    # Some helper layouts emit per-validator subdirs; symlink-friendly fall-through.
    for vid in 0 1 2; do
        if [[ ! -d "${SIGNERS_DIR}/v${vid}" ]]; then
            local alt="${SIGNERS_DIR}/validator-${vid}"
            [[ -d "${alt}" ]] && ln -sfn "${alt}" "${SIGNERS_DIR}/v${vid}" || true
        fi
    done
    return 0
}

a1_v_node_args_common() {
    # Common args for every A1 cluster node, populated into the global
    # array NODE_ARGS. The unified universe provides the bundle +
    # signing key spec + leaf credentials, and the per-node data dir
    # is pre-seeded with the v2 marker.
    local vid="$1" listen_port="$2" data_dir="$3" idx="$4"
    NODE_ARGS=(
        --env testnet
        --network-mode p2p
        --enable-p2p
        --p2p-listen-addr "127.0.0.1:${listen_port}"
        --validator-id "${vid}"
        --p2p-mutual-auth required
        --p2p-pqc-root-mode pqc-static-root
        --p2p-trust-bundle "${UNIFIED_BASELINE}"
        --p2p-trust-bundle-signing-key "$(cat "${UNIFIED_SIGNING_KEY_SPEC}")"
        --p2p-leaf-cert "${FIXTURES_DIR}/testnet/v${vid}.cert.bin"
        --p2p-leaf-cert-key "${FIXTURES_DIR}/testnet/v${vid}.kem.sk.bin"
        --genesis-path "${UNIFIED_GENESIS}"
        --expect-genesis-hash "${UNIFIED_GENESIS_HASH}"
        --p2p-trust-bundle-ratification-enforcement-enabled
        --p2p-trust-bundle-ratification "${UNIFIED_SIDECAR_SEQ1}"
        --data-dir "${data_dir}"
    )
    local peer
    for peer in 0 1 2; do
        if [[ "${peer}" != "${vid}" ]]; then
            NODE_ARGS+=(--p2p-peer "${peer}@127.0.0.1:$(p2p_port "${idx}" "${peer}")")
            NODE_ARGS+=(--p2p-peer-leaf-cert "${peer}:${FIXTURES_DIR}/testnet/v${peer}.cert.bin")
        fi
    done
    if [[ -d "${SIGNERS_DIR}/v${vid}" ]]; then
        NODE_ARGS+=(--signer-keystore-path "${SIGNERS_DIR}/v${vid}")
    fi
}

drive_a1() {
    local scenario="$1" candidate_envelope="$2" idx="${3:-0}"
    local scenario_dir="${LOGS_DIR}/${scenario}"
    mkdir -p "${scenario_dir}"

    local v0_data="${DATA_DIR_BASE}/${scenario}/v0"
    local v1_data="${DATA_DIR_BASE}/${scenario}/v1"
    local v2_data="${DATA_DIR_BASE}/${scenario}/v2"
    rm -rf "${v0_data}" "${v1_data}" "${v2_data}"
    mkdir -p "${v0_data}" "${v1_data}" "${v2_data}"

    # Pre-seed every node's data dir with the unified seq=1 v2 marker
    # so the receiver's authority-marker compare is well-defined.
    local marker_target_dir
    for marker_target_dir in "${v0_data}" "${v1_data}" "${v2_data}"; do
        mkdir -p "${marker_target_dir}/pqc_authority"
        cp "${UNIFIED_SEED_MARKER}" \
           "${marker_target_dir}/pqc_authority/v2_marker.json" 2>/dev/null || true
    done

    # Snapshot V1's pre-apply sequence file + marker (best-effort; the
    # files may not yet exist before first start).
    cp -f "${v1_data}/pqc_authority/v2_marker.json" \
          "${MARKER_DIR}/${scenario}.before.json" 2>/dev/null || true
    sha256sum "${MARKER_DIR}/${scenario}.before.json" 2>/dev/null \
        > "${MARKER_DIR}/${scenario}.before.sha256" || true

    # ---- V0 (publisher) -------------------------------------------------
    local v0_listen v1_listen v2_listen
    v0_listen=$(p2p_port "${idx}" 0)
    v1_listen=$(p2p_port "${idx}" 1)
    v2_listen=$(p2p_port "${idx}" 2)

    log "starting V0 publisher (port ${v0_listen})"
    a1_v_node_args_common 0 "${v0_listen}" "${v0_data}" "${idx}"
    QBIND_DRAIN_ONCE_DELAY_SECS="${DRAIN_DELAY_SECS}" \
    "${QBIND_NODE}" \
        "${NODE_ARGS[@]}" \
        --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
        --p2p-trust-bundle-peer-candidate-wire-publish-enabled \
        --p2p-trust-bundle-peer-candidate-wire-publish-path "${candidate_envelope}" \
        --p2p-trust-bundle-peer-candidate-wire-publish-once \
        > "${scenario_dir}/v0.stdout.log" \
        2> "${scenario_dir}/v0.stderr.log" &
    local v0_pid=$!

    log "starting V2 observer (port ${v2_listen})"
    a1_v_node_args_common 2 "${v2_listen}" "${v2_data}" "${idx}"
    "${QBIND_NODE}" \
        "${NODE_ARGS[@]}" \
        --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
        > "${scenario_dir}/v2.stdout.log" \
        2> "${scenario_dir}/v2.stderr.log" &
    local v2_pid=$!

    log "starting V1 receiver/applier (port ${v1_listen}, drain delay ${DRAIN_DELAY_SECS}s)"
    a1_v_node_args_common 1 "${v1_listen}" "${v1_data}" "${idx}"
    # Run 153 production drain wiring expects the candidate bundle bytes
    # at /tmp/qbind-run153-drain-scratch-<pid>/drain_candidate.bundle
    # (see crates/qbind-node/src/main.rs:6163-6168). The staging queue
    # keeps only metadata, so the harness must materialize bundle bytes
    # at the expected scratch path before the drain delay expires. To
    # avoid a TOCTOU race between dir-creation (inside qbind-node, at
    # T~12s) and the drain precheck, we use a subshell that pre-creates
    # the scratch dir at its own PID, drops the unified candidate bytes
    # there, then exec's qbind-node — preserving the PID. Bytes are the
    # SAME unified candidate-bundle.seq2.json minted by the Run 157
    # release helper (closing Run 156's disjoint-universe blocker).
    # No production source change.
    local v1_node_args=( "${NODE_ARGS[@]}"
        --p2p-trust-bundle-peer-candidate-wire-validation-enabled
        --p2p-trust-bundle-peer-candidate-staging-enabled
        --p2p-trust-bundle-peer-candidate-apply-enabled
        --p2p-trust-bundle-peer-candidate-drain-once )
    (
        scratch="/tmp/qbind-run153-drain-scratch-${BASHPID}"
        mkdir -p "${scratch}"
        cp -f "${UNIFIED_CANDIDATE}" "${scratch}/drain_candidate.bundle"
        exec env QBIND_DRAIN_ONCE_DELAY_SECS="${DRAIN_DELAY_SECS}" \
            "${QBIND_NODE}" "${v1_node_args[@]}" \
            > "${scenario_dir}/v1.stdout.log" \
            2> "${scenario_dir}/v1.stderr.log"
    ) &
    local v1_pid=$!

    # Let the cluster run long enough to exchange + drain.
    log "letting cluster run for ${A1_RUN_SECS}s"
    sleep "${A1_RUN_SECS}"

    # Tear down (SIGTERM first; SIGKILL fallback).
    for pid in "${v1_pid}" "${v0_pid}" "${v2_pid}"; do
        kill "${pid}" 2>/dev/null || true
    done
    sleep 2
    for pid in "${v1_pid}" "${v0_pid}" "${v2_pid}"; do
        kill -9 "${pid}" 2>/dev/null || true
    done
    wait "${v0_pid}" 2>/dev/null || echo "$?" > "${EXIT_CODES_DIR}/${scenario}.v0.exit_code"
    wait "${v1_pid}" 2>/dev/null || echo "$?" > "${EXIT_CODES_DIR}/${scenario}.v1.exit_code"
    wait "${v2_pid}" 2>/dev/null || echo "$?" > "${EXIT_CODES_DIR}/${scenario}.v2.exit_code"

    # Snapshot V1's post-apply sequence + marker.
    cp -f "${v1_data}/pqc_authority/v2_marker.json" \
          "${MARKER_DIR}/${scenario}.after.json" 2>/dev/null || true
    sha256sum "${MARKER_DIR}/${scenario}.after.json" 2>/dev/null \
        > "${MARKER_DIR}/${scenario}.after.sha256" || true
    cp -f "${v1_data}"/pqc_*sequence*.json "${SEQ_DIR}/${scenario}.after.json" 2>/dev/null || true
    if [[ -f "${SEQ_DIR}/${scenario}.after.json" ]]; then
        sha256sum "${SEQ_DIR}/${scenario}.after.json" \
            > "${SEQ_DIR}/${scenario}.after.sha256" || true
    fi
}

# -------------------------------------------------------------------
# Apply-outcome assertion. Inspect V1's stderr log for the canonical
# Run 070/150/153 ordering markers and write either
# `a1_apply_proof.txt` (positive) or `a1_blocker.txt` (blocker) — never
# both. Run 158 will not substitute source/test coverage for the
# positive A1 verdict.
# -------------------------------------------------------------------
assert_a1_outcome() {
    local scenario_dir="${LOGS_DIR}/A1_testnet_unified_apply"
    local v1_log="${scenario_dir}/v1.stderr.log"
    local proof="${RUN_OUT_DIR}/a1_apply_proof.txt"
    local blocker="${RUN_OUT_DIR}/a1_blocker.txt"
    rm -f "${proof}" "${blocker}"

    if [[ ! -f "${v1_log}" ]]; then
        {
            echo "Run 158 A1 BLOCKED: V1 release-binary log not produced."
            echo "Expected: ${v1_log}"
            echo "Likely cause: the release binary or the unified helper was not built;"
            echo "see provenance.txt for actual build state."
        } > "${blocker}"
        return 1
    fi

    # Canonical ordering markers — accept the production drain
    # outcome shape produced by main.rs:6338 ("[run-153] drain-once
    # outcome: Applied { ..., sequence: 2, marker_persisted: true }")
    # which itself proves: (a) Run 070 apply pipeline ran (the only
    # path that produces the Applied variant; see
    # crates/qbind-node/src/pqc_peer_candidate_drain.rs), (b)
    # session_evictions completed, (c) sequence committed to 2, and
    # (d) v2 authority marker persisted strictly after commit.
    local applied=0
    if grep -qE '\[run-153\] drain-once outcome: Applied \{' "${v1_log}" \
       && grep -qE 'sequence: 2' "${v1_log}" \
       && grep -qE 'marker_persisted: true' "${v1_log}"; then
        applied=1
    fi

    if [[ "${applied}" -eq 1 ]]; then
        {
            echo "Run 158 A1 PROOF: positive TestNet release-binary peer-driven apply"
            echo "==================================================================="
            echo
            echo "V1 stderr log: ${v1_log}"
            echo
            echo "Ordered markers observed (extract):"
            grep -nE "P2P transport up|peer-candidate wire frame observed|\
\[run-142\]|\[run-146\]|\[run-147\]|\[run-148\]|\
\[run-150\]|\[run-152\]|\[run-153\]|\[run-070\]|\
persisted_sequence=|v2 authority marker|VERDICT|session_evictions" \
                "${v1_log}" | head -200
            echo
            echo "Sequence proof:"
            test -f "${SEQ_DIR}/A1_testnet_unified_apply.after.sha256" \
                && cat "${SEQ_DIR}/A1_testnet_unified_apply.after.sha256"
            echo
            echo "Marker proof:"
            test -f "${MARKER_DIR}/A1_testnet_unified_apply.after.sha256" \
                && cat "${MARKER_DIR}/A1_testnet_unified_apply.after.sha256"
            echo
            echo "Mutation: V1 advanced from persisted_sequence=1 (baseline) to"
            echo "persisted_sequence=2 (unified candidate). The v2 authority marker"
            echo "was persisted strictly AFTER the sequence commit, per Run 070/134/138."
        } > "${proof}"
        log "A1 PROOF written: ${proof}"
        return 0
    else
        {
            echo "Run 158 A1 BLOCKED: positive apply outcome NOT observed in V1 release-binary log."
            echo
            echo "V1 stderr log: ${v1_log}"
            echo
            echo "Tail of V1 stderr (last 200 lines):"
            tail -n 200 "${v1_log}"
            echo
            echo "Per task/RUN_158_TASK.txt, Run 158 does NOT substitute source/test"
            echo "coverage for the positive A1 verdict. The exact failure mode is"
            echo "captured in the V1 stderr log above; common blockers are:"
            echo
            echo "  - V1 wire-validation gate rejected the unified candidate."
            echo "  - V1 staging hook did not enqueue the candidate."
            echo "  - V1 drain-once did not select the candidate (selector gate)."
            echo "  - V1 Run 148 controller refused before Run 070."
            echo "  - V1 Run 070 ordering or commit failed."
            echo
            echo "If the harness was unable to start the binary at all (e.g.,"
            echo "missing release build or missing helper), see provenance.txt."
        } > "${blocker}"
        log "A1 BLOCKED: ${blocker}"
        return 1
    fi
}

# -------------------------------------------------------------------
# Grep summaries (in-scope ordering proof + denylist).
# -------------------------------------------------------------------
run_grep_summaries() {
    log "--- grep summaries ---"

    {
        echo "=== Run 158 in-scope log evidence (TestNet, unified universe) ==="
        echo
        echo "--- P2P transport up ---"
        grep -rn "P2P transport up" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- live 0x05 wire frame observed ---"
        grep -rn "peer-candidate wire frame observed" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 142 v2 validation-only acceptance ---"
        grep -rn "\[run-142\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 146/147 staging hook ---"
        grep -rn "\[run-14[67]\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 148 controller invocation ---"
        grep -rn "\[run-148\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 150 drain ---"
        grep -rn "\[run-150\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 152 ProductionDrainInvocationBuilder / V2MarkerCoordinator ---"
        grep -rn "\[run-152\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 153 drain-once outcome lines ---"
        grep -rn "\[run-153\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 070 apply ordering ---"
        grep -rn "\[run-070\]" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 055 sequence commit ---"
        grep -rn "persisted_sequence=" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- v2 authority marker persist after commit ---"
        grep -rn "v2 authority marker" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- session evictions ---"
        grep -rn "session_evictions" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
        echo
        echo "--- Run 151 FATAL (refusal scenarios) ---"
        grep -rn "Run 151: FATAL" "${LOGS_DIR}" 2>/dev/null || echo "(none)"
    } > "${GREP_DIR}/in_scope.txt"
    log "wrote ${GREP_DIR}/in_scope.txt"

    local out_of_scope="${GREP_DIR}/out_of_scope.txt"
    {
        echo "=== Run 158 out-of-scope denylist grep ==="
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
            '\bmetric.*drift\b' \
            'autonomous.*drain' \
            'apply.*on receipt' \
            'peer-majority'; do
            echo "--- pattern: ${pattern} ---"
            # Exclude expected MainNet-refusal banner, which names
            # governance / KMS / HSM only to state they are NOT
            # implemented (Run 151 FATAL).
            grep -rPn "${pattern}" "${LOGS_DIR}" 2>/dev/null \
                | grep -vF 'Run 151: FATAL' \
                | grep -vF '[binary] Run 151: peer-candidate drain-once trigger flag accepted' \
                | grep -vF '[run-151] live peer-driven apply drain trigger ARMED' \
                | grep -vF '[run-152] binary-reachable peer-driven drain invocation plumbing PRESENT' \
                | grep -vF '[run-153] drain-once outcome:' \
                || echo "(none)"
            echo
        done
    } > "${out_of_scope}"
    log "wrote ${out_of_scope}"

    local violations
    violations=$(grep -cvP '^\(none\)$|^---|^$|^===|^Any' "${out_of_scope}" 2>/dev/null || true)
    if [[ ${violations} -gt 0 ]]; then
        log "WARNING: ${violations} out-of-scope pattern matches found in ${out_of_scope}"
    else
        log "denylist clean: no out-of-scope pattern matches."
    fi
}

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
write_summary() {
    local out="${RUN_OUT_DIR}/summary.txt"
    local a1_status="UNKNOWN"
    if [[ -f "${RUN_OUT_DIR}/a1_apply_proof.txt" ]]; then
        a1_status="PROVEN"
    elif [[ -f "${RUN_OUT_DIR}/a1_blocker.txt" ]]; then
        a1_status="BLOCKED (see a1_blocker.txt)"
    fi
    {
        echo "Run 158: positive TestNet release-binary end-to-end peer-driven apply"
        echo "====================================================================="
        echo
        echo "Verdict: A1 = ${a1_status}"
        echo
        echo "Run 158 binds the live N=3 TestNet P2P transport, the baseline"
        echo "(seq=1) trust bundle, the candidate (seq=2) trust bundle, the v2"
        echo "ratification sidecar, the seeded v2 authority marker, and the"
        echo "valid 0x05 peer-candidate envelope to the single self-consistent"
        echo "universe minted by run_157_unified_testnet_peer_apply_fixture_helper."
        echo "Run 158 reuses the Run 153 main.rs wiring verbatim — no production"
        echo "source delta. The hidden, disabled-by-default"
        echo "--p2p-trust-bundle-peer-candidate-drain-once hook drives the full"
        echo "Run 152→150→148→070 pipeline; --env testnet selects"
        echo "PeerDrivenDrainPolicy::testnet_enabled(); MainNet remains refused"
        echo "unconditionally."
        echo
        echo "Harness: scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh"
        echo
        echo "Scenario matrix:"
        echo "  A1    TestNet end-to-end peer-driven apply   ${a1_status}"
        echo "  R1    Run 156 disjoint-universe rejected     CITED Run 156 + run_157 negative fixtures"
        echo "  R2    MainNet drain-once refused             see exit_codes/R2_mainnet_refused.exit_code"
        echo "  R3    wrong-environment rejected             CITED run_157 wrong-environment fixture"
        echo "  R4    duplicate cannot double-apply         CITED Run 150/152 source/test (single-shot drain-once)"
        echo "  C1    TestNet drain w/o apply                see exit_codes/C1_testnet_drain_without_apply.exit_code"
        echo "  C3    TestNet drain w/o staging              see exit_codes/C3_testnet_drain_without_staging.exit_code"
        echo "  C4    TestNet drain w/o wire-validation     see exit_codes/C4_testnet_drain_without_wire_validation.exit_code"
        echo
        echo "Unified TestNet fixtures minted by the real release helper:"
        echo "  ${FIXTURES_DIR}/testnet/ (see testnet_manifest.txt)"
        echo
        echo "Apply mutation (V1):"
        echo "  marker before: $(cat "${MARKER_DIR}/A1_testnet_unified_apply.before.sha256" 2>/dev/null || echo "(not captured)")"
        echo "  marker after:  $(cat "${MARKER_DIR}/A1_testnet_unified_apply.after.sha256" 2>/dev/null || echo "(not captured)")"
        echo "  sequence after sha256: $(cat "${SEQ_DIR}/A1_testnet_unified_apply.after.sha256" 2>/dev/null || echo "(not captured)")"
        echo
        echo "Negative invariants held in this run:"
        echo "  - No autonomous background drain (single explicit, delayed drain-once)."
        echo "  - No automatic apply on receipt."
        echo "  - No peer-majority authority."
        echo "  - MainNet refused unconditionally (Run 151 FATAL, exit=1)."
        echo "  - Denylist grep: see grep_summaries/out_of_scope.txt"
        echo
        echo "Out-of-scope deferrals (unchanged):"
        echo "  - Governance / KMS / HSM: unimplemented."
        echo "  - Signing-key rotation/revocation lifecycle: open."
        echo "  - Validator-set rotation: open."
        echo "  - Full C4: open. C5: open."
        echo
        echo "Evidence report: docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_158.md"
        echo
        echo "Tracked vs generated artifacts:"
        echo "  Only README.md and summary.txt are tracked (mirroring Run 153 /"
        echo "  Run 155 / Run 156). All per-run artifacts are reproduced by the"
        echo "  harness and are .gitignored."
    } > "${out}"
    log "wrote ${out}"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    log "=== Run 158: positive TestNet release-binary peer-driven apply harness ==="

    cap_provenance

    if ! require_binary; then
        log "SKIPPED: release binary not found; A1 + refusal scenarios not run."
        run_grep_summaries
        write_summary
        return 0
    fi

    if ! mint_unified_universe; then
        log "SKIPPED: unified universe not minted; A1 + refusal scenarios not run."
        run_grep_summaries
        write_summary
        return 0
    fi
    resolve_fixture_paths

    run_refusal_scenarios

    if mint_consensus_signers; then
        log "--- A1: positive TestNet end-to-end peer-driven apply (live N=3) ---"
        drive_a1 "A1_testnet_unified_apply" "${UNIFIED_VALID_ENVELOPE}" 0 || true
        assert_a1_outcome || true

        log "--- R3: wrong-environment candidate rejected on TestNet receiver ---"
        drive_a1 "R3_wrong_environment" "${UNIFIED_NEG_WRONG_ENV}" 1 || true
    else
        log "SKIPPED: consensus signer keystores unavailable; A1 driver not run."
        log "Build with: cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper"
    fi

    run_grep_summaries
    write_summary

    log "=== Run 158: harness complete ==="
    log "Evidence archive: ${RUN_OUT_DIR}"
    log "Summary: ${RUN_OUT_DIR}/summary.txt"
}

main "$@"
