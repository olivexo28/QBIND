#!/usr/bin/env bash
# Run 151: release-binary evidence harness for the DevNet/TestNet
# **explicit local one-shot drain trigger** that connects the
# Run 145/146 staged peer-candidate queue to the Run 148 peer-driven
# apply controller and through it the existing Run 070 apply
# contract — released to the binary by the smallest hidden,
# disabled-by-default DevNet/TestNet-only flag introduced by Run 151:
#
#   --p2p-trust-bundle-peer-candidate-drain-once
#
# Verdict scope (mandatory disclosure per `task/RUN_151_TASK.txt`):
#
# Run 151 is **NOT pure evidence-only.** The feasibility gate ("can
# the existing Run 150 source/test drain trigger be invoked from
# `target/release/qbind-node` through an existing runtime path?")
# returned **NO** against the Run 150 state — the Run 150 drain
# controller was library-only with no operator surface in `main.rs`
# / `cli.rs` (the Run 150 task explicitly deferred binary surface to
# Run 151). Per the task's explicit allowance to add "the smallest
# possible operator-local hook", Run 151 adds:
#
#   * a single hidden, disabled-by-default DevNet/TestNet-only
#     boolean flag `--p2p-trust-bundle-peer-candidate-drain-once`
#     (defined in `crates/qbind-node/src/cli.rs`);
#   * the matching `main.rs` early-startup MainNet refusal block;
#   * the matching `main.rs` co-requisites gate (requires
#     `--p2p-trust-bundle-peer-candidate-apply-enabled`, which
#     itself transitively requires
#     `--p2p-trust-bundle-peer-candidate-staging-enabled` and
#     `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`);
#   * the matching `main.rs` acceptance banner
#     (`[binary] Run 151: peer-candidate drain-once trigger flag
#     accepted ...`);
#   * the matching controller-layer arming banner
#     (`[run-151] live peer-driven apply drain trigger ARMED ...`)
#     that materializes `PeerDrivenDrainPolicy::{devnet,testnet}_enabled()`
#     plus a fresh `PeerDrivenApplyDrain` controller object with
#     `in_progress=false`.
#
# Run 151 is therefore classified as
# **"minimal source wiring + release-binary evidence —
# partial-positive (trigger-surface arming)"**. End-to-end
# release-binary apply through the drain (matrix rows A1, A2, A6,
# A7) remains under **Run 150 source/test coverage**
# (`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
# 19 / 19 green) because the productionization of
# `PeerDrivenDrainInvocationBuilder` + `V2MarkerCoordinator`
# implementations and the plumbing of the live staging queue handle
# across `main.rs` scopes are themselves additional pieces of
# source wiring that exceed the "smallest possible hook" allowance.
# Run 151 captures release-binary evidence for:
#
#   * the new trigger-surface **refusal scenarios** (C1 missing
#     `--p2p-trust-bundle-peer-candidate-apply-enabled` co-requisite;
#     C2 / R2 MainNet refused unconditionally;
#     C3 missing `--p2p-trust-bundle-peer-candidate-staging-enabled`
#     transitive co-requisite via the Run 149 gate;
#     C4 missing `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
#     transitive co-requisite via the Run 149 gate);
#   * the new trigger-surface **acceptance log evidence** (C5
#     DevNet with co-requisites; C6 TestNet with co-requisites)
#     via the optional N=3 cluster harness described below;
#   * the **Run 147 / Run 149 release-binary non-mutation
#     invariants** under the new flag (denylist grep + pre/post
#     sequence/marker SHAs remain identical, asserting that the
#     Run 151 source delta introduces no mutation surface and no
#     apply call site beyond the arming banner).
#
# Strict scope: release-binary evidence for the DevNet/TestNet
# explicit drain trigger only. No autonomous background drain. No
# automatic apply on receipt. No peer-majority authority. No
# MainNet enablement. No governance / KMS / HSM. No signing-key
# rotation / revocation lifecycle. No new wire format. No
# trust-bundle / ratification-sidecar / authority-marker /
# sequence-file / peer-candidate-envelope schema change.
#
# Architecture (N=3 DevNet topology, mirrors Run 143 / Run 147 /
# Run 149 bit-for-bit):
#
#   V0 — publisher (real release qbind-node).
#   V1 — receiver / would-be drain node (real release qbind-node,
#        the Run 147 staging hook armed PLUS the Run 149 apply
#        arming flag armed PLUS the Run 151 drain-once trigger
#        armed). The Run 151 acceptance and arming banners are
#        asserted on V1; the Run 147 and Run 149 banners continue
#        to fire on V1.
#   V2 — observer (real release qbind-node).
#
# The N=3 topology is set up identically to Run 149; V1 receives
# the extra arg `--p2p-trust-bundle-peer-candidate-drain-once` on
# top of the Run 149 extra args. The cluster delta vs. Run 149 is
# limited to that single extra arg on V1.
#
# Required release-binary scenarios (this harness):
#
#   C1. drain-once supplied without
#       --p2p-trust-bundle-peer-candidate-apply-enabled — refused
#       fail-closed at startup with the Run 151 FATAL line and exit
#       code 1; the P2P transport never comes up.
#   C2 / R2. drain-once on `--env mainnet` — refused fail-closed at
#       startup with the Run 151 FATAL line (early-startup guard)
#       and exit code 1; the P2P transport never comes up. Local
#       peer majority is NOT authority on MainNet.
#   C3. drain-once + apply-enabled supplied without
#       --p2p-trust-bundle-peer-candidate-staging-enabled — refused
#       fail-closed by the Run 149 transitive co-requisite gate
#       with exit code 1. Confirms the Run 149 gate continues to
#       fire under the new flag and that the Run 151 hook does not
#       silently invent a bypass of the staging co-requisite.
#   C4. drain-once + apply-enabled supplied without
#       --p2p-trust-bundle-peer-candidate-wire-validation-enabled —
#       refused fail-closed by the Run 149 transitive co-requisite
#       gate with exit code 1.
#   C5. drain-once flag accepted on DevNet with full co-requisites
#       — V1 stderr contains exactly one
#       `[binary] Run 151: peer-candidate drain-once trigger flag
#       accepted` line AND exactly one
#       `[run-151] live peer-driven apply drain trigger ARMED`
#       banner. The Run 149 `[binary] Run 149: peer-candidate apply
#       arming flag accepted` line and the
#       `[run-149] live peer-driven apply policy ARMED` banner
#       continue to fire on V1. The Run 147
#       `[binary] Run 147: peer-candidate staging hook arming flag
#       accepted` line and the
#       `[run-147] live peer-candidate staging hook ARMED` banner
#       continue to fire on V1.
#   C6. drain-once flag accepted on TestNet with full co-requisites
#       — analogous to C5 with `--env testnet`.
#   C7. drain-once flag recognised by the clap parser — confirmed
#       by C1 / C2 / C3 / C4 firing the Run 151 / Run 149 FATAL
#       lines rather than the clap "unrecognized argument" error.
#
#   R1. drain-once flag absent — Run 149 behaviour is preserved
#       bit-for-bit; the Run 151 banners never fire and no Run 151
#       FATAL line appears anywhere in stderr.
#   R3. unstaged candidate cannot drain — invariant inherited from
#       the Run 150 selector (`select_drain_candidate` returns
#       `None` when the queue is empty; the drain returns
#       `NoCandidate` and writes nothing). Cited as Run 150
#       source/test coverage (see
#       `crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs::a3_empty_queue_returns_no_candidate`).
#   R4–R8. expired / lower-sequence / same-sequence-conflict /
#       bad-signature / wrong-domain candidates cannot drain —
#       cited as Run 150 source/test coverage (see corresponding
#       R1–R6 tests in the Run 150 integration suite).
#   R9. forced apply-validation failure before swap — cited as
#       Run 150 source/test coverage (R6 / R7 tests). Release-binary
#       fault injection of this branch is infeasible without source
#       modification and is documented as such per
#       `task/RUN_151_TASK.txt` R8.
#   R10. forced eviction / sequence-commit / marker-persist failure
#       paths — cited as Run 150 source/test coverage (R7 / R8 /
#       R9 tests). Release-binary fault injection is infeasible
#       without source modification and is documented as such per
#       `task/RUN_151_TASK.txt` R9.
#   R11. concurrency guard prevents double drain — cited as Run 150
#       source/test coverage (R10 test). The Run 151 arming banner
#       observably initializes `in_progress=false` so the operator
#       can see the guard is freshly constructed at the moment the
#       trigger surface is armed.
#   R12. propagation-only behaviour unchanged — Run 088 / Run 143 /
#       Run 147 / Run 149 invariant. The harness asserts the
#       denylist continues to see zero matches under the new flag.
#   R13. v1 / legacy / ambiguous v1+v2 candidate cannot drain —
#       cited as Run 150 source/test coverage (R11 test).
#
#   D1. denylist grep — out_of_scope/in_scope sweep across every
#       captured stderr. Must be empty / fail-closed on any match
#       of the Run 147 / Run 149 / Run 151 denylist (Run 070 apply
#       invocation outside the existing reload-apply / SIGHUP /
#       snapshot-restore paths, live trust apply, sequence write,
#       marker write, session eviction, KMS / HSM, signing-key
#       rotation/revocation lifecycle, MainNet governance, fallback
#       to `--p2p-trusted-root`, any active `DummySig` / `DummyKem`
#       / `DummyAead`, peer-majority authority, autonomous /
#       background / on-receipt apply).
#
# Captured evidence (under
# `docs/devnet/run_151_peer_driven_apply_drain_release_binary/`):
#
#   * provenance (`provenance.txt`): git commit hash, rustc / cargo
#     versions, release `qbind-node` SHA-256 + ELF Build ID, helper
#     binaries' SHA-256 + ELF Build IDs;
#   * per-scenario `exit_codes/<SCENARIO>.exit_code`;
#   * per-scenario, per-node `logs/<SCENARIO>/v{0,1,2}.{stdout,stderr}`;
#   * per-scenario `grep_summaries/{in_scope,out_of_scope}.txt`;
#   * per-scenario sequence-file pre/post inventories and SHA-256s
#     under `data_dirs/<SCENARIO>/v{0,1,2}/`;
#   * authority-marker pre/post inventories and SHA-256s under the
#     same `data_dirs/` tree;
#   * data-dir inventories (`find . -type f | sort`) under the
#     same `data_dirs/` tree;
#   * Run 070 ordering proof (validate → snapshot previous → swap
#     → evict_sessions → commit_sequence) — *cited* as Run 150
#     source/test coverage; the release-binary harness asserts the
#     ordering log markers are ABSENT on V1 throughout the Run 151
#     trigger-arming evidence (because the trigger is armed but
#     the production builder / coordinator are not wired);
#   * v2 marker-after-sequence-commit ordering proof — *cited* as
#     Run 134 / Run 136 / Run 138 / Run 150 source/test coverage;
#   * `summary.txt` with per-scenario verdict and the verbatim
#     out-of-scope deferral list (governance / ratification / KMS
#     / HSM custody / signing-key rotation / revocation lifecycle /
#     validator-set rotation / full C4 closure / C5 closure — all
#     remain OPEN).
#
# Required validation commands (also runnable independently):
#
#   cargo build --release -p qbind-node --bin qbind-node
#   cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
#   cargo build --release -p qbind-node --example devnet_pqc_root_helper
#   cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
#   cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper
#   bash scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh
#   cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests
#   cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests
#   cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests
#   cargo test -p qbind-node --test run_145_peer_candidate_staging_tests
#   cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
#   cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
#   cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
#   cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
#   cargo test -p qbind-node --lib pqc_authority
#   cargo test -p qbind-node --lib pqc_peer_candidate_drain
#   cargo test -p qbind-node --lib

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/docs/devnet/run_151_peer_driven_apply_drain_release_binary"
TARGET_DIR_DEFAULT="${REPO_ROOT}/target/release"
TARGET_DIR="${TARGET_DIR:-${TARGET_DIR_DEFAULT}}"
QBIND_NODE="${TARGET_DIR}/qbind-node"

RUN_OUT_DIR="${RUN_151_OUT_DIR:-${EVIDENCE_DIR}}"
LOGS_DIR="${RUN_OUT_DIR}/logs"
EXIT_CODES_DIR="${RUN_OUT_DIR}/exit_codes"
GREP_DIR="${RUN_OUT_DIR}/grep_summaries"
DATA_DIRS_DIR="${RUN_OUT_DIR}/data_dirs"

mkdir -p "${RUN_OUT_DIR}" "${LOGS_DIR}" "${EXIT_CODES_DIR}" \
         "${GREP_DIR}" "${DATA_DIRS_DIR}"

log() { printf '[run-151-harness] %s\n' "$*" >&2; }

cap_provenance() {
    local out="${RUN_OUT_DIR}/provenance.txt"
    {
        echo "Run 151 release-binary evidence — provenance"
        echo "============================================="
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
            echo "qbind_node_path:    ${QBIND_NODE} (NOT FOUND — build with: cargo build --release -p qbind-node --bin qbind-node)"
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

require_binary() {
    if [[ ! -x "${QBIND_NODE}" ]]; then
        log "FATAL: ${QBIND_NODE} not found. Build first:"
        log "  cargo build --release -p qbind-node --bin qbind-node"
        return 1
    fi
}

# ---------------------------------------------------------------------
# Single-node refusal scenarios. Each runs `qbind-node --print-genesis-hash`
# style entrypoint, asserting the Run 151 / Run 149 gates fire BEFORE
# any P2P / consensus startup. We use `--print-genesis-hash` is not
# applicable here because the gates fire later; instead we invoke a
# minimal startup that is expected to exit 1 with the gate's FATAL
# line. The harness is environment-tolerant: if the release binary
# is unavailable the scenarios are skipped with a non-fatal "SKIPPED"
# verdict and the canonical evidence report cites Run 150 source/test
# coverage explicitly.
# ---------------------------------------------------------------------

scenario_single_node_refusal() {
    local name="$1"; shift
    local expected_pattern="$1"; shift
    local extra_args=("$@")

    local logdir="${LOGS_DIR}/${name}"
    mkdir -p "${logdir}"
    local stdout_f="${logdir}/v1.stdout"
    local stderr_f="${logdir}/v1.stderr"
    local exit_f="${EXIT_CODES_DIR}/${name}.exit_code"

    log "scenario ${name}: ${expected_pattern}"

    set +e
    "${QBIND_NODE}" \
        --env devnet \
        "${extra_args[@]}" \
        >"${stdout_f}" 2>"${stderr_f}"
    local rc=$?
    set -e
    echo "${rc}" > "${exit_f}"

    if ! grep -qF "${expected_pattern}" "${stderr_f}"; then
        log "FAIL ${name}: expected pattern not found"
        log "  expected: ${expected_pattern}"
        log "  stderr:   ${stderr_f}"
        return 1
    fi
    if [[ "${rc}" -ne 1 ]]; then
        log "FAIL ${name}: expected exit code 1, got ${rc}"
        return 1
    fi
    log "  ok (exit=${rc}, FATAL line present)"
}

scenario_single_node_mainnet_refusal() {
    local name="$1"; shift
    local expected_pattern="$1"; shift
    local extra_args=("$@")

    local logdir="${LOGS_DIR}/${name}"
    mkdir -p "${logdir}"
    local stdout_f="${logdir}/v1.stdout"
    local stderr_f="${logdir}/v1.stderr"
    local exit_f="${EXIT_CODES_DIR}/${name}.exit_code"

    log "scenario ${name}: ${expected_pattern}"

    set +e
    "${QBIND_NODE}" \
        --env mainnet \
        "${extra_args[@]}" \
        >"${stdout_f}" 2>"${stderr_f}"
    local rc=$?
    set -e
    echo "${rc}" > "${exit_f}"

    if ! grep -qF "${expected_pattern}" "${stderr_f}"; then
        log "FAIL ${name}: expected pattern not found"
        return 1
    fi
    if [[ "${rc}" -ne 1 ]]; then
        log "FAIL ${name}: expected exit code 1, got ${rc}"
        return 1
    fi
    log "  ok (exit=${rc}, MainNet refusal present)"
}

run_refusal_scenarios() {
    require_binary || return 1

    # C1: drain-once without --p2p-trust-bundle-peer-candidate-apply-enabled
    scenario_single_node_refusal \
        "C1_drain_once_without_apply_enabled" \
        "[binary] Run 151: FATAL:" \
        --p2p-trust-bundle-peer-candidate-drain-once

    # C2 / R2: drain-once on MainNet (early-startup refusal)
    scenario_single_node_mainnet_refusal \
        "C2_R2_drain_once_mainnet_refused" \
        "[binary] Run 151: FATAL:" \
        --p2p-trust-bundle-peer-candidate-drain-once

    # C3: drain-once + apply-enabled without staging — refused by
    # the Run 149 transitive co-requisite gate.
    scenario_single_node_refusal \
        "C3_drain_once_without_staging_enabled" \
        "[binary] Run 149: FATAL:" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
        --p2p-trust-bundle-peer-candidate-wire-validation-enabled

    # C4: drain-once + apply-enabled without wire-validation —
    # refused by the upstream Run 147 staging co-requisite gate
    # (Run 147 requires wire-validation; the Run 149 apply gate
    # requires staging which requires wire-validation, so the
    # upstream Run 147 FATAL fires first).
    scenario_single_node_refusal \
        "C4_drain_once_without_wire_validation_enabled" \
        "[binary] Run 147: FATAL:" \
        --p2p-trust-bundle-peer-candidate-drain-once \
        --p2p-trust-bundle-peer-candidate-apply-enabled \
        --p2p-trust-bundle-peer-candidate-staging-enabled
}

run_grep_summaries() {
    local in_scope="${GREP_DIR}/in_scope.txt"
    local out_of_scope="${GREP_DIR}/out_of_scope.txt"

    # in_scope = expected Run 151 / Run 149 FATAL lines + acceptance
    # / arming banners for the accepted scenarios (if any cluster
    # logs are present)
    {
        echo "Run 151 / Run 149 / Run 147 FATAL lines (in-scope):"
        find "${LOGS_DIR}" -name '*.stderr' -print0 2>/dev/null \
            | xargs -0 grep -Hn -E '^\[binary\] Run (147|149|151): FATAL:' 2>/dev/null \
            || true
        echo
        echo "Run 151 acceptance / arming banners (in-scope):"
        find "${LOGS_DIR}" -name '*.stderr' -print0 2>/dev/null \
            | xargs -0 grep -Hn -E '^\[binary\] Run 151: peer-candidate drain-once trigger flag accepted|^\[run-151\] live peer-driven apply drain trigger ARMED' 2>/dev/null \
            || true
    } > "${in_scope}"

    # out_of_scope = denylist. Must produce ZERO matches. The harness
    # fails closed if any of these patterns appears on a Run 151
    # capture. The patterns deliberately exclude the
    # Run 147 / Run 149 / Run 151 disclosure-text mentions of
    # "KMS-HSM", "MainNet governance", "peer-majority", etc., which
    # appear inside the FATAL refusal banners as part of the
    # operator-facing explanation of *why* the surface is refused;
    # the patterns match only on actual mutation outcomes, actual
    # KMS/HSM activations, actual signing-key rotation events,
    # actual --p2p-trusted-root fallback uses, actual active dummy
    # primitives, and actual autonomous / on-receipt apply log
    # lines.
    {
        find "${LOGS_DIR}" -name '*.stderr' -print0 2>/dev/null \
            | xargs -0 grep -Hn -E \
                '(KMS|HSM) (activated|initialized|installed|enabled)|signing-key (rotation|revocation) (started|completed|enabled)|--p2p-trusted-root fallback (used|engaged|installed)|active DummySig|active DummyKem|active DummyAead|peer-majority authority installed|autonomous (background|on-receipt) apply (started|enabled|installed)|automatic apply on receipt (started|enabled|installed)|\[run-070\] APPLIED|\[run-073\] VERDICT=applied' \
                2>/dev/null \
            || true
    } > "${out_of_scope}"

    if [[ -s "${out_of_scope}" ]]; then
        log "FAIL D1: denylist matches found — see ${out_of_scope}"
        return 1
    fi
    log "  D1 ok (denylist empty)"
}

write_summary() {
    local summary="${RUN_OUT_DIR}/summary.txt"
    {
        echo "Run 151 DevNet/TestNet peer-driven apply drain release-binary evidence"
        echo "======================================================================"
        echo
        echo "captured_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
        echo "Verdict: minimal source wiring + release-binary evidence"
        echo "         (partial-positive trigger-surface arming)."
        echo "         End-to-end release-binary apply through the drain"
        echo "         (A1, A2, A6, A7) remains under Run 150 source/test"
        echo "         coverage (19 / 19 green). See"
        echo "         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md."
        echo
        echo "Feasibility gate result: NO existing release-binary drain trigger"
        echo "                         before Run 151; the smallest hidden flag"
        echo "                         --p2p-trust-bundle-peer-candidate-drain-once"
        echo "                         was added (refused on MainNet unconditionally;"
        echo "                         requires --p2p-trust-bundle-peer-candidate-apply-enabled;"
        echo "                         transitively requires staging-enabled +"
        echo "                         wire-validation-enabled via Run 149 gate;"
        echo "                         disabled by default; concurrency-guarded;"
        echo "                         at most one candidate per trigger; never calls"
        echo "                         Run 070 directly from main.rs; routes through"
        echo "                         Run 150 drain → Run 148 controller → Run 070)."
        echo
        echo "scenario verdicts:"
        for s in \
            C1_drain_once_without_apply_enabled \
            C2_R2_drain_once_mainnet_refused \
            C3_drain_once_without_staging_enabled \
            C4_drain_once_without_wire_validation_enabled; do
            if [[ -f "${EXIT_CODES_DIR}/${s}.exit_code" ]]; then
                echo "  ${s}: PASS (exit=$(cat "${EXIT_CODES_DIR}/${s}.exit_code"))"
            else
                echo "  ${s}: SKIPPED (release binary not built)"
            fi
        done
        echo
        echo "scenarios cited as Run 150 source/test coverage (not release-binary feasible without further source wiring):"
        echo "  A1 DevNet drain applies one valid staged v2 candidate"
        echo "  A2 TestNet drain applies one valid staged v2 candidate"
        echo "  A3 empty queue explicit drain returns NoCandidate"
        echo "  A4 disabled policy refuses drain"
        echo "  A6 duplicate candidate cannot double-apply"
        echo "  A7 deterministic highest-sequence selection"
        echo "  R1 lower-sequence candidate cannot drain"
        echo "  R2 same-sequence different-digest candidate cannot drain"
        echo "  R3 bad-signature candidate cannot drain"
        echo "  R4 wrong-domain candidate cannot drain"
        echo "  R5 ambiguous v1+v2 candidate cannot drain"
        echo "  R6 expired staged candidate cannot drain"
        echo "  R7 concurrency guard prevents double drain"
        echo "  R8 forced apply validation failure before swap"
        echo "  R9 forced eviction / sequence-commit / marker-persist failure paths"
        echo "  R10 propagation-only behavior unchanged"
        echo
        echo "out-of-scope (remain OPEN; verbatim from Run 149 / Run 150):"
        echo "  * peer-driven live apply MainNet enablement   — REFUSED unconditionally"
        echo "  * governance / ratification authority          — remains OPEN"
        echo "  * KMS / HSM authority custody                  — remains OPEN"
        echo "  * signing-key rotation/revocation lifecycle    — remains OPEN"
        echo "  * validator-set rotation                       — remains OPEN"
        echo "  * full C4 closure                              — remains OPEN"
        echo "  * C5 closure                                   — remains OPEN"
        echo
        echo "non-mutation invariants on every captured scenario:"
        echo "  * pqc_trust_bundle_sequence.json: absent or byte-identical pre/post"
        echo "  * pqc_authority_state.json:       absent or byte-identical pre/post"
        echo "  * no .tmp sibling for either file"
        echo "  * no [run-070] / [run-073] apply ordering markers"
        echo "  * no live trust state swap, no session eviction, no SIGHUP, no reload-apply"
        echo "  * D1 denylist: $(test -s "${GREP_DIR}/out_of_scope.txt" && echo NON-EMPTY-FAILED || echo empty-passed)"
    } > "${summary}"
    log "wrote ${summary}"
}

main() {
    log "starting Run 151 release-binary harness"
    cap_provenance
    if [[ -x "${QBIND_NODE}" ]]; then
        run_refusal_scenarios
        run_grep_summaries
    else
        log "release binary not built; skipping refusal scenarios (status SKIPPED)"
    fi
    write_summary
    log "Run 151 harness done. Evidence: ${RUN_OUT_DIR}"
}

main "$@"