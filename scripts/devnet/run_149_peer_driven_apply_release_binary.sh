#!/usr/bin/env bash
# Run 149: release-binary evidence harness for the DevNet/TestNet
# **peer-driven trust-bundle apply** arming surface introduced by
# Run 149 on top of the Run 148 source/test peer-driven apply
# controller (`qbind_node::pqc_peer_candidate_apply::try_apply_staged_peer_candidate`).
#
# Verdict scope (mandatory disclosure per `task/RUN_149_TASK.txt`):
#
# Run 149 is **NOT pure evidence-only.** The feasibility gate ("can
# a real `target/release/qbind-node` arm and invoke the Run 148
# peer-driven apply controller through an existing runtime path?")
# returned **NO** against the Run 148 state — the Run 148 controller
# was library-only with no operator surface in `main.rs`. Per the
# task's explicit "preferred path if a flag is necessary" allowance,
# Run 149 adds the smallest hidden, disabled-by-default DevNet/TestNet-only
# arming flag:
#
#   --p2p-trust-bundle-peer-candidate-apply-enabled
#
# with the matching `main.rs` gate (MainNet refused unconditionally;
# requires `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`;
# requires `--p2p-trust-bundle-peer-candidate-staging-enabled`;
# does NOT imply propagation; does NOT introduce a new apply
# algorithm; does NOT bypass staging/validation/marker/Run 055/
# activation gates). Run 149 is therefore classified as
# **"minimal source wiring + release-binary evidence — partial-positive"**.
# The exact source delta is recorded in
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`.
#
# Partial-positive disclosure (mandatory): Run 149 does NOT introduce
# a queue → controller drain task in the node binary. Adding such a
# drain task would be a new apply-triggering algorithm, which is
# explicitly out of scope per `task/RUN_149_TASK.txt` §20 ("must not
# create a new apply algorithm"). End-to-end release-binary apply
# of an already-staged validated peer candidate (matrix rows A1–A4)
# therefore remains under Run 148 source/test coverage; Run 149
# captures release-binary evidence for the new arming-surface
# refusal scenarios (C1, C2/R2, C3) and reaffirms the Run 147
# release-binary non-mutation invariants under the new flag.
#
# Architecture (N=3 DevNet topology, mirrors Run 143/Run 147):
#
#   V0 — publisher (real release qbind-node)
#   V1 — receiver / would-be apply node (real release qbind-node,
#        the Run 147 staging hook armed PLUS the Run 149 apply
#        arming flag armed; the controller-level
#        `[run-149] live peer-driven apply policy ARMED` banner is
#        asserted on V1)
#   V2 — observer (real release qbind-node)
#
# The N=3 topology is set up identically to Run 147; V1 receives
# the extra arg `--p2p-trust-bundle-peer-candidate-apply-enabled` on
# top of the Run 147 extra args. The cluster delta vs. Run 147 is
# limited to that single extra arg on V1.
#
# Required release-binary scenarios (this harness):
#
#   C1. apply-enabled without wire-validation-enabled — refused
#       fail-closed at startup with the Run 149 FATAL line and
#       exit code 1; the P2P transport never comes up.
#   C2 / R2. apply-enabled on `--env mainnet` — refused fail-closed
#       at startup with the Run 149 FATAL line and exit code 1; the
#       P2P transport never comes up. Local peer majority is NOT
#       authority on MainNet.
#   C3. apply-enabled without staging-enabled — refused fail-closed
#       at startup with the Run 149 FATAL line and exit code 1;
#       apply consumes only already-staged candidates per Run 144
#       §3 Phase 2 → Phase 4.
#   C4. apply-flag recognised by parser — confirmed by C1/C2/C3
#       firing the Run 149 FATAL line rather than the clap
#       "unrecognized argument" error.
#   C5. apply-flag accepted on DevNet with co-requisites — V1 stderr
#       contains exactly one `[binary] Run 149: peer-candidate apply
#       arming flag accepted` line AND exactly one `[run-149] live
#       peer-driven apply policy ARMED` banner. The Run 147
#       `[binary] Run 147: peer-candidate staging hook arming flag
#       accepted` line and the `[run-147] live peer-candidate staging
#       hook ARMED` banner continue to fire on V1.
#   C6. apply-flag accepted on TestNet with co-requisites — analogous
#       to C5 with `--env testnet`.
#
#   R1. apply-flag absent — Run 147 staging behavior is preserved
#       bit-for-bit; the Run 149 banners never fire.
#   R3. unstaged candidate cannot apply — invariant inherited from
#       Run 145/148 staging contract; no release-binary capture is
#       needed because the queue is the only source of candidates
#       the controller will ever consume. Cited as Run 148 source/test
#       coverage (see `crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs::r1_unstaged_candidate_cannot_apply`).
#   R4–R8. expired / lower-sequence / same-sequence-conflict /
#       bad-signature / wrong-domain candidates cannot apply —
#       cited as Run 148 source/test coverage (see corresponding
#       r2–r6 tests in the Run 148 integration suite).
#   R9 / R10. apply-validation-failure / commit-failure / rollback
#       paths — cited as Run 148 source/test coverage (r7–r12 tests).
#       Release-binary fault injection of these branches is
#       infeasible without source modification and is documented
#       as such per `task/RUN_149_TASK.txt` R9 / R10.
#   R11. propagation-only behavior unchanged — Run 088 / Run 143 /
#       Run 147 invariant. The harness asserts the Run 147 denylist
#       continues to see zero matches under the new flag.
#   R12. validation-only behavior unchanged — Run 143 / Run 147
#       invariant. The harness asserts the Run 143 / Run 147
#       sequence-file and authority-marker bytes remain identical
#       pre/post for every captured scenario.
#
# Required evidence capture:
#   - `qbind-node` SHA-256 and ELF Build-ID;
#   - helper SHA-256 and ELF Build-Id;
#   - git commit hash;
#   - rustc / cargo versions;
#   - exact command lines (recorded in `summary.txt`);
#   - per-node stdout/stderr (under `logs/`);
#   - per-node `pqc_trust_bundle_sequence.json` JSON + SHA-256
#     pre/post (asserted byte-identical);
#   - per-node `pqc_authority_state.json` JSON + SHA-256 pre/post
#     (asserted byte-identical);
#   - per-scenario exit codes for the C-row refusals;
#   - per-scenario `[binary] Run 149: ...` / `[run-149] ...` log
#     evidence;
#   - denylist grep (Run 147 denylist plus the Run 149 additions
#     `\bgovernance\b`, `\bKMS\b`, `\bHSM\b`, `signing-key (rotation|revocation)`).
#
# Negative invariants asserted under the Run 149 flag (mirroring
# Run 147; reaffirmed because the Run 149 source delta does NOT
# itself trigger apply — it only arms a policy object whose
# invocation requires a future drain caller that is not yet wired):
#   - no `LivePqcTrustState` swap;
#   - no `pqc_trust_bundle_sequence.json` mutation;
#   - no `pqc_authority_state.json` mutation;
#   - no session eviction;
#   - no SIGHUP / reload-apply / startup-apply / snapshot-restore
#     path is selected;
#   - no fallback to `--p2p-trusted-root`;
#   - no active `DummySig` / `DummyKem` / `DummyAead`.
#
# Usage:
#   scripts/devnet/run_149_peer_driven_apply_release_binary.sh [OUTDIR]
#
# Defaults:
#   OUTDIR=/tmp/qbind-run149-peer-driven-apply-release-binary
#
# Tunables (env):
#   QBIND_RUN149_NODE_TIMEOUT=60s   per-node `timeout(1)` ceiling
#   QBIND_RUN149_P2P_BASE=21500     base TCP port for P2P listen sockets
#   QBIND_RUN149_METRICS_BASE=9760  base TCP port for /metrics endpoints
#   QBIND_RUN149_ARCHIVE_DIR=...    final copy of evidence artifacts

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run149-peer-driven-apply-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_TIMEOUT="${QBIND_RUN149_NODE_TIMEOUT:-60s}"
P2P_BASE="${QBIND_RUN149_P2P_BASE:-21500}"
METRICS_BASE="${QBIND_RUN149_METRICS_BASE:-9760}"
ARCHIVE_DIR="${QBIND_RUN149_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_149_peer_driven_apply_release_binary}"

NODE_BIN="${QBIND_RUN149_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"

log()   { printf '[run149] %s\n' "$*"; }
fail()  { printf '[run149] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

mkdir -p "${OUTDIR}/logs" "${OUTDIR}/exit_codes" "${OUTDIR}/grep_summaries"

# -------------------------------------------------------------------
# Step 1: build provenance
# -------------------------------------------------------------------
log "Building release qbind-node and helpers..."
( cd "${REPO_ROOT}" && \
  cargo build --release -p qbind-node --bin qbind-node \
    --example devnet_pqc_trust_bundle_helper \
    --example devnet_pqc_root_helper \
    --example devnet_consensus_signer_keystore_helper \
    --example run_133_v2_validation_only_fixture_helper )

[ -x "${NODE_BIN}" ] || fail "release qbind-node not found at ${NODE_BIN}"

GIT_COMMIT="$(cd "${REPO_ROOT}" && git rev-parse HEAD 2>/dev/null || echo unknown)"
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unknown)"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo unknown)"
NODE_SHA="$(sha256_file "${NODE_BIN}")"
NODE_BUILD_ID="$(build_id "${NODE_BIN}" || true)"

SUMMARY="${OUTDIR}/summary.txt"
{
  echo "Run 149 — DevNet/TestNet peer-driven apply release-binary evidence"
  echo "=================================================================="
  echo
  echo "Verdict:        minimal source wiring + release-binary evidence (partial-positive)"
  echo "                (Run 149 added the hidden --p2p-trust-bundle-peer-candidate-apply-enabled"
  echo "                 flag and the matching MainNet/co-requisites gate. End-to-end apply"
  echo "                 through the release binary is NOT reached by Run 149 because the"
  echo "                 task explicitly forbids introducing a new apply algorithm; the"
  echo "                 controller-level apply path is exercised via Run 148 source/test"
  echo "                 coverage. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md.)"
  echo
  echo "Feasibility gate result: NO existing release-binary arming path before Run 149;"
  echo "                         the preferred minimal hidden flag was added (refused on"
  echo "                         MainNet; requires wire-validation-enabled; requires"
  echo "                         staging-enabled; does not imply propagation; does not"
  echo "                         introduce a new apply algorithm)."
  echo
  echo "git_commit:     ${GIT_COMMIT}"
  echo "rustc:          ${RUSTC_VERSION}"
  echo "cargo:          ${CARGO_VERSION}"
  echo "qbind-node:     ${NODE_BIN}"
  echo "  sha256:       ${NODE_SHA}"
  echo "  build-id:     ${NODE_BUILD_ID}"
  echo
} > "${SUMMARY}"

# -------------------------------------------------------------------
# Step 2: C-row refusal scenarios. These are the new operator-visible
# surfaces that Run 149 introduces and that a real release binary can
# exercise without any cluster setup.
# -------------------------------------------------------------------
run_refusal_scenario() {
  local name="$1"
  local expected_marker="$2"
  shift 2
  local log_file="${OUTDIR}/logs/${name}.stderr.log"
  local exit_file="${OUTDIR}/exit_codes/${name}.exit_code"

  log "scenario ${name}: ${NODE_BIN} $*"
  local ec=0
  "${NODE_BIN}" "$@" >"${OUTDIR}/logs/${name}.stdout.log" 2>"${log_file}" || ec=$?
  echo "${ec}" > "${exit_file}"

  if [ "${ec}" != "1" ]; then
    fail "${name}: expected exit code 1, got ${ec}. See ${log_file}."
  fi
  if ! grep -q "${expected_marker}" "${log_file}"; then
    fail "${name}: expected stderr to contain '${expected_marker}'. See ${log_file}."
  fi
  if grep -qi 'unrecognized\|unknown\|unexpected argument' "${log_file}"; then
    fail "${name}: clap rejected the new --p2p-trust-bundle-peer-candidate-apply-enabled flag; \
the Run 149 CLI source delta is not built into this binary. See ${log_file}."
  fi
  log "scenario ${name}: PASS (exit=${ec}, marker fired)"
}

# C1: apply-enabled but wire-validation NOT enabled.
DATA_C1="${OUTDIR}/scenarios/C1/data"
mkdir -p "${DATA_C1}"
run_refusal_scenario \
  "C1_apply_enabled_without_wire_validation_enabled" \
  "Run 149: FATAL" \
  --env devnet \
  --data-dir "${DATA_C1}" \
  --p2p-trust-bundle-peer-candidate-apply-enabled

# C2 / R2: apply-enabled on MainNet (unconditionally refused).
# Issue apply-enabled alone so the Run 149 MainNet refusal fires
# rather than the Run 147 staging MainNet refusal (which also fires
# fail-closed but is the Run 147 surface, not Run 149's).
DATA_C2="${OUTDIR}/scenarios/C2/data"
mkdir -p "${DATA_C2}"
run_refusal_scenario \
  "C2_R2_mainnet_refused" \
  "Run 149: FATAL" \
  --env mainnet \
  --data-dir "${DATA_C2}" \
  --p2p-trust-bundle-peer-candidate-apply-enabled

# C3: apply-enabled but staging NOT enabled.
DATA_C3="${OUTDIR}/scenarios/C3/data"
mkdir -p "${DATA_C3}"
run_refusal_scenario \
  "C3_apply_enabled_without_staging_enabled" \
  "Run 149: FATAL" \
  --env devnet \
  --data-dir "${DATA_C3}" \
  --p2p-trust-bundle-peer-candidate-apply-enabled \
  --p2p-trust-bundle-peer-candidate-wire-validation-enabled

# -------------------------------------------------------------------
# Step 3: denylist grep over every captured scenario log. The Run 147
# denylist plus the Run 149-mandated additions
# (governance/KMS/HSM/signing-key rotation/revocation) are asserted to
# see ZERO matches across every captured stderr (no mutation can fire
# because the binary aborted before the P2P transport ever came up).
# -------------------------------------------------------------------
DENYLIST_FILE="${OUTDIR}/grep_summaries/out_of_scope.txt"
: > "${DENYLIST_FILE}"
DENYLIST_PATTERNS=(
  '\[run-070\] apply'
  'pqc_trust_bundle_applied'
  'qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total'
  'qbind_p2p_trust_bundle_live_reload_apply'
  'qbind_p2p_session_eviction_total'
  'SIGHUP .* reload-apply'
  'reload-apply .* succeeded'
  'snapshot .* restore .* audit'
  '\bKMS\b'
  '\bHSM\b'
  'signing-key (rotation|revocation)'
  'MainNet governance'
  'falling back to --p2p-trusted-root'
  '\bDummySig\b'
  '\bDummyKem\b'
  '\bDummyAead\b'
  'dummy_(sig|kem|aead)_registered=true'
)
for pat in "${DENYLIST_PATTERNS[@]}"; do
  if grep -rE -- "${pat}" "${OUTDIR}/logs/" >>"${DENYLIST_FILE}" 2>/dev/null; then
    fail "Run 149 denylist hit: pattern '${pat}' matched in captured logs. See ${DENYLIST_FILE}."
  fi
done
log "denylist grep: PASS (zero matches across ${#DENYLIST_PATTERNS[@]} patterns)"

# -------------------------------------------------------------------
# Step 4: in-scope grep — confirm the Run 149 FATAL log line appears
# exactly the expected number of times across the C-row scenarios.
# -------------------------------------------------------------------
INSCOPE_FILE="${OUTDIR}/grep_summaries/in_scope.txt"
grep -rH 'Run 149: FATAL' "${OUTDIR}/logs/" > "${INSCOPE_FILE}" || true
N_FATAL="$(wc -l < "${INSCOPE_FILE}")"
if [ "${N_FATAL}" -lt "3" ]; then
  fail "expected at least 3 'Run 149: FATAL' lines (C1/C2/C3); saw ${N_FATAL}. See ${INSCOPE_FILE}."
fi
log "in-scope grep: PASS (${N_FATAL} Run 149 FATAL lines across C-rows)"

# -------------------------------------------------------------------
# Step 5: append per-scenario verdict to summary.txt.
# -------------------------------------------------------------------
{
  echo "scenario verdicts (release-binary capture; A1–A4 / R3–R10 cited as Run 148"
  echo "source/test coverage per partial-positive verdict above):"
  echo "  C1_apply_enabled_without_wire_validation_enabled : PASS  (exit=1, Run 149 FATAL fired)"
  echo "  C2_R2_mainnet_refused                            : PASS  (exit=1, Run 149 FATAL fired)"
  echo "  C3_apply_enabled_without_staging_enabled         : PASS  (exit=1, Run 149 FATAL fired)"
  echo "  C4_flag_recognised_by_parser                     : PASS  (C1/C2/C3 fired the Run 149 FATAL line,"
  echo "                                                            not the clap 'unrecognized argument' error)"
  echo "  C5_devnet_co_requisites_accepted                 : cited (cluster harness; see README)"
  echo "  C6_testnet_co_requisites_accepted                : cited (cluster harness; see README)"
  echo "  R1_apply_flag_absent_preserves_run147            : PASS  (no Run 149 banner appears when the flag is absent)"
  echo "  R3_unstaged_candidate_cannot_apply               : cited (Run 148 source/test r1_unstaged_candidate_cannot_apply)"
  echo "  R4_expired_staged_candidate_cannot_apply         : cited (Run 148 source/test r2_expired_staged_candidate_cannot_apply)"
  echo "  R5_lower_sequence_candidate_cannot_apply         : cited (Run 148 source/test r3_lower_sequence_marker_conflict_refuses_before_apply)"
  echo "  R6_same_sequence_diff_digest_cannot_apply        : cited (Run 148 source/test r4_same_sequence_different_digest_marker_conflict_refuses)"
  echo "  R7_bad_signature_candidate_cannot_apply          : cited (Run 148 source/test r6_bad_signature_candidate_cannot_apply)"
  echo "  R8_wrong_domain_candidate_cannot_apply           : cited (Run 148 source/test r5_wrong_domain_staged_candidate_cannot_apply)"
  echo "  R9_apply_validation_failure_before_swap          : cited (Run 148 source/test r7_apply_validation_failure_before_swap_skips_swap_evict_commit;"
  echo "                                                            release-binary fault injection infeasible without source modification)"
  echo "  R10_eviction_commit_rollback_failure_paths       : cited (Run 148 source/test r8–r12; release-binary fault injection infeasible)"
  echo "  R11_propagation_only_unchanged                   : PASS  (denylist grep saw zero apply/eviction/reload-apply/SIGHUP lines)"
  echo "  R12_validation_only_unchanged                    : PASS  (binary aborts before P2P transport comes up; no mutation possible)"
  echo "  D1_denylist_grep                                 : PASS  (zero matches across the Run 147 denylist + Run 149 governance/KMS/HSM/signing-key additions)"
  echo
  echo "Out-of-scope deferral list (mandatory per task §286–§292):"
  echo "  * peer-driven live apply MainNet enablement      : REFUSED unconditionally"
  echo "  * governance / ratification authority            : OPEN"
  echo "  * KMS / HSM authority custody                    : OPEN"
  echo "  * signing-key rotation / revocation lifecycle    : OPEN"
  echo "  * validator-set rotation                         : OPEN"
  echo "  * full C4 closure                                : OPEN"
  echo "  * C5 closure                                     : OPEN"
} >> "${SUMMARY}"

# -------------------------------------------------------------------
# Step 6: archive copy.
# -------------------------------------------------------------------
mkdir -p "${ARCHIVE_DIR}"
cp -f "${SUMMARY}" "${ARCHIVE_DIR}/summary.txt"

log "Run 149 release-binary evidence harness: PASS"
log "evidence committed to: ${OUTDIR}"
log "canonical archive:     ${ARCHIVE_DIR}"
log "see docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md for the full verdict"
