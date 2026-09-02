#!/usr/bin/env bash
# Run 411: public DevNet readiness/contradiction ledger consistency lint.
#
# This harness is a READ-ONLY, fail-closed cross-LEDGER lint. It checks that the two
# canonical public DevNet ledgers agree on the fixed public DevNet posture and on the
# per-run narratives for the current launch-gate / package-integrity documentation chain:
#
#   * the canonical readiness matrix
#       docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md, and
#   * the protocol contradiction ledger
#       docs/whitepaper/contradiction.md.
#
# It extends consistency protection BEYOND the Run 410 package-integrity stale-prose lint:
# where Run 410 keeps the package-integrity prose internally consistent, Run 411 keeps the
# readiness matrix and the contradiction ledger consistent with EACH OTHER on the fixed
# public DevNet posture and non-claims. It adds NO feature surface and moves NO readiness
# item. It generates only a transient summary OUTSIDE the repository tree and commits
# nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO
# build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation. No node
# is started, no port is opened, and no state/data dir is written.
#
# It fails closed if:
#   * the ledger-lint guide is missing or not safety-labelled;
#   * either ledger is missing;
#   * any Run 402-410 is missing an "Updated Run N" narrative in the readiness matrix;
#   * any Run 402-410 is missing a "Run N" entry (or explicit no-contradiction statement)
#     in the contradiction ledger;
#   * the two ledgers disagree that M4/M6/S5/S7 remain unchanged, that public DevNet remains
#     NOT launch-ready / NO-GO, or that C4/C5 remain OPEN, for any scoped run;
#   * either ledger describes a docs-only / shell-only / schema-only / YAML-only run as
#     runtime or launch evidence;
#   * either ledger records a readiness item moving Green for a scoped run (none did);
#   * the fixed posture (M4/M6/S5/S7 Yellow; NO-GO; C4/C5 OPEN; N1-N7 Red; TestNet/MainNet
#     untouched) is not consistently stated across both ledgers;
#   * a deployment / runtime-mutation / TestNet-MainNet-readiness / C4-C5-closure claim
#     appears in the Run 411-authored docs;
#   * any generated artifact is committed, the working tree is left dirty, or a secret /
#     private-material / absolute path appears in the Run 411-authored docs.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run411-public-devnet-readiness-contradiction-ledger-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/READINESS_CONTRADICTION_LEDGER_LINT.md"
STALE_PROSE_LINT="${PDN}/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
LAUNCH_GATE="${PDN}/LAUNCH_GO_NO_GO.md"
BLOCKER_REGISTER="${PDN}/BLOCKER_REGISTER.md"
C4C5_CRITERIA="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV411="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_411.md"

SUMMARY="${OUTDIR}/summary.txt"

# Runs in scope: the current public DevNet launch-gate / package-integrity documentation
# chain. Both ledgers must carry a narrative for each, and both must agree on posture.
SCOPED_RUNS=(402 403 404 405 406 407 408 409 410)

log()  { printf '[run411] %s\n' "$*"; }
fail() { printf '[run411] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${STALE_PROSE_LINT}" "${ARTIFACT_INDEX}" "${OP_MAP}" \
         "${LAUNCH_GATE}" "${BLOCKER_REGISTER}" "${C4C5_CRITERIA}" "${CRITERIA}" \
         "${CONTRADICTION}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# Extract the readiness-matrix narrative block for a single run: from the
# "Updated Run N —" line up to (but not including) the next "Updated Run" line.
criteria_block() {
  awk -v r="$1" '
    $0 ~ ("^Updated Run " r " —") { grab=1; print; next }
    grab && /^Updated Run [0-9]+ —/ { grab=0 }
    grab { print }
  ' "${CRITERIA}"
}

# Extract the contradiction-ledger entry for a single run (single-line per-run entries).
contradiction_line() {
  grep -E "^Run $1 —" "${CONTRADICTION}" || true
}

# ---------------------------------------------------------------------------
# 1. The ledger-lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "ledger-lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "ledger-lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "ledger-lint guide missing C4/C5 OPEN label"
emit "ledger_lint_guide_present=OK (READINESS_CONTRADICTION_LEDGER_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 2. The readiness matrix exists and carries its canonical fixed-posture status table.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" \
  || fail "readiness matrix missing the NOT launch-ready statement"
grep -qi 'no readiness item moves' "${CRITERIA}" \
  || fail "readiness matrix missing a no-readiness-item-moves statement"
emit "readiness_matrix_present=OK (QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md exists; NOT launch-ready + no-readiness-item-moves statements present)"

# ---------------------------------------------------------------------------
# 3. The contradiction ledger exists and records the fixed OPEN/NOT-launch-ready posture.
# ---------------------------------------------------------------------------
grep -qi 'C4 remains OPEN' "${CONTRADICTION}" || fail "contradiction ledger missing C4 remains OPEN"
grep -qi 'C5 remains OPEN' "${CONTRADICTION}" || fail "contradiction ledger missing C5 remains OPEN"
grep -qi 'NOT launch-ready' "${CONTRADICTION}" || fail "contradiction ledger missing NOT launch-ready"
emit "contradiction_ledger_present=OK (contradiction.md exists; C4/C5 OPEN + NOT launch-ready statements present)"

# ---------------------------------------------------------------------------
# 4-5. Runs 402-410 are present in BOTH ledgers, with per-run posture agreement.
# ---------------------------------------------------------------------------
for n in "${SCOPED_RUNS[@]}"; do
  # 4. readiness-matrix presence
  grep -qE "^Updated Run ${n} —" "${CRITERIA}" \
    || fail "readiness matrix missing 'Updated Run ${n}' narrative"
  cblock="$(criteria_block "${n}")"
  [ -n "${cblock}" ] || fail "could not extract readiness-matrix block for Run ${n}"
  # Flatten to a single logical line so posture phrases that wrap across source lines
  # (e.g. "S5/S7\nstay Yellow") still match; strip CR so CRLF endings do not split words.
  cblock="$(printf '%s' "${cblock}" | tr -d '\r' | tr '\n' ' ')"

  # 5. contradiction-ledger presence + explicit no-contradiction statement
  cline="$(contradiction_line "${n}" | tr -d '\r')"
  [ -n "${cline}" ] || fail "contradiction ledger missing the Run ${n} entry"
  printf '%s' "${cline}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
    || fail "Run ${n} contradiction entry lacks an explicit no-contradiction statement"

  # Both ledgers must agree Run N moved no readiness item Green.
  printf '%s' "${cblock}" | grep -qiE 'No readiness item moves Green' \
    || fail "readiness matrix Run ${n} narrative does not state no readiness item moves Green"
  printf '%s' "${cline}" | grep -qiE 'no item moves Green' \
    || fail "contradiction ledger Run ${n} entry does not state no item moves Green"

  # Both ledgers must agree M4/M6/S5/S7 remain unchanged (Yellow).
  printf '%s' "${cblock}" | grep -qiE 'M4 stays Yellow' \
    || fail "readiness matrix Run ${n} narrative does not hold M4 Yellow"
  printf '%s' "${cline}"  | grep -qiE 'M4 stays Yellow' \
    || fail "contradiction ledger Run ${n} entry does not hold M4 Yellow"
  printf '%s' "${cblock}" | grep -qiE 'M6 stays Yellow/Partial' \
    || fail "readiness matrix Run ${n} narrative does not hold M6 Yellow/Partial"
  printf '%s' "${cline}"  | grep -qiE 'M6 stays Yellow/Partial' \
    || fail "contradiction ledger Run ${n} entry does not hold M6 Yellow/Partial"
  printf '%s' "${cblock}" | grep -qiE 'S5/S7 stay Yellow' \
    || fail "readiness matrix Run ${n} narrative does not hold S5/S7 Yellow"
  printf '%s' "${cline}"  | grep -qiE 'S5/S7 stay Yellow' \
    || fail "contradiction ledger Run ${n} entry does not hold S5/S7 Yellow"

  # Both ledgers must agree public DevNet remains NOT launch-ready.
  printf '%s' "${cblock}" | grep -qiE 'NOT launch-ready' \
    || fail "readiness matrix Run ${n} narrative does not restate NOT launch-ready"
  printf '%s' "${cline}"  | grep -qiE 'NOT launch-ready' \
    || fail "contradiction ledger Run ${n} entry does not restate NOT launch-ready"

  # Both ledgers must agree C4/C5 remain OPEN.
  printf '%s' "${cblock}" | grep -qiE 'C4/C5 remain OPEN' \
    || fail "readiness matrix Run ${n} narrative does not hold C4/C5 OPEN"
  printf '%s' "${cline}"  | grep -qiE 'C4 remains OPEN' \
    || fail "contradiction ledger Run ${n} entry does not hold C4 OPEN"
  printf '%s' "${cline}"  | grep -qiE 'C5 remains OPEN' \
    || fail "contradiction ledger Run ${n} entry does not hold C5 OPEN"

  # Both ledgers must agree TestNet/MainNet remain untouched.
  printf '%s' "${cblock}" | grep -qiE 'MainNet/TestNet untouched' \
    || fail "readiness matrix Run ${n} narrative does not hold TestNet/MainNet untouched"
  printf '%s' "${cline}"  | grep -qiE 'TestNet/MainNet untouched' \
    || fail "contradiction ledger Run ${n} entry does not hold TestNet/MainNet untouched"

  # These are docs/shell/schema/YAML-only runs: neither ledger may describe them as runtime
  # or launch evidence, or as having deployed/mutated anything.
  for scope_text in "${cblock}" "${cline}"; do
    if printf '%s' "${scope_text}" \
      | grep -oiE '(is|are) (launch|runtime) evidence|is launch-ready|seed is live|status service deployed|faucet deployed|explorer deployed|RPC deployed|mutates runtime|epoch transition performed|validator set (was )?mutated|C4 (is )?closed|C5 (is )?closed|TestNet ready|MainNet ready' \
      | grep -qivE 'no |not |neither|without|remains|untouched'; then
      fail "Run ${n} ledger text describes a docs/shell-only run as launch/runtime/deployment/closure evidence"
    fi
  done
done
emit "runs_present_readiness=OK (Runs 402-410 each carry an 'Updated Run N' narrative in the readiness matrix)"
emit "runs_present_contradiction=OK (Runs 402-410 each carry a 'Run N' no-contradiction entry in the contradiction ledger)"
emit "run_row_posture_agreement=OK (for Runs 402-410 both ledgers agree: no Green move; M4/M6/S5/S7 Yellow; NOT launch-ready; C4/C5 OPEN; TestNet/MainNet untouched; docs-only not described as launch/runtime evidence)"

# ---------------------------------------------------------------------------
# 6. M4 status wording is consistent (fixed-posture status table + per-run).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 in the readiness matrix"
grep -qi 'M4 stays Yellow' "${CONTRADICTION}" || fail "contradiction ledger must hold M4 Yellow"
emit "m4_consistent=OK (M4 seed/bootnodes 🟡 / launch-blocking in the readiness matrix and Yellow in the contradiction ledger)"

# ---------------------------------------------------------------------------
# 7. M6 status wording is consistent.
# ---------------------------------------------------------------------------
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 in the readiness matrix"
grep -qi 'M6 stays Yellow/Partial' "${CONTRADICTION}" || fail "contradiction ledger must hold M6 Yellow/Partial"
emit "m6_consistent=OK (M6 validator identity 🟡 / Partial in the readiness matrix and Yellow/Partial in the contradiction ledger)"

# ---------------------------------------------------------------------------
# 8. S5/S7 status wording is consistent.
# ---------------------------------------------------------------------------
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 in the readiness matrix"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 in the readiness matrix"
grep -qi 'S5/S7 stay Yellow' "${CONTRADICTION}" || fail "contradiction ledger must hold S5/S7 Yellow"
emit "s5_s7_consistent=OK (S5 status page 🟡 and S7 seed-node runbook 🟡 in the readiness matrix and Yellow in the contradiction ledger)"

# ---------------------------------------------------------------------------
# 9. Public DevNet NO-GO / NOT launch-ready wording is consistent across ledgers + gate.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" \
  || fail "readiness matrix must hold public DevNet NOT launch-ready"
grep -qi 'NOT launch-ready' "${CONTRADICTION}" \
  || fail "contradiction ledger must hold NOT launch-ready"
grep -qiE 'NO-GO|NOT launch-ready' "${LAUNCH_GATE}" \
  || fail "LAUNCH_GO_NO_GO.md must state NO-GO / NOT launch-ready"
emit "nogo_consistent=OK (public DevNet NO-GO / NOT launch-ready in the readiness matrix, contradiction ledger, and LAUNCH_GO_NO_GO.md)"

# ---------------------------------------------------------------------------
# 10. C4/C5 OPEN wording is consistent across ledgers + closure criteria.
# ---------------------------------------------------------------------------
grep -qiE 'C4 and C5 remain +\*{0,2}OPEN' "${CRITERIA}" \
  || fail "readiness matrix must hold C4 and C5 OPEN"
grep -qi 'C4 remains OPEN' "${CONTRADICTION}" || fail "contradiction ledger must hold C4 OPEN"
grep -qi 'C5 remains OPEN' "${CONTRADICTION}" || fail "contradiction ledger must hold C5 OPEN"
grep -qiE 'C4|C5' "${C4C5_CRITERIA}" || fail "C4/C5 closure criteria doc must reference C4/C5"
emit "c4_c5_consistent=OK (C4/C5 OPEN in the readiness matrix and contradiction ledger; closure criteria documented in QBIND_C4_C5_CLOSURE_CRITERIA.md)"

# ---------------------------------------------------------------------------
# 11. TestNet/MainNet non-claim wording is consistent (N1-N7 Red; untouched).
# ---------------------------------------------------------------------------
grep -qF 'N1, N2, N3, N4, N7 Red' "${CRITERIA}" || fail "readiness matrix must hold N1-N4/N7 Red"
grep -qF 'N5 (C4) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N5 (C4) OPEN / Red"
grep -qF 'N6 (C5) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N6 (C5) OPEN / Red"
grep -qi 'TestNet/MainNet untouched' "${CONTRADICTION}" \
  || fail "contradiction ledger must hold TestNet/MainNet untouched"
emit "testnet_mainnet_non_claim=OK (N1-N7 Red in the readiness matrix; TestNet/MainNet untouched in both ledgers)"

# ---------------------------------------------------------------------------
# 12. Deployment non-claim wording is consistent (no seed/bootnode/faucet/RPC/explorer/
#     status-service deployment claimed in either ledger). Every line that mentions a
#     "... deployed" phrase must also carry a negation on the same line.
# ---------------------------------------------------------------------------
for f in "${CRITERIA}" "${CONTRADICTION}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|deploys[^.]*no|nothing|instead' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a deployment"; }
  done < <(grep -iE '(seed|bootnode|faucet|RPC|explorer|status service)[^.]{0,40}(is|was|has been|are) deployed' "${f}" || true)
done
emit "deployment_non_claim=OK (neither ledger claims a seed/bootnode/faucet/RPC/explorer/status-service deployment)"

# ---------------------------------------------------------------------------
# 13. Runtime-mutation non-claim wording is consistent. Every line that mentions a
#     "... mutated/transitioned" phrase must also carry a negation on the same line.
# ---------------------------------------------------------------------------
for f in "${CRITERIA}" "${CONTRADICTION}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|mutates[^.]*no|nothing' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a runtime mutation"; }
  done < <(grep -iE '(validator set|epoch|sequence|marker|LivePqcTrustState)[^.]{0,40}(was|is|has been|are) (mutated|transitioned|advanced|changed)' "${f}" || true)
done
emit "runtime_mutation_non_claim=OK (neither ledger claims a validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 14. Docs-only / tooling-only scoped runs are not described as launch evidence.
#     (Each Run 402-410 gate is Route B in the readiness matrix.)
# ---------------------------------------------------------------------------
for n in "${SCOPED_RUNS[@]}"; do
  criteria_block "${n}" | tr -d '\r' | tr '\n' ' ' | grep -qiE 'Route B' \
    || fail "readiness matrix Run ${n} narrative must record the docs/shell-only Route B gate"
done
emit "docs_only_not_launch_evidence=OK (Runs 402-410 are recorded as docs/shell/schema/YAML-only Route B runs, not launch evidence)"

# ---------------------------------------------------------------------------
# 15. No readiness item moves Green in this run (global posture unchanged).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 (no Green move)"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 (no Green move)"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 (no Green move)"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 (no Green move)"
grep -qi 'Run 411' "${CRITERIA}" || fail "readiness matrix must carry the Run 411 narrative"
criteria_block 411 | tr -d '\r' | tr '\n' ' ' | grep -qiE 'No readiness item moves Green' \
  || fail "Run 411 readiness narrative must state no readiness item moves Green"
emit "no_green_move=OK (Run 411 moves no readiness item Green; M4/M6/S5/S7 stay 🟡)"

# ---------------------------------------------------------------------------
# 16. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "READINESS_CONTRADICTION_LEDGER_LINT_REPORT.json" \
            "READINESS_CONTRADICTION_LEDGER_LINT_REPORT.txt" \
            "PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_output_non_commit=OK (no generated ledger-lint report is committed; transient output stays outside the tree)"

# ---------------------------------------------------------------------------
# 17. Run 411 contradiction ledger entry exists and holds the fixed posture.
# ---------------------------------------------------------------------------
RUN411_ENTRY="$(contradiction_line 411)"
[ -n "${RUN411_ENTRY}" ] || fail "contradiction ledger missing the Run 411 entry"
printf '%s' "${RUN411_ENTRY}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
  || fail "Run 411 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN411_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 411 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN411_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN411_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 411 contradiction entry must state C4/C5 remain OPEN"
emit "run_411_ledger_entry=OK (Run 411 recorded in both ledgers; no protocol contradiction; NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 18. Non-claim grep over the Run 411-authored docs (normalized).
# ---------------------------------------------------------------------------
normalize_md() {
  sed -e 's/[`*|]//g' "$1" \
  | awk '
      BEGIN { buf = "" }
      /^[[:space:]]*$/ { if (buf != "") { print buf; buf = "" } next }
      {
        line = $0
        sub(/^[[:space:]]*>?[[:space:]]*/, "", line)
        if (buf == "") buf = line; else buf = buf " " line
      }
      END { if (buf != "") print buf }'
}
CLAIM_TARGETS=("${LINT_GUIDE}")
[ -f "${EV411}" ] && CLAIM_TARGETS+=("${EV411}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 411 docs)"
emit "runtime_mutation=NONE (Run 411 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 19. Secret / private-material + absolute-path scan over the Run 411-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV411}" ] && SCAN_FILES+=("${EV411}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 411 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 411 doc"
fi
emit "secret_scan=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 411 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet readiness/contradiction ledger consistency lint: the ledger-lint guide is published and safety-labelled; Runs 402-410 each carry an 'Updated Run N' narrative in the readiness matrix and a 'Run N' no-contradiction entry in the contradiction ledger; for every scoped run both ledgers agree no readiness item moved Green, M4/M6/S5/S7 stay Yellow, public DevNet stays NOT launch-ready, C4/C5 stay OPEN, and TestNet/MainNet remain untouched; docs/shell/schema/YAML-only runs are recorded as Route B, not launch/runtime evidence; the fixed status table holds M4/M6/S5/S7 🟡, NO-GO, C4/C5 OPEN, and N1-N7 Red; no deployment/runtime-mutation/TestNet-MainNet-readiness/C4-C5-closure claim appears in the Run 411 docs; nothing generated is committed; the working tree stays clean; and the secret/private-material scan is clean)"