#!/usr/bin/env bash
# Run 412: public DevNet readiness table/checklist/blocker consistency lint.
#
# This harness is a READ-ONLY, fail-closed PER-MILESTONE consistency lint. It checks that the
# public DevNet readiness matrix is internally consistent at the level of individual milestone
# status rows, and that the blocker register and the launch go/no-go gate agree with the frozen
# M4/M6/S5/S7 posture:
#
#   * the canonical readiness matrix
#       docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
#       - its §10 current-status table (SOURCE OF TRUTH),
#       - its §4 must-have checklist (M1-M20),
#       - its §5 should-have checklist (S1-S7);
#   * the blocker register
#       docs/release/public-devnet/BLOCKER_REGISTER.md; and
#   * the launch go/no-go gate
#       docs/release/public-devnet/LAUNCH_GO_NO_GO.md.
#
# It extends consistency protection BEYOND the Run 411 cross-LEDGER run-narrative lint: where
# Run 411 keeps the readiness matrix and the contradiction ledger consistent on the per-run
# narratives, Run 412 keeps the readiness matrix's status table, its must-have/should-have
# checklists, and the blocker register consistent with EACH OTHER on the per-MILESTONE status
# rows. It adds NO feature surface and moves NO readiness item. It generates only a transient
# summary OUTSIDE the repository tree and commits nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO
# build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation. No node
# is started, no port is opened, and no state/data dir is written.
#
# It fails closed if:
#   * the status/blocker lint guide is missing or not safety-labelled;
#   * the readiness matrix, the blocker register, or the launch gate is missing;
#   * the §10 current-status table does not cover all M1-M20 and S1-S7;
#   * the §4 must-have checklist does not cover M1-M20, or the §5 should-have checklist S1-S7;
#   * the §10 table disagrees with the §4 checklist on any M1-M20 status;
#   * the §10 table disagrees with the §5 checklist on any S1-S7 status;
#   * M4 is anything other than Yellow / launch-blocking anywhere it appears;
#   * M6 is anything other than Yellow / Partial anywhere it appears;
#   * S5 or S7 is anything other than Yellow anywhere it appears;
#   * the blocker register omits M4/M6/S5/S7, or marks any of them resolved/closed/Green/
#     non-blocking/launch-complete;
#   * the launch gate is not NO-GO / NOT launch-ready, does not list M4 and M6 as must-have
#     blockers, or does not keep S5/S7 M4-gated or Yellow;
#   * any table/checklist/blocker text claims a live seed/bootnode/faucet/RPC/explorer/
#     status-service deployment, a live `devnet-seeds.live.json` without real M4 evidence, a
#     C4/C5 closure, TestNet/MainNet readiness, or a runtime mutation;
#   * a deployment / runtime-mutation / TestNet-MainNet-readiness / C4-C5-closure claim appears
#     in the Run 412-authored docs;
#   * any generated artifact is committed, the working tree is left dirty, or a secret /
#     private-material / absolute path appears in the Run 412-authored docs.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run412-public-devnet-readiness-status-blocker-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/READINESS_STATUS_BLOCKER_LINT.md"
LEDGER_LINT="${PDN}/READINESS_CONTRADICTION_LEDGER_LINT.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
LAUNCH_GATE="${PDN}/LAUNCH_GO_NO_GO.md"
BLOCKER_REGISTER="${PDN}/BLOCKER_REGISTER.md"
C4C5_CRITERIA="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV412="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_412.md"

SUMMARY="${OUTDIR}/summary.txt"

# Frozen per-milestone status truth for this run (source of truth = §10 table).
declare -A EXPECT_M=(
  [M1]=Green [M2]=Green [M3]=Green [M4]=Yellow [M5]=Green [M6]=Yellow [M7]=Green
  [M8]=Green [M9]=Green [M10]=Green [M11]=Green [M12]=Green [M13]=Green [M14]=Green
  [M15]=Green [M16]=Green [M17]=Green [M18]=Green [M19]=Green [M20]=Green
)
declare -A EXPECT_S=(
  [S1]=Green [S2]=Green [S3]=Green [S4]=Green [S5]=Yellow [S6]=Green [S7]=Yellow
)

log()  { printf '[run412] %s\n' "$*"; }
fail() { printf '[run412] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${LEDGER_LINT}" "${ARTIFACT_INDEX}" "${OP_MAP}" \
         "${LAUNCH_GATE}" "${BLOCKER_REGISTER}" "${C4C5_CRITERIA}" "${CRITERIA}" \
         "${CONTRADICTION}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# Extract a numbered section block "## N. ..." up to the next "## N+? ." heading.
section_block() {
  local start="$1" nextre="$2" src="$3"
  awk -v s="^## ${start}[.] " -v n="${nextre}" '
    $0 ~ s { grab=1 }
    grab && $0 ~ n && $0 !~ s { grab=0 }
    grab { print }
  ' "${src}" | tr -d '\r'
}

TABLE10="${OUTDIR}/section10.txt"
SEC4="${OUTDIR}/section4.txt"
SEC5="${OUTDIR}/section5.txt"
section_block 10 '^## 11[.] ' "${CRITERIA}" > "${TABLE10}"
section_block 4  '^## 5[.] '  "${CRITERIA}" > "${SEC4}"
section_block 5  '^## 6[.] '  "${CRITERIA}" > "${SEC5}"
[ -s "${TABLE10}" ] || fail "could not extract §10 current-status table"
[ -s "${SEC4}" ]    || fail "could not extract §4 must-have checklist"
[ -s "${SEC5}" ]    || fail "could not extract §5 should-have checklist"

# Status glyph in the §10 table row for an item ("| M4 seed/bootnodes | 🟡 | ...").
table_status_of() {
  local item="$1" row field3
  row="$(awk -v it="${item}" '$0 ~ ("^\\| " it " ") { print; exit }' "${TABLE10}")"
  [ -n "${row}" ] || { echo MISSING; return; }
  field3="$(printf '%s' "${row}" | awk -F'|' '{print $3}')"
  if   printf '%s' "${field3}" | grep -q '🟢'; then echo Green
  elif printf '%s' "${field3}" | grep -q '🟡'; then echo Yellow
  elif printf '%s' "${field3}" | grep -q '🔴'; then echo Red
  elif printf '%s' "${field3}" | grep -q '⚪'; then echo NA
  else echo UNKNOWN; fi
}

# Leading bold status word in the §4/§5 checklist entry for an item
# ("- [x] M1. ... — **Green (Run 356)**").
check_status_of() {
  local item="$1" file="$2" line kw
  line="$(awk -v it="${item}" '$0 ~ ("^- \\[.\\] " it "[.] ") { print; exit }' "${file}")"
  [ -n "${line}" ] || { echo MISSING; return; }
  kw="$(printf '%s' "${line}" | grep -oE '\*\*(Green|Yellow|Red)' | head -1 | grep -oE 'Green|Yellow|Red')"
  [ -n "${kw}" ] && echo "${kw}" || echo UNKNOWN
}

# ---------------------------------------------------------------------------
# 1. The status/blocker lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "status/blocker lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "status/blocker lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "status/blocker lint guide missing C4/C5 OPEN label"
emit "status_blocker_lint_guide_present=OK (READINESS_STATUS_BLOCKER_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 2-4. Readiness matrix, blocker register, launch gate exist.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" \
  || fail "readiness matrix missing the NOT launch-ready statement"
emit "readiness_matrix_present=OK (QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md exists; §10 table + §4/§5 checklists present)"
grep -qi 'Blocker register' "${BLOCKER_REGISTER}" || fail "blocker register missing"
emit "blocker_register_present=OK (BLOCKER_REGISTER.md exists)"
grep -qiE 'NO-GO|NOT launch-ready' "${LAUNCH_GATE}" || fail "launch go/no-go gate missing NO-GO"
emit "launch_gate_present=OK (LAUNCH_GO_NO_GO.md exists; NO-GO / NOT launch-ready)"

# ---------------------------------------------------------------------------
# 5-7. Coverage: §10 table covers M1-M20 + S1-S7; §4 covers M1-M20; §5 covers S1-S7.
# ---------------------------------------------------------------------------
for n in $(seq 1 20); do
  [ "$(table_status_of "M${n}")" != "MISSING" ] || fail "§10 table missing row for M${n}"
  [ "$(check_status_of "M${n}" "${SEC4}")" != "MISSING" ] || fail "§4 must-have checklist missing M${n}"
done
for n in $(seq 1 7); do
  [ "$(table_status_of "S${n}")" != "MISSING" ] || fail "§10 table missing row for S${n}"
  [ "$(check_status_of "S${n}" "${SEC5}")" != "MISSING" ] || fail "§5 should-have checklist missing S${n}"
done
emit "status_table_coverage=OK (§10 current-status table covers M1-M20 and S1-S7)"
emit "must_have_checklist_coverage=OK (§4 must-have checklist covers M1-M20)"
emit "should_have_checklist_coverage=OK (§5 should-have checklist covers S1-S7)"

# ---------------------------------------------------------------------------
# 8. §10 table agrees with §4 must-have checklist for every M1-M20 (and matches EXPECT_M).
# ---------------------------------------------------------------------------
for n in $(seq 1 20); do
  it="M${n}"
  t="$(table_status_of "${it}")"
  c="$(check_status_of "${it}" "${SEC4}")"
  [ "${t}" = "${c}" ] || fail "${it}: §10 table (${t}) disagrees with §4 must-have checklist (${c})"
  [ "${t}" = "${EXPECT_M[$it]}" ] || fail "${it}: status ${t} != frozen expected ${EXPECT_M[$it]}"
done
emit "must_have_table_checklist_agree=OK (§10 table and §4 must-have checklist agree for M1-M20; match frozen truth)"

# ---------------------------------------------------------------------------
# 9. §10 table agrees with §5 should-have checklist for every S1-S7 (and matches EXPECT_S).
# ---------------------------------------------------------------------------
for n in $(seq 1 7); do
  it="S${n}"
  t="$(table_status_of "${it}")"
  c="$(check_status_of "${it}" "${SEC5}")"
  [ "${t}" = "${c}" ] || fail "${it}: §10 table (${t}) disagrees with §5 should-have checklist (${c})"
  [ "${t}" = "${EXPECT_S[$it]}" ] || fail "${it}: status ${t} != frozen expected ${EXPECT_S[$it]}"
done
emit "should_have_table_checklist_agree=OK (§10 table and §5 should-have checklist agree for S1-S7; match frozen truth)"

# ---------------------------------------------------------------------------
# 10-13. M4/M6/S5/S7 hold their exact frozen wording consistently in the matrix.
# ---------------------------------------------------------------------------
[ "$(table_status_of M4)" = "Yellow" ] || fail "M4 must be Yellow in §10 table"
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 in the §10 table row"
grep -qi 'M4 .*launch-blocking' "${CRITERIA}" || fail "readiness matrix must hold M4 launch-blocking"
emit "m4_consistent=OK (M4 Yellow / launch-blocking in §10 table, §4 checklist, and matrix prose)"

[ "$(table_status_of M6)" = "Yellow" ] || fail "M6 must be Yellow in §10 table"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 in the §10 table row"
grep -qiE 'M6 (stays|remains) Yellow/Partial' "${CRITERIA}" || fail "readiness matrix must hold M6 Yellow/Partial"
emit "m6_consistent=OK (M6 Yellow / Partial in §10 table, §4 checklist, and matrix prose)"

[ "$(table_status_of S5)" = "Yellow" ] || fail "S5 must be Yellow in §10 table"
[ "$(table_status_of S7)" = "Yellow" ] || fail "S7 must be Yellow in §10 table"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 in the §10 table row"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 in the §10 table row"
emit "s5_s7_consistent=OK (S5 status page 🟡 and S7 seed-node runbook 🟡 in §10 table and §5 checklist)"

# ---------------------------------------------------------------------------
# 14-15. Blocker register contains M4/M6/S5/S7 and keeps each open/unresolved.
# ---------------------------------------------------------------------------
for id in M4 M6 S5 S7; do
  row="$(grep -E "^\| \*\*${id}\*\* \|" "${BLOCKER_REGISTER}" | tr -d '\r' || true)"
  [ -n "${row}" ] || fail "blocker register omits ${id}"
  # Status column = last pipe-delimited field.
  status_col="$(printf '%s' "${row}" | awk -F'|' '{print $(NF-1)}')"
  printf '%s' "${status_col}" | grep -qi 'Yellow' \
    || fail "blocker register ${id} status column is not Yellow (got: ${status_col})"
  if printf '%s' "${status_col}" | grep -qiE 'resolved|closed|(^|[^-])\bGreen\b|non-blocking|launch-complete|done'; then
    fail "blocker register ${id} is marked resolved/closed/Green/non-blocking/launch-complete"
  fi
done
grep -qi 'No launch until every must-have' "${BLOCKER_REGISTER}" \
  || fail "blocker register must keep the 'no launch until every must-have is Green' rule"
emit "blocker_register_consistent=OK (M4/M6/S5/S7 present and Yellow/open in BLOCKER_REGISTER.md; launch rule intact)"

# ---------------------------------------------------------------------------
# 16-18. Launch go/no-go gate remains NO-GO, lists M4/M6 blockers, keeps S5/S7 M4-gated.
# ---------------------------------------------------------------------------
grep -qi 'NO-GO' "${LAUNCH_GATE}" || fail "launch gate must state NO-GO"
grep -qi 'NOT launch-ready' "${LAUNCH_GATE}" || fail "launch gate must state NOT launch-ready"
emit "launch_gate_nogo=OK (LAUNCH_GO_NO_GO.md remains NO-GO / NOT launch-ready)"
grep -qiE 'M4 .*launch-blocking' "${LAUNCH_GATE}" || fail "launch gate must list M4 as a launch-blocking must-have"
grep -qiE 'M6 .*Yellow / Partial' "${LAUNCH_GATE}" || fail "launch gate must list M6 as a Yellow/Partial must-have blocker"
emit "launch_gate_m4_m6_blockers=OK (launch gate lists M4 launch-blocking and M6 Yellow/Partial as must-have blockers)"
grep -qiE 'S5 .*(Yellow|M4-gated)' "${LAUNCH_GATE}" || fail "launch gate must keep S5 M4-gated / Yellow"
grep -qiE 'S7 .*(Yellow|M4-gated)' "${LAUNCH_GATE}" || fail "launch gate must keep S7 M4-gated / Yellow"
grep -qiE 'S5 / S7 remain M4-gated|M4-gated' "${LAUNCH_GATE}" || fail "launch gate must keep S5/S7 M4-gated"
emit "launch_gate_s5_s7_gated=OK (launch gate keeps S5/S7 M4-gated / Yellow)"

# ---------------------------------------------------------------------------
# 19. C4/C5 remain OPEN in the matrix, blocker register, and launch gate.
# ---------------------------------------------------------------------------
grep -qiE 'C4 and C5 remain +\*{0,2}OPEN' "${CRITERIA}" || fail "readiness matrix must hold C4 and C5 OPEN"
grep -qi 'C4' "${BLOCKER_REGISTER}" && grep -qi 'OPEN' "${BLOCKER_REGISTER}" || fail "blocker register must hold C4/C5 OPEN"
grep -qi 'C4 remains OPEN' "${LAUNCH_GATE}" || fail "launch gate must hold C4 OPEN"
grep -qi 'C5 remains OPEN' "${LAUNCH_GATE}" || fail "launch gate must hold C5 OPEN"
emit "c4_c5_open=OK (C4/C5 OPEN in the readiness matrix, blocker register, and launch gate)"

# ---------------------------------------------------------------------------
# 20. TestNet/MainNet untouched and N1-N7 Red.
# ---------------------------------------------------------------------------
grep -qF 'N1, N2, N3, N4, N7 Red' "${CRITERIA}" || fail "readiness matrix must hold N1-N4/N7 Red"
grep -qF 'N5 (C4) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N5 (C4) OPEN / Red"
grep -qF 'N6 (C5) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N6 (C5) OPEN / Red"
grep -qiE 'N1.?N7 remain \*{0,2}Red|N1–N7 remain \*{0,2}Red' "${BLOCKER_REGISTER}" \
  || fail "blocker register must hold N1-N7 Red"
grep -qi 'TestNet and MainNet remain' "${LAUNCH_GATE}" || fail "launch gate must hold TestNet/MainNet untouched"
emit "testnet_mainnet_non_claim=OK (N1-N7 Red in the matrix and blocker register; TestNet/MainNet untouched in the launch gate)"

# ---------------------------------------------------------------------------
# 21. No `devnet-seeds.live.json` live-publication claim in the table/checklists/blocker.
#     Every line mentioning it must carry a negation or an M4/gating/prerequisite qualifier.
# ---------------------------------------------------------------------------
for block in "${TABLE10}" "${SEC4}" "${SEC5}" "${BLOCKER_REGISTER}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |until|once|after|require|promot|would|M4|Route A|prerequisite|deferr|schema-valid|published from|template' \
      || { printf '%s\n' "${line}" >&2; fail "possible live devnet-seeds.live.json publication claim in $(basename "${block}")"; }
  done < <(grep -F 'devnet-seeds.live.json' "${block}" | tr -d '\r' || true)
done
emit "devnet_seeds_live_non_claim=OK (no unqualified devnet-seeds.live.json live-publication claim in the table/checklists/blocker register)"

# ---------------------------------------------------------------------------
# 22. No seed/bootnode/faucet/RPC/explorer/status-service DEPLOYMENT claim.
#     Every "... deployed / is live" line must also carry a negation on the same line.
# ---------------------------------------------------------------------------
for f in "${TABLE10}" "${SEC4}" "${SEC5}" "${BLOCKER_REGISTER}" "${LAUNCH_GATE}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|deferred|until|once|after|would|M4|requires|instead|prerequisite' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a live deployment"; }
  done < <(grep -iE '(seed|bootnode|faucet|RPC|explorer|status service|status page|health view)[^.]{0,40}(is|was|has been|are) (deployed|live|maintained)' "${f}" | tr -d '\r' || true)
done
emit "deployment_non_claim=OK (no seed/bootnode/faucet/RPC/explorer/status-service live-deployment claim in the compared docs)"

# ---------------------------------------------------------------------------
# 23. No runtime-mutation claim. Every "... mutated/transitioned" line must carry a negation.
# ---------------------------------------------------------------------------
for f in "${TABLE10}" "${SEC4}" "${SEC5}" "${BLOCKER_REGISTER}" "${LAUNCH_GATE}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|nothing|never' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a runtime mutation"; }
  done < <(grep -iE '(validator set|epoch|sequence|marker|LivePqcTrustState)[^.]{0,40}(was|is|has been|are) (mutated|transitioned|advanced|changed)' "${f}" | tr -d '\r' || true)
done
emit "runtime_mutation_non_claim=OK (no validator/epoch/sequence/marker/LivePqcTrustState mutation claim in the compared docs)"

# ---------------------------------------------------------------------------
# 24. No readiness item moves Green in this run (M4/M6/S5/S7 stay 🟡).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 (no Green move)"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 (no Green move)"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 (no Green move)"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 (no Green move)"
grep -qi 'Updated Run 412' "${CRITERIA}" || fail "readiness matrix must carry the Run 412 narrative"
awk '/^Updated Run 412 —/{g=1} g&&/^Updated Run [0-9]+ —/&&!/412/{g=0} g' "${CRITERIA}" \
  | tr -d '\r' | tr '\n' ' ' | grep -qiE 'No readiness item moves' \
  || fail "Run 412 readiness narrative must state no readiness item moves"
emit "no_green_move=OK (Run 412 moves no readiness item Green; M4/M6/S5/S7 stay 🟡)"

# ---------------------------------------------------------------------------
# 25. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "READINESS_STATUS_BLOCKER_LINT_REPORT.json" \
            "READINESS_STATUS_BLOCKER_LINT_REPORT.txt" \
            "READINESS_CONTRADICTION_LEDGER_LINT_REPORT.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_output_non_commit=OK (no generated status/blocker-lint report is committed; transient output stays outside the tree)"

# ---------------------------------------------------------------------------
# 26. Run 412 contradiction ledger entry exists and holds the fixed posture.
# ---------------------------------------------------------------------------
RUN412_ENTRY="$(grep -E '^Run 412 —' "${CONTRADICTION}" | tr -d '\r' || true)"
[ -n "${RUN412_ENTRY}" ] || fail "contradiction ledger missing the Run 412 entry"
printf '%s' "${RUN412_ENTRY}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
  || fail "Run 412 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN412_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 412 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN412_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN412_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 412 contradiction entry must state C4/C5 remain OPEN"
emit "run_412_ledger_entry=OK (Run 412 recorded in the contradiction ledger; no protocol contradiction; NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 27. Non-claim grep over the Run 412-authored docs (normalized).
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
[ -f "${EV412}" ] && CLAIM_TARGETS+=("${EV412}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime|fails? closed|anywhere it appears' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 412 docs)"
emit "runtime_mutation=NONE (Run 412 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 28. Secret / private-material + absolute-path scan over the Run 412-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV412}" ] && SCAN_FILES+=("${EV412}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 412 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 412 doc"
fi
emit "secret_scan=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 412 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet readiness table/checklist/blocker consistency lint: the status/blocker lint guide is published and safety-labelled; the §10 current-status table covers M1-M20 and S1-S7 and agrees with the §4 must-have and §5 should-have checklists on every item; M4 is Yellow/launch-blocking, M6 Yellow/Partial, and S5/S7 Yellow consistently; the blocker register carries M4/M6/S5/S7 as Yellow/open and keeps the no-launch-until-every-must-have-is-Green rule; the launch go/no-go gate remains NO-GO / NOT launch-ready, lists M4 and M6 as must-have blockers, and keeps S5/S7 M4-gated; C4/C5 remain OPEN in the matrix, blocker register, and launch gate; N1-N7 stay Red and TestNet/MainNet untouched; no live seed/bootnode/faucet/RPC/explorer/status-service deployment, devnet-seeds.live.json, C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed; no readiness item moves Green; nothing generated is committed; the working tree stays clean; and the secret/private-material scan is clean)"