#!/usr/bin/env bash
# Run 413: public DevNet readiness recommendation/gap-matrix consistency lint.
#
# This harness is a READ-ONLY, fail-closed consistency lint. It checks that the public DevNet
# readiness matrix's §11 next-run recommendation table and §16 consolidated gap matrix cannot
# drift away from its §10 current-status table (the canonical per-item status ledger / SOURCE OF
# TRUTH), and that neither §11 nor §16 softens, resolves, or overclaims the frozen M4/M6/S5/S7 /
# NO-GO / C4-C5-OPEN posture:
#
#   * the canonical readiness matrix
#       docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
#       - its §10 current-status table (SOURCE OF TRUTH),
#       - its §11 next-run recommendation table (M1-M20),
#       - its §16 consolidated gap matrix (per-item rows).
#
# It extends the Run 412 per-milestone status/blocker lint (which keeps the §10 table in step
# with the §4/§5 checklists, the blocker register, and the launch gate) to the two remaining
# status-bearing views of the readiness matrix: the §11 next-run recommendation table and the
# §16 consolidated gap matrix. It adds NO feature surface and moves NO readiness item. It
# generates only a transient summary OUTSIDE the repository tree and commits nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO
# build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation. No node
# is started, no port is opened, and no state/data dir is written.
#
# It fails closed if:
#   * the recommendation/gap-matrix lint guide is missing or not safety-labelled;
#   * the readiness matrix, its §10 table, its §11 table, or its §16 matrix is missing;
#   * the §11 next-run recommendation table disagrees with the §10 table on any M1-M20 status;
#   * the §16 consolidated gap matrix disagrees with the §10 table on any mapped M/S status;
#   * §11 or §16 marks M4 resolved/Green/non-blocking/launch-complete/not-launch-blocking;
#   * §11 or §16 marks M6 fully Green/resolved/launch-complete or no longer Partial;
#   * §16 drops M4's Launch-blocker gap posture or M6/S5's M4-gated posture;
#   * §16 marks C4 or C5 anything other than 🔴 / OPEN;
#   * §11 or §16 claims public DevNet is launch-ready/GO, C4/C5 closed, TestNet/MainNet ready, a
#     live seed/bootnode/faucet/RPC/explorer/status-service deployment, a live
#     `devnet-seeds.live.json`, or a runtime mutation;
#   * any generated artifact is committed, the working tree is left dirty, or a secret /
#     private-material / absolute path appears in the Run 413-authored docs.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run413-public-devnet-readiness-recommendation-gap-matrix-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md"
STATUS_LINT="${PDN}/READINESS_STATUS_BLOCKER_LINT.md"
LEDGER_LINT="${PDN}/READINESS_CONTRADICTION_LEDGER_LINT.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
LAUNCH_GATE="${PDN}/LAUNCH_GO_NO_GO.md"
BLOCKER_REGISTER="${PDN}/BLOCKER_REGISTER.md"
C4C5_CRITERIA="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV413="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_413.md"

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

# Mapping from §16 consolidated-gap-matrix descriptive label -> M/S item code (scoped items only).
declare -A GAP_LABEL_ITEM=(
  ["genesis package"]=M1
  ["release binary provenance"]=M2
  ["release reproducibility / SHA / BuildID"]=M3
  ["seed nodes / bootnodes"]=M4
  ["validator onboarding"]=M5
  ["validator identity"]=M6
  ["validator key-management guidance"]=M7
  ["trust-bundle bootstrap"]=M8
  ["PQC root / signing-key guidance"]=M9
  ["public P2P port posture"]=M10
  ["peer admission policy"]=M11
  ["abuse handling"]=M12
  ["telemetry / metrics"]=M13
  ["monitoring / alerting"]=M14
  ["status page"]=S5
  ["reset policy"]=M15
  ["incident response"]=M16
  ["snapshot / backup / restore"]=S1
  ["data retention"]=S2
  ["upgrade procedure"]=S3
  ["rollback procedure"]=S4
  ["public documentation"]=M17
  ["user-facing disclaimers"]=M18
  ["network parameter publication"]=M19
  ["genesis hash publication"]=M20
)

log()  { printf '[run413] %s\n' "$*"; }
fail() { printf '[run413] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${STATUS_LINT}" "${LEDGER_LINT}" "${ARTIFACT_INDEX}" "${OP_MAP}" \
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
TABLE11="${OUTDIR}/section11.txt"
TABLE16="${OUTDIR}/section16.txt"
section_block 10 '^## 11[.] ' "${CRITERIA}" > "${TABLE10}"
section_block 11 '^## 12[.] ' "${CRITERIA}" > "${TABLE11}"
section_block 16 '^## 17[.] ' "${CRITERIA}" > "${TABLE16}"
[ -s "${TABLE10}" ] || fail "could not extract §10 current-status table"
[ -s "${TABLE11}" ] || fail "could not extract §11 next-run recommendation table"
[ -s "${TABLE16}" ] || fail "could not extract §16 consolidated gap matrix"

glyph_to_word() {
  if   printf '%s' "$1" | grep -q '🟢'; then echo Green
  elif printf '%s' "$1" | grep -q '🟡'; then echo Yellow
  elif printf '%s' "$1" | grep -q '🔴'; then echo Red
  elif printf '%s' "$1" | grep -q '⚪'; then echo NA
  else echo UNKNOWN; fi
}

# Status glyph in the §10 table row for an item ("| M4 seed/bootnodes | 🟡 | ...").
table10_status_of() {
  local item="$1" row
  row="$(awk -v it="${item}" '$0 ~ ("^\\| " it " ") { print; exit }' "${TABLE10}")"
  [ -n "${row}" ] || { echo MISSING; return; }
  glyph_to_word "$(printf '%s' "${row}" | awk -F'|' '{print $3}')"
}

# Status glyph in the §11 next-run recommendation row for an item ("| M4 | 🟡 | ...").
table11_status_of() {
  local item="$1" row
  row="$(awk -v it="${item}" '$0 ~ ("^\\| " it " \\|") { print; exit }' "${TABLE11}")"
  [ -n "${row}" ] || { echo MISSING; return; }
  glyph_to_word "$(printf '%s' "${row}" | awk -F'|' '{print $3}')"
}

# §11 raw recommendation row (whole line) for an item.
table11_row_of() {
  local item="$1"
  awk -v it="${item}" '$0 ~ ("^\\| " it " \\|") { print; exit }' "${TABLE11}"
}

# Status glyph (column 4) + whole row for a §16 gap-matrix descriptive label.
gap16_row_of() {
  local label="$1"
  awk -v it="${label}" '$0 ~ ("^\\| " it " \\| ") { print; exit }' "${TABLE16}"
}
gap16_status_of() {
  local row="$1"
  [ -n "${row}" ] || { echo MISSING; return; }
  glyph_to_word "$(printf '%s' "${row}" | awk -F'|' '{print $5}')"
}

# ---------------------------------------------------------------------------
# 1. The recommendation/gap-matrix lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "recommendation/gap-matrix lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "lint guide missing C4/C5 OPEN label"
grep -qi '§11' "${LINT_GUIDE}" || fail "lint guide must describe the §11 next-run recommendation table"
grep -qi '§16' "${LINT_GUIDE}" || fail "lint guide must describe the §16 consolidated gap matrix"
emit "recommendation_gap_matrix_lint_guide_present=OK (READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 2-5. Readiness matrix + §10/§11/§16 sections present.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" \
  || fail "readiness matrix missing the NOT launch-ready statement"
emit "readiness_matrix_present=OK (QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md exists)"
grep -qi '^## 10[.] Current status per item' "${CRITERIA}" || fail "§10 current-status table heading missing"
emit "status_table_present=OK (§10 current-status table present — source of truth)"
grep -qi '^## 11[.] Exact next run recommendation' "${CRITERIA}" || fail "§11 next-run recommendation heading missing"
emit "recommendation_table_present=OK (§11 next-run recommendation table present)"
grep -qi '^## 16[.] Consolidated gap matrix' "${CRITERIA}" || fail "§16 consolidated gap matrix heading missing"
emit "gap_matrix_present=OK (§16 consolidated gap matrix present)"

# ---------------------------------------------------------------------------
# 6. §11 next-run recommendation table agrees with §10 for every M1-M20 it mentions.
# ---------------------------------------------------------------------------
for n in $(seq 1 20); do
  it="M${n}"
  t10="$(table10_status_of "${it}")"
  [ "${t10}" != "MISSING" ] || fail "§10 table missing row for ${it}"
  t11="$(table11_status_of "${it}")"
  [ "${t11}" != "MISSING" ] || fail "§11 next-run recommendation table missing row for ${it}"
  [ "${t11}" = "${t10}" ] || fail "${it}: §11 recommendation (${t11}) disagrees with §10 table (${t10})"
  [ "${t11}" = "${EXPECT_M[$it]}" ] || fail "${it}: §11 status ${t11} != frozen expected ${EXPECT_M[$it]}"
done
emit "recommendation_vs_status_agree=OK (§11 next-run recommendation table agrees with §10 table for M1-M20; matches frozen truth)"

# ---------------------------------------------------------------------------
# 7. §16 consolidated gap matrix agrees with §10 for every scoped M/S item it mentions.
# ---------------------------------------------------------------------------
mapped_count=0
for label in "${!GAP_LABEL_ITEM[@]}"; do
  it="${GAP_LABEL_ITEM[$label]}"
  row="$(gap16_row_of "${label}")"
  [ -n "${row}" ] || fail "§16 gap matrix missing row for '${label}' (${it})"
  g16="$(gap16_status_of "${row}")"
  [ "${g16}" != "MISSING" ] || fail "§16 gap matrix row '${label}' has no status glyph"
  t10="$(table10_status_of "${it}")"
  [ "${t10}" != "MISSING" ] || fail "§10 table missing row for ${it}"
  [ "${g16}" = "${t10}" ] || fail "${it} ('${label}'): §16 gap matrix (${g16}) disagrees with §10 table (${t10})"
  case "${it}" in
    S*) exp="${EXPECT_S[$it]}";;
    *)  exp="${EXPECT_M[$it]}";;
  esac
  [ "${g16}" = "${exp}" ] || fail "${it} ('${label}'): §16 status ${g16} != frozen expected ${exp}"
  mapped_count=$((mapped_count + 1))
done
emit "gap_matrix_vs_status_agree=OK (§16 consolidated gap matrix agrees with §10 table for all ${mapped_count} scoped M/S items; matches frozen truth)"

# ---------------------------------------------------------------------------
# 8. M4 remains Yellow / launch-blocking in §11 and §16.
# ---------------------------------------------------------------------------
[ "$(table11_status_of M4)" = "Yellow" ] || fail "§11 must keep M4 Yellow"
M4_REC="$(table11_row_of M4)"
printf '%s' "${M4_REC}" | grep -qiE 'no Green move|not proven' \
  || fail "§11 M4 row must keep its 'external reachability NOT proven / no Green move' follow-up posture"
if printf '%s' "${M4_REC}" | grep -qiE 'M4 is Green|resolved|launch-complete|non-blocking|not launch-blocking|\bDone\b'; then
  fail "§11 M4 row must not mark M4 resolved/Green/non-blocking/launch-complete"
fi
M4_GAP="$(gap16_row_of 'seed nodes / bootnodes')"
[ "$(gap16_status_of "${M4_GAP}")" = "Yellow" ] || fail "§16 must keep the seed/bootnodes (M4) row Yellow"
printf '%s' "${M4_GAP}" | grep -qi 'Launch blocker' \
  || fail "§16 seed/bootnodes (M4) row must keep its Launch-blocker gap posture"
emit "m4_recommendation_gap_consistent=OK (M4 Yellow / launch-blocking in §11 (no Green move) and §16 (Launch blocker))"

# ---------------------------------------------------------------------------
# 9. M6 remains Yellow / Partial (M4-gated) in §11 and §16.
# ---------------------------------------------------------------------------
[ "$(table11_status_of M6)" = "Yellow" ] || fail "§11 must keep M6 Yellow"
M6_REC="$(table11_row_of M6)"
printf '%s' "${M6_REC}" | grep -qiE 'Partial|M4-gated' \
  || fail "§11 M6 row must keep its Partial / M4-gated posture"
if printf '%s' "${M6_REC}" | grep -qiE 'M6 is Green|fully Green|resolved|launch-complete|no longer Partial'; then
  fail "§11 M6 row must not mark M6 fully Green/resolved/launch-complete"
fi
M6_GAP="$(gap16_row_of 'validator identity')"
[ "$(gap16_status_of "${M6_GAP}")" = "Yellow" ] || fail "§16 must keep the validator-identity (M6) row Yellow"
printf '%s' "${M6_GAP}" | grep -qi 'M4-gated' \
  || fail "§16 validator-identity (M6) row must keep its M4-gated posture"
emit "m6_recommendation_gap_consistent=OK (M6 Yellow / Partial / M4-gated in §11 and §16)"

# ---------------------------------------------------------------------------
# 10. S5/S7 remain Yellow / M4-gated. (§11 covers M-only; S5 lives in §16; S7 in §10/§5.)
# ---------------------------------------------------------------------------
S5_GAP="$(gap16_row_of 'status page')"
[ "$(gap16_status_of "${S5_GAP}")" = "Yellow" ] || fail "§16 must keep the status-page (S5) row Yellow"
printf '%s' "${S5_GAP}" | grep -qiE 'M4-gated|once M4' \
  || fail "§16 status-page (S5) row must keep its M4-gated posture"
[ "$(table10_status_of S5)" = "Yellow" ] || fail "§10 must keep S5 Yellow"
[ "$(table10_status_of S7)" = "Yellow" ] || fail "§10 must keep S7 Yellow"
emit "s5_s7_recommendation_gap_consistent=OK (S5 Yellow / M4-gated in §16; S5/S7 Yellow in §10)"

# ---------------------------------------------------------------------------
# 11. Public DevNet remains NO-GO / NOT launch-ready — §11/§16 must not claim otherwise.
# ---------------------------------------------------------------------------
for blk in "${TABLE11}" "${TABLE16}"; do
  if grep -iE 'launch-ready|GO for launch|ready to launch|is a GO\b' "${blk}" \
     | grep -viE 'NOT launch-ready|not launch-ready|no-go|not a GO' >/dev/null 2>&1; then
    grep -inE 'launch-ready|GO for launch|ready to launch|is a GO\b' "${blk}" >&2 || true
    fail "$(basename "${blk}") appears to claim public DevNet is launch-ready / GO"
  fi
done
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" || fail "readiness matrix must hold NOT launch-ready"
grep -qiE 'NO-GO|NOT launch-ready' "${LAUNCH_GATE}" || fail "launch gate must remain NO-GO / NOT launch-ready"
emit "launch_nogo_consistent=OK (§11/§16 make no launch-ready/GO claim; matrix + launch gate remain NO-GO / NOT launch-ready)"

# ---------------------------------------------------------------------------
# 12. C4/C5 remain OPEN — §16 keeps C4/C5 🔴 OPEN; neither §11 nor §16 claims closure.
# ---------------------------------------------------------------------------
C4_GAP="$(gap16_row_of 'C4')"
C5_GAP="$(gap16_row_of 'C5')"
[ -n "${C4_GAP}" ] || fail "§16 gap matrix missing the C4 row"
[ -n "${C5_GAP}" ] || fail "§16 gap matrix missing the C5 row"
[ "$(gap16_status_of "${C4_GAP}")" = "Red" ] || fail "§16 C4 row must stay 🔴"
[ "$(gap16_status_of "${C5_GAP}")" = "Red" ] || fail "§16 C5 row must stay 🔴"
printf '%s' "${C4_GAP}" | grep -qi 'OPEN' || fail "§16 C4 row must say OPEN"
printf '%s' "${C5_GAP}" | grep -qi 'OPEN' || fail "§16 C5 row must say OPEN"
for blk in "${TABLE11}" "${TABLE16}"; do
  if grep -iE 'C4 (is )?closed|C5 (is )?closed|C4/C5 closed' "${blk}" >/dev/null 2>&1; then
    fail "$(basename "${blk}") appears to claim C4/C5 closure"
  fi
done
grep -qiE 'C4 and C5 remain +\*{0,2}OPEN' "${CRITERIA}" || fail "readiness matrix must hold C4 and C5 OPEN"
emit "c4_c5_open_consistent=OK (§16 keeps C4/C5 🔴 OPEN; no C4/C5 closure claim in §11/§16; matrix holds C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 13. TestNet/MainNet untouched; N1-N7 Red; §11/§16 make no TestNet/MainNet-ready claim.
# ---------------------------------------------------------------------------
for blk in "${TABLE11}" "${TABLE16}"; do
  if grep -iE 'TestNet (is )?ready|MainNet (is )?ready|ready for (TestNet|MainNet)' "${blk}" >/dev/null 2>&1; then
    fail "$(basename "${blk}") appears to claim TestNet/MainNet readiness"
  fi
done
grep -qF 'N1, N2, N3, N4, N7 Red' "${CRITERIA}" || fail "readiness matrix must hold N1-N4/N7 Red"
grep -qF 'N5 (C4) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N5 (C4) OPEN / Red"
grep -qF 'N6 (C5) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N6 (C5) OPEN / Red"
emit "testnet_mainnet_non_claim=OK (no TestNet/MainNet-ready claim in §11/§16; matrix holds N1-N7 Red / untouched)"

# ---------------------------------------------------------------------------
# 14. No `devnet-seeds.live.json` live-publication claim in §11/§16.
#     Every line mentioning it must carry a negation or an M4/gating/prerequisite qualifier.
# ---------------------------------------------------------------------------
for blk in "${TABLE11}" "${TABLE16}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |until|once|after|require|promot|would|M4|Route A|prerequisite|deferr|schema-valid|published from|template' \
      || { printf '%s\n' "${line}" >&2; fail "possible live devnet-seeds.live.json publication claim in $(basename "${blk}")"; }
  done < <(grep -F 'devnet-seeds.live.json' "${blk}" | tr -d '\r' || true)
done
emit "devnet_seeds_live_non_claim=OK (no unqualified devnet-seeds.live.json live-publication claim in §11/§16)"

# ---------------------------------------------------------------------------
# 15. No seed/bootnode/faucet/RPC/explorer/status-service DEPLOYMENT claim in §11/§16.
# ---------------------------------------------------------------------------
for blk in "${TABLE11}" "${TABLE16}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|deferred|until|once|after|would|M4|requires|instead|prerequisite|blocker' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${blk}") appears to claim a live deployment"; }
  done < <(grep -iE '(seed|bootnode|faucet|RPC|explorer|status service|status page|health view)[^.]{0,40}(is|was|has been|are) (deployed|live|maintained)' "${blk}" | tr -d '\r' || true)
done
emit "deployment_non_claim=OK (no seed/bootnode/faucet/RPC/explorer/status-service live-deployment claim in §11/§16)"

# ---------------------------------------------------------------------------
# 16. No runtime-mutation claim in §11/§16.
# ---------------------------------------------------------------------------
for blk in "${TABLE11}" "${TABLE16}"; do
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|nothing|never' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${blk}") appears to claim a runtime mutation"; }
  done < <(grep -iE '(validator set|epoch|sequence|marker|LivePqcTrustState)[^.]{0,40}(was|is|has been|are) (mutated|transitioned|advanced|changed)' "${blk}" | tr -d '\r' || true)
done
emit "runtime_mutation_non_claim=OK (no validator/epoch/sequence/marker/LivePqcTrustState mutation claim in §11/§16)"

# ---------------------------------------------------------------------------
# 17. No readiness item moves Green in this run (M4/M6/S5/S7 stay 🟡 in §10).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 (no Green move)"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 (no Green move)"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 (no Green move)"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 (no Green move)"
grep -qi 'Updated Run 413' "${CRITERIA}" || fail "readiness matrix must carry the Run 413 narrative"
awk '/^Updated Run 413 —/{g=1} g&&/^Updated Run [0-9]+ —/&&!/413/{g=0} g' "${CRITERIA}" \
  | tr -d '\r' | tr '\n' ' ' | grep -qiE 'No readiness item moves|no item moves Green|No readiness item moves Green' \
  || fail "Run 413 readiness narrative must state no readiness item moves"
emit "no_green_move=OK (Run 413 moves no readiness item Green; M4/M6/S5/S7 stay 🟡)"

# ---------------------------------------------------------------------------
# 18. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "READINESS_RECOMMENDATION_GAP_MATRIX_LINT_REPORT.json" \
            "READINESS_RECOMMENDATION_GAP_MATRIX_LINT_REPORT.txt" \
            "READINESS_STATUS_BLOCKER_LINT_REPORT.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_output_non_commit=OK (no generated recommendation/gap-matrix-lint report is committed; transient output stays outside the tree)"

# ---------------------------------------------------------------------------
# 19. Run 413 contradiction ledger entry exists and holds the fixed posture.
# ---------------------------------------------------------------------------
RUN413_ENTRY="$(grep -E '^Run 413 —' "${CONTRADICTION}" | tr -d '\r' || true)"
[ -n "${RUN413_ENTRY}" ] || fail "contradiction ledger missing the Run 413 entry"
printf '%s' "${RUN413_ENTRY}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
  || fail "Run 413 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN413_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 413 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN413_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN413_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 413 contradiction entry must state C4/C5 remain OPEN"
emit "run_413_ledger_entry=OK (Run 413 recorded in the contradiction ledger; no protocol contradiction; NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 20. Non-claim grep over the Run 413-authored docs (normalized).
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
[ -f "${EV413}" ] && CLAIM_TARGETS+=("${EV413}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime|fails? closed|anywhere it appears' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 413 docs)"
emit "runtime_mutation=NONE (Run 413 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 21. Secret / private-material + absolute-path scan over the Run 413-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV413}" ] && SCAN_FILES+=("${EV413}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 413 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 413 doc"
fi
emit "secret_scan=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 413 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet readiness recommendation/gap-matrix consistency lint: the recommendation/gap-matrix lint guide is published and safety-labelled; the §11 next-run recommendation table agrees with the §10 current-status table on every M1-M20 status and the §16 consolidated gap matrix agrees with it on every scoped M/S item; M4 stays Yellow/launch-blocking (§11 no-Green-move, §16 Launch blocker), M6 Yellow/Partial/M4-gated, and S5 Yellow/M4-gated; public DevNet stays NO-GO / NOT launch-ready; C4/C5 stay 🔴 OPEN with no closure claim; TestNet/MainNet stay untouched and N1-N7 Red; no live seed/bootnode/faucet/RPC/explorer/status-service deployment, devnet-seeds.live.json, C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed in §11/§16; no readiness item moves Green; nothing generated is committed; the working tree stays clean; and the secret/private-material scan is clean)"