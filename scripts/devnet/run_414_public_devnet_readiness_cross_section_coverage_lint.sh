#!/usr/bin/env bash
# Run 414: public DevNet readiness cross-section coverage lint.
#
# This harness is a READ-ONLY, fail-closed COVERAGE lint. It checks that the public DevNet
# readiness matrix's status-bearing views cannot silently DROP a milestone row that its §10
# current-status table (the canonical per-item status ledger / SOURCE OF TRUTH) still carries:
#
#   * the canonical readiness matrix
#       docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
#       - its §10 current-status table (SOURCE OF TRUTH; must carry M1-M20 + S1-S7 exactly once),
#       - its §11 next-run recommendation table (must carry M1-M20 exactly once; must-have-only),
#       - its §16 consolidated gap matrix (per-item rows, keyed by descriptive label).
#
# It extends the Run 412 per-milestone status/blocker lint and the Run 413 recommendation/gap-matrix
# STATUS lint (which compare the VALUES of rows that exist) to the COVERAGE dimension: the SET of
# rows that must exist. It adds NO feature surface and moves NO readiness item. It generates only a
# transient summary OUTSIDE the repository tree and commits nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO build.rs
# change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation. No node is
# started, no port is opened, and no state/data dir is written.
#
# It fails closed if:
#   * the cross-section coverage lint guide is missing or not safety-labelled;
#   * the readiness matrix, its §10 table, its §11 table, or its §16 matrix is missing;
#   * §10 omits or duplicates any M1-M20 / S1-S7 row;
#   * §11 omits or duplicates any M1-M20 row, or gains an S row without a documented scope change;
#   * §16 omits or duplicates any required mapped label, or carries a status-bearing row whose
#     label is not in the full label-to-item map (an unknown / renamed label);
#   * an existing Run 413 scoped §16 mapped row is removed;
#   * a §16 coverage exception is missing item code / reason / protection source, or is used for
#     M4/M6/S5/S7 without explicit Yellow / M4-gated protection;
#   * §10/§11/§16 status values disagree for a represented item, or M4/M6/S5/S7 leave Yellow;
#   * §11/§16 claims launch-ready/GO, C4/C5 closure, TestNet/MainNet readiness, a live
#     seed/bootnode/faucet/RPC/explorer/status-service deployment, a `devnet-seeds.live.json`, or a
#     runtime mutation;
#   * any generated artifact is committed, the working tree is left dirty, or a secret /
#     private-material / absolute path appears in the Run 414-authored docs.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run414-public-devnet-readiness-cross-section-coverage-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/READINESS_CROSS_SECTION_COVERAGE_LINT.md"
RECGAP_LINT="${PDN}/READINESS_RECOMMENDATION_GAP_MATRIX_LINT.md"
STATUS_LINT="${PDN}/READINESS_STATUS_BLOCKER_LINT.md"
LEDGER_LINT="${PDN}/READINESS_CONTRADICTION_LEDGER_LINT.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
LAUNCH_GATE="${PDN}/LAUNCH_GO_NO_GO.md"
BLOCKER_REGISTER="${PDN}/BLOCKER_REGISTER.md"
C4C5_CRITERIA="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV414="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_414.md"

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

# REQUIRED §16 label -> item map: the scoped M/S rows §16 must carry exactly once (Run 413 set).
declare -A REQUIRED_GAP=(
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

# FULL §16 label -> item map: REQUIRED plus every other status-bearing §16 label (non-scoped),
# so the unmapped-label check can distinguish a known deferred/boundary row from an unknown one.
declare -A FULL_GAP
for k in "${!REQUIRED_GAP[@]}"; do FULL_GAP["$k"]="${REQUIRED_GAP[$k]}"; done
FULL_GAP["faucet"]=T1
FULL_GAP["RPC gateway"]=T2
FULL_GAP["RPC rate limiting"]=T3
FULL_GAP["explorer"]=T4
FULL_GAP["governance proof status"]=T5
FULL_GAP["validator-set rotation status"]=T6
FULL_GAP["runtime wiring for authority lifecycle"]=N3
FULL_GAP["MainNet custody"]=N1
FULL_GAP["MainNet authority rotation/revocation"]=N2
FULL_GAP["DevNet authority lifecycle"]=AUTHORITY-LIFECYCLE-BOUNDARY
FULL_GAP["C4"]=C4
FULL_GAP["C5"]=C5

# §10 M/S items not covered by a §16 mapped label -> documented §16 coverage exceptions.
COVERAGE_EXCEPTIONS=(S6 S7)

log()  { printf '[run414] %s\n' "$*"; }
fail() { printf '[run414] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${RECGAP_LINT}" "${STATUS_LINT}" "${LEDGER_LINT}" "${ARTIFACT_INDEX}" \
         "${OP_MAP}" "${LAUNCH_GATE}" "${BLOCKER_REGISTER}" "${C4C5_CRITERIA}" "${CRITERIA}" \
         "${CONTRADICTION}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# Extract a numbered section block "## N. ..." up to the next "## N+? ." heading, from any file.
section_block() {
  local start="$1" nextre="$2" src="$3"
  awk -v s="^## ${start}[.] " -v n="${nextre}" '
    $0 ~ s { grab=1 }
    grab && $0 ~ n && $0 !~ s { grab=0 }
    grab { print }
  ' "${src}" | tr -d '\r'
}

# Extract §10/§11/§16 section blocks from a given criteria file into <pfx>.s10/.s11/.s16.
extract_sections() {
  local src="$1" pfx="$2"
  section_block 10 '^## 11[.] ' "${src}" > "${pfx}.s10"
  section_block 11 '^## 12[.] ' "${src}" > "${pfx}.s11"
  section_block 16 '^## 17[.] ' "${src}" > "${pfx}.s16"
}

glyph_to_word() {
  if   printf '%s' "$1" | grep -q '🟢'; then echo Green
  elif printf '%s' "$1" | grep -q '🟡'; then echo Yellow
  elif printf '%s' "$1" | grep -q '🔴'; then echo Red
  elif printf '%s' "$1" | grep -q '⚪'; then echo NA
  else echo UNKNOWN; fi
}

# --- coverage extractors (operate on a section file so self-tests can reuse them) ---

# §10 M/S item codes (first token of column 2), one per line.
s10_ms_items() {
  awk -F'|' 'NF>=3 { c=$2; gsub(/^ +| +$/,"",c); split(c,a," "); if(a[1] ~ /^[MS][0-9]+$/) print a[1] }' "$1"
}
# §11 M item codes (column 2 == M#), one per line.
s11_m_items() {
  awk -F'|' 'NF>=3 { c=$2; gsub(/^ +| +$/,"",c); if(c ~ /^M[0-9]+$/) print c }' "$1"
}
# §11 S rows (column 2 == S#), one per line — expected to be empty (must-have-only view).
s11_s_items() {
  awk -F'|' 'NF>=3 { c=$2; gsub(/^ +| +$/,"",c); if(c ~ /^S[0-9]+$/) print c }' "$1"
}
# §16 status-bearing row labels (column 2 where column 4 carries a glyph), one per line.
s16_labels() {
  awk -F'|' 'NF>=6 { lbl=$2; gsub(/^ +| +$/,"",lbl); st=$5;
    if(lbl!="Item" && lbl !~ /^-+$/ && (st ~ /🟢/||st ~ /🟡/||st ~ /🔴/||st ~ /⚪/)) print lbl }' "$1"
}

count_of() { grep -Fxc "$2" <<<"$1" 2>/dev/null || true; }

# check_s10_coverage <s10file>: every M1-M20 + S1-S7 present exactly once. 0=ok, 1=violation.
check_s10_coverage() {
  local items; items="$(s10_ms_items "$1")"
  local n it c
  for n in $(seq 1 20); do it="M${n}"; c="$(count_of "${items}" "${it}")"
    [ "${c}" = "1" ] || { echo "§10 coverage: ${it} count=${c} (want 1)" >&2; return 1; }; done
  for n in $(seq 1 7); do it="S${n}"; c="$(count_of "${items}" "${it}")"
    [ "${c}" = "1" ] || { echo "§10 coverage: ${it} count=${c} (want 1)" >&2; return 1; }; done
  return 0
}

# check_s11_coverage <s11file>: every M1-M20 present exactly once; no S rows. 0=ok, 1=violation.
check_s11_coverage() {
  local items; items="$(s11_m_items "$1")"
  local n it c
  for n in $(seq 1 20); do it="M${n}"; c="$(count_of "${items}" "${it}")"
    [ "${c}" = "1" ] || { echo "§11 coverage: ${it} count=${c} (want 1)" >&2; return 1; }; done
  local srows; srows="$(s11_s_items "$1")"
  [ -z "${srows}" ] || { echo "§11 unexpected should-have row(s): ${srows}" >&2; return 1; }
  return 0
}

# check_s16_required <s16file>: every REQUIRED_GAP label present exactly once. 0=ok, 1=violation.
check_s16_required() {
  local labels; labels="$(s16_labels "$1")"
  local lbl c
  for lbl in "${!REQUIRED_GAP[@]}"; do c="$(count_of "${labels}" "${lbl}")"
    [ "${c}" = "1" ] || { echo "§16 required mapped label '${lbl}' (${REQUIRED_GAP[$lbl]}) count=${c} (want 1)" >&2; return 1; }; done
  return 0
}

# check_s16_unmapped <s16file>: every status-bearing §16 label is in FULL_GAP. 0=ok, 1=violation.
check_s16_unmapped() {
  local labels; labels="$(s16_labels "$1")"
  local lbl
  while IFS= read -r lbl; do
    [ -n "${lbl}" ] || continue
    [ -n "${FULL_GAP[$lbl]:-}" ] || { echo "§16 status-bearing row label does not map to a known item: '${lbl}'" >&2; return 1; }
  done <<<"${labels}"
  return 0
}

# ---------------------------------------------------------------------------
# Extract the real sections used for the main run.
# ---------------------------------------------------------------------------
REAL="${OUTDIR}/real"
extract_sections "${CRITERIA}" "${REAL}"
TABLE10="${REAL}.s10"
TABLE11="${REAL}.s11"
TABLE16="${REAL}.s16"
[ -s "${TABLE10}" ] || fail "could not extract §10 current-status table"
[ -s "${TABLE11}" ] || fail "could not extract §11 next-run recommendation table"
[ -s "${TABLE16}" ] || fail "could not extract §16 consolidated gap matrix"

# Status glyph helpers on the real sections.
table10_status_of() {
  local item="$1" row
  row="$(awk -v it="${item}" '$0 ~ ("^\\| " it " ") { print; exit }' "${TABLE10}")"
  [ -n "${row}" ] || { echo MISSING; return; }
  glyph_to_word "$(printf '%s' "${row}" | awk -F'|' '{print $3}')"
}
table11_status_of() {
  local item="$1" row
  row="$(awk -v it="${item}" '$0 ~ ("^\\| " it " \\|") { print; exit }' "${TABLE11}")"
  [ -n "${row}" ] || { echo MISSING; return; }
  glyph_to_word "$(printf '%s' "${row}" | awk -F'|' '{print $3}')"
}
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
# 1. The cross-section coverage lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "cross-section coverage lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "lint guide missing C4/C5 OPEN label"
grep -qi 'coverage' "${LINT_GUIDE}" || fail "lint guide must describe coverage"
grep -qi '§11' "${LINT_GUIDE}" || fail "lint guide must describe §11 coverage"
grep -qi '§16' "${LINT_GUIDE}" || fail "lint guide must describe §16 coverage"
emit "cross_section_coverage_lint_guide_present=OK (READINESS_CROSS_SECTION_COVERAGE_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

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
# 6. §10 covers M1-M20 + S1-S7 exactly once.
# ---------------------------------------------------------------------------
check_s10_coverage "${TABLE10}" || fail "§10 current-status table does not cover M1-M20 + S1-S7 exactly once"
emit "status_table_coverage=OK (§10 covers M1-M20 and S1-S7 exactly once — source-of-truth coverage)"

# ---------------------------------------------------------------------------
# 7-8. §11 covers M1-M20 exactly once; §11 is must-have-only (documented).
# ---------------------------------------------------------------------------
check_s11_coverage "${TABLE11}" || fail "§11 next-run recommendation table does not cover M1-M20 exactly once (must-have-only)"
grep -qi 'must-have-only' "${LINT_GUIDE}" || fail "lint guide must document that §11 is must-have-only"
grep -qi 'Red/Yellow must-have' "${CRITERIA}" || fail "§11 must-have scope statement missing from the matrix"
emit "recommendation_coverage=OK (§11 covers M1-M20 exactly once; no should-have row; must-have-only scope documented)"

# ---------------------------------------------------------------------------
# 9-11. §16 label-to-item map present; required labels covered exactly once; every label maps.
# ---------------------------------------------------------------------------
grep -qi 'label-to-item' "${LINT_GUIDE}" || fail "lint guide must publish the §16 label-to-item coverage map"
for probe in "seed nodes / bootnodes" "validator identity" "status page"; do
  grep -qF "${probe}" "${LINT_GUIDE}" || fail "lint guide label-to-item map missing '${probe}'"
done
check_s16_required "${TABLE16}" || fail "§16 gap matrix does not cover every required mapped label exactly once"
emit "gap_matrix_required_coverage=OK (§16 covers all ${#REQUIRED_GAP[@]} required mapped labels exactly once; label-to-item map published)"
check_s16_unmapped "${TABLE16}" || fail "§16 gap matrix carries a status-bearing row whose label does not map to a known item"
emit "gap_matrix_unmapped_check=OK (every status-bearing §16 row maps to a known M/S/N/C/T item via the full label-to-item map)"

# ---------------------------------------------------------------------------
# 12. §16 coverage exceptions are exactly {S6,S7}, explicit, and safely protected.
# ---------------------------------------------------------------------------
# Derive the §10 M/S items NOT covered by a required §16 mapped label.
declare -A REQUIRED_ITEMS=()
for lbl in "${!REQUIRED_GAP[@]}"; do REQUIRED_ITEMS["${REQUIRED_GAP[$lbl]}"]=1; done
UNCOVERED=()
for n in $(seq 1 20); do it="M${n}"; [ -n "${REQUIRED_ITEMS[$it]:-}" ] || UNCOVERED+=("${it}"); done
for n in $(seq 1 7);  do it="S${n}"; [ -n "${REQUIRED_ITEMS[$it]:-}" ] || UNCOVERED+=("${it}"); done
# The declared exception set must equal the derived uncovered set.
EXP_SORTED="$(printf '%s\n' "${COVERAGE_EXCEPTIONS[@]}" | sort -u | tr '\n' ' ' | sed 's/ *$//')"
UNC_SORTED="$(printf '%s\n' "${UNCOVERED[@]}" | sort -u | tr '\n' ' ' | sed 's/ *$//')"
[ "${EXP_SORTED}" = "${UNC_SORTED}" ] \
  || fail "§16 coverage exceptions {${EXP_SORTED}} != §10 items not covered by a §16 mapped label {${UNC_SORTED}}"
# Each exception has an explicit guide row with a reason + protection source; S7 keeps M4-gated/Yellow.
COVERAGE_SECTION="$(awk '/^## 7[.] /{g=1} g&&/^## 8[.] /{g=0} g' "${LINT_GUIDE}" | tr -d '\r')"
grep -qi 'coverage exception' "${LINT_GUIDE}" || fail "lint guide missing a §16 coverage exceptions section"
for it in "${COVERAGE_EXCEPTIONS[@]}"; do
  EXROW="$(printf '%s\n' "${COVERAGE_SECTION}" | awk -v it="${it}" -F'|' '$0 ~ ("\\| " it " \\|") { print; exit }')"
  [ -n "${EXROW}" ] || fail "§16 coverage exception row for ${it} missing from the guide table"
  # reason column (3) and protection column (4) must be non-empty.
  reason="$(printf '%s' "${EXROW}" | awk -F'|' '{print $4}' | sed 's/^ *//;s/ *$//')"
  prot="$(printf '%s' "${EXROW}" | awk -F'|' '{print $5}' | sed 's/^ *//;s/ *$//')"
  [ -n "${reason}" ] || fail "§16 coverage exception ${it} has no reason"
  [ -n "${prot}" ]   || fail "§16 coverage exception ${it} has no protection source"
  printf '%s' "${prot}" | grep -qi '§10' || fail "§16 coverage exception ${it} protection source must cite §10"
done
# S7 (a Yellow / M4-gated item) may only be an exception with explicit Yellow / M4-gated protection.
S7ROW="$(printf '%s\n' "${COVERAGE_SECTION}" | awk -F'|' '$0 ~ /\| S7 \|/ { print; exit }')"
printf '%s' "${S7ROW}" | grep -qiE 'M4-gated|Yellow' \
  || fail "§16 coverage exception S7 must keep its Yellow / M4-gated protection"
emit "gap_matrix_coverage_exceptions=OK (§16 coverage exceptions are exactly {${EXP_SORTED}}; each explicit with reason + §10 protection; S7 Yellow/M4-gated)"

# ---------------------------------------------------------------------------
# 13. No existing Run 413 scoped §16 mapped row was silently removed.
#     (Same set as REQUIRED_GAP — assert each present; complements check 9.)
# ---------------------------------------------------------------------------
labels_now="$(s16_labels "${TABLE16}")"
for lbl in "${!REQUIRED_GAP[@]}"; do
  grep -Fxq "${lbl}" <<<"${labels_now}" \
    || fail "Run 413 scoped §16 row '${lbl}' (${REQUIRED_GAP[$lbl]}) was removed"
done
emit "run_413_row_preservation=OK (all ${#REQUIRED_GAP[@]} Run 413 scoped §16 mapped rows still present; none silently removed)"

# ---------------------------------------------------------------------------
# 14. §10/§11/§16 status values still agree for every represented item.
# ---------------------------------------------------------------------------
for n in $(seq 1 20); do
  it="M${n}"
  t10="$(table10_status_of "${it}")"; t11="$(table11_status_of "${it}")"
  [ "${t10}" != "MISSING" ] || fail "§10 table missing row for ${it}"
  [ "${t11}" != "MISSING" ] || fail "§11 table missing row for ${it}"
  [ "${t11}" = "${t10}" ] || fail "${it}: §11 (${t11}) disagrees with §10 (${t10})"
  [ "${t11}" = "${EXPECT_M[$it]}" ] || fail "${it}: §11 status ${t11} != frozen expected ${EXPECT_M[$it]}"
done
for lbl in "${!REQUIRED_GAP[@]}"; do
  it="${REQUIRED_GAP[$lbl]}"
  row="$(gap16_row_of "${lbl}")"; g16="$(gap16_status_of "${row}")"
  t10="$(table10_status_of "${it}")"
  [ "${g16}" = "${t10}" ] || fail "${it} ('${lbl}'): §16 (${g16}) disagrees with §10 (${t10})"
  case "${it}" in S*) exp="${EXPECT_S[$it]}";; *) exp="${EXPECT_M[$it]}";; esac
  [ "${g16}" = "${exp}" ] || fail "${it} ('${lbl}'): §16 status ${g16} != frozen expected ${exp}"
done
emit "status_consistency_preserved=OK (§10/§11/§16 status values agree for every represented item; match frozen truth)"

# ---------------------------------------------------------------------------
# 15. M4 remains Yellow / launch-blocking in §10/§11/§16.
# ---------------------------------------------------------------------------
[ "$(table10_status_of M4)" = "Yellow" ] || fail "§10 must keep M4 Yellow"
[ "$(table11_status_of M4)" = "Yellow" ] || fail "§11 must keep M4 Yellow"
M4_GAP="$(gap16_row_of 'seed nodes / bootnodes')"
[ "$(gap16_status_of "${M4_GAP}")" = "Yellow" ] || fail "§16 must keep the seed/bootnodes (M4) row Yellow"
printf '%s' "${M4_GAP}" | grep -qi 'Launch blocker' || fail "§16 seed/bootnodes (M4) row must keep its Launch-blocker posture"
emit "m4_status=OK (M4 Yellow / launch-blocking in §10, §11 and §16 (Launch blocker))"

# ---------------------------------------------------------------------------
# 16. M6 remains Yellow / Partial (M4-gated) in §10/§11/§16.
# ---------------------------------------------------------------------------
[ "$(table10_status_of M6)" = "Yellow" ] || fail "§10 must keep M6 Yellow"
[ "$(table11_status_of M6)" = "Yellow" ] || fail "§11 must keep M6 Yellow"
M6_GAP="$(gap16_row_of 'validator identity')"
[ "$(gap16_status_of "${M6_GAP}")" = "Yellow" ] || fail "§16 must keep the validator-identity (M6) row Yellow"
printf '%s' "${M6_GAP}" | grep -qi 'M4-gated' || fail "§16 validator-identity (M6) row must keep its M4-gated posture"
emit "m6_status=OK (M6 Yellow / Partial / M4-gated in §10, §11 and §16)"

# ---------------------------------------------------------------------------
# 17. S5/S7 remain Yellow or M4-gated. (S5 has a §16 row; S7 is an exception.)
# ---------------------------------------------------------------------------
S5_GAP="$(gap16_row_of 'status page')"
[ "$(gap16_status_of "${S5_GAP}")" = "Yellow" ] || fail "§16 must keep the status-page (S5) row Yellow"
printf '%s' "${S5_GAP}" | grep -qiE 'M4-gated|once M4' || fail "§16 status-page (S5) row must keep its M4-gated posture"
[ "$(table10_status_of S5)" = "Yellow" ] || fail "§10 must keep S5 Yellow"
[ "$(table10_status_of S7)" = "Yellow" ] || fail "§10 must keep S7 Yellow"
emit "s5_s7_status=OK (S5 Yellow / M4-gated in §16; S5/S7 Yellow in §10; S7 a documented Yellow/M4-gated §16 coverage exception)"

# ---------------------------------------------------------------------------
# 18. Public DevNet remains NO-GO / NOT launch-ready — §11/§16 must not claim otherwise.
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
# 19. C4/C5 remain OPEN — §16 keeps C4/C5 🔴 OPEN; neither §11 nor §16 claims closure.
# ---------------------------------------------------------------------------
C4_GAP="$(gap16_row_of 'C4')"; C5_GAP="$(gap16_row_of 'C5')"
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
# 20. TestNet/MainNet untouched; N1-N7 Red; §11/§16 make no TestNet/MainNet-ready claim.
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
# 21. No `devnet-seeds.live.json` live-publication claim in §11/§16.
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
# 22. No seed/bootnode/faucet/RPC/explorer/status-service DEPLOYMENT claim in §11/§16.
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
# 23. No runtime-mutation claim in §11/§16.
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
# 24. No readiness item moves Green in this run (M4/M6/S5/S7 stay 🟡 in §10).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 (no Green move)"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 (no Green move)"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 (no Green move)"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 (no Green move)"
grep -qi 'Updated Run 414' "${CRITERIA}" || fail "readiness matrix must carry the Run 414 narrative"
awk '/^Updated Run 414 —/{g=1} g&&/^Updated Run [0-9]+ —/&&!/414/{g=0} g' "${CRITERIA}" \
  | tr -d '\r' | tr '\n' ' ' | grep -qiE 'No readiness item moves|no item moves Green' \
  || fail "Run 414 readiness narrative must state no readiness item moves"
emit "no_green_move=OK (Run 414 moves no readiness item Green; M4/M6/S5/S7 stay 🟡)"

# ---------------------------------------------------------------------------
# 25. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "READINESS_CROSS_SECTION_COVERAGE_LINT_REPORT.json" \
            "READINESS_CROSS_SECTION_COVERAGE_LINT_REPORT.txt" \
            "READINESS_RECOMMENDATION_GAP_MATRIX_LINT_REPORT.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_output_non_commit=OK (no generated cross-section-coverage-lint report is committed; transient output stays outside the tree)"

# ---------------------------------------------------------------------------
# 26. Run 414 contradiction ledger entry exists and holds the fixed posture.
# ---------------------------------------------------------------------------
RUN414_ENTRY="$(grep -E '^Run 414 —' "${CONTRADICTION}" | tr -d '\r' || true)"
[ -n "${RUN414_ENTRY}" ] || fail "contradiction ledger missing the Run 414 entry"
printf '%s' "${RUN414_ENTRY}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
  || fail "Run 414 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN414_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 414 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN414_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN414_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 414 contradiction entry must state C4/C5 remain OPEN"
emit "run_414_ledger_entry=OK (Run 414 recorded in the contradiction ledger; no protocol contradiction; NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 27. Fail-closed self-tests: mutate temp copies OUTSIDE the tree and confirm the coverage
#     checks abort. Proves the deletion/rename failure modes are actually caught.
# ---------------------------------------------------------------------------
TMPC="${OUTDIR}/selftest.criteria.md"

# (a) §11 missing-M-row: delete the §11 M7 recommendation row (Green must-have, not M4/M6).
cp "${CRITERIA}" "${TMPC}"
awk 'BEGIN{s=0} /^## 11[.] /{s=1} /^## 12[.] /{s=0} { if (s==1 && $0 ~ /^\| M7 \|/) next; print }' \
  "${CRITERIA}" > "${TMPC}"
extract_sections "${TMPC}" "${OUTDIR}/st_s11"
if check_s11_coverage "${OUTDIR}/st_s11.s11" >/dev/null 2>&1; then
  fail "self-test FAILED: §11 missing-M-row (M7 deleted) was not caught"
fi
emit "selftest_s11_missing_row=OK (deleting the §11 M7 row is caught fail-closed)"

# (b) §16 missing-mapped-row: delete the §16 'peer admission policy' (M11) row.
awk 'BEGIN{s=0} /^## 16[.] /{s=1} /^## 17[.] /{s=0} { if (s==1 && $0 ~ /^\| peer admission policy \|/) next; print }' \
  "${CRITERIA}" > "${TMPC}"
extract_sections "${TMPC}" "${OUTDIR}/st_s16m"
if check_s16_required "${OUTDIR}/st_s16m.s16" >/dev/null 2>&1; then
  fail "self-test FAILED: §16 missing-mapped-row (peer admission policy deleted) was not caught"
fi
emit "selftest_s16_missing_row=OK (deleting the §16 'peer admission policy' (M11) row is caught fail-closed)"

# (c) §16 unmapped-label: rename the §16 'peer admission policy' label to an unknown label.
sed 's/^| peer admission policy |/| totally bogus admission label |/' "${CRITERIA}" > "${TMPC}"
extract_sections "${TMPC}" "${OUTDIR}/st_s16u"
if check_s16_unmapped "${OUTDIR}/st_s16u.s16" >/dev/null 2>&1; then
  fail "self-test FAILED: §16 unmapped-label (renamed row) was not caught"
fi
emit "selftest_s16_unmapped_label=OK (a §16 status-bearing row with an unmapped/renamed label is caught fail-closed)"

# Confirm the sanity control: on the UNMODIFIED file all three coverage checks pass.
check_s11_coverage "${TABLE11}" || fail "self-test control: real §11 coverage should pass"
check_s16_required "${TABLE16}" || fail "self-test control: real §16 required coverage should pass"
check_s16_unmapped "${TABLE16}" || fail "self-test control: real §16 unmapped check should pass"
emit "selftest_control=OK (all coverage checks pass on the unmodified matrix)"

# ---------------------------------------------------------------------------
# 28. Non-claim grep over the Run 414-authored docs (normalized).
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
[ -f "${EV414}" ] && CLAIM_TARGETS+=("${EV414}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime|fails? closed|anywhere it appears' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 414 docs)"
emit "runtime_mutation=NONE (Run 414 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 29. Secret / private-material + absolute-path scan over the Run 414-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV414}" ] && SCAN_FILES+=("${EV414}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 414 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 414 doc"
fi
emit "secret_scan=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 414 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet readiness cross-section coverage lint: the coverage lint guide is published and safety-labelled; §10 covers M1-M20 + S1-S7 exactly once; §11 covers every must-have M1-M20 row exactly once and stays must-have-only; §16 covers all ${#REQUIRED_GAP[@]} required mapped labels exactly once, every status-bearing §16 row maps to a known item via the full label-to-item map, and the S6/S7 coverage exceptions are explicit and safely protected; no Run 413 scoped §16 row was removed; §10/§11/§16 status values still agree; M4 stays Yellow/launch-blocking, M6 Yellow/Partial/M4-gated, S5 Yellow/M4-gated, S7 Yellow/M4-gated; public DevNet stays NO-GO / NOT launch-ready; C4/C5 stay 🔴 OPEN; TestNet/MainNet stay untouched and N1-N7 Red; the fail-closed self-tests for §11 row deletion, §16 row deletion, and §16 unmapped labels all abort as intended; no live seed/bootnode/faucet/RPC/explorer/status-service deployment, devnet-seeds.live.json, C4/C5 closure, TestNet/MainNet readiness, or runtime mutation is claimed; no readiness item moves Green; nothing generated is committed; the working tree stays clean; and the secret/private-material scan is clean)"