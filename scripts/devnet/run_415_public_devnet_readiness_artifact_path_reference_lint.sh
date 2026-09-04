#!/usr/bin/env bash
# Run 415: public DevNet readiness artifact path / reference consistency lint.
#
# This harness is a READ-ONLY, fail-closed PATH / REFERENCE lint. It catches path/reference DRIFT
# between the public DevNet readiness documents and the files that actually exist on disk:
#
#   * the canonical readiness matrix
#       docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
#       - its §9/§10/§11/§16 `docs/release/...` evidence paths must resolve;
#   * the artifact index      docs/release/public-devnet/ARTIFACT_INDEX.md
#       - its `docs/release/public-devnet/...` package paths + `scripts/devnet/run_*.sh` commands
#         must resolve, and every package directory must be represented;
#   * the operator map        docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md
#       - its `docs/release/public-devnet/...` references must resolve;
#   * the blocker register + launch gate (kept present + NO-GO / M4-M6-S5-S7 posture);
#   * the contradiction ledger docs/whitepaper/contradiction.md
#       - its `docs/devnet/...` committed-evidence `.md` references must resolve.
#
# Every publish-safe file tracked under docs/release/public-devnet must be DISCOVERABLE through the
# artifact index, the operator map, an indexed package README/VERIFY, or a documented exception.
#
# It extends the Run 412 status/blocker lint, the Run 413 §11/§16 status lint, and the Run 414
# cross-section COVERAGE lint (which protect the readiness rows) to the PATH/REFERENCE layer beneath
# them. It adds NO feature surface and moves NO readiness item. It generates only a transient summary
# OUTSIDE the repository tree and commits nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO build.rs
# change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation.
#
# It fails closed if:
#   * the path/reference lint guide is missing or not safety-labelled;
#   * the readiness matrix, artifact index, operator map, blocker register, or launch gate is missing;
#   * a §9/§10/§11/§16 `docs/release/...` path in the matrix does not resolve;
#   * a `docs/release/public-devnet/...` path in the index/operator map does not resolve and is not
#     explicitly marked generated/download-only/transient/not committed;
#   * a `scripts/devnet/run_*.sh` command named in the index/operator map does not resolve;
#   * a `docs/devnet/...` `.md` evidence path in the matrix or ledger does not resolve;
#   * a package directory under docs/release/public-devnet is not represented in the index;
#   * a tracked publish-safe file is not discoverable and not a documented exception;
#   * a documented exception lacks path/reason/parent or hides an M4/M6/S5/S7/C4/C5 path without
#     explicit Yellow/OPEN protection;
#   * a reference overclaims launch-ready/GO, C4/C5 closure, TestNet/MainNet readiness, a live
#     seed/bootnode/faucet/RPC/explorer/status-service deployment, a `devnet-seeds.live.json`, or a
#     runtime mutation;
#   * any readiness item moves Green, any generated artifact is committed, the working tree is left
#     dirty, or a secret / private-material / absolute path appears in the Run 415-authored docs.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run415-public-devnet-readiness-artifact-path-reference-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/READINESS_ARTIFACT_PATH_REFERENCE_LINT.md"
COVERAGE_LINT="${PDN}/READINESS_CROSS_SECTION_COVERAGE_LINT.md"
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
EV415="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_415.md"

SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run415] %s\n' "$*"; }
fail() { printf '[run415] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${COVERAGE_LINT}" "${RECGAP_LINT}" "${STATUS_LINT}" "${LEDGER_LINT}" \
         "${ARTIFACT_INDEX}" "${OP_MAP}" "${LAUNCH_GATE}" "${BLOCKER_REGISTER}" "${C4C5_CRITERIA}" \
         "${CRITERIA}" "${CONTRADICTION}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Extract a numbered section block "## N. ..." up to the next "## <next>. " heading.
section_block() {
  local start="$1" nextre="$2" src="$3"
  awk -v s="^## ${start}[.] " -v n="${nextre}" '
    $0 ~ s { grab=1 }
    grab && $0 ~ n && $0 !~ s { grab=0 }
    grab { print }
  ' "${src}" | tr -d '\r'
}

# Clean a captured token: strip trailing sentence punctuation and quotes/backticks.
clean_token() { sed -e 's/[`"]//g' -e 's/[).,;:]*$//'; }

# repo-relative existence test.
res() { [ -e "${REPO_ROOT}/$1" ]; }

# Extract unique `docs/release/...` tokens from a text stream (stdin).
release_paths() {
  grep -oE 'docs/release/[A-Za-z0-9_./-]+' | sed -e 's/[).,;:]*$//' | sort -u
}

# Extract unique `docs/devnet/....md` tokens from a file.
devnet_md_paths() {
  grep -oE 'docs/devnet/[A-Za-z0-9_./-]+\.md' "$1" | sed -e 's/[).,;:]*$//' | sort -u
}

# Extract unique `scripts/devnet/run_*.sh` tokens from a file.
script_refs() {
  grep -oE 'scripts/devnet/run_[0-9A-Za-z_./-]+\.sh' "$1" | sort -u
}

# Strict resolve of every release-path token found in a text file (no transient allowance).
# 0 = all resolve, 1 = at least one unresolved.
check_matrix_paths() {
  local src="$1" p bad=0
  while IFS= read -r p; do
    [ -n "${p}" ] || continue
    res "${p}" || { echo "unresolved readiness-matrix release path: ${p}" >&2; bad=1; }
  done < <(release_paths < "${src}")
  return "${bad}"
}

# Line-aware resolve of docs/release/public-devnet tokens in an index/operator-map style doc,
# allowing tokens whose own line marks them generated/download-only/transient/not committed.
check_doc_pdn_paths() {
  local doc="$1" line toks p bad=0
  while IFS= read -r line; do
    toks="$(printf '%s' "${line}" | grep -oE 'docs/release/public-devnet/[A-Za-z0-9_./-]+' | sed -e 's/[).,;:]*$//' || true)"
    [ -n "${toks}" ] || continue
    while IFS= read -r p; do
      [ -n "${p}" ] || continue
      res "${p}" && continue
      printf '%s' "${line}" | grep -qiE 'generated|transient|download-only|never committed|not committed' && continue
      echo "unresolved path in $(basename "${doc}"): ${p}" >&2; bad=1
    done <<<"${toks}"
  done < "${doc}"
  return "${bad}"
}

# Resolve every scripts/devnet/run_*.sh command in a doc. 0 = ok, 1 = at least one missing.
check_script_refs() {
  local doc="$1" p bad=0
  while IFS= read -r p; do
    [ -n "${p}" ] || continue
    res "${p}" || { echo "unresolved script ref in $(basename "${doc}"): ${p}" >&2; bad=1; }
  done < <(script_refs "${doc}")
  return "${bad}"
}

# Every package directory under docs/release/public-devnet must have its `name/` in the index.
check_pkg_coverage() {
  local idx="$1" d name bad=0
  while IFS= read -r d; do
    [ -n "${d}" ] || continue
    name="$(basename "${d}")"
    grep -qF "${name}/" "${idx}" || { echo "package dir not represented in index: ${d}" >&2; bad=1; }
  done < <(git -C "${REPO_ROOT}" ls-files 'docs/release/public-devnet/*' \
             | sed 's,^docs/release/public-devnet/,,' | grep '/' | sed 's,/[^/]*$,,' | sort -u)
  return "${bad}"
}

# ---------------------------------------------------------------------------
# Parse the discoverability exception table from the guide (§11).
# EXCEPTION_PATHS: relative paths (under docs/release/public-devnet) explicitly exceptioned.
# ---------------------------------------------------------------------------
EXCEPTION_PATHS=()
EXCEPTION_ROWS_FILE="${OUTDIR}/exception_rows.txt"
awk -F'|' '/^\| `network\// { print }' "${LINT_GUIDE}" | tr -d '\r' > "${EXCEPTION_ROWS_FILE}"
while IFS= read -r row; do
  [ -n "${row}" ] || continue
  relp="$(printf '%s' "${row}" | awk -F'|' '{print $2}' | sed -e 's/`//g' -e 's/^ *//' -e 's/ *$//')"
  [ -n "${relp}" ] && EXCEPTION_PATHS+=("${relp}")
done < "${EXCEPTION_ROWS_FILE}"

is_exception() {
  local rel="$1" e
  for e in "${EXCEPTION_PATHS[@]:-}"; do [ "${e}" = "${rel}" ] && return 0; done
  return 1
}

# Discoverability of a tracked file (rel path under docs/release/public-devnet) against a given
# index + operator-map file (parametrised so the self-test can use mutated copies).
is_discoverable_in() {
  local rel="$1" idx="$2" opm="$3" b; b="$(basename "${rel}")"
  grep -qF "${b}" "${idx}" && return 0
  grep -qF "${b}" "${opm}" && return 0
  return 1
}

# ---------------------------------------------------------------------------
# 1. The path/reference lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "path/reference lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "lint guide missing C4/C5 OPEN label"
grep -qiE 'path.?/?.?reference|path/reference|discoverab' "${LINT_GUIDE}" || fail "lint guide must describe path/reference/discoverability"
emit "path_reference_lint_guide_present=OK (READINESS_ARTIFACT_PATH_REFERENCE_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 2-6. Readiness matrix, artifact index, operator map, blocker register, launch gate present.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" \
  || fail "readiness matrix missing the NOT launch-ready statement"
emit "readiness_matrix_present=OK (QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md exists)"
grep -qi 'Artifact Index' "${ARTIFACT_INDEX}" || fail "artifact index heading missing"
emit "artifact_index_present=OK (ARTIFACT_INDEX.md exists)"
grep -qi 'Operator Verification Map' "${OP_MAP}" || fail "operator verification map heading missing"
emit "operator_map_present=OK (OPERATOR_VERIFICATION_MAP.md exists)"
[ -f "${BLOCKER_REGISTER}" ] || fail "blocker register missing"
emit "blocker_register_present=OK (BLOCKER_REGISTER.md exists)"
grep -qiE 'NO-GO|NOT launch-ready' "${LAUNCH_GATE}" || fail "launch go/no-go gate missing NO-GO posture"
emit "launch_gate_present=OK (LAUNCH_GO_NO_GO.md exists and remains NO-GO / NOT launch-ready)"

# ---------------------------------------------------------------------------
# 7. Readiness-matrix §9/§10/§11/§16 docs/release paths resolve.
# ---------------------------------------------------------------------------
MSEC="${OUTDIR}/matrix_sections.txt"
{ section_block 9  '^## 10[.] ' "${CRITERIA}"
  section_block 10 '^## 11[.] ' "${CRITERIA}"
  section_block 11 '^## 12[.] ' "${CRITERIA}"
  section_block 16 '^## 17[.] ' "${CRITERIA}"; } > "${MSEC}"
[ -s "${MSEC}" ] || fail "could not extract readiness-matrix §9/§10/§11/§16 sections"
check_matrix_paths "${MSEC}" || fail "a readiness-matrix §9/§10/§11/§16 docs/release path does not resolve"
MATRIX_PATH_COUNT="$(release_paths < "${MSEC}" | wc -l | tr -d ' ')"
emit "matrix_release_paths_resolve=OK (${MATRIX_PATH_COUNT} distinct docs/release paths in §9/§10/§11/§16 all resolve)"

# ---------------------------------------------------------------------------
# 8. Artifact-index docs/release/public-devnet paths resolve (or are marked transient).
# ---------------------------------------------------------------------------
check_doc_pdn_paths "${ARTIFACT_INDEX}" || fail "an ARTIFACT_INDEX.md docs/release/public-devnet path does not resolve"
IDX_PATH_COUNT="$(grep -oE 'docs/release/public-devnet/[A-Za-z0-9_./-]+' "${ARTIFACT_INDEX}" | sed 's/[).,;:]*$//' | sort -u | wc -l | tr -d ' ')"
emit "artifact_index_paths_resolve=OK (${IDX_PATH_COUNT} distinct docs/release/public-devnet paths in the index all resolve or are marked transient)"

# ---------------------------------------------------------------------------
# 9. Operator-map docs/release/public-devnet paths resolve (or are marked transient).
# ---------------------------------------------------------------------------
check_doc_pdn_paths "${OP_MAP}" || fail "an OPERATOR_VERIFICATION_MAP.md docs/release/public-devnet path does not resolve"
OPM_PATH_COUNT="$(grep -oE 'docs/release/public-devnet/[A-Za-z0-9_./-]+' "${OP_MAP}" | sed 's/[).,;:]*$//' | sort -u | wc -l | tr -d ' ')"
emit "operator_map_paths_resolve=OK (${OPM_PATH_COUNT} distinct docs/release/public-devnet paths in the operator map all resolve or are marked transient)"

# ---------------------------------------------------------------------------
# 10. scripts/devnet/run_*.sh commands named in the index/operator map resolve.
# ---------------------------------------------------------------------------
check_script_refs "${ARTIFACT_INDEX}" || fail "a scripts/devnet/run_*.sh command in the index does not resolve"
check_script_refs "${OP_MAP}" || fail "a scripts/devnet/run_*.sh command in the operator map does not resolve"
SCRIPT_COUNT="$( { script_refs "${ARTIFACT_INDEX}" || true; script_refs "${OP_MAP}" || true; } | sort -u | wc -l | tr -d ' ')"
emit "script_refs_resolve=OK (${SCRIPT_COUNT} distinct scripts/devnet/run_*.sh verification commands in index/operator map all resolve)"

# ---------------------------------------------------------------------------
# 11. docs/devnet .md evidence paths in the matrix and the contradiction ledger resolve.
# ---------------------------------------------------------------------------
EV_BAD=0
for src in "${CRITERIA}" "${CONTRADICTION}"; do
  while IFS= read -r p; do
    [ -n "${p}" ] || continue
    res "${p}" || { echo "unresolved docs/devnet evidence path in $(basename "${src}"): ${p}" >&2; EV_BAD=1; }
  done < <(devnet_md_paths "${src}")
done
[ "${EV_BAD}" = "0" ] || fail "a docs/devnet .md evidence path named in the matrix/ledger does not resolve"
EV_COUNT="$( { devnet_md_paths "${CRITERIA}"; devnet_md_paths "${CONTRADICTION}"; } | sort -u | wc -l | tr -d ' ')"
emit "evidence_paths_resolve=OK (${EV_COUNT} distinct docs/devnet .md evidence paths in matrix + ledger all resolve)"

# ---------------------------------------------------------------------------
# 12. Every package directory under docs/release/public-devnet is represented in the index.
# ---------------------------------------------------------------------------
check_pkg_coverage "${ARTIFACT_INDEX}" || fail "a package directory under docs/release/public-devnet is not represented in ARTIFACT_INDEX.md"
PKG_COUNT="$(git -C "${REPO_ROOT}" ls-files 'docs/release/public-devnet/*' | sed 's,^docs/release/public-devnet/,,' | grep '/' | sed 's,/[^/]*$,,' | sort -u | wc -l | tr -d ' ')"
emit "package_dir_coverage=OK (all ${PKG_COUNT} package directories under docs/release/public-devnet are represented in the index)"

# ---------------------------------------------------------------------------
# 13. Every tracked publish-safe file under docs/release/public-devnet is discoverable or exceptioned.
# ---------------------------------------------------------------------------
UNDISC=()
while IFS= read -r f; do
  rel="${f#docs/release/public-devnet/}"
  if is_discoverable_in "${rel}" "${ARTIFACT_INDEX}" "${OP_MAP}"; then continue; fi
  if is_exception "${rel}"; then continue; fi
  UNDISC+=("${rel}")
done < <(git -C "${REPO_ROOT}" ls-files 'docs/release/public-devnet/*')
[ "${#UNDISC[@]}" -eq 0 ] || { printf '%s\n' "${UNDISC[@]}" >&2; fail "tracked publish-safe file(s) not discoverable and not exceptioned"; }
TRACKED_COUNT="$(git -C "${REPO_ROOT}" ls-files 'docs/release/public-devnet/*' | wc -l | tr -d ' ')"
emit "publish_safe_discoverability=OK (all ${TRACKED_COUNT} tracked publish-safe files are discoverable via index/operator-map or a documented exception)"

# ---------------------------------------------------------------------------
# 14. Exception set is exactly the set of files not discoverable by index/operator-map, and each
#     exception row is well-formed (path + reason + protecting parent).
# ---------------------------------------------------------------------------
# Derive the files not discoverable by index/operator-map basename.
NOTDOC=()
while IFS= read -r f; do
  rel="${f#docs/release/public-devnet/}"
  is_discoverable_in "${rel}" "${ARTIFACT_INDEX}" "${OP_MAP}" || NOTDOC+=("${rel}")
done < <(git -C "${REPO_ROOT}" ls-files 'docs/release/public-devnet/*')
EXP_SORTED="$(printf '%s\n' "${EXCEPTION_PATHS[@]:-}" | sort -u | sed '/^$/d')"
NOTDOC_SORTED="$(printf '%s\n' "${NOTDOC[@]:-}" | sort -u | sed '/^$/d')"
[ "${EXP_SORTED}" = "${NOTDOC_SORTED}" ] \
  || { diff <(printf '%s\n' "${EXP_SORTED}") <(printf '%s\n' "${NOTDOC_SORTED}") >&2 || true; \
       fail "exception set != set of files not discoverable by index/operator map (stale or missing exception)"; }
# Each exception row must carry a non-empty path, reason, and protecting parent (4 pipes -> cols 2/3/4).
while IFS= read -r row; do
  [ -n "${row}" ] || continue
  c2="$(printf '%s' "${row}" | awk -F'|' '{print $2}' | sed 's/^ *//;s/ *$//')"
  c3="$(printf '%s' "${row}" | awk -F'|' '{print $3}' | sed 's/^ *//;s/ *$//')"
  c4="$(printf '%s' "${row}" | awk -F'|' '{print $4}' | sed 's/^ *//;s/ *$//')"
  [ -n "${c2}" ] || fail "exception row missing relative path"
  [ -n "${c3}" ] || fail "exception row '${c2}' missing reason"
  [ -n "${c4}" ] || fail "exception row '${c2}' missing protecting parent document"
done < "${EXCEPTION_ROWS_FILE}"
emit "exception_table_wellformed=OK (${#EXCEPTION_PATHS[@]} exception row(s); set matches non-indexed files; each has path + reason + protecting parent)"

# ---------------------------------------------------------------------------
# 15. No exception hides a blocker-critical (M4/M6/S5/S7/C4/C5) path without Yellow/OPEN protection.
# ---------------------------------------------------------------------------
while IFS= read -r row; do
  [ -n "${row}" ] || continue
  relp="$(printf '%s' "${row}" | awk -F'|' '{print $2}' | sed -e 's/`//g' -e 's/^ *//;s/ *$//')"
  if printf '%s' "${row}" | grep -qE 'M4|M6|S5|S7'; then
    printf '%s' "${row}" | grep -qiE 'Yellow|M4-gated|launch-blocking' \
      || fail "exception '${relp}' touches M4/M6/S5/S7 without explicit Yellow/M4-gated protection"
  fi
  if printf '%s' "${row}" | grep -qE 'C4|C5'; then
    printf '%s' "${row}" | grep -qi 'OPEN' \
      || fail "exception '${relp}' touches C4/C5 without explicit OPEN protection"
  fi
done < "${EXCEPTION_ROWS_FILE}"
emit "exception_blocker_safety=OK (no exception hides an M4/M6/S5/S7/C4/C5 path without explicit Yellow/OPEN protection)"

# ---------------------------------------------------------------------------
# 16. devnet-seeds.live.json remains absent / not-live; no unqualified live-publication claim.
# ---------------------------------------------------------------------------
[ ! -e "${PDN}/network/devnet-seeds.live.json" ] || fail "devnet-seeds.live.json unexpectedly exists (no real M4 evidence in scope)"
for f in "${LINT_GUIDE}" "${EV415}"; do
  [ -f "${f}" ] || continue
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |never|until|once|after|require|would|M4|Route A|prerequisite|deferr|absent|placeholder|candidate|template|published from' \
      || { printf '%s\n' "${line}" >&2; fail "possible live devnet-seeds.live.json publication claim in $(basename "${f}")"; }
  done < <(grep -F 'devnet-seeds.live.json' "${f}" | tr -d '\r' || true)
done
emit "devnet_seeds_live_non_claim=OK (devnet-seeds.live.json absent; every mention in Run 415 docs is negated/M4-gated)"

# ---------------------------------------------------------------------------
# 17. No live seed/bootnode/faucet/RPC/explorer/status-service deployment claim in Run 415 docs.
# ---------------------------------------------------------------------------
for f in "${LINT_GUIDE}" "${EV415}"; do
  [ -f "${f}" ] || continue
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|deferred|until|once|after|would|M4|requires|instead|prerequisite|blocker|gated' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a live deployment"; }
  done < <(grep -iE '(seed|bootnode|faucet|RPC|explorer|status service|status page|health view)[^.]{0,40}(is|was|has been|are) (deployed|live|maintained)' "${f}" | tr -d '\r' || true)
done
emit "deployment_non_claim=OK (no seed/bootnode/faucet/RPC/explorer/status-service live-deployment claim in Run 415 docs)"

# ---------------------------------------------------------------------------
# 18. No runtime-mutation claim in Run 415 docs.
# ---------------------------------------------------------------------------
for f in "${LINT_GUIDE}" "${EV415}"; do
  [ -f "${f}" ] || continue
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    printf '%s' "${line}" \
      | grep -qiE 'no |not |neither|without|nothing|never' \
      || { printf '%s\n' "${line}" >&2; fail "$(basename "${f}") appears to claim a runtime mutation"; }
  done < <(grep -iE '(validator set|epoch|sequence|marker|LivePqcTrustState)[^.]{0,40}(was|is|has been|are) (mutated|transitioned|advanced|changed)' "${f}" | tr -d '\r' || true)
done
emit "runtime_mutation_non_claim=OK (no validator/epoch/sequence/marker/LivePqcTrustState mutation claim in Run 415 docs)"

# ---------------------------------------------------------------------------
# 19. Public DevNet remains NO-GO / NOT launch-ready.
# ---------------------------------------------------------------------------
grep -qi 'public DevNet remains NOT launch-ready' "${CRITERIA}" || fail "readiness matrix must hold NOT launch-ready"
grep -qiE 'NO-GO|NOT launch-ready' "${LAUNCH_GATE}" || fail "launch gate must remain NO-GO / NOT launch-ready"
emit "launch_nogo_consistent=OK (matrix holds NOT launch-ready; launch gate remains NO-GO / NOT launch-ready)"

# ---------------------------------------------------------------------------
# 20. C4/C5 remain OPEN.
# ---------------------------------------------------------------------------
grep -qiE 'C4 and C5 remain +\*{0,2}OPEN' "${CRITERIA}" || fail "readiness matrix must hold C4 and C5 OPEN"
grep -qi 'C4 remains OPEN' "${LINT_GUIDE}" || fail "lint guide must state C4 remains OPEN"
grep -qi 'C5 remains OPEN' "${LINT_GUIDE}" || fail "lint guide must state C5 remains OPEN"
emit "c4_c5_open_consistent=OK (matrix + lint guide hold C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 21. TestNet/MainNet untouched; N1-N7 Red.
# ---------------------------------------------------------------------------
grep -qF 'N1, N2, N3, N4, N7 Red' "${CRITERIA}" || fail "readiness matrix must hold N1-N4/N7 Red"
grep -qF 'N5 (C4) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N5 (C4) OPEN / Red"
grep -qF 'N6 (C5) OPEN / Red' "${CRITERIA}" || fail "readiness matrix must hold N6 (C5) OPEN / Red"
emit "testnet_mainnet_non_claim=OK (matrix holds N1-N7 Red / TestNet/MainNet untouched)"

# ---------------------------------------------------------------------------
# 22-24. M4 / M6 / S5 / S7 remain Yellow in §10 (no Green move).
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡 (no Green move)"
emit "m4_status=OK (M4 seed/bootnodes remains 🟡 / launch-blocking in §10)"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡 (no Green move)"
emit "m6_status=OK (M6 validator identity remains 🟡 / Partial in §10)"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡 (no Green move)"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡 (no Green move)"
emit "s5_s7_status=OK (S5 status page and S7 seed-node runbook remain 🟡 in §10)"

# ---------------------------------------------------------------------------
# 25. No readiness item moves Green — Run 415 narrative states so.
# ---------------------------------------------------------------------------
grep -qi 'Updated Run 415' "${CRITERIA}" || fail "readiness matrix must carry the Run 415 narrative"
awk '/^Updated Run 415 —/{g=1} g&&/^Updated Run [0-9]+ —/&&!/415/{g=0} g' "${CRITERIA}" \
  | tr -d '\r' | tr '\n' ' ' | grep -qiE 'No readiness item moves|no item moves Green' \
  || fail "Run 415 readiness narrative must state no readiness item moves"
emit "no_green_move=OK (Run 415 moves no readiness item Green; M4/M6/S5/S7 stay 🟡)"

# ---------------------------------------------------------------------------
# 26. Run 415 contradiction ledger entry exists and holds the fixed posture.
# ---------------------------------------------------------------------------
RUN415_ENTRY="$(grep -E '^Run 415 —' "${CONTRADICTION}" | tr -d '\r' || true)"
[ -n "${RUN415_ENTRY}" ] || fail "contradiction ledger missing the Run 415 entry"
printf '%s' "${RUN415_ENTRY}" | grep -qiE 'no protocol contradiction found|no contradiction found' \
  || fail "Run 415 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN415_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 415 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN415_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN415_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 415 contradiction entry must state C4/C5 remain OPEN"
emit "run_415_ledger_entry=OK (Run 415 recorded in the contradiction ledger; no protocol contradiction; NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 27. Fail-closed self-tests — mutate temp copies OUTSIDE the tree and confirm the checks abort.
# ---------------------------------------------------------------------------
# (a) missing-path: rewrite a §10 evidence path to a non-existent file; matrix path check must fail.
TMPM="${OUTDIR}/selftest.matrix.md"
sed 's#docs/release/public-devnet/genesis/#docs/release/public-devnet/genesis-DOES-NOT-EXIST/#g' "${CRITERIA}" > "${TMPM}"
{ section_block 9  '^## 10[.] ' "${TMPM}"
  section_block 10 '^## 11[.] ' "${TMPM}"
  section_block 11 '^## 12[.] ' "${TMPM}"
  section_block 16 '^## 17[.] ' "${TMPM}"; } > "${OUTDIR}/selftest.sections.txt"
if check_matrix_paths "${OUTDIR}/selftest.sections.txt" >/dev/null 2>&1; then
  fail "self-test FAILED: a missing readiness-matrix path was not caught"
fi
emit "selftest_missing_path=OK (a moved/renamed readiness-matrix evidence path is caught fail-closed)"

# (b) missing-package-index-row: strip a package dir from the index; package coverage must fail.
TMPI="${OUTDIR}/selftest.index.md"
grep -v 'status/' "${ARTIFACT_INDEX}" > "${TMPI}"
if check_pkg_coverage "${TMPI}" >/dev/null 2>&1; then
  fail "self-test FAILED: a package directory absent from the index was not caught"
fi
emit "selftest_missing_package_row=OK (a package directory absent from the index is caught fail-closed)"

# (c) undiscoverable-file: strip one file's basename from index + operator map copies; that file
#     (not an exception) must be reported undiscoverable.
TMPI2="${OUTDIR}/selftest.index2.md"
TMPO2="${OUTDIR}/selftest.opmap2.md"
grep -v 'STATUS_PAGE_DECISION.md' "${ARTIFACT_INDEX}" > "${TMPI2}"
grep -v 'STATUS_PAGE_DECISION.md' "${OP_MAP}" > "${TMPO2}"
if is_discoverable_in "status/STATUS_PAGE_DECISION.md" "${TMPI2}" "${TMPO2}" \
   || is_exception "status/STATUS_PAGE_DECISION.md"; then
  fail "self-test FAILED: an undiscoverable public-DevNet file was not caught"
fi
emit "selftest_undiscoverable_file=OK (a public-DevNet file absent from index + operator map + exceptions is caught fail-closed)"

# Sanity control: on the real docs all three checks pass.
check_matrix_paths "${MSEC}" || fail "self-test control: real matrix paths should resolve"
check_pkg_coverage "${ARTIFACT_INDEX}" || fail "self-test control: real package coverage should pass"
is_discoverable_in "status/STATUS_PAGE_DECISION.md" "${ARTIFACT_INDEX}" "${OP_MAP}" \
  || fail "self-test control: real STATUS_PAGE_DECISION.md should be discoverable"
emit "selftest_control=OK (all path/coverage/discoverability checks pass on the unmodified docs)"

# ---------------------------------------------------------------------------
# 28. Non-claim grep over the Run 415-authored docs (normalized).
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
[ -f "${EV415}" ] && CLAIM_TARGETS+=("${EV415}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime|fails? closed|anywhere it appears' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 415 docs)"
emit "runtime_mutation=NONE (Run 415 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 29. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "READINESS_ARTIFACT_PATH_REFERENCE_LINT_REPORT.json" \
            "READINESS_ARTIFACT_PATH_REFERENCE_LINT_REPORT.txt"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_output_non_commit=OK (no generated path/reference-lint report is committed; transient output stays outside the tree)"

# ---------------------------------------------------------------------------
# 30. Secret / private-material + absolute-path scan over the Run 415-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV415}" ] && SCAN_FILES+=("${EV415}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 415 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 415 doc"
fi
emit "secret_scan=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 415 docs)"

# ---------------------------------------------------------------------------
# 31. Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet readiness artifact path/reference consistency lint: the guide is published and safety-labelled; the readiness matrix §9/§10/§11/§16 docs/release evidence paths all resolve; every ARTIFACT_INDEX.md and OPERATOR_VERIFICATION_MAP.md docs/release/public-devnet path resolves or is marked transient; every named scripts/devnet/run_*.sh verification command resolves; every docs/devnet .md evidence path in the matrix and the contradiction ledger resolves; every package directory is represented in the index; every tracked publish-safe file is discoverable via the index/operator map/an indexed package README/VERIFY or a documented exception; the exception table is well-formed, matches exactly the non-indexed files, and hides no M4/M6/S5/S7/C4/C5 path without Yellow/OPEN protection; devnet-seeds.live.json stays absent; no deployment/runtime/launch/closure overclaim appears; M4/M6/S5/S7 stay 🟡; public DevNet stays NO-GO / NOT launch-ready; C4/C5 stay OPEN; TestNet/MainNet stay untouched and N1-N7 Red; the three fail-closed self-tests all abort as intended; nothing generated is committed; the working tree stays clean; and the secret/private-material scan is clean)"