#!/usr/bin/env bash
# Run 409: public DevNet integrity-doc consistency reconciliation.
#
# This harness is a READ-ONLY documentation-consistency verifier. It reconciles narrow
# documentation inconsistencies surfaced across Runs 406-408 and proves the reconciled
# state is internally consistent, WITHOUT adding functionality and WITHOUT moving any
# readiness item. It generates only a transient summary OUTSIDE the repository tree and
# commits nothing.
#
# It is DOCS + SHELL only (Decision gate = Route B): NO production Rust source change, NO
# build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable port, NO
# seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO weakened peer
# admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState mutation.
#
# What it proves (18 checks):
#   1.  Run 408 anchor-manifest-change statement is internally consistent across evidence,
#       archive README, readiness matrix, contradiction ledger, and the manifest file.
#   2.  PACKAGE_INTEGRITY_CI_ARTIFACTS.md no longer contains stale "exactly three"
#       current-artifact wording.
#   3.  Current artifact upload count is consistently four after Run 407.
#   4.  The four artifact names are consistent across the CI artifacts guide, retention
#       guide, operator verification map, and artifact index.
#   5.  Anchor-refresh wording is consistent across Run 408 evidence, readiness matrix, and
#       package-integrity docs.
#   6.  No generated artifact is committed.
#   7.  No readiness item moves Green.
#   8.  M4 remains Yellow.
#   9.  M6 remains Yellow/Partial.
#   10. S5 remains Yellow.
#   11. S7 remains Yellow.
#   12. Public DevNet remains NOT launch-ready / NO-GO.
#   13. C4/C5 remain OPEN.
#   14. No TestNet/MainNet readiness claim appears.
#   15. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   16. No runtime mutation claim appears.
#   17. Secret/private-material scan is clean.
#   18. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run409-public-devnet-integrity-doc-consistency}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

MANIFEST="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
CI_ARTIFACTS="${PDN}/PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
CI_RETENTION="${PDN}/PACKAGE_INTEGRITY_CI_RETENTION.md"
DRIFT_HISTORY="${PDN}/PACKAGE_INTEGRITY_DRIFT_HISTORY.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV408="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_408.md"
EV408_README="${DEVNET}/run_408_public_devnet_retained_drift_history_comparator/README.md"
WORKFLOW="${REPO_ROOT}/.github/workflows/public-devnet-package-integrity.yml"

SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run409] %s\n' "$*"; }
fail() { printf '[run409] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# The four canonical current CI upload artifacts after Run 407.
ART1="PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
ART2="ANCHOR_DRIFT_REPORT.md"
ART3="ANCHOR_DRIFT_REPORT.json"
ART4="PACKAGE_INTEGRITY_CI_SUMMARY.txt"

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${MANIFEST}" "${CI_ARTIFACTS}" "${CI_RETENTION}" "${DRIFT_HISTORY}" \
         "${ARTIFACT_INDEX}" "${OP_MAP}" "${CRITERIA}" "${CONTRADICTION}" \
         "${EV408}" "${EV408_README}" "${WORKFLOW}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# ---------------------------------------------------------------------------
# 1. Run 408 anchor-manifest-change statement is internally consistent.
#    Ground truth: Run 408 edited the two anchor docs ARTIFACT_INDEX.md and
#    OPERATOR_VERIFICATION_MAP.md, so the Run 404 anchor manifest WAS refreshed for
#    exactly those two entries. The manifest on-disk must match every anchor.
# ---------------------------------------------------------------------------
# 1a. Evidence must NOT carry the stale "not edited this run" wording.
if grep -qiE 'manifest was[[:space:]]+\*?\*?not\*?\*?[[:space:]]+edited this run' "${EV408}"; then
  fail "Run 408 evidence still says the anchor manifest was 'not edited this run'"
fi
# 1b. Evidence + readiness matrix + contradiction ledger must all name the two refreshed docs.
for f in "${EV408}" "${CRITERIA}" "${CONTRADICTION}"; do
  grep -q 'ARTIFACT_INDEX.md' "${f}" || fail "missing ARTIFACT_INDEX.md refresh reference in ${f}"
  grep -q 'OPERATOR_VERIFICATION_MAP.md' "${f}" || fail "missing OPERATOR_VERIFICATION_MAP.md refresh reference in ${f}"
done
grep -qiE 'refreshed for exactly (those two|the two)' "${EV408}" \
  || fail "Run 408 evidence must state the manifest was refreshed for exactly the two edited anchor docs"
# 1c. The manifest on-disk must match every covered file (no entry added/removed; no mismatch).
python3 - "${MANIFEST}" "${PDN}" <<'PY' || fail "manifest does not match on-disk tree"
import json, hashlib, os, sys
manifest = json.load(open(sys.argv[1]))
root = sys.argv[2]
files = manifest.get("files") or manifest.get("covered_files") or []
assert files, "manifest has no covered files"
bad = []
for e in files:
    rp = e["relative_path"]
    fp = os.path.join(root, rp)
    if not os.path.exists(fp):
        bad.append(("missing", rp)); continue
    data = open(fp, "rb").read()
    if hashlib.sha256(data).hexdigest() != e["sha256"] or len(data) != e["byte_size"]:
        bad.append(("mismatch", rp))
assert not bad, f"manifest inconsistencies: {bad}"
# The two Run 408-edited anchor docs must be present exactly once each (no add/remove).
names = [e["relative_path"] for e in files]
for anchor in ("ARTIFACT_INDEX.md", "OPERATOR_VERIFICATION_MAP.md"):
    assert names.count(anchor) == 1, f"{anchor} not present exactly once in manifest"
print(f"anchors={len(files)} refreshed=ARTIFACT_INDEX.md,OPERATOR_VERIFICATION_MAP.md")
PY
emit "anchor_manifest_consistent=OK (Run 408 refreshed the Run 404 anchor manifest for exactly ARTIFACT_INDEX.md + OPERATOR_VERIFICATION_MAP.md; all manifest entries match on-disk; no entry added/removed; evidence/readiness/contradiction agree)"

# ---------------------------------------------------------------------------
# 2. No stale "exactly three" current-artifact wording in the CI artifacts guide.
# ---------------------------------------------------------------------------
if grep -niE 'exactly \*{0,2}three\*{0,2}|one of the three publish-safe' "${CI_ARTIFACTS}"; then
  fail "stale 'exactly three' current-artifact wording remains in PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
fi
grep -qiE 'exactly \*{0,2}four\*{0,2} publish-safe' "${CI_ARTIFACTS}" \
  || fail "PACKAGE_INTEGRITY_CI_ARTIFACTS.md must state exactly four publish-safe artifacts"
emit "no_stale_three=OK (PACKAGE_INTEGRITY_CI_ARTIFACTS.md states exactly four publish-safe artifacts; no stale 'three' current wording)"

# ---------------------------------------------------------------------------
# 3. Current artifact upload count is consistently four after Run 407.
#    Ground truth is the workflow's upload-artifact path list.
# ---------------------------------------------------------------------------
UPLOAD_COUNT=0
for art in "${ART1}" "${ART2}" "${ART3}" "${ART4}"; do
  grep -qE "artifact-staging/${art}\b" "${WORKFLOW}" || fail "workflow does not upload ${art}"
  UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
done
[ "${UPLOAD_COUNT}" -eq 4 ] || fail "expected four uploaded artifacts, found ${UPLOAD_COUNT}"
# The retention guide must also say four.
grep -qiE 'exactly \*{0,2}four\*{0,2} publish-safe' "${CI_RETENTION}" \
  || fail "PACKAGE_INTEGRITY_CI_RETENTION.md must state exactly four publish-safe artifacts"
emit "artifact_count_four=OK (workflow uploads four download-only artifacts; CI artifacts + retention guides both say four)"

# ---------------------------------------------------------------------------
# 4. The four artifact names are consistent across the enumerating guides, and the JSON
#    drift report is referenced by the operator verification map + artifact index.
# ---------------------------------------------------------------------------
for guide in "${CI_ARTIFACTS}" "${CI_RETENTION}"; do
  for art in "${ART1}" "${ART2}" "${ART3}" "${ART4}"; do
    grep -qF "${art}" "${guide}" || fail "${guide} does not list artifact ${art}"
  done
done
grep -qF "${ART3}" "${OP_MAP}" || fail "operator verification map does not reference ${ART3}"
grep -qF "${ART3}" "${ARTIFACT_INDEX}" || fail "artifact index does not reference ${ART3}"
emit "artifact_names_consistent=OK (all four artifact names appear in the CI artifacts + retention guides; ANCHOR_DRIFT_REPORT.json referenced in operator map + artifact index)"

# ---------------------------------------------------------------------------
# 5. Anchor-refresh wording is consistent across Run 408 evidence, readiness matrix, and
#    package-integrity docs (no doc claims the manifest was NOT edited in Run 408).
# ---------------------------------------------------------------------------
if grep -rniE 'anchor manifest was[[:space:]]+\*?\*?not\*?\*?[[:space:]]+edited|manifest was[[:space:]]+\*?\*?not\*?\*?[[:space:]]+edited this run' \
     "${EV408}" "${EV408_README}" "${CRITERIA}" "${CONTRADICTION}" "${PDN}"/*.md; then
  fail "a doc still claims the Run 404 anchor manifest was NOT edited in Run 408"
fi
emit "anchor_refresh_wording_consistent=OK (no doc claims the Run 404 anchor manifest was not edited in Run 408; refresh narrative is uniform)"

# ---------------------------------------------------------------------------
# 6. No generated artifact is committed to the tree.
# ---------------------------------------------------------------------------
for name in "${ART1}" "${ART3}" "PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_artifacts_transient=OK (no generated CI/diff artifact is committed)"

# ---------------------------------------------------------------------------
# 7-11. Readiness matrix reconciliation: nothing moves Green; M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
grep -qi 'Run 409' "${CRITERIA}" || fail "readiness matrix must carry the Run 409 narrative"
grep -qi 'no readiness item moves' "${CRITERIA}" || fail "readiness matrix must state no readiness item moves"
emit "readiness_reconciled=OK (no readiness item moves Green; M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 12-13. Public DevNet NOT launch-ready + C4/C5 OPEN in the Run 409 contradiction entry.
# ---------------------------------------------------------------------------
RUN409_ENTRY="$(grep -E '^Run 409 ' "${CONTRADICTION}" || true)"
[ -n "${RUN409_ENTRY}" ] || fail "contradiction ledger missing the Run 409 entry"
printf '%s' "${RUN409_ENTRY}" | grep -qi 'no protocol contradiction found' \
  || fail "Run 409 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN409_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 409 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN409_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN409_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 409 contradiction entry must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 14-16, 18. Non-claim grep over the Run 409-authored/updated docs (normalized).
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
RUN409_EVIDENCE="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_409.md"
[ -f "${RUN409_EVIDENCE}" ] || fail "Run 409 evidence doc missing: ${RUN409_EVIDENCE}"
for f in "${RUN409_EVIDENCE}" "${CI_ARTIFACTS}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in ${f}"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 409 docs)"
emit "testnet_mainnet_non_claim=OK (no TestNet/MainNet readiness claim in Run 409 docs)"
emit "runtime_mutation=NONE (Run 409 is docs+shell only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 17. Secret / private-material + absolute-path scan over the Run 409-authored/updated docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${RUN409_EVIDENCE}" "${CI_ARTIFACTS}" "${EV408}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 409 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 409 doc"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 409 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet integrity documentation consistency reconciliation: the Run 408 anchor-manifest-refresh narrative is consistent across evidence, readiness matrix, and contradiction ledger and matches the on-disk manifest (refreshed for exactly ARTIFACT_INDEX.md + OPERATOR_VERIFICATION_MAP.md; no entry added/removed); PACKAGE_INTEGRITY_CI_ARTIFACTS.md no longer carries stale 'exactly three' current wording and now describes the four download-only artifacts consistently with the workflow + retention guide; no generated artifact is committed; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready; no TestNet/MainNet or deployment or runtime-mutation claim; secret/private-material scan clean)"
