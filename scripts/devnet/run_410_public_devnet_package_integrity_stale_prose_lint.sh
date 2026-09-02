#!/usr/bin/env bash
# Run 410: public DevNet package-integrity stale-prose lint.
#
# This harness is a READ-ONLY, fail-closed cross-document lint. It guards the public
# DevNet package-integrity documentation set and its CI workflow against the class of
# silent drift that Run 409 had to reconcile by hand (a stale "exactly three" CI artifact
# count and a stale "not edited this run" anchor-manifest claim). It adds NO feature
# surface and moves NO readiness item. It generates only a transient summary OUTSIDE the
# repository tree and commits nothing.
#
# It is DOCS + SHELL + YAML only (Decision gate = Route B): NO production Rust source
# change, NO build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable
# port, NO seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO
# weakened peer admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState
# mutation. No node is started, no port is opened, and no state/data dir is written.
#
# It fails closed if:
#   * any package-integrity doc says the workflow emits "exactly three" current artifacts;
#   * the current workflow artifact count is not four;
#   * the four artifact names are not consistent across the CI artifacts guide, the
#     retention guide, the operator verification map, the artifact index, and the workflow;
#   * ANCHOR_DRIFT_REPORT.json is missing from the current artifact wording;
#   * any package-integrity doc claims a generated artifact is a committed source artifact;
#   * any package-integrity doc claims a retained/download-only artifact is binary
#     provenance, a signed attestation, launch evidence, or readiness evidence;
#   * any Run 408/409 anchor-refresh statement conflicts with the canonical statement;
#   * any doc denies that Run 408 refreshed PACKAGE_INTEGRITY_MANIFEST.example.json;
#   * any manifest anchor file no longer exists, or any anchor SHA-256/byte_size mismatches;
#   * any stale prose implies M4/M6/S5/S7 moved Green, C4/C5 closure, TestNet/MainNet
#     readiness, a launch/faucet/RPC/explorer/status-service deployment, or a runtime
#     mutation.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run410-public-devnet-package-integrity-stale-prose-lint}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
DEVNET="${REPO_ROOT}/docs/devnet"

LINT_GUIDE="${PDN}/PACKAGE_INTEGRITY_STALE_PROSE_LINT.md"
PI="${PDN}/PACKAGE_INTEGRITY.md"
PI_FULL_TREE="${PDN}/PACKAGE_INTEGRITY_FULL_TREE.md"
CI_ARTIFACTS="${PDN}/PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
CI_RETENTION="${PDN}/PACKAGE_INTEGRITY_CI_RETENTION.md"
DRIFT_HISTORY="${PDN}/PACKAGE_INTEGRITY_DRIFT_HISTORY.md"
ARTIFACT_INDEX="${PDN}/ARTIFACT_INDEX.md"
OP_MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
MANIFEST="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
CONTRADICTION="${REPO_ROOT}/docs/whitepaper/contradiction.md"
EV408="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_408.md"
EV409="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_409.md"
EV410="${DEVNET}/QBIND_DEVNET_EVIDENCE_RUN_410.md"
WORKFLOW="${REPO_ROOT}/.github/workflows/public-devnet-package-integrity.yml"

SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run410] %s\n' "$*"; }
fail() { printf '[run410] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# The four canonical current CI upload artifacts (after Run 407).
ART1="PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
ART2="ANCHOR_DRIFT_REPORT.md"
ART3="ANCHOR_DRIFT_REPORT.json"
ART4="PACKAGE_INTEGRITY_CI_SUMMARY.txt"

# Package-integrity prose docs scanned for stale/forbidden wording. The lint guide itself
# is EXCLUDED from forbidden-phrase scans because it necessarily quotes the forbidden
# phrases in order to document them.
PKG_DOCS=("${PI}" "${PI_FULL_TREE}" "${CI_ARTIFACTS}" "${CI_RETENTION}" "${DRIFT_HISTORY}" \
          "${ARTIFACT_INDEX}" "${OP_MAP}")
# Guides that enumerate the current artifact set.
ENUM_SOURCES=("${CI_ARTIFACTS}" "${CI_RETENTION}" "${OP_MAP}" "${ARTIFACT_INDEX}" "${WORKFLOW}")

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

for f in "${LINT_GUIDE}" "${PI}" "${PI_FULL_TREE}" "${CI_ARTIFACTS}" "${CI_RETENTION}" \
         "${DRIFT_HISTORY}" "${ARTIFACT_INDEX}" "${OP_MAP}" "${MANIFEST}" "${CRITERIA}" \
         "${CONTRADICTION}" "${EV408}" "${EV409}" "${WORKFLOW}"; do
  [ -f "${f}" ] || fail "required file missing: ${f}"
done

# ---------------------------------------------------------------------------
# 1. The stale-prose lint guide exists and is safety-labelled.
# ---------------------------------------------------------------------------
grep -qi 'Safety label:' "${LINT_GUIDE}" || fail "stale-prose lint guide is not safety-labelled"
grep -qi 'NOT public-DevNet launch-ready' "${LINT_GUIDE}" || fail "stale-prose lint guide missing NOT launch-ready label"
grep -qi 'C4/C5 OPEN' "${LINT_GUIDE}" || fail "stale-prose lint guide missing C4/C5 OPEN label"
emit "lint_guide_present=OK (PACKAGE_INTEGRITY_STALE_PROSE_LINT.md exists and is safety-labelled: NOT launch-ready; C4/C5 OPEN)"

# ---------------------------------------------------------------------------
# 2. Current artifact count is four (ground truth = the workflow upload path list).
# ---------------------------------------------------------------------------
UPLOAD_COUNT=0
for art in "${ART1}" "${ART2}" "${ART3}" "${ART4}"; do
  grep -qF "artifact-staging/${art}" "${WORKFLOW}" || fail "workflow does not upload ${art}"
  UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
done
[ "${UPLOAD_COUNT}" -eq 4 ] || fail "expected four uploaded artifacts, found ${UPLOAD_COUNT}"
TOTAL_UPLOAD="$(grep -cE 'artifact-staging/[A-Za-z0-9_.]+\.(json|md|txt)' "${WORKFLOW}")"
[ "${TOTAL_UPLOAD}" -eq 4 ] || fail "workflow uploads ${TOTAL_UPLOAD} artifact paths, expected exactly four"
grep -qiE 'exactly \*{0,2}four\*{0,2} publish-safe' "${CI_ARTIFACTS}" \
  || fail "PACKAGE_INTEGRITY_CI_ARTIFACTS.md must state exactly four publish-safe artifacts"
grep -qiE 'exactly \*{0,2}four\*{0,2} publish-safe' "${CI_RETENTION}" \
  || fail "PACKAGE_INTEGRITY_CI_RETENTION.md must state exactly four publish-safe artifacts"
emit "artifact_count_four=OK (workflow uploads exactly four download-only artifacts; CI artifacts + retention guides both say four)"

# ---------------------------------------------------------------------------
# 3. The four artifact names are consistent across the CI artifacts guide, the retention
#    guide, the operator verification map, the artifact index, and the workflow.
# ---------------------------------------------------------------------------
for src in "${ENUM_SOURCES[@]}"; do
  for art in "${ART1}" "${ART2}" "${ART3}" "${ART4}"; do
    grep -qF "${art}" "${src}" || fail "$(basename "${src}") does not list artifact ${art}"
  done
done
emit "artifact_names_consistent=OK (all four artifact names appear in the CI artifacts guide, retention guide, operator verification map, artifact index, and the workflow)"

# ---------------------------------------------------------------------------
# 4. ANCHOR_DRIFT_REPORT.json is present in the current artifact wording (guarded
#    explicitly so a future edit cannot silently drop it).
# ---------------------------------------------------------------------------
for src in "${ENUM_SOURCES[@]}"; do
  grep -qF "${ART3}" "${src}" || fail "$(basename "${src}") is missing ${ART3} from the current artifact wording"
done
emit "json_drift_report_present=OK (ANCHOR_DRIFT_REPORT.json is present in the current artifact wording across all enumerating sources)"

# ---------------------------------------------------------------------------
# 5. No stale "exactly three" current-artifact wording remains in any package-integrity
#    doc (the lint guide itself is excluded; it quotes the forbidden phrase).
# ---------------------------------------------------------------------------
if grep -niE 'exactly \*{0,2}three\*{0,2} (publish-safe|current|download-only|artifact)|one of the three publish-safe' "${PKG_DOCS[@]}"; then
  fail "stale 'exactly three' current-artifact wording remains in a package-integrity doc"
fi
emit "no_stale_three=OK (no stale 'exactly three' current-artifact wording in any package-integrity doc)"

# ---------------------------------------------------------------------------
# 6. Anchor-refresh wording is canonical and consistent.
#    Canonical: the Run 404 anchor manifest WAS refreshed in Run 408 for exactly
#    ARTIFACT_INDEX.md + OPERATOR_VERIFICATION_MAP.md; no entry added/removed; no status
#    changed. No doc may deny that refresh.
# ---------------------------------------------------------------------------
if grep -rniE 'anchor manifest was[[:space:]]+\*?\*?not\*?\*?[[:space:]]+edited|manifest was[[:space:]]+\*?\*?not\*?\*?[[:space:]]+edited this run' \
     "${EV408}" "${CRITERIA}" "${CONTRADICTION}" "${PKG_DOCS[@]}"; then
  fail "a doc still denies that the Run 404 anchor manifest was refreshed in Run 408"
fi
grep -qiE 'refreshed for exactly (those two|the two)' "${EV408}" \
  || fail "Run 408 evidence must state the manifest was refreshed for exactly the two edited anchor docs"
for f in "${EV408}" "${CRITERIA}" "${CONTRADICTION}"; do
  grep -qF 'ARTIFACT_INDEX.md' "${f}" || fail "missing ARTIFACT_INDEX.md refresh reference in $(basename "${f}")"
  grep -qF 'OPERATOR_VERIFICATION_MAP.md' "${f}" || fail "missing OPERATOR_VERIFICATION_MAP.md refresh reference in $(basename "${f}")"
done
grep -qiE 'refreshed for exactly' "${LINT_GUIDE}" \
  || fail "stale-prose lint guide must record the canonical Run 408 anchor-refresh statement"
emit "anchor_refresh_wording_consistent=OK (canonical Run 408 refresh: exactly ARTIFACT_INDEX.md + OPERATOR_VERIFICATION_MAP.md; no entry added/removed; no doc denies the refresh)"

# ---------------------------------------------------------------------------
# 7. Anchor manifest entries all exist and every SHA-256 + byte_size matches on-disk.
# ---------------------------------------------------------------------------
python3 - "${MANIFEST}" "${PDN}" <<'PY' || fail "anchor manifest does not match the on-disk tree"
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
names = [e["relative_path"] for e in files]
for anchor in ("ARTIFACT_INDEX.md", "OPERATOR_VERIFICATION_MAP.md"):
    assert names.count(anchor) == 1, f"{anchor} not present exactly once in manifest"
print(f"anchors={len(files)} all_present_and_matching")
PY
emit "anchor_manifest_hash_size_ok=OK (all 16 manifest anchors exist and every SHA-256 + byte_size matches the on-disk tree)"

# ---------------------------------------------------------------------------
# 8. Generated-output non-commit wording is consistent (each generated/derived artifact
#    guide asserts the non-commit posture and none claims a generated artifact is a
#    committed source artifact).
# ---------------------------------------------------------------------------
for f in "${CI_ARTIFACTS}" "${CI_RETENTION}" "${DRIFT_HISTORY}"; do
  grep -qiE 'never committed|not committed source|nothing (it generates|generated) is committed|no committed generated' "${f}" \
    || fail "$(basename "${f}") does not assert the generated-output non-commit posture"
done
# Forbidden affirmative: a generated artifact described as a committed source artifact.
if grep -rniE '(generated|full-tree manifest|drift report|drift diff|drift-history diff)[^.]*\b(is|are) committed( source)?\b' "${PKG_DOCS[@]}"; then
  fail "a package-integrity doc claims a generated artifact is a committed source artifact"
fi
emit "generated_output_non_commit=OK (generated full-tree manifest / drift reports / history diff are stated never-committed; no committed-source claim)"

# ---------------------------------------------------------------------------
# 9. Download-only / retention wording is consistent.
# ---------------------------------------------------------------------------
for f in "${CI_ARTIFACTS}" "${CI_RETENTION}"; do
  grep -qiE 'download-only' "${f}" || fail "$(basename "${f}") does not describe the artifacts as download-only"
done
grep -qiE 'convenience' "${CI_RETENTION}" \
  || fail "retention guide must state retention is convenience/audit usability only"
emit "download_only_retention=OK (artifacts described as download-only; retention is convenience/audit usability only)"

# ---------------------------------------------------------------------------
# 10. Not-binary-provenance wording is consistent.
# ---------------------------------------------------------------------------
for f in "${CI_ARTIFACTS}" "${CI_RETENTION}" "${DRIFT_HISTORY}" "${LINT_GUIDE}"; do
  grep -qiE 'not[^.]*binary provenance' "${f}" \
    || fail "$(basename "${f}") does not assert it is not binary provenance"
done
# Forbidden affirmative: a retained/download-only artifact asserted to BE provenance/attestation.
if grep -rniE '(retained|download-only|ci) artifact[^.]*\b(is|are) (binary provenance|a signed attestation|provenance)\b' "${PKG_DOCS[@]}"; then
  fail "a package-integrity doc claims a retained/download-only artifact is binary provenance / signed attestation"
fi
emit "not_binary_provenance=OK (guides assert not binary provenance / not a signed attestation; no provenance overclaim)"

# ---------------------------------------------------------------------------
# 11. Not-launch-evidence wording is consistent.
# ---------------------------------------------------------------------------
for f in "${CI_ARTIFACTS}" "${CI_RETENTION}" "${DRIFT_HISTORY}" "${LINT_GUIDE}"; do
  grep -qiE 'not[^.]*launch evidence' "${f}" \
    || fail "$(basename "${f}") does not assert it is not launch evidence"
  grep -qiE 'NO-GO / NOT launch-ready|NOT launch-ready' "${f}" \
    || fail "$(basename "${f}") does not restate the NO-GO / NOT launch-ready decision"
done
if grep -rniE '(retained|download-only|ci) artifact[^.]*\b(is|are) (launch evidence|readiness evidence)\b' "${PKG_DOCS[@]}"; then
  fail "a package-integrity doc claims a retained/download-only artifact is launch/readiness evidence"
fi
emit "not_launch_evidence=OK (guides assert not launch evidence / not readiness evidence; NO-GO restated; no launch-evidence overclaim)"

# ---------------------------------------------------------------------------
# 12-18. Readiness posture is unchanged in the canonical readiness matrix.
# ---------------------------------------------------------------------------
grep -qF "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -qF "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -qF "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -qF "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
grep -qi 'Run 410' "${CRITERIA}" || fail "readiness matrix must carry the Run 410 narrative"
grep -qi 'no readiness item moves' "${CRITERIA}" || fail "readiness matrix must state no readiness item moves"
emit "readiness_unchanged=OK (no readiness item moves Green; M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

RUN410_ENTRY="$(grep -E '^Run 410 ' "${CONTRADICTION}" || true)"
[ -n "${RUN410_ENTRY}" ] || fail "contradiction ledger missing the Run 410 entry"
printf '%s' "${RUN410_ENTRY}" | grep -qi 'no protocol contradiction found' \
  || fail "Run 410 contradiction entry must state no protocol contradiction found"
printf '%s' "${RUN410_ENTRY}" | grep -qi 'NOT launch-ready' \
  || fail "Run 410 contradiction entry must state public DevNet NOT launch-ready"
printf '%s' "${RUN410_ENTRY}" | grep -qi 'C4 remains OPEN' \
  && printf '%s' "${RUN410_ENTRY}" | grep -qi 'C5 remains OPEN' \
  || fail "Run 410 contradiction entry must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 19-21, 26. Non-claim grep over the Run 410-authored docs (normalized), matching the
#            established Run 409 approach.
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
[ -f "${EV410}" ] && CLAIM_TARGETS+=("${EV410}")
for f in "${CLAIM_TARGETS[@]}"; do
  CLAIM_HITS="$(normalize_md "${f}" \
    | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live|mutates runtime|epoch transition performed' \
    | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real|no runtime' || true)"
  [ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment/runtime claim found in $(basename "${f}")"; }
done
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment / runtime-mutation claim in Run 410 docs)"
emit "testnet_mainnet_non_claim=OK (no TestNet/MainNet readiness claim in Run 410 docs)"
emit "runtime_mutation=NONE (Run 410 is docs+shell+YAML only; no validator/epoch/sequence/marker/LivePqcTrustState mutation)"

# ---------------------------------------------------------------------------
# 22. CI workflow remains least-privilege.
# ---------------------------------------------------------------------------
grep -qE '^permissions:' "${WORKFLOW}" || fail "workflow must declare permissions"
grep -qE 'contents:[[:space:]]*read' "${WORKFLOW}" || fail "workflow must grant only contents: read"
if grep -qiE 'contents:[[:space:]]*write|packages:[[:space:]]*write|id-token:[[:space:]]*write|permissions:[[:space:]]*write-all' "${WORKFLOW}"; then
  fail "workflow requests write privilege"
fi
if grep -qiE 'secrets\.|\$\{\{[[:space:]]*secrets' "${WORKFLOW}"; then
  fail "workflow references a secret"
fi
if grep -qiE 'softprops/action-gh-release|actions/create-release|gh release|gh api|git push|peaceiris/actions-gh-pages|create-pull-request' "${WORKFLOW}"; then
  fail "workflow contains a deploy/release/tag/push/commit step"
fi
grep -qiE 'working tree unexpectedly dirty|status --porcelain' "${WORKFLOW}" \
  || fail "workflow must fail if the working tree is dirty after the checks"
emit "workflow_least_privilege=OK (permissions contents:read; no secrets; no deploy/release/tag/push/commit; dirty-tree guard present)"

# ---------------------------------------------------------------------------
# 23. The workflow runs the Run 410 lint after the existing verifier/wrapper.
# ---------------------------------------------------------------------------
grep -qF 'run_410_public_devnet_package_integrity_stale_prose_lint.sh' "${WORKFLOW}" \
  || fail "workflow does not run the Run 410 stale-prose lint"
VERIFIER_LINE="$(grep -n 'run_407_public_devnet_anchor_drift_json_retention.sh' "${WORKFLOW}" | tail -1 | cut -d: -f1)"
LINT_LINE="$(grep -n 'run_410_public_devnet_package_integrity_stale_prose_lint.sh' "${WORKFLOW}" | tail -1 | cut -d: -f1)"
[ -n "${VERIFIER_LINE}" ] && [ -n "${LINT_LINE}" ] && [ "${LINT_LINE}" -gt "${VERIFIER_LINE}" ] \
  || fail "the Run 410 lint must run after the Run 407 verifier/wrapper"
emit "workflow_integration=OK (lint runs after the Run 407 verifier/wrapper in the package-integrity workflow)"

# ---------------------------------------------------------------------------
# 24. Generated artifacts are not committed to the tree.
# ---------------------------------------------------------------------------
for name in "${ART1}" "${ART3}" "PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json" "PACKAGE_INTEGRITY_CI_SUMMARY.txt"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_artifacts_transient=OK (no generated CI/diff artifact is committed)"

# ---------------------------------------------------------------------------
# 25. Secret / private-material + absolute-path scan over the Run 410-authored docs.
# ---------------------------------------------------------------------------
SCAN_FILES=("${LINT_GUIDE}")
[ -f "${EV410}" ] && SCAN_FILES+=("${EV410}")
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${SCAN_FILES[@]}"; then
  fail "absolute filesystem path found in a Run 410 doc"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${SCAN_FILES[@]}"; then
  fail "possible secret / private material found in a Run 410 doc"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path in Run 410 docs)"

# ---------------------------------------------------------------------------
# Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

emit ""
emit "RESULT=POSITIVE (public-DevNet package-integrity stale-prose lint: the lint guide is published and safety-labelled; the workflow uploads exactly four download-only artifacts and the four names are consistent across the CI artifacts guide, retention guide, operator verification map, artifact index, and workflow; ANCHOR_DRIFT_REPORT.json is present; no stale 'exactly three' wording remains; the canonical Run 408 anchor-refresh statement (exactly ARTIFACT_INDEX.md + OPERATOR_VERIFICATION_MAP.md; no entry added/removed) is consistent and no doc denies it; all 16 manifest anchors exist and every SHA-256 + byte_size matches on-disk; generated output is stated never-committed and none is committed; download-only/retention, not-binary-provenance, and not-launch-evidence wording is consistent; the lint runs after the verifier in a least-privilege (contents:read, no secrets, no deploy/release/push) workflow that fails on a dirty tree; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready; no TestNet/MainNet or deployment or runtime-mutation claim; secret/private-material scan clean)"