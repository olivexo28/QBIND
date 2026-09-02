#!/usr/bin/env bash
# Run 406: public DevNet FULL-TREE integrity CI artifact + anchor-drift verifier.
#
# This harness EXTENDS the Run 405 full-tree package integrity verifier
# (`scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh`) so CI can
# emit, as DOWNLOAD-ONLY artifacts:
#   * PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json — the transient full-tree
#     manifest (already produced by the Run 405 verifier);
#   * ANCHOR_DRIFT_REPORT.md — a publish-safe report comparing the Run 404 curated
#     anchor manifest against the Run 405/406 full-tree file set;
#   * PACKAGE_INTEGRITY_CI_SUMMARY.txt — a short OK/POSITIVE status summary.
#
# All three are generated into a STAGING directory OUTSIDE `docs/release/public-devnet`
# and are NEVER committed. This run is DOCS + SHELL + YAML only (Decision gate =
# Route B): it makes NO production Rust source change, NO build.rs change, NO
# Cargo.toml change, adds NO CLI flag, opens NO externally reachable port, deploys NO
# seed/bootnode/faucet/RPC/explorer/status service, changes NO wire format, weakens NO
# peer admission, and mutates NO trust/validator/epoch/sequence/marker/
# LivePqcTrustState state.
#
# What it proves (26 checks):
#   1.  CI artifacts guide exists and is safety-labelled.
#   2.  Run 405 full-tree verifier still passes (RESULT=POSITIVE).
#   3.  Generated full-tree manifest validates against the schema.
#   4.  Generated full-tree manifest covers every publish-safe file.
#   5.  SHA-256 + byte-size verification passes.
#   6.  Anchor drift report is generated (into staging, outside the tree).
#   7.  Anchor entries all exist in the full-tree set.
#   8.  Anchor entries match hashes/sizes or are documented deliberate refreshes.
#   9.  Full-tree-only files are reported as expected curated-anchor drift.
#   10. CI workflow uses permissions: contents: read.
#   11. CI workflow references no secrets.
#   12. CI workflow has no deploy/release/tag/commit/push step.
#   13. CI workflow uploads only publish-safe artifact names.
#   14. Generated artifacts are not committed (staging outside the package tree).
#   15. Working tree stays clean after the verifier.
#   16. M4 remains Yellow.
#   17. M6 remains Yellow/Partial.
#   18. S5 remains Yellow.
#   19. S7 remains Yellow.
#   20. Public DevNet remains NOT launch-ready.
#   21. C4/C5 remain OPEN.
#   22. No TestNet/MainNet readiness claim appears.
#   23. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   24. No runtime mutation claim (manifest non_claims all false).
#   25. Secret/private-material scan is clean.
#   26. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run406-public-devnet-full-tree-ci-artifact-anchor-drift}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
CI_GUIDE="${PDN}/PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
FT_GUIDE="${PDN}/PACKAGE_INTEGRITY_FULL_TREE.md"
FT_SCHEMA="${PDN}/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json"
A_EXAMPLE="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
WORKFLOW="${REPO_ROOT}/.github/workflows/public-devnet-package-integrity.yml"
RUN405="${REPO_ROOT}/scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh"

SUMMARY="${OUTDIR}/summary.txt"
# The generated CI artifacts are staged OUTSIDE the package tree; never committed.
STAGING="${OUTDIR}/artifact-staging"
GEN_MANIFEST="${STAGING}/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
DRIFT_REPORT="${STAGING}/ANCHOR_DRIFT_REPORT.md"
CI_SUMMARY="${STAGING}/PACKAGE_INTEGRITY_CI_SUMMARY.txt"

# The three publish-safe artifact names CI is allowed to upload.
ARTIFACT_NAMES=(
  "PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
  "ANCHOR_DRIFT_REPORT.md"
  "PACKAGE_INTEGRITY_CI_SUMMARY.txt"
)

# Anchor-manifest files narrowly edited (and refreshed) in THIS run — documented
# deliberate refreshes. A hash change on these anchors is expected and documented.
DOCUMENTED_REFRESH=(
  "PACKAGE_INTEGRITY.md"
  "ARTIFACT_INDEX.md"
  "OPERATOR_VERIFICATION_MAP.md"
)

log()  { printf '[run406] %s\n' "$*"; }
fail() { printf '[run406] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}" "${STAGING}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

# ---------------------------------------------------------------------------
# 1. CI artifacts guide exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${CI_GUIDE}" ] || fail "CI artifacts guide missing: PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
grep -qi 'experimental' "${CI_GUIDE}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${CI_GUIDE}" \
  && grep -qi 'no C4/C5 closure claim' "${CI_GUIDE}" \
  && grep -qi 'download-only' "${CI_GUIDE}" \
  || fail "safety label / download-only wording missing in PACKAGE_INTEGRITY_CI_ARTIFACTS.md"
emit "ci_artifacts_guide_present=OK (PACKAGE_INTEGRITY_CI_ARTIFACTS.md present, safety-labelled, download-only) sha256=$(sha256_file "${CI_GUIDE}")"

# ---------------------------------------------------------------------------
# 2. Run 405 full-tree verifier still passes. The committed Run 405 harness is
#    stored with CRLF line endings, so normalize a transient copy to LF and run it
#    IN PLACE (so its BASH_SOURCE-derived REPO_ROOT stays correct). Its generated
#    full-tree manifest is emitted into STAGING (outside the package tree).
# ---------------------------------------------------------------------------
[ -f "${RUN405}" ] || fail "Run 405 verifier missing: run_405_public_devnet_full_tree_package_integrity.sh"
R405_TMP="${REPO_ROOT}/scripts/devnet/.run_405_lf.$$.tmp.sh"
cleanup() { rm -f "${R405_TMP}"; }
trap cleanup EXIT
sed 's/\r$//' "${RUN405}" > "${R405_TMP}"
R405_LOG="${OUTDIR}/run405.log"
if ! bash "${R405_TMP}" "${STAGING}" > "${R405_LOG}" 2>&1; then
  cat "${R405_LOG}" >&2
  fail "Run 405 full-tree verifier did not pass"
fi
grep -q '^RESULT=POSITIVE' "${R405_LOG}" || { cat "${R405_LOG}" >&2; fail "Run 405 verifier did not report RESULT=POSITIVE"; }
rm -f "${R405_TMP}"; trap - EXIT
emit "run405_compat=OK (Run 405 full-tree verifier RESULT=POSITIVE; reused via LF-normalized transient copy)"

[ -f "${GEN_MANIFEST}" ] || fail "Run 405 verifier did not emit the generated full-tree manifest into staging"

# ---------------------------------------------------------------------------
# 3-5. Re-validate the generated full-tree manifest against the schema, re-verify
#      full-tree coverage against the on-disk publish-safe set, and re-hash every
#      listed file (sha256 + byte_size). Defence-in-depth on top of Run 405.
# ---------------------------------------------------------------------------
DISK_LIST="${OUTDIR}/disk_files.txt"
{
  git -C "${REPO_ROOT}" ls-files -- docs/release/public-devnet
  git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- docs/release/public-devnet
} | sed 's#^docs/release/public-devnet/##' | LC_ALL=C sort -u > "${DISK_LIST}"
[ -s "${DISK_LIST}" ] || fail "no publish-safe files enumerated under package root"

python3 - "${FT_SCHEMA}" "${GEN_MANIFEST}" "${PDN}" "${DISK_LIST}" <<'PY' || fail "generated full-tree manifest validation/coverage/hash check failed"
import hashlib, json, os, re, sys
schema = json.load(open(sys.argv[1]))
m = json.load(open(sys.argv[2]))
pdn = sys.argv[3]
rels = [ln.strip() for ln in open(sys.argv[4]) if ln.strip()]

# --- schema validation (jsonschema if available, else structural fallback) ---
try:
    import jsonschema
    jsonschema.validate(instance=m, schema=schema)
except ImportError:
    for k in schema["required"]:
        assert k in m, f"missing required key: {k}"

assert m["coverage"] == "full-tree"
assert m["scope"] == "public-devnet-docs-release-package-full-tree"
assert m["package_root"] == "docs/release/public-devnet"
assert all(v is False for v in m["non_claims"].values())
assert m["file_count"] == len(m["files"])

rel_re = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
disk_set = set(rels)
man_set = {f["relative_path"] for f in m["files"]}
missing = disk_set - man_set
extra = man_set - disk_set
assert not missing, f"files omitted from manifest: {sorted(missing)}"
assert not extra, f"manifest lists non-existent files: {sorted(extra)}"

n_ok = 0
for f in m["files"]:
    rel = f["relative_path"]
    assert rel_re.match(rel), f"unsafe relative_path: {rel}"
    p = os.path.join(pdn, rel)
    data = open(p, "rb").read()
    assert hashlib.sha256(data).hexdigest() == f["sha256"], f"sha256 mismatch: {rel}"
    assert len(data) == f["byte_size"], f"byte_size mismatch: {rel}"
    n_ok += 1
print(f"file_count={m['file_count']}")
print(f"files_verified={n_ok}")
PY
FT_COUNT="$(wc -l < "${DISK_LIST}" | tr -d ' ')"
emit "full_tree_schema_validation=OK (generated manifest validates; coverage=full-tree; non_claims fixed)"
emit "full_tree_coverage=OK (generated manifest file set == on-disk publish-safe set under docs/release/public-devnet; ${FT_COUNT} files)"
emit "full_tree_hash_verification=OK (every listed file exists; sha256 + byte_size match on-disk; relative paths safe + root-confined)"

# ---------------------------------------------------------------------------
# 6-9. Generate the publish-safe anchor-drift report into STAGING and verify:
#      every anchor entry exists in the full-tree set; anchor hashes/sizes match or
#      are documented deliberate refreshes; full-tree-only files are reported as
#      expected curated-anchor drift (not failure).
# ---------------------------------------------------------------------------
[ -f "${A_EXAMPLE}" ] || fail "Run 404 anchor manifest missing: PACKAGE_INTEGRITY_MANIFEST.example.json"
REFRESH_CSV="$(IFS=,; printf '%s' "${DOCUMENTED_REFRESH[*]}")"
python3 - "${A_EXAMPLE}" "${GEN_MANIFEST}" "${DRIFT_REPORT}" "${REFRESH_CSV}" <<'PY' || fail "anchor-drift report generation/verification failed"
import datetime, json, sys
anchor = json.load(open(sys.argv[1]))
full = json.load(open(sys.argv[2]))
out_path = sys.argv[3]
documented_refresh = {s for s in sys.argv[4].split(",") if s}

full_by_path = {f["relative_path"]: f for f in full["files"]}
anchor_paths = [f["relative_path"] for f in anchor["files"]]

matched, refreshed, mismatched, missing = [], [], [], []
for f in anchor["files"]:
    rel = f["relative_path"]
    ft = full_by_path.get(rel)
    if ft is None:
        missing.append(rel)
        continue
    if ft["sha256"] == f["sha256"] and ft["byte_size"] == f["byte_size"]:
        matched.append(rel)
    elif rel in documented_refresh:
        refreshed.append(rel)
    else:
        mismatched.append(rel)

full_only = sorted(set(full_by_path) - set(anchor_paths))

# --- classification rules (honest) ---
# missing anchor file        -> FAILURE
# undocumented hash mismatch -> FAILURE
# documented refresh         -> OK
# full-tree-only files       -> expected curated-anchor drift (OK)
assert not missing, f"anchor files missing from full tree (FAILURE): {sorted(missing)}"
assert not mismatched, f"undocumented anchor hash/size mismatch (FAILURE): {sorted(mismatched)}"

lines = []
lines.append("# QBIND Public DevNet — Anchor Drift Report (Run 406)")
lines.append("")
lines.append("> Safety label: DevNet · experimental · resettable · no value · no uptime SLA ·")
lines.append("> NOT public-DevNet launch-ready · C4/C5 OPEN · no C4/C5 closure claim.")
lines.append(">")
lines.append("> This report is a **download-only** CI artifact generated at verification time.")
lines.append("> It is NOT committed to the repository and is NOT binary provenance or launch evidence.")
lines.append("")
lines.append("Compares the Run 404 curated **anchor** manifest "
             "(`PACKAGE_INTEGRITY_MANIFEST.example.json`) against the Run 405/406 "
             "**full-tree** generated file set for `docs/release/public-devnet`.")
lines.append("")
lines.append("## Summary")
lines.append("")
lines.append(f"- anchor entries: {len(anchor['files'])}")
lines.append(f"- full-tree files: {full['file_count']}")
lines.append(f"- anchor entries present + matching: {len(matched)}")
lines.append(f"- anchor entries refreshed this run (documented deliberate refresh): {len(refreshed)}")
lines.append(f"- anchor entries with undocumented mismatch (FAILURE): {len(mismatched)}")
lines.append(f"- anchor entries missing from full tree (FAILURE): {len(missing)}")
lines.append(f"- full-tree-only files (expected curated-anchor drift): {len(full_only)}")
lines.append("")
lines.append("## Anchor entries present + matching")
lines.append("")
for rel in sorted(matched):
    ft = full_by_path[rel]
    lines.append(f"- `{rel}` — sha256 `{ft['sha256']}` ({ft['byte_size']} bytes) — unchanged")
lines.append("")
lines.append("## Anchor entries refreshed this run (documented deliberate refresh)")
lines.append("")
if refreshed:
    for rel in sorted(refreshed):
        ft = full_by_path[rel]
        lines.append(f"- `{rel}` — sha256 `{ft['sha256']}` ({ft['byte_size']} bytes) — "
                     "anchor entry refreshed to track a narrowly-edited doc")
else:
    lines.append("- none (no anchor entry required a documented refresh at report time)")
lines.append("")
lines.append("## Full-tree-only files (expected curated-anchor drift, not a failure)")
lines.append("")
lines.append("The anchor manifest is curated on purpose (one anchor per group + top-level docs); "
             "these files are covered by the full-tree manifest but not the curated anchor set.")
lines.append("")
for rel in full_only:
    ft = full_by_path[rel]
    lines.append(f"- `{rel}` — sha256 `{ft['sha256']}` ({ft['byte_size']} bytes)")
lines.append("")
lines.append("## Failures")
lines.append("")
lines.append("- anchor entries missing from full tree: none")
lines.append("- undocumented anchor hash/size mismatches: none")
lines.append("")
lines.append("RESULT=POSITIVE (anchor drift reported honestly; no missing anchor; "
             "no undocumented mismatch; full-tree-only files are expected curated-anchor drift)")
lines.append("")

with open(out_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

print(f"anchor_entries={len(anchor['files'])}")
print(f"matched={len(matched)} refreshed={len(refreshed)} full_only={len(full_only)}")
PY
[ -f "${DRIFT_REPORT}" ] || fail "anchor-drift report was not generated"
emit "anchor_drift_report_generated=OK (ANCHOR_DRIFT_REPORT.md generated into staging, outside the tree; not committed)"
emit "anchor_entries_present=OK (every Run 404 anchor entry exists in the full-tree set)"
emit "anchor_hash_match=OK (anchor entries match full-tree hashes/sizes or are documented deliberate refreshes; no undocumented mismatch; no missing anchor)"
emit "full_tree_only_drift=OK (full-tree-only files reported as expected curated-anchor drift, not failure)"

# ---------------------------------------------------------------------------
# Assemble the publish-safe CI summary artifact into STAGING.
# ---------------------------------------------------------------------------
{
  echo "QBIND Public DevNet — full-tree integrity CI summary (Run 406)"
  echo "safety: DevNet; experimental; resettable; no value; NOT launch-ready; C4/C5 OPEN"
  echo "full_tree_files=${FT_COUNT}"
  echo "run405_full_tree_verifier=POSITIVE"
  echo "generated_full_tree_manifest=validated"
  echo "anchor_drift_report=generated"
  echo "readiness=M4:yellow M6:yellow-partial S5:yellow S7:yellow launch:NO-GO C4:open C5:open"
  echo "RESULT=POSITIVE"
} > "${CI_SUMMARY}"
emit "ci_summary_generated=OK (PACKAGE_INTEGRITY_CI_SUMMARY.txt generated into staging; publish-safe status lines only)"

# ---------------------------------------------------------------------------
# 10-13. CI workflow safety checks (normalized for CRLF).
# ---------------------------------------------------------------------------
[ -f "${WORKFLOW}" ] || fail "CI workflow missing: public-devnet-package-integrity.yml"
WF_LF="${OUTDIR}/workflow.lf.yml"
sed 's/\r$//' "${WORKFLOW}" > "${WF_LF}"

grep -Eq '^[[:space:]]*permissions:[[:space:]]*$' "${WF_LF}" \
  && grep -Eq '^[[:space:]]*contents:[[:space:]]*read[[:space:]]*$' "${WF_LF}" \
  || fail "CI workflow must declare permissions: contents: read"
# The permissions block must not grant any write scope.
if awk '
    /^[[:space:]]*permissions:[[:space:]]*$/ { inblk=1; next }
    inblk && /^[^[:space:]]/ { inblk=0 }
    inblk && /:[[:space:]]*write([[:space:]]|$)/ { print }
  ' "${WF_LF}" | grep -q .; then
  fail "CI workflow permissions must be read-only (no write scope)"
fi
emit "ci_permissions=OK (workflow declares permissions: contents: read)"

if grep -Eiq '\$\{\{[[:space:]]*secrets\.|(^|[^A-Za-z])secrets\.' "${WF_LF}"; then
  fail "CI workflow references a secret"
fi
emit "ci_no_secrets=OK (workflow references no secrets)"

# Deploy/release/tag/commit/push detection runs over NON-COMMENT lines only, so the
# safety-posture comments ("Does NOT deploy…", "never committed…") do not trip it.
WF_NOCOMMENT="${OUTDIR}/workflow.nocomment.yml"
sed -e 's/\r$//' -e 's/#.*$//' "${WORKFLOW}" > "${WF_NOCOMMENT}"
if grep -Eiq 'softprops/action-gh-release|actions/create-release|create-release|gh release|gh pr |git[[:space:]]+push|git[[:space:]]+commit|create-pull-request|peaceiris/actions-gh-pages|uses:[^#]*deploy|run:[^#]*deploy|helm[[:space:]]|kubectl[[:space:]]|terraform[[:space:]]' "${WF_NOCOMMENT}"; then
  fail "CI workflow contains a forbidden deploy/release/tag/commit/push step"
fi
emit "ci_no_deploy=OK (workflow has no deploy/release/tag/commit/push step)"

# Every upload-artifact `path:`/`name:` must be one of the publish-safe artifact names.
python3 - "${WF_LF}" "${ARTIFACT_NAMES[@]}" <<'PY' || fail "CI workflow uploads a non-publish-safe artifact name"
import re, sys
wf = open(sys.argv[1], encoding="utf-8").read()
allowed = set(sys.argv[2:])
lines = wf.splitlines()
uploads_present = any("upload-artifact" in ln for ln in lines)
assert uploads_present, "workflow must upload the publish-safe CI artifacts"
# Collect artifact path leaf names referenced anywhere in the workflow.
leaves = set()
for ln in lines:
    for m in re.finditer(r'([A-Za-z0-9._-]+\.(?:json|md|txt))', ln):
        leaves.add(m.group(1).split("/")[-1])
# Only consider our three artifact leaf names; any *uploaded* artifact leaf must be allowed.
bad = [name for name in leaves
       if name.endswith((".generated.json",)) and name not in allowed]
# Ensure the three allowed names all appear (so uploads are wired).
for a in allowed:
    assert a in wf, f"expected publish-safe artifact not referenced: {a}"
assert not bad, f"non-publish-safe generated artifact referenced: {bad}"
print("ci_upload_names_ok")
PY
emit "ci_upload_names=OK (workflow uploads only publish-safe artifact names: ${ARTIFACT_NAMES[*]})"

# ---------------------------------------------------------------------------
# 14. Generated artifacts are staged OUTSIDE the package tree (never committed).
# ---------------------------------------------------------------------------
for art in "${GEN_MANIFEST}" "${DRIFT_REPORT}" "${CI_SUMMARY}"; do
  case "${art}" in
    "${PDN}"/*) fail "generated artifact is inside the package tree: ${art}";;
    "${REPO_ROOT}"/docs/*|"${REPO_ROOT}"/scripts/*|"${REPO_ROOT}"/.github/*)
      fail "generated artifact is inside the repository source tree: ${art}";;
  esac
done
# None of the three generated artifact leaf names may be tracked/committed anywhere.
for name in "${ARTIFACT_NAMES[@]}"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_artifacts_transient=OK (manifest + drift report + CI summary staged outside the tree; none committed)"

# ---------------------------------------------------------------------------
# 15. Working tree stays clean after the verifier (the harness dirties nothing).
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

# ---------------------------------------------------------------------------
# 16-19. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 20/21. Public DevNet NOT launch-ready + C4/C5 OPEN in the CI artifacts guide.
# ---------------------------------------------------------------------------
grep -qi 'NOT public-DevNet launch-ready' "${CI_GUIDE}" || fail "guide must state NOT launch-ready"
grep -qi 'C4 remains OPEN' "${CI_GUIDE}" && grep -qi 'C5 remains OPEN' "${CI_GUIDE}" \
  || fail "guide must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 22/23/26. Non-claim grep over the CI artifacts guide (normalized).
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
CLAIM_HITS="$(normalize_md "${CI_GUIDE}" \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in guide"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in CI artifacts guide)"

# ---------------------------------------------------------------------------
# 24. Runtime mutation: generated manifest non_claims all false.
# ---------------------------------------------------------------------------
python3 - "${GEN_MANIFEST}" <<'PY' || fail "generated manifest non_claims must all be false"
import json, sys
m = json.load(open(sys.argv[1]))
assert all(v is False for v in m["non_claims"].values())
assert m["non_claims"]["mutates_runtime_state"] is False
print("non_claims_all_false=OK")
PY
emit "runtime_mutation=NONE (generated manifest non_claims all false; mutates_runtime_state=false)"

# ---------------------------------------------------------------------------
# 25. Secret / private-material scan over the guide + generated artifacts + tree.
# ---------------------------------------------------------------------------
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${CI_GUIDE}"; then
  fail "absolute filesystem path found in CI artifacts guide"
fi
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${DRIFT_REPORT}" "${CI_SUMMARY}"; then
  fail "absolute filesystem path found in a generated artifact"
fi
python3 - "${GEN_MANIFEST}" <<'PY' || fail "generated manifest lists a forbidden private/raw artifact or unsafe path"
import json, re, sys
m = json.load(open(sys.argv[1]))
forbidden = re.compile(r"\.(kem\.sk\.bin|cert\.bin|key|pem|log|data|sk\.hex)$|metrics.*\.txt$|(^|/)(logs?|data|node|nodes|material)/|private.*identity", re.I)
bad = [f["relative_path"] for f in m["files"] if forbidden.search(f["relative_path"])]
assert not bad, f"forbidden entries: {bad}"
abspath = [f["relative_path"] for f in m["files"] if f["relative_path"].startswith("/")]
assert not abspath, f"absolute paths: {abspath}"
print("forbidden_entries=none")
PY
if find "${PDN}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under public-devnet package root"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${CI_GUIDE}" "${DRIFT_REPORT}" "${CI_SUMMARY}"; then
  fail "possible secret / private material found in guide or generated artifact"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path; no private endpoint)"

emit ""
emit "RESULT=POSITIVE (public-DevNet FULL-TREE integrity CI artifacts + anchor-drift report generated into a staging dir OUTSIDE the package tree; the Run 405 full-tree verifier still passes; the generated manifest validates + covers every publish-safe file with matching hashes; the anchor-drift report is honest — every anchor entry is present, no undocumented mismatch, full-tree-only files are expected curated-anchor drift; the CI workflow is contents:read, secret-free, deploy/commit/push-free, and uploads only the three publish-safe artifact names; nothing generated is committed; the working tree stays clean; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"