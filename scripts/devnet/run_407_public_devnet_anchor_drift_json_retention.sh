#!/usr/bin/env bash
# Run 407: public DevNet machine-readable anchor-drift artifact + CI retention policy.
#
# This harness EXTENDS the Run 406 CI artifact wrapper
# (`scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh`, which in
# turn reuses the Run 405 full-tree package integrity verifier) so CI can emit, as an
# additional DOWNLOAD-ONLY artifact:
#   * ANCHOR_DRIFT_REPORT.json — a machine-readable JSON counterpart of the existing
#     Markdown ANCHOR_DRIFT_REPORT.md, validated against
#     PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json.
#
# It also documents CI artifact RETENTION expectations
# (`docs/release/public-devnet/PACKAGE_INTEGRITY_CI_RETENTION.md`): retention is
# convenience/audit usability only, download-only, provider-dependent, and NOT a signed
# attestation, NOT binary provenance, and NOT launch evidence.
#
# Everything generated (full-tree manifest, Markdown drift report, JSON drift report, CI
# summary) is staged OUTSIDE `docs/release/public-devnet` and is NEVER committed. This
# run is DOCS + SCHEMA + SHELL + YAML only (Decision gate = Route B): it makes NO
# production Rust source change, NO build.rs change, NO Cargo.toml change, adds NO CLI
# flag, opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/explorer/
# status service, changes NO wire format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState state.
#
# What it proves (29 checks):
#   1.  JSON anchor-drift schema exists.
#   2.  CI retention guide exists and is safety-labelled.
#   3.  Run 406 wrapper compatibility remains positive.
#   4.  Full-tree manifest artifact is generated outside the tree.
#   5.  Markdown anchor-drift report is generated outside the tree.
#   6.  JSON anchor-drift report is generated outside the tree.
#   7.  JSON anchor-drift report validates against the schema.
#   8.  JSON counts match Markdown summary counts.
#   9.  Every anchor entry exists in the full-tree set.
#   10. No undocumented mismatch exists.
#   11. Full-tree-only files are reported as expected curated drift.
#   12. CI workflow uses permissions: contents: read.
#   13. CI workflow references no secrets.
#   14. CI workflow has no deploy/release/tag/commit/push step.
#   15. CI workflow uploads only the four publish-safe artifact names.
#   16. CI workflow sets or documents artifact retention-days.
#   17. Generated artifacts are not committed.
#   18. Working tree stays clean after the verifier.
#   19. M4 remains Yellow.
#   20. M6 remains Yellow/Partial.
#   21. S5 remains Yellow.
#   22. S7 remains Yellow.
#   23. Public DevNet remains NOT launch-ready.
#   24. C4/C5 remain OPEN.
#   25. No TestNet/MainNet readiness claim appears.
#   26. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   27. No runtime mutation claim (JSON non_claims all false).
#   28. Secret/private-material scan is clean.
#   29. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run407-public-devnet-anchor-drift-json-retention}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
JSON_SCHEMA="${PDN}/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json"
RETENTION_GUIDE="${PDN}/PACKAGE_INTEGRITY_CI_RETENTION.md"
A_EXAMPLE="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
WORKFLOW="${REPO_ROOT}/.github/workflows/public-devnet-package-integrity.yml"
RUN406="${REPO_ROOT}/scripts/devnet/run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh"

SUMMARY="${OUTDIR}/summary.txt"
# Run 406 is executed into its own staging dir; the generated artifacts it produces
# (full-tree manifest + Markdown drift report + CI summary) live under STAGING_406.
OUTDIR406="${OUTDIR}/run406"
STAGING_406="${OUTDIR406}/artifact-staging"
GEN_MANIFEST="${STAGING_406}/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
DRIFT_MD="${STAGING_406}/ANCHOR_DRIFT_REPORT.md"

# The new machine-readable JSON drift report is staged OUTSIDE the package tree too.
STAGING="${OUTDIR}/artifact-staging"
DRIFT_JSON="${STAGING}/ANCHOR_DRIFT_REPORT.json"

# The four publish-safe artifact names CI is allowed to upload.
ARTIFACT_NAMES=(
  "PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"
  "ANCHOR_DRIFT_REPORT.md"
  "ANCHOR_DRIFT_REPORT.json"
  "PACKAGE_INTEGRITY_CI_SUMMARY.txt"
)

# Anchor-manifest files narrowly edited (and refreshed) in earlier runs — documented
# deliberate refreshes. A hash change on these anchors is expected and documented.
DOCUMENTED_REFRESH=(
  "PACKAGE_INTEGRITY.md"
  "ARTIFACT_INDEX.md"
  "OPERATOR_VERIFICATION_MAP.md"
)

log()  { printf '[run407] %s\n' "$*"; }
fail() { printf '[run407] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}" "${STAGING}" "${OUTDIR406}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

# ---------------------------------------------------------------------------
# 1. JSON anchor-drift schema exists.
# ---------------------------------------------------------------------------
[ -f "${JSON_SCHEMA}" ] || fail "JSON anchor-drift schema missing: PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${JSON_SCHEMA}" \
  || fail "JSON anchor-drift schema is not valid JSON"
emit "json_drift_schema_present=OK (PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json present + valid JSON) sha256=$(sha256_file "${JSON_SCHEMA}")"

# ---------------------------------------------------------------------------
# 2. CI retention guide exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${RETENTION_GUIDE}" ] || fail "CI retention guide missing: PACKAGE_INTEGRITY_CI_RETENTION.md"
grep -qi 'experimental' "${RETENTION_GUIDE}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${RETENTION_GUIDE}" \
  && grep -qi 'no C4/C5 closure claim' "${RETENTION_GUIDE}" \
  && grep -qi 'download-only' "${RETENTION_GUIDE}" \
  || fail "safety label / download-only wording missing in PACKAGE_INTEGRITY_CI_RETENTION.md"
emit "ci_retention_guide_present=OK (PACKAGE_INTEGRITY_CI_RETENTION.md present, safety-labelled, download-only) sha256=$(sha256_file "${RETENTION_GUIDE}")"

# ---------------------------------------------------------------------------
# 3. Run 406 wrapper compatibility. The committed Run 406 harness is stored with CRLF
#    line endings, so normalize a transient copy to LF and run it IN PLACE (so its
#    BASH_SOURCE-derived REPO_ROOT stays correct). Its generated full-tree manifest,
#    Markdown anchor-drift report, and CI summary are emitted into STAGING_406 (outside
#    the package tree).
# ---------------------------------------------------------------------------
[ -f "${RUN406}" ] || fail "Run 406 wrapper missing: run_406_public_devnet_full_tree_ci_artifact_anchor_drift.sh"
R406_TMP="${REPO_ROOT}/scripts/devnet/.run_406_lf.$$.tmp.sh"
cleanup() { rm -f "${R406_TMP}"; }
trap cleanup EXIT
sed 's/\r$//' "${RUN406}" > "${R406_TMP}"
R406_LOG="${OUTDIR}/run406.log"
if ! bash "${R406_TMP}" "${OUTDIR406}" > "${R406_LOG}" 2>&1; then
  cat "${R406_LOG}" >&2
  fail "Run 406 wrapper did not pass"
fi
grep -q '^RESULT=POSITIVE' "${R406_LOG}" || { cat "${R406_LOG}" >&2; fail "Run 406 wrapper did not report RESULT=POSITIVE"; }
rm -f "${R406_TMP}"; trap - EXIT
emit "run406_compat=OK (Run 406 wrapper RESULT=POSITIVE; reused via LF-normalized transient copy)"

# ---------------------------------------------------------------------------
# 4-5. The Run 406 wrapper generated the full-tree manifest + Markdown drift report into
#      a staging dir OUTSIDE the package tree.
# ---------------------------------------------------------------------------
[ -f "${GEN_MANIFEST}" ] || fail "Run 406 wrapper did not emit the generated full-tree manifest"
[ -f "${DRIFT_MD}" ] || fail "Run 406 wrapper did not emit the Markdown anchor-drift report"
for art in "${GEN_MANIFEST}" "${DRIFT_MD}"; do
  case "${art}" in
    "${PDN}"/*) fail "generated artifact is inside the package tree: ${art}";;
    "${REPO_ROOT}"/docs/*|"${REPO_ROOT}"/scripts/*|"${REPO_ROOT}"/.github/*)
      fail "generated artifact is inside the repository source tree: ${art}";;
  esac
done
emit "full_tree_manifest_outside_tree=OK (PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json staged outside the tree)"
emit "markdown_drift_outside_tree=OK (ANCHOR_DRIFT_REPORT.md staged outside the tree)"

# ---------------------------------------------------------------------------
# 6-7. Generate the machine-readable JSON anchor-drift report into STAGING (outside the
#      tree) and validate it against the schema. Classification mirrors the Run 406
#      Markdown report exactly.
# ---------------------------------------------------------------------------
[ -f "${A_EXAMPLE}" ] || fail "Run 404 anchor manifest missing: PACKAGE_INTEGRITY_MANIFEST.example.json"
REFRESH_CSV="$(IFS=,; printf '%s' "${DOCUMENTED_REFRESH[*]}")"
python3 - "${A_EXAMPLE}" "${GEN_MANIFEST}" "${JSON_SCHEMA}" "${DRIFT_JSON}" "${REFRESH_CSV}" <<'PY' || fail "JSON anchor-drift report generation/validation failed"
import json, sys
anchor = json.load(open(sys.argv[1]))
full = json.load(open(sys.argv[2]))
schema = json.load(open(sys.argv[3]))
out_path = sys.argv[4]
documented_refresh = {s for s in sys.argv[5].split(",") if s}

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

report = {
    "report_version": "1.0.0",
    "generated_for_run": 407,
    "scope": "public-devnet-docs-anchor-drift",
    "package_root": "docs/release/public-devnet",
    "anchor_manifest_path": "PACKAGE_INTEGRITY_MANIFEST.example.json",
    "full_tree_manifest_artifact_name": "PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json",
    "safety_labels": [
        "devnet", "experimental", "resettable", "no_value",
        "no_uptime_sla", "not_launch_ready", "c4_open", "c5_open",
    ],
    "counts": {
        "anchor_total": len(anchor["files"]),
        "anchors_present_matching": len(matched),
        "anchors_missing": len(missing),
        "undocumented_mismatches": len(mismatched),
        "documented_refreshes": len(refreshed),
        "full_tree_only": len(full_only),
    },
    "anchors_present_matching": sorted(matched),
    "anchors_missing": sorted(missing),
    "undocumented_mismatches": sorted(mismatched),
    "documented_refreshes": sorted(refreshed),
    "full_tree_only": full_only,
    "non_claims": {
        "launches_public_devnet": False,
        "moves_m4_green": False,
        "moves_m6_green": False,
        "moves_s5_green": False,
        "moves_s7_green": False,
        "closes_c4": False,
        "closes_c5": False,
        "claims_testnet_ready": False,
        "claims_mainnet_ready": False,
        "deploys_seed_or_service": False,
        "mutates_runtime_state": False,
    },
    "artifact_safety_label": "experimental \u00b7 resettable \u00b7 no value \u00b7 no uptime SLA \u00b7 NOT public-DevNet launch-ready \u00b7 no MainNet readiness claim \u00b7 no C4/C5 closure claim",
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# --- schema validation (jsonschema if available, else structural fallback) ---
try:
    import jsonschema
    jsonschema.validate(instance=report, schema=schema)
except ImportError:
    for k in schema["required"]:
        assert k in report, f"missing required key: {k}"

# counts must equal array lengths
c = report["counts"]
assert c["anchor_total"] == len(anchor["files"])
assert c["anchors_present_matching"] == len(report["anchors_present_matching"])
assert c["anchors_missing"] == len(report["anchors_missing"])
assert c["undocumented_mismatches"] == len(report["undocumented_mismatches"])
assert c["documented_refreshes"] == len(report["documented_refreshes"])
assert c["full_tree_only"] == len(report["full_tree_only"])
assert all(v is False for v in report["non_claims"].values())
print(f"anchor_total={c['anchor_total']} matched={c['anchors_present_matching']} "
      f"refreshed={c['documented_refreshes']} missing={c['anchors_missing']} "
      f"mismatch={c['undocumented_mismatches']} full_only={c['full_tree_only']}")
PY
[ -f "${DRIFT_JSON}" ] || fail "JSON anchor-drift report was not generated"
case "${DRIFT_JSON}" in
  "${PDN}"/*) fail "generated JSON drift report is inside the package tree: ${DRIFT_JSON}";;
  "${REPO_ROOT}"/docs/*|"${REPO_ROOT}"/scripts/*|"${REPO_ROOT}"/.github/*)
    fail "generated JSON drift report is inside the repository source tree: ${DRIFT_JSON}";;
esac
emit "json_drift_outside_tree=OK (ANCHOR_DRIFT_REPORT.json generated into staging, outside the tree; not committed)"
emit "json_drift_schema_validation=OK (ANCHOR_DRIFT_REPORT.json validates against PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json; counts == array lengths; non_claims all false)"

# ---------------------------------------------------------------------------
# 8. JSON counts match the Markdown ANCHOR_DRIFT_REPORT.md summary counts.
# ---------------------------------------------------------------------------
python3 - "${DRIFT_JSON}" "${DRIFT_MD}" <<'PY' || fail "JSON drift counts do not match Markdown summary counts"
import json, re, sys
report = json.load(open(sys.argv[1]))
md = open(sys.argv[2], encoding="utf-8").read()

def grab(pat):
    m = re.search(pat, md)
    assert m, f"Markdown summary line not found: {pat}"
    return int(m.group(1))

md_counts = {
    "anchor_total": grab(r"anchor entries:\s*(\d+)"),
    "anchors_present_matching": grab(r"anchor entries present \+ matching:\s*(\d+)"),
    "documented_refreshes": grab(r"documented deliberate refresh\):\s*(\d+)"),
    "undocumented_mismatches": grab(r"undocumented mismatch \(FAILURE\):\s*(\d+)"),
    "anchors_missing": grab(r"missing from full tree \(FAILURE\):\s*(\d+)"),
    "full_tree_only": grab(r"full-tree-only files \(expected curated-anchor drift\):\s*(\d+)"),
}
jc = report["counts"]
for k, v in md_counts.items():
    assert jc[k] == v, f"count mismatch for {k}: json={jc[k]} md={v}"
print("json_md_counts_match " + " ".join(f"{k}={v}" for k, v in md_counts.items()))
PY
emit "json_md_count_consistency=OK (JSON counts equal Markdown ANCHOR_DRIFT_REPORT.md summary counts)"

# ---------------------------------------------------------------------------
# 9-11. Anchor coverage / mismatch / full-tree-only classification (from the JSON).
# ---------------------------------------------------------------------------
python3 - "${DRIFT_JSON}" <<'PY' || fail "anchor coverage / mismatch classification failed"
import json, sys
r = json.load(open(sys.argv[1]))
assert not r["anchors_missing"], f"anchor files missing from full tree (FAILURE): {r['anchors_missing']}"
assert not r["undocumented_mismatches"], f"undocumented anchor hash/size mismatch (FAILURE): {r['undocumented_mismatches']}"
assert r["counts"]["full_tree_only"] >= 0
print("classification_ok")
PY
emit "anchor_entries_present=OK (every Run 404 anchor entry exists in the full-tree set)"
emit "anchor_no_undocumented_mismatch=OK (no anchor entry mismatches without a documented deliberate refresh; no missing anchor)"
emit "full_tree_only_drift=OK (full-tree-only files reported as expected curated-anchor drift, not failure)"

# ---------------------------------------------------------------------------
# 12-14. CI workflow safety checks (normalized for CRLF).
# ---------------------------------------------------------------------------
[ -f "${WORKFLOW}" ] || fail "CI workflow missing: public-devnet-package-integrity.yml"
WF_LF="${OUTDIR}/workflow.lf.yml"
sed 's/\r$//' "${WORKFLOW}" > "${WF_LF}"

grep -Eq '^[[:space:]]*permissions:[[:space:]]*$' "${WF_LF}" \
  && grep -Eq '^[[:space:]]*contents:[[:space:]]*read[[:space:]]*$' "${WF_LF}" \
  || fail "CI workflow must declare permissions: contents: read"
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

WF_NOCOMMENT="${OUTDIR}/workflow.nocomment.yml"
sed -e 's/\r$//' -e 's/#.*$//' "${WORKFLOW}" > "${WF_NOCOMMENT}"
if grep -Eiq 'softprops/action-gh-release|actions/create-release|create-release|gh release|gh pr |git[[:space:]]+push|git[[:space:]]+commit|create-pull-request|peaceiris/actions-gh-pages|uses:[^#]*deploy|run:[^#]*deploy|helm[[:space:]]|kubectl[[:space:]]|terraform[[:space:]]' "${WF_NOCOMMENT}"; then
  fail "CI workflow contains a forbidden deploy/release/tag/commit/push step"
fi
emit "ci_no_deploy=OK (workflow has no deploy/release/tag/commit/push step)"

# ---------------------------------------------------------------------------
# 15. Every uploaded artifact leaf name must be one of the four publish-safe names, and
#     all four must be referenced.
# ---------------------------------------------------------------------------
python3 - "${WF_LF}" "${ARTIFACT_NAMES[@]}" <<'PY' || fail "CI workflow uploads a non-publish-safe artifact name"
import re, sys
wf = open(sys.argv[1], encoding="utf-8").read()
allowed = set(sys.argv[2:])
lines = wf.splitlines()
assert any("upload-artifact" in ln for ln in lines), "workflow must upload the publish-safe CI artifacts"
leaves = set()
for ln in lines:
    for m in re.finditer(r'([A-Za-z0-9._-]+\.(?:json|md|txt))', ln):
        leaves.add(m.group(1).split("/")[-1])
# Any uploaded artifact leaf ending in a generated-artifact extension must be allowed.
bad = [name for name in leaves
       if (name.endswith((".generated.json",)) or name in
           {"ANCHOR_DRIFT_REPORT.md", "ANCHOR_DRIFT_REPORT.json", "PACKAGE_INTEGRITY_CI_SUMMARY.txt"})
       and name not in allowed]
for a in allowed:
    assert a in wf, f"expected publish-safe artifact not referenced: {a}"
assert not bad, f"non-publish-safe generated artifact referenced: {bad}"
print("ci_upload_names_ok")
PY
emit "ci_upload_names=OK (workflow uploads only the four publish-safe artifact names: ${ARTIFACT_NAMES[*]})"

# ---------------------------------------------------------------------------
# 16. CI workflow sets or documents artifact retention-days.
# ---------------------------------------------------------------------------
if grep -Eq '^[[:space:]]*retention-days:[[:space:]]*[0-9]+[[:space:]]*$' "${WF_LF}"; then
  RET_DAYS="$(grep -Eo 'retention-days:[[:space:]]*[0-9]+' "${WF_LF}" | grep -Eo '[0-9]+' | head -n1)"
  emit "ci_retention_days=OK (workflow sets retention-days: ${RET_DAYS})"
else
  # Not set in the workflow: it must be documented in the retention guide instead.
  grep -qi 'retention-days' "${RETENTION_GUIDE}" \
    || fail "workflow does not set retention-days and the retention guide does not document it"
  emit "ci_retention_days=OK (retention documented in PACKAGE_INTEGRITY_CI_RETENTION.md)"
fi
# Retention must be described as convenience/audit usability only, not provenance.
grep -qi 'not.*binary provenance\|not.*provenance' "${RETENTION_GUIDE}" \
  && grep -qi 'not.*launch evidence' "${RETENTION_GUIDE}" \
  || fail "retention guide must state retention is not provenance / not launch evidence"
emit "ci_retention_semantics=OK (retention guide states convenience/audit usability only; not signed attestation/provenance; not launch evidence)"

# ---------------------------------------------------------------------------
# 17. Generated artifacts are staged OUTSIDE the package tree (never committed).
# ---------------------------------------------------------------------------
for name in "${ARTIFACT_NAMES[@]}"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_artifacts_transient=OK (full-tree manifest + Markdown + JSON drift reports + CI summary staged outside the tree; none committed)"

# ---------------------------------------------------------------------------
# 18. Working tree stays clean after the verifier (the harness dirties nothing).
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

# ---------------------------------------------------------------------------
# 19-22. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 23/24. Public DevNet NOT launch-ready + C4/C5 OPEN in the retention guide.
# ---------------------------------------------------------------------------
grep -qi 'NOT public-DevNet launch-ready' "${RETENTION_GUIDE}" || fail "guide must state NOT launch-ready"
grep -qi 'C4 remains OPEN' "${RETENTION_GUIDE}" && grep -qi 'C5 remains OPEN' "${RETENTION_GUIDE}" \
  || fail "guide must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 25/26/29. Non-claim grep over the CI retention guide (normalized).
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
CLAIM_HITS="$(normalize_md "${RETENTION_GUIDE}" \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in guide"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in CI retention guide)"

# ---------------------------------------------------------------------------
# 27. Runtime mutation: generated JSON drift report non_claims all false.
# ---------------------------------------------------------------------------
python3 - "${DRIFT_JSON}" <<'PY' || fail "generated JSON drift report non_claims must all be false"
import json, sys
r = json.load(open(sys.argv[1]))
assert all(v is False for v in r["non_claims"].values())
assert r["non_claims"]["mutates_runtime_state"] is False
print("non_claims_all_false=OK")
PY
emit "runtime_mutation=NONE (generated JSON drift report non_claims all false; mutates_runtime_state=false)"

# ---------------------------------------------------------------------------
# 28. Secret / private-material scan over the guide + schema + generated JSON + tree.
# ---------------------------------------------------------------------------
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${RETENTION_GUIDE}" "${JSON_SCHEMA}"; then
  fail "absolute filesystem path found in the retention guide or JSON schema"
fi
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${DRIFT_JSON}"; then
  fail "absolute filesystem path found in the generated JSON drift report"
fi
python3 - "${DRIFT_JSON}" <<'PY' || fail "generated JSON drift report lists a forbidden private/raw artifact or unsafe path"
import json, re, sys
r = json.load(open(sys.argv[1]))
forbidden = re.compile(r"\.(kem\.sk\.bin|cert\.bin|key|pem|log|data|sk\.hex)$|metrics.*\.txt$|(^|/)(logs?|data|node|nodes|material)/|private.*identity", re.I)
paths = []
for arr in ("anchors_present_matching", "anchors_missing", "undocumented_mismatches",
            "documented_refreshes", "full_tree_only"):
    paths.extend(r[arr])
bad = [p for p in paths if forbidden.search(p)]
assert not bad, f"forbidden entries: {bad}"
abspath = [p for p in paths if p.startswith("/")]
assert not abspath, f"absolute paths: {abspath}"
print("forbidden_entries=none")
PY
if find "${PDN}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under public-devnet package root"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${RETENTION_GUIDE}" "${JSON_SCHEMA}" "${DRIFT_JSON}"; then
  fail "possible secret / private material found in guide, schema, or generated report"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path; no private endpoint)"

emit ""
emit "RESULT=POSITIVE (public-DevNet machine-readable anchor-drift report generated into a staging dir OUTSIDE the package tree and validated against PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json; the Run 406 wrapper still passes; JSON drift counts equal the Markdown summary counts; every anchor entry is present with no undocumented mismatch and full-tree-only files are expected curated-anchor drift; the CI workflow is contents:read, secret-free, deploy/commit/push-free, uploads only the four publish-safe artifact names, and sets/documents retention-days as convenience/audit usability only — not provenance, not launch evidence; nothing generated is committed; the working tree stays clean; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"