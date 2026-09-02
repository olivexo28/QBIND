#!/usr/bin/env bash
# Run 408: public DevNet retained anchor-drift artifact historical comparator.
#
# This harness publishes and verifies a LOCAL, NON-MUTATING historical comparator for
# retained Run 407-style `ANCHOR_DRIFT_REPORT.json` artifacts. It lets an operator/reviewer
# compare TWO downloaded JSON drift reports (a base and a candidate) and produce a
# publish-safe TRANSIENT diff summary (`PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json`),
# validated against `PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json`, WITHOUT fetching CI
# artifacts automatically, WITHOUT any token/secret, WITHOUT committing generated output,
# and WITHOUT changing any readiness status.
#
# It is DOCS + SCHEMA + SHELL only (Decision gate = Route B): NO production Rust source
# change, NO build.rs change, NO Cargo.toml change, NO CLI flag, NO externally reachable
# port, NO seed/bootnode/faucet/RPC/explorer/status service, NO wire-format change, NO
# weakened peer admission, and NO trust/validator/epoch/sequence/marker/LivePqcTrustState
# mutation.
#
# What it proves (25 checks):
#   1.  Drift history guide exists and is safety-labelled.
#   2.  Drift history diff schema exists and is valid JSON.
#   3.  Run 407 wrapper compatibility remains positive.
#   4.  Two transient Run 407-style JSON reports validate against the Run 407 schema.
#   5.  Comparator emits diff JSON outside the repo tree.
#   6.  Diff JSON validates against the Run 408 schema.
#   7.  Safe relative-path rules hold for all diff arrays.
#   8.  Positive no-new-failures case passes.
#   9.  New missing-anchor fixture fails closed.
#   10. New undocumented-mismatch fixture fails closed.
#   11. Full-tree-only added/removed drift is reported, not treated as failure by itself.
#   12. Generated artifacts are not committed.
#   13. Working tree remains clean after the run.
#   14. No automatic CI/API fetch and no token/secret requirement.
#   15. M4 remains Yellow.
#   16. M6 remains Yellow/Partial.
#   17. S5 remains Yellow.
#   18. S7 remains Yellow.
#   19. Public DevNet remains NOT launch-ready.
#   20. C4/C5 remain OPEN.
#   21. No TestNet/MainNet readiness claim appears.
#   22. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   23. No runtime mutation claim appears.
#   24. Secret/private-material scan is clean.
#   25. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run408-public-devnet-retained-drift-history-comparator}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
INPUT_SCHEMA="${PDN}/PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json"
DIFF_SCHEMA="${PDN}/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json"
GUIDE="${PDN}/PACKAGE_INTEGRITY_DRIFT_HISTORY.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
RUN407="${REPO_ROOT}/scripts/devnet/run_407_public_devnet_anchor_drift_json_retention.sh"

SUMMARY="${OUTDIR}/summary.txt"
# Transient staging dirs OUTSIDE the package tree.
STAGING="${OUTDIR}/artifact-staging"
FIXTURES="${STAGING}/fixtures"
DIFF_OUT="${STAGING}/PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json"
COMPARATOR_PY="${OUTDIR}/comparator.py"
OUTDIR407="${OUTDIR}/run407"

log()  { printf '[run408] %s\n' "$*"; }
fail() { printf '[run408] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}" "${STAGING}" "${FIXTURES}" "${OUTDIR407}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# Snapshot the working tree so we can prove the harness itself dirties nothing.
GIT_BEFORE="$(git -C "${REPO_ROOT}" status --porcelain)"

# ---------------------------------------------------------------------------
# 1. Drift history guide exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${GUIDE}" ] || fail "drift history guide missing: PACKAGE_INTEGRITY_DRIFT_HISTORY.md"
grep -qi 'experimental' "${GUIDE}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${GUIDE}" \
  && grep -qi 'no C4/C5 closure claim' "${GUIDE}" \
  && grep -qi 'may expire' "${GUIDE}" \
  || fail "safety label / provider-expiry wording missing in PACKAGE_INTEGRITY_DRIFT_HISTORY.md"
emit "drift_history_guide_present=OK (PACKAGE_INTEGRITY_DRIFT_HISTORY.md present, safety-labelled) sha256=$(sha256_file "${GUIDE}")"

# ---------------------------------------------------------------------------
# 2. Drift history diff schema exists + is valid JSON.
# ---------------------------------------------------------------------------
[ -f "${DIFF_SCHEMA}" ] || fail "diff schema missing: PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${DIFF_SCHEMA}" \
  || fail "diff schema is not valid JSON"
[ -f "${INPUT_SCHEMA}" ] || fail "Run 407 input schema missing: PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json"
emit "diff_schema_present=OK (PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json present + valid JSON) sha256=$(sha256_file "${DIFF_SCHEMA}")"

# ---------------------------------------------------------------------------
# 3. Run 407 wrapper compatibility. The committed Run 407 harness is stored with CRLF line
#    endings, so normalize a transient LF copy and run it IN PLACE (so its
#    BASH_SOURCE-derived REPO_ROOT stays correct).
# ---------------------------------------------------------------------------
[ -f "${RUN407}" ] || fail "Run 407 wrapper missing: run_407_public_devnet_anchor_drift_json_retention.sh"
R407_TMP="${REPO_ROOT}/scripts/devnet/.run_407_lf.$$.tmp.sh"
cleanup() { rm -f "${R407_TMP}"; }
trap cleanup EXIT
sed 's/\r$//' "${RUN407}" > "${R407_TMP}"
R407_LOG="${OUTDIR}/run407.log"
if ! bash "${R407_TMP}" "${OUTDIR407}" > "${R407_LOG}" 2>&1; then
  cat "${R407_LOG}" >&2
  fail "Run 407 wrapper did not pass"
fi
grep -q '^RESULT=POSITIVE' "${R407_LOG}" || { cat "${R407_LOG}" >&2; fail "Run 407 wrapper did not report RESULT=POSITIVE"; }
rm -f "${R407_TMP}"; trap - EXIT
emit "run407_compat=OK (Run 407 wrapper RESULT=POSITIVE; reused via LF-normalized transient copy)"

# ---------------------------------------------------------------------------
# 4. Generate two transient Run 407-style JSON reports (base + several candidates) into a
#    staging dir OUTSIDE the tree, and validate every one against the Run 407 schema.
# ---------------------------------------------------------------------------
python3 - "${INPUT_SCHEMA}" "${FIXTURES}" <<'PY' || fail "Run 407-style fixture generation/validation failed"
import json, sys, os

input_schema = json.load(open(sys.argv[1]))
outdir = sys.argv[2]

SAFETY = ["devnet", "experimental", "resettable", "no_value",
          "no_uptime_sla", "not_launch_ready", "c4_open", "c5_open"]
NON_CLAIMS = {k: False for k in [
    "launches_public_devnet", "moves_m4_green", "moves_m6_green", "moves_s5_green",
    "moves_s7_green", "closes_c4", "closes_c5", "claims_testnet_ready",
    "claims_mainnet_ready", "deploys_seed_or_service", "mutates_runtime_state"]}
LABEL = ("experimental \u00b7 resettable \u00b7 no value \u00b7 no uptime SLA \u00b7 "
         "NOT public-DevNet launch-ready \u00b7 no MainNet readiness claim \u00b7 "
         "no C4/C5 closure claim")

def report(matching, missing, mismatched, refreshed, full_only):
    total = len(matching) + len(missing) + len(mismatched) + len(refreshed)
    return {
        "report_version": "1.0.0",
        "generated_for_run": 407,
        "scope": "public-devnet-docs-anchor-drift",
        "package_root": "docs/release/public-devnet",
        "anchor_manifest_path": "PACKAGE_INTEGRITY_MANIFEST.example.json",
        "full_tree_manifest_artifact_name": "PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json",
        "safety_labels": list(SAFETY),
        "counts": {
            "anchor_total": total,
            "anchors_present_matching": len(matching),
            "anchors_missing": len(missing),
            "undocumented_mismatches": len(mismatched),
            "documented_refreshes": len(refreshed),
            "full_tree_only": len(full_only),
        },
        "anchors_present_matching": sorted(matching),
        "anchors_missing": sorted(missing),
        "undocumented_mismatches": sorted(mismatched),
        "documented_refreshes": sorted(refreshed),
        "full_tree_only": list(full_only),
        "non_claims": dict(NON_CLAIMS),
        "artifact_safety_label": LABEL,
    }

# 16 curated anchors (representative safe relative paths).
anchors = [
    "PACKAGE_INTEGRITY.md", "ARTIFACT_INDEX.md", "OPERATOR_VERIFICATION_MAP.md",
    "LAUNCH_GO_NO_GO.md", "BLOCKER_REGISTER.md",
    "genesis/VERIFY.md", "binary/VERIFY.md", "operator/VERIFY.md",
    "identity/IDENTITY_VERIFY.md", "p2p/VERIFY.md", "network/VERIFY.md",
    "security/VERIFY.md", "observability/VERIFY.md", "ops/VERIFY.md",
    "recovery/VERIFY.md", "status/VERIFY.md",
]
base_full_only = [
    "PACKAGE_INTEGRITY_FULL_TREE.md",
    "PACKAGE_INTEGRITY_CI_ARTIFACTS.md",
    "PACKAGE_INTEGRITY_CI_RETENTION.md",
    "PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json",
    "network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md",
]
# Candidate adds two new package files and removes one that left the tree.
cand_full_only = [p for p in base_full_only if p != "network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md"]
cand_full_only += ["PACKAGE_INTEGRITY_DRIFT_HISTORY.md",
                   "PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json"]

fixtures = {
    # base: clean, all anchors matching.
    "base.json": report(anchors, [], [], [], base_full_only),
    # positive candidate: clean, only full-tree-only drift changed.
    "candidate_positive.json": report(anchors, [], [], [], cand_full_only),
    # candidate with a NEW missing anchor -> fail closed.
    "candidate_missing.json": report(
        [a for a in anchors if a != "genesis/VERIFY.md"],
        ["genesis/VERIFY.md"], [], [], cand_full_only),
    # candidate with a NEW undocumented mismatch -> fail closed.
    "candidate_mismatch.json": report(
        [a for a in anchors if a != "OPERATOR_VERIFICATION_MAP.md"],
        [], ["OPERATOR_VERIFICATION_MAP.md"], [], cand_full_only),
}

try:
    import jsonschema
    have_js = True
except ImportError:
    have_js = False

for name, rep in fixtures.items():
    path = os.path.join(outdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    if have_js:
        jsonschema.validate(instance=rep, schema=input_schema)
    else:
        for k in input_schema["required"]:
            assert k in rep, f"{name}: missing required key {k}"
    c = rep["counts"]
    assert c["anchors_present_matching"] == len(rep["anchors_present_matching"])
    assert c["anchors_missing"] == len(rep["anchors_missing"])
    assert c["undocumented_mismatches"] == len(rep["undocumented_mismatches"])
    assert c["documented_refreshes"] == len(rep["documented_refreshes"])
    assert c["full_tree_only"] == len(rep["full_tree_only"])
    assert all(v is False for v in rep["non_claims"].values())

print("fixtures_ok " + " ".join(sorted(fixtures)))
PY
for f in base.json candidate_positive.json candidate_missing.json candidate_mismatch.json; do
  [ -f "${FIXTURES}/${f}" ] || fail "fixture not generated: ${f}"
  case "${FIXTURES}/${f}" in
    "${PDN}"/*|"${REPO_ROOT}"/docs/*|"${REPO_ROOT}"/scripts/*|"${REPO_ROOT}"/.github/*)
      fail "fixture generated inside the repository tree: ${f}";;
  esac
done
emit "input_reports_valid=OK (base + candidate Run 407-style reports generated outside the tree; validate against PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json; counts == array lengths; non_claims all false)"

# ---------------------------------------------------------------------------
# Write the standalone, non-mutating comparator to a transient file OUTSIDE the tree.
# It NEVER fetches CI artifacts and requires NO token/secret: it reads two local files.
# Exit 0 = positive-no-new-failures; exit 3 = any negative verdict (fail closed).
# ---------------------------------------------------------------------------
cat > "${COMPARATOR_PY}" <<'PY'
import json, re, sys

INPUT_SCHEMA, DIFF_SCHEMA, BASE, CAND, OUT = sys.argv[1:6]

SAFETY = ["devnet", "experimental", "resettable", "no_value",
          "no_uptime_sla", "not_launch_ready", "c4_open", "c5_open"]
NON_CLAIM_KEYS = [
    "launches_public_devnet", "moves_m4_green", "moves_m6_green", "moves_s5_green",
    "moves_s7_green", "closes_c4", "closes_c5", "claims_testnet_ready",
    "claims_mainnet_ready", "deploys_seed_or_service", "mutates_runtime_state"]
LABEL = ("experimental \u00b7 resettable \u00b7 no value \u00b7 no uptime SLA \u00b7 "
         "NOT public-DevNet launch-ready \u00b7 no MainNet readiness claim \u00b7 "
         "no C4/C5 closure claim")
COUNT_KEYS = ["anchor_total", "anchors_present_matching", "anchors_missing",
              "undocumented_mismatches", "documented_refreshes", "full_tree_only"]
PATH_ARRAYS = ["anchors_present_matching", "anchors_missing", "undocumented_mismatches",
               "documented_refreshes", "full_tree_only"]
SAFE_REL = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
FORBIDDEN = re.compile(
    r"\.(kem\.sk\.bin|cert\.bin|key|pem|log|data|sk\.hex)$|metrics.*\.txt$|"
    r"(^|/)(logs?|data|node|nodes|material)/|private.*identity|"
    r"://|@|:[0-9]{2,5}(/|$)|token|secret|password", re.I)

input_schema = json.load(open(INPUT_SCHEMA))
diff_schema = json.load(open(DIFF_SCHEMA))

try:
    import jsonschema
    HAVE_JS = True
except ImportError:
    HAVE_JS = False

def load(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return None

def valid_input(rep):
    if rep is None:
        return False
    if HAVE_JS:
        try:
            jsonschema.validate(instance=rep, schema=input_schema)
        except Exception:
            return False
    else:
        for k in input_schema["required"]:
            if k not in rep:
                return False
    nc = rep.get("non_claims", {})
    if not (isinstance(nc, dict) and all(nc.get(k) is False for k in NON_CLAIM_KEYS)):
        return False
    for arr in PATH_ARRAYS:
        for p in rep.get(arr, []):
            if not isinstance(p, str) or not SAFE_REL.match(p) or FORBIDDEN.search(p) or p.startswith("/"):
                return False
    return True

def counts_of(rep):
    c = rep.get("counts", {}) if isinstance(rep, dict) else {}
    return {k: int(c.get(k, 0)) for k in COUNT_KEYS}

def ref_of(rep):
    return {"scope": "public-devnet-docs-anchor-drift",
            "generated_for_run": 407,
            "counts": counts_of(rep)}

def s(rep, key):
    return set(rep.get(key, [])) if isinstance(rep, dict) else set()

base, cand = load(BASE), load(CAND)
base_ok, cand_ok = valid_input(base), valid_input(cand)

count_delta = {k: 0 for k in COUNT_KEYS}
path_delta = {
    "added_full_tree_only": [], "removed_full_tree_only": [],
    "new_missing_anchors": [], "cleared_missing_anchors": [],
    "new_undocumented_mismatches": [], "cleared_undocumented_mismatches": [],
    "changed_documented_refreshes": [],
}

if base_ok and cand_ok:
    bc, cc = counts_of(base), counts_of(cand)
    count_delta = {k: cc[k] - bc[k] for k in COUNT_KEYS}
    path_delta["added_full_tree_only"] = sorted(s(cand, "full_tree_only") - s(base, "full_tree_only"))
    path_delta["removed_full_tree_only"] = sorted(s(base, "full_tree_only") - s(cand, "full_tree_only"))
    path_delta["new_missing_anchors"] = sorted(s(cand, "anchors_missing") - s(base, "anchors_missing"))
    path_delta["cleared_missing_anchors"] = sorted(s(base, "anchors_missing") - s(cand, "anchors_missing"))
    path_delta["new_undocumented_mismatches"] = sorted(s(cand, "undocumented_mismatches") - s(base, "undocumented_mismatches"))
    path_delta["cleared_undocumented_mismatches"] = sorted(s(base, "undocumented_mismatches") - s(cand, "undocumented_mismatches"))
    path_delta["changed_documented_refreshes"] = sorted(s(base, "documented_refreshes") ^ s(cand, "documented_refreshes"))
    if path_delta["new_missing_anchors"]:
        verdict = "negative-new-missing-anchor"
    elif path_delta["new_undocumented_mismatches"]:
        verdict = "negative-new-undocumented-mismatch"
    else:
        verdict = "positive-no-new-failures"
else:
    verdict = "negative-invalid-input"

diff = {
    "diff_version": "1.0.0",
    "generated_for_run": 408,
    "scope": "public-devnet-docs-anchor-drift-history-diff",
    "package_root": "docs/release/public-devnet",
    "base_report": ref_of(base if base_ok else {}),
    "candidate_report": ref_of(cand if cand_ok else {}),
    "safety_labels": list(SAFETY),
    "count_delta": count_delta,
    "path_delta": path_delta,
    "verdict": verdict,
    "non_claims": {k: False for k in NON_CLAIM_KEYS},
    "artifact_safety_label": LABEL,
}

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(diff, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# Validate the emitted diff against the Run 408 schema.
if HAVE_JS:
    jsonschema.validate(instance=diff, schema=diff_schema)
else:
    for k in diff_schema["required"]:
        assert k in diff, f"diff missing required key {k}"

# Safe-relative-path rule holds for every diff path array.
for arr in path_delta.values():
    for p in arr:
        assert SAFE_REL.match(p) and not FORBIDDEN.search(p) and not p.startswith("/"), f"unsafe diff path {p}"

assert all(v is False for v in diff["non_claims"].values())
print("verdict=" + verdict)
print("added_full_tree_only=" + ",".join(path_delta["added_full_tree_only"]))
print("removed_full_tree_only=" + ",".join(path_delta["removed_full_tree_only"]))
sys.exit(0 if verdict == "positive-no-new-failures" else 3)
PY

# ---------------------------------------------------------------------------
# 5-8, 11. Positive no-new-failures comparison: base vs candidate_positive.
# ---------------------------------------------------------------------------
POS_LOG="${OUTDIR}/compare_positive.log"
if ! python3 "${COMPARATOR_PY}" "${INPUT_SCHEMA}" "${DIFF_SCHEMA}" \
      "${FIXTURES}/base.json" "${FIXTURES}/candidate_positive.json" "${DIFF_OUT}" \
      > "${POS_LOG}" 2>&1; then
  cat "${POS_LOG}" >&2
  fail "positive comparison did not pass (expected positive-no-new-failures)"
fi
grep -q '^verdict=positive-no-new-failures' "${POS_LOG}" || { cat "${POS_LOG}" >&2; fail "positive comparison verdict mismatch"; }
[ -f "${DIFF_OUT}" ] || fail "comparator did not emit PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json"
case "${DIFF_OUT}" in
  "${PDN}"/*|"${REPO_ROOT}"/docs/*|"${REPO_ROOT}"/scripts/*|"${REPO_ROOT}"/.github/*)
    fail "generated diff JSON is inside the repository tree: ${DIFF_OUT}";;
esac
emit "diff_outside_tree=OK (PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json generated into staging, outside the tree; not committed)"
emit "diff_schema_validation=OK (diff validates against PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json; non_claims all false)"
emit "positive_case=OK (base vs candidate_positive -> verdict=positive-no-new-failures)"

# The positive diff must report full-tree-only add/remove but NO new failure.
python3 - "${DIFF_OUT}" <<'PY' || fail "positive diff classification is not as expected"
import json, sys
d = json.load(open(sys.argv[1]))
pd = d["path_delta"]
assert d["verdict"] == "positive-no-new-failures"
assert pd["added_full_tree_only"], "expected added full-tree-only paths"
assert pd["removed_full_tree_only"], "expected removed full-tree-only paths"
assert not pd["new_missing_anchors"], "positive case must have no new missing anchors"
assert not pd["new_undocumented_mismatches"], "positive case must have no new undocumented mismatches"
print("full_tree_only_reported added=%d removed=%d" % (
    len(pd["added_full_tree_only"]), len(pd["removed_full_tree_only"])))
PY
emit "full_tree_only_drift=OK (added/removed full-tree-only paths reported as expected curated-anchor drift, not a failure by itself)"

# ---------------------------------------------------------------------------
# 6-7. Re-assert diff schema validity + safe-path rules over the emitted diff.
# ---------------------------------------------------------------------------
python3 - "${DIFF_OUT}" "${DIFF_SCHEMA}" <<'PY' || fail "emitted diff failed schema/safe-path re-check"
import json, re, sys
d = json.load(open(sys.argv[1]))
schema = json.load(open(sys.argv[2]))
try:
    import jsonschema
    jsonschema.validate(instance=d, schema=schema)
except ImportError:
    for k in schema["required"]:
        assert k in d
safe = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
for name, arr in d["path_delta"].items():
    for p in arr:
        assert safe.match(p) and not p.startswith("/"), f"unsafe path in {name}: {p}"
assert d["scope"] == "public-devnet-docs-anchor-drift-history-diff"
assert d["package_root"] == "docs/release/public-devnet"
print("diff_schema_and_paths_ok")
PY
emit "diff_safe_paths=OK (all diff path_delta arrays are safe relative paths; scope/package_root fixed)"

# ---------------------------------------------------------------------------
# 9. New missing-anchor fixture fails closed.
# ---------------------------------------------------------------------------
MISS_LOG="${OUTDIR}/compare_missing.log"
MISS_DIFF="${STAGING}/diff_missing.json"
set +e
python3 "${COMPARATOR_PY}" "${INPUT_SCHEMA}" "${DIFF_SCHEMA}" \
  "${FIXTURES}/base.json" "${FIXTURES}/candidate_missing.json" "${MISS_DIFF}" > "${MISS_LOG}" 2>&1
MISS_RC=$?
set -e
[ "${MISS_RC}" -ne 0 ] || { cat "${MISS_LOG}" >&2; fail "missing-anchor fixture must fail closed (non-zero exit)"; }
grep -q '^verdict=negative-new-missing-anchor' "${MISS_LOG}" || { cat "${MISS_LOG}" >&2; fail "missing-anchor verdict mismatch"; }
emit "missing_anchor_fail_closed=OK (new missing anchor -> verdict=negative-new-missing-anchor; comparator exit=${MISS_RC})"

# ---------------------------------------------------------------------------
# 10. New undocumented-mismatch fixture fails closed.
# ---------------------------------------------------------------------------
MM_LOG="${OUTDIR}/compare_mismatch.log"
MM_DIFF="${STAGING}/diff_mismatch.json"
set +e
python3 "${COMPARATOR_PY}" "${INPUT_SCHEMA}" "${DIFF_SCHEMA}" \
  "${FIXTURES}/base.json" "${FIXTURES}/candidate_mismatch.json" "${MM_DIFF}" > "${MM_LOG}" 2>&1
MM_RC=$?
set -e
[ "${MM_RC}" -ne 0 ] || { cat "${MM_LOG}" >&2; fail "undocumented-mismatch fixture must fail closed (non-zero exit)"; }
grep -q '^verdict=negative-new-undocumented-mismatch' "${MM_LOG}" || { cat "${MM_LOG}" >&2; fail "undocumented-mismatch verdict mismatch"; }
emit "undocumented_mismatch_fail_closed=OK (new undocumented mismatch -> verdict=negative-new-undocumented-mismatch; comparator exit=${MM_RC})"

# ---------------------------------------------------------------------------
# 12. Generated artifacts are not committed (none of the transient leaf names is tracked).
# ---------------------------------------------------------------------------
for name in "PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json" "ANCHOR_DRIFT_REPORT.json" \
            "PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"; do
  if git -C "${REPO_ROOT}" ls-files --error-unmatch -- "**/${name}" >/dev/null 2>&1; then
    fail "generated artifact appears committed in the repo: ${name}"
  fi
done
emit "generated_artifacts_transient=OK (diff JSON + fixtures + reused Run 407 artifacts staged outside the tree; none committed)"

# ---------------------------------------------------------------------------
# 13. Working tree stays clean after the run.
# ---------------------------------------------------------------------------
GIT_AFTER="$(git -C "${REPO_ROOT}" status --porcelain)"
[ "${GIT_BEFORE}" = "${GIT_AFTER}" ] || { diff <(printf '%s' "${GIT_BEFORE}") <(printf '%s' "${GIT_AFTER}") >&2 || true; fail "harness left new changes in the working tree"; }
emit "working_tree_clean=OK (harness generated nothing under the repo tree; git status unchanged by this run)"

# ---------------------------------------------------------------------------
# 14. No automatic CI/API fetch and no token/secret requirement. The comparator + guide
#     use only manual, local inputs: assert the harness and comparator contain no artifact
#     fetch command and require no token/secret env.
# ---------------------------------------------------------------------------
if grep -Eiq 'gh[[:space:]]+run[[:space:]]+download|gh[[:space:]]+api|curl[[:space:]]|wget[[:space:]]|GITHUB_TOKEN|\$\{\{[[:space:]]*secrets\.|Authorization:[[:space:]]*(Bearer|token)|urllib|requests\.get|http\.client|socket\.' "${COMPARATOR_PY}"; then
  fail "auto-fetch/token/secret/network usage found in the comparator"
fi
grep -qi 'download .*ANCHOR_DRIFT_REPORT.json .*manually\|download.*manually\|manual and interactive' "${GUIDE}" \
  || fail "guide must document MANUAL artifact download"
grep -qi 'token or secret' "${GUIDE}" \
  || fail "guide must state no token/secret is required"
emit "no_auto_fetch=OK (comparator + guide use manual local inputs only; no gh/curl/wget/GITHUB_TOKEN/secret usage)"

# ---------------------------------------------------------------------------
# 15-18. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 19-20. Public DevNet NOT launch-ready + C4/C5 OPEN in the guide.
# ---------------------------------------------------------------------------
grep -qi 'NOT public-DevNet launch-ready' "${GUIDE}" || fail "guide must state NOT launch-ready"
grep -qi 'C4 remains OPEN' "${GUIDE}" && grep -qi 'C5 remains OPEN' "${GUIDE}" \
  || fail "guide must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 21-22, 25. Non-claim grep over the drift history guide (normalized).
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
CLAIM_HITS="$(normalize_md "${GUIDE}" \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in guide"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in drift history guide)"

# ---------------------------------------------------------------------------
# 23. Runtime mutation: generated diff non_claims all false.
# ---------------------------------------------------------------------------
python3 - "${DIFF_OUT}" <<'PY' || fail "generated diff non_claims must all be false"
import json, sys
d = json.load(open(sys.argv[1]))
assert all(v is False for v in d["non_claims"].values())
assert d["non_claims"]["mutates_runtime_state"] is False
print("non_claims_all_false=OK")
PY
emit "runtime_mutation=NONE (generated diff non_claims all false; mutates_runtime_state=false)"

# ---------------------------------------------------------------------------
# 24. Secret / private-material scan over the guide + schema + generated diff + tree.
# ---------------------------------------------------------------------------
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${GUIDE}" "${DIFF_SCHEMA}"; then
  fail "absolute filesystem path found in the guide or diff schema"
fi
if grep -nE '(^|[^A-Za-z])/(home|root|Users|var|etc)/' "${DIFF_OUT}"; then
  fail "absolute filesystem path found in the generated diff"
fi
python3 - "${DIFF_OUT}" <<'PY' || fail "generated diff lists a forbidden private/raw artifact or unsafe path"
import json, re, sys
d = json.load(open(sys.argv[1]))
forbidden = re.compile(r"\.(kem\.sk\.bin|cert\.bin|key|pem|log|data|sk\.hex)$|metrics.*\.txt$|(^|/)(logs?|data|node|nodes|material)/|private.*identity", re.I)
paths = []
for arr in d["path_delta"].values():
    paths.extend(arr)
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
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${GUIDE}" "${DIFF_SCHEMA}" "${DIFF_OUT}"; then
  fail "possible secret / private material found in guide, schema, or generated diff"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path; no private endpoint)"

emit ""
emit "RESULT=POSITIVE (public-DevNet retained anchor-drift history comparator: two Run 407-style ANCHOR_DRIFT_REPORT.json inputs validate against PACKAGE_INTEGRITY_ANCHOR_DRIFT_REPORT.schema.json; the Run 407 wrapper still passes; the comparator emits a transient PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.json OUTSIDE the package tree that validates against PACKAGE_INTEGRITY_DRIFT_HISTORY_DIFF.schema.json with safe relative paths only; the positive no-new-failures case passes while reporting added/removed full-tree-only drift as expected; new missing-anchor and new undocumented-mismatch fixtures fail closed; the comparator never fetches CI artifacts and needs no token/secret; nothing generated is committed; the working tree stays clean; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"
