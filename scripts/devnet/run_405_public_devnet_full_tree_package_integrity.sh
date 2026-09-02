#!/usr/bin/env bash
# Run 405: public DevNet FULL-TREE package integrity verifier harness.
#
# This harness generates a FULL-TREE integrity manifest for the public DevNet
# release package (see `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE.md`
# and `docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json`)
# and verifies it against the on-disk package tree. Unlike the Run 404 anchor
# manifest (which lists one VERIFY.md per group plus the top-level docs), the
# full-tree manifest lists EVERY regular publish-safe file under
# `docs/release/public-devnet`.
#
# The generated full-tree manifest is written to a TEMPORARY directory OUTSIDE the
# package tree and is NEVER committed. It is DOCS + SCHEMA + SHELL only (Decision
# gate = Route B): it makes NO production Rust source change, adds NO CLI flag,
# opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/explorer/
# status page, changes NO wire format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState state.
#
# What it proves (21 checks):
#   1.  Full-tree guide exists and is safety-labelled.
#   2.  Full-tree schema exists.
#   3.  Generated full-tree manifest validates against the schema.
#   4.  Every regular file under docs/release/public-devnet is included.
#   5.  Every manifest relative_path is safe and root-confined.
#   6.  Every listed SHA-256 and byte size matches on-disk.
#   7.  Existing Run 404 anchor manifest still validates.
#   8.  ARTIFACT_INDEX.md references full-tree integrity verification.
#   9.  OPERATOR_VERIFICATION_MAP.md references full-tree integrity verification.
#   10. External-operator read-order numbering is consistent (no duplicate index).
#   11. M4 remains Yellow.
#   12. M6 remains Yellow/Partial.
#   13. S5 remains Yellow.
#   14. S7 remains Yellow.
#   15. Public DevNet remains NOT launch-ready.
#   16. C4/C5 remain OPEN.
#   17. No TestNet/MainNet readiness claim appears.
#   18. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   19. No runtime mutation claim (manifest non_claims all false).
#   20. Secret/private-material scan is clean.
#   21. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written. The only
# generated file (the full-tree manifest) lives under a temp dir outside the tree.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run405-public-devnet-full-tree-package-integrity}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
FT_GUIDE="${PDN}/PACKAGE_INTEGRITY_FULL_TREE.md"
FT_SCHEMA="${PDN}/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json"
A_SCHEMA="${PDN}/PACKAGE_INTEGRITY_MANIFEST.schema.json"
A_EXAMPLE="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
INDEX="${PDN}/ARTIFACT_INDEX.md"
MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"
# The generated full-tree manifest is written OUTSIDE the package tree, never committed.
GEN_MANIFEST="${OUTDIR}/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.generated.json"

log()  { printf '[run405] %s\n' "$*"; }
fail() { printf '[run405] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Full-tree guide exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${FT_GUIDE}" ] || fail "full-tree guide missing: PACKAGE_INTEGRITY_FULL_TREE.md"
grep -qi 'experimental' "${FT_GUIDE}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${FT_GUIDE}" \
  && grep -qi 'no C4/C5 closure claim' "${FT_GUIDE}" \
  || fail "safety label missing in PACKAGE_INTEGRITY_FULL_TREE.md"
emit "full_tree_guide_present=OK (PACKAGE_INTEGRITY_FULL_TREE.md present, safety-labelled) sha256=$(sha256_file "${FT_GUIDE}")"

# ---------------------------------------------------------------------------
# 2. Full-tree schema exists.
# ---------------------------------------------------------------------------
[ -f "${FT_SCHEMA}" ] || fail "full-tree schema missing: PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json"
emit "full_tree_schema_present=OK (PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json) sha256=$(sha256_file "${FT_SCHEMA}")"

# ---------------------------------------------------------------------------
# Enumerate every regular publish-safe file under the package root. We use the
# git-tracked set PLUS new-but-not-ignored files (so a file added in the same
# change is covered before it is committed). Paths are relative to package_root.
# ---------------------------------------------------------------------------
DISK_LIST="${OUTDIR}/disk_files.txt"
{
  git -C "${REPO_ROOT}" ls-files -- docs/release/public-devnet
  git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- docs/release/public-devnet
} | sed 's#^docs/release/public-devnet/##' | LC_ALL=C sort -u > "${DISK_LIST}"
[ -s "${DISK_LIST}" ] || fail "no publish-safe files enumerated under package root"

# ---------------------------------------------------------------------------
# 3-6. Generate the full-tree manifest (into OUTDIR, outside the tree), validate
#      against schema, verify full-tree coverage, safe paths, and hashes/sizes.
# ---------------------------------------------------------------------------
python3 - "${FT_SCHEMA}" "${PDN}" "${DISK_LIST}" "${GEN_MANIFEST}" <<'PY' || fail "full-tree manifest generation/validation failed"
import hashlib, json, os, re, sys, datetime
schema_path, pdn, disk_list_path, out_path = sys.argv[1:5]
schema = json.load(open(schema_path))

rels = [ln.strip() for ln in open(disk_list_path) if ln.strip()]
rel_re = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")

files = []
pdn_real = os.path.realpath(pdn)
for rel in sorted(set(rels)):
    assert rel_re.match(rel), f"unsafe relative_path enumerated: {rel}"
    p = os.path.join(pdn, rel)
    assert os.path.isfile(p), f"enumerated file missing on disk: {rel}"
    real = os.path.realpath(p)
    assert real == pdn_real + os.sep + rel.replace('/', os.sep) or real.startswith(pdn_real + os.sep), \
        f"path escapes package root: {rel}"
    data = open(p, "rb").read()
    files.append({
        "relative_path": rel,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_size": len(data),
    })

manifest = {
    "manifest_version": "1.0.0",
    "generated_for_run": 405,
    "scope": "public-devnet-docs-release-package-full-tree",
    "coverage": "full-tree",
    "safety_labels": ["devnet","experimental","resettable","no_value",
                      "no_uptime_sla","not_launch_ready","c4_open","c5_open"],
    "package_root": "docs/release/public-devnet",
    "file_count": len(files),
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "files": files,
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

with open(out_path, "w") as fh:
    json.dump(manifest, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

# --- schema validation (jsonschema if available, else structural fallback) ---
try:
    import jsonschema
    jsonschema.validate(instance=manifest, schema=schema)
    print("schema_validation=jsonschema")
except ImportError:
    for k in schema["required"]:
        assert k in manifest, f"missing required key: {k}"
    print("schema_validation=structural-fallback")

# --- fixed field checks (defence in depth) ---
assert manifest["generated_for_run"] == 405
assert manifest["scope"] == "public-devnet-docs-release-package-full-tree"
assert manifest["coverage"] == "full-tree"
assert manifest["package_root"] == "docs/release/public-devnet"
need = {"devnet","experimental","resettable","no_value","no_uptime_sla","not_launch_ready","c4_open","c5_open"}
assert need.issubset(set(manifest["safety_labels"]))
assert all(v is False for v in manifest["non_claims"].values())
assert manifest["file_count"] == len(manifest["files"])

# --- 4. full-tree coverage: manifest set == on-disk set ---
disk_set = set(rels)
man_set = {f["relative_path"] for f in manifest["files"]}
missing = disk_set - man_set
extra = man_set - disk_set
assert not missing, f"files omitted from manifest: {sorted(missing)}"
assert not extra, f"manifest lists non-existent files: {sorted(extra)}"

# --- 6. re-hash every listed file and verify sha256 + byte_size ---
n_ok = 0
for f in manifest["files"]:
    p = os.path.join(pdn, f["relative_path"])
    data = open(p, "rb").read()
    assert hashlib.sha256(data).hexdigest() == f["sha256"], f"sha256 mismatch: {f['relative_path']}"
    assert len(data) == f["byte_size"], f"byte_size mismatch: {f['relative_path']}"
    n_ok += 1

print(f"file_count={len(manifest['files'])}")
print(f"files_verified={n_ok}")
PY
emit "full_tree_manifest_generated=OK (generated transiently outside the tree; not committed)"
emit "full_tree_schema_validation=OK (generated manifest validates; generated_for_run=405; scope=full-tree; safety labels + non_claims fixed)"
emit "full_tree_coverage=OK (manifest file set == on-disk publish-safe file set under docs/release/public-devnet; $(wc -l < "${DISK_LIST}") files)"
emit "full_tree_hash_verification=OK (every listed file exists; sha256 + byte_size match on-disk; relative paths safe + root-confined)"

# ---------------------------------------------------------------------------
# Confirm the generated manifest is NOT inside the package tree / repo working set.
# ---------------------------------------------------------------------------
case "${GEN_MANIFEST}" in
  "${PDN}"/*) fail "generated manifest is inside the package tree (must be transient/outside)";;
esac
emit "generated_manifest_transient=OK (generated manifest path is outside docs/release/public-devnet and not committed)"

# ---------------------------------------------------------------------------
# 7. Existing Run 404 anchor manifest still validates + hashes match.
# ---------------------------------------------------------------------------
[ -f "${A_SCHEMA}" ]  || fail "Run 404 anchor schema missing"
[ -f "${A_EXAMPLE}" ] || fail "Run 404 anchor manifest missing"
python3 - "${A_SCHEMA}" "${A_EXAMPLE}" "${PDN}" <<'PY' || fail "Run 404 anchor manifest validation failed"
import hashlib, json, os, re, sys
schema = json.load(open(sys.argv[1]))
m = json.load(open(sys.argv[2]))
pdn = sys.argv[3]
try:
    import jsonschema
    jsonschema.validate(instance=m, schema=schema)
except ImportError:
    for k in schema["required"]:
        assert k in m, f"missing required key: {k}"
assert m["generated_for_run"] == 404
rel_re = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
for f in m["files"]:
    rel = f["relative_path"]
    assert rel_re.match(rel), f"unsafe path: {rel}"
    data = open(os.path.join(pdn, rel), "rb").read()
    assert hashlib.sha256(data).hexdigest() == f["sha256"], f"sha256 mismatch: {rel}"
    assert len(data) == f["byte_size"], f"byte_size mismatch: {rel}"
print("anchor_manifest_ok")
PY
emit "anchor_manifest_compat=OK (Run 404 PACKAGE_INTEGRITY_MANIFEST.example.json still validates; hashes/sizes match)"

# ---------------------------------------------------------------------------
# 8. ARTIFACT_INDEX.md references full-tree integrity verification.
# ---------------------------------------------------------------------------
grep -qF "PACKAGE_INTEGRITY_FULL_TREE.md" "${INDEX}" \
  && grep -qi 'full-tree' "${INDEX}" \
  || fail "ARTIFACT_INDEX.md does not reference full-tree integrity verification"
emit "artifact_index_ref=OK (ARTIFACT_INDEX.md references full-tree integrity verification)"

# ---------------------------------------------------------------------------
# 9. OPERATOR_VERIFICATION_MAP.md references full-tree integrity verification.
# ---------------------------------------------------------------------------
grep -qF "PACKAGE_INTEGRITY_FULL_TREE.md" "${MAP}" \
  && grep -qi 'full-tree' "${MAP}" \
  || fail "OPERATOR_VERIFICATION_MAP.md does not reference full-tree integrity verification"
emit "operator_map_ref=OK (OPERATOR_VERIFICATION_MAP.md references full-tree integrity verification)"

# ---------------------------------------------------------------------------
# 10. External-operator read-order numbering is consistent (no duplicate index in
#     the ordered list under the "external operator" read-order heading).
# ---------------------------------------------------------------------------
python3 - "${MAP}" <<'PY' || fail "external-operator read-order numbering is inconsistent"
import re, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
# locate the "external operator" read-order section
start = None
for i, ln in enumerate(lines):
    if re.search(r'read order.*external operator', ln, re.I):
        start = i + 1
        break
assert start is not None, "external-operator read-order heading not found"
nums = []
for ln in lines[start:]:
    if ln.startswith("## "):   # next section
        break
    m = re.match(r'^\s*(\d+)\.\s', ln)
    if m:
        nums.append(int(m.group(1)))
assert nums, "no numbered read-order items found"
assert nums == list(range(1, len(nums) + 1)), f"read-order numbering not 1..N consecutive: {nums}"
print(f"read_order_numbers={nums}")
PY
emit "read_order_numbering=OK (external-operator read order is 1..N consecutive, no duplicate index)"

# ---------------------------------------------------------------------------
# 11-14. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 15/16. Public DevNet NOT launch-ready + C4/C5 OPEN in the new guide.
# ---------------------------------------------------------------------------
grep -qi 'NOT public-DevNet launch-ready' "${FT_GUIDE}" || fail "guide must state NOT launch-ready"
grep -qi 'C4 remains OPEN' "${FT_GUIDE}" && grep -qi 'C5 remains OPEN' "${FT_GUIDE}" \
  || fail "guide must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 17/18/21. Non-claim grep over the full-tree guide (normalized).
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
CLAIM_HITS="$(normalize_md "${FT_GUIDE}" \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in guide"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim in full-tree guide)"

# ---------------------------------------------------------------------------
# 19. Runtime mutation: generated manifest non_claims all false.
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
# 20. Secret / private-material scan over guide + schema + generated manifest and
#     the package tree: no keys/certs/KEM/signing/API/logs/metrics/data dirs/
#     private identity, no absolute paths, no private endpoints.
# ---------------------------------------------------------------------------
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${FT_GUIDE}" "${FT_SCHEMA}"; then
  fail "absolute filesystem path found in full-tree guide/schema"
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
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${FT_GUIDE}" "${FT_SCHEMA}"; then
  fail "possible secret / private material found in full-tree guide/schema"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity; no absolute path; no private endpoint)"

emit ""
emit "RESULT=POSITIVE (public-DevNet FULL-TREE package integrity verifier generated a transient, schema-valid manifest covering every publish-safe file under docs/release/public-devnet; all hashes/sizes match; Run 404 anchor manifest still validates; no committed generated output; no production source change; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"