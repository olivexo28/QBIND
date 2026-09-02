#!/usr/bin/env bash
# Run 404: public DevNet package integrity manifest verification harness.
#
# This harness produces the Run 404 acceptance evidence for the public DevNet
# release-package **integrity manifest** (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_404.md`,
# `docs/release/public-devnet/PACKAGE_INTEGRITY.md`,
# `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.schema.json`, and
# `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json`). It is a
# DOCS + SCHEMA + VERIFICATION run (Decision gate = Route B): it validates the
# published machine-readable package integrity manifest against the on-disk
# package tree and the canonical readiness matrix. It makes NO production Rust
# source change, adds NO CLI flag, opens NO externally reachable port, deploys NO
# seed/bootnode/faucet/RPC/explorer/status page, changes NO wire format, weakens
# NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves (21 checks):
#   1.  Schema exists.
#   2.  Example manifest exists.
#   3.  PACKAGE_INTEGRITY.md exists and is safety-labelled.
#   4.  Manifest validates against schema.
#   5.  Every manifest file path exists.
#   6.  Every manifest sha256 matches the current on-disk file.
#   7.  Every listed file uses a relative path under docs/release/public-devnet.
#   8.  No absolute paths are embedded.
#   9.  No private endpoints are embedded.
#   10. No raw logs/metrics/data dirs/key/cert/KEM/signing/API/private-identity
#       material is included.
#   11. ARTIFACT_INDEX.md references PACKAGE_INTEGRITY.md.
#   12. OPERATOR_VERIFICATION_MAP.md references the package integrity check.
#   13. M4 remains Yellow.
#   14. M6 remains Yellow/Partial.
#   15. S5 remains Yellow.
#   16. S7 remains Yellow.
#   17. Public DevNet remains NOT launch-ready.
#   18. C4/C5 remain OPEN.
#   19. No TestNet/MainNet readiness claim appears.
#   20. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   21. Non-claim grep passes.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run404-public-devnet-package-integrity-manifest}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
SCHEMA="${PDN}/PACKAGE_INTEGRITY_MANIFEST.schema.json"
EXAMPLE="${PDN}/PACKAGE_INTEGRITY_MANIFEST.example.json"
GUIDE="${PDN}/PACKAGE_INTEGRITY.md"
INDEX="${PDN}/ARTIFACT_INDEX.md"
MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run404] %s\n' "$*"; }
fail() { printf '[run404] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Schema exists.
# ---------------------------------------------------------------------------
[ -f "${SCHEMA}" ] || fail "manifest schema missing: PACKAGE_INTEGRITY_MANIFEST.schema.json"
emit "schema_present=OK (PACKAGE_INTEGRITY_MANIFEST.schema.json) sha256=$(sha256_file "${SCHEMA}")"

# ---------------------------------------------------------------------------
# 2. Example manifest exists.
# ---------------------------------------------------------------------------
[ -f "${EXAMPLE}" ] || fail "example manifest missing: PACKAGE_INTEGRITY_MANIFEST.example.json"
emit "example_present=OK (PACKAGE_INTEGRITY_MANIFEST.example.json) sha256=$(sha256_file "${EXAMPLE}")"

# ---------------------------------------------------------------------------
# 3. PACKAGE_INTEGRITY.md exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${GUIDE}" ] || fail "integrity guide missing: PACKAGE_INTEGRITY.md"
grep -qi 'experimental' "${GUIDE}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${GUIDE}" \
  && grep -qi 'no C4/C5 closure claim' "${GUIDE}" \
  || fail "safety label missing in PACKAGE_INTEGRITY.md"
emit "guide_present=OK (PACKAGE_INTEGRITY.md present, safety-labelled) sha256=$(sha256_file "${GUIDE}")"

# ---------------------------------------------------------------------------
# 4. Manifest validates against schema. 5/6/7. Path exists, sha256 matches,
#    relative path under package root.
# ---------------------------------------------------------------------------
python3 - "${SCHEMA}" "${EXAMPLE}" "${PDN}" <<'PY' || fail "manifest schema/hash/path validation failed"
import hashlib, json, os, re, sys
schema_path, example_path, pdn = sys.argv[1], sys.argv[2], sys.argv[3]
schema = json.load(open(schema_path))
m = json.load(open(example_path))

# --- schema validation (jsonschema if available, else structural fallback) ---
try:
    import jsonschema
    jsonschema.validate(instance=m, schema=schema)
    print("schema_validation=jsonschema")
except ImportError:
    for k in schema["required"]:
        assert k in m, f"missing required key: {k}"
    assert m["generated_for_run"] == 404
    assert m["scope"] == "public-devnet-docs-release-package"
    assert m["package_root"] == "docs/release/public-devnet"
    print("schema_validation=structural-fallback")

# --- fixed field checks (defence in depth) ---
assert m["generated_for_run"] == 404, "generated_for_run must be 404"
assert m["scope"] == "public-devnet-docs-release-package"
assert m["package_root"] == "docs/release/public-devnet"
need = {"devnet","experimental","resettable","no_value","no_uptime_sla","not_launch_ready","c4_open","c5_open"}
assert need.issubset(set(m["safety_labels"])), "missing safety labels"
nc = m["non_claims"]
for k, v in nc.items():
    assert v is False, f"non_claim {k} must be false"
for req in ["launches_public_devnet","moves_m4_green","moves_m6_green","moves_s5_green",
            "moves_s7_green","closes_c4","closes_c5","claims_testnet_ready",
            "claims_mainnet_ready","deploys_seed_or_service","mutates_runtime_state"]:
    assert req in nc, f"missing non_claim: {req}"

rel_re = re.compile(r"^(?!/)(?!.*\.\.)(?![A-Za-z]:)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
n_ok = 0
for f in m["files"]:
    rel = f["relative_path"]
    assert rel_re.match(rel), f"relative_path not a safe relative path: {rel}"
    assert not rel.startswith("/"), f"absolute path: {rel}"
    p = os.path.join(pdn, rel)
    assert os.path.isfile(p), f"listed file missing on disk: {rel}"
    data = open(p, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    assert got == f["sha256"], f"sha256 mismatch for {rel}: {got} != {f['sha256']}"
    assert len(data) == f["byte_size"], f"byte_size mismatch for {rel}"
    # 7: resolved path must stay under the package root
    real = os.path.realpath(p)
    assert real.startswith(os.path.realpath(pdn) + os.sep), f"path escapes package root: {rel}"
    n_ok += 1
print(f"files_verified={n_ok}")
PY
emit "schema_validation=OK (PACKAGE_INTEGRITY_MANIFEST.example.json validates; generated_for_run=404; scope + safety labels + non_claims fixed)"
emit "hash_verification=OK (every listed file exists; sha256 + byte_size match on-disk; relative paths resolve under docs/release/public-devnet)"

# ---------------------------------------------------------------------------
# 8. No absolute paths embedded in manifest / schema / guide.
# ---------------------------------------------------------------------------
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${EXAMPLE}" "${SCHEMA}" "${GUIDE}"; then
  fail "absolute filesystem path found in manifest/schema/guide"
fi
emit "no_absolute_paths=OK (no /home|/root|/Users|/tmp|/var|/etc path in manifest/schema/guide)"

# ---------------------------------------------------------------------------
# 9. No private endpoints embedded (IP:port / private hostnames).
# ---------------------------------------------------------------------------
if grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}|https?://[A-Za-z0-9.-]+:[0-9]{2,5}' "${EXAMPLE}"; then
  fail "possible private endpoint found in manifest example"
fi
emit "no_private_endpoints=OK (no IP:port / host:port endpoint embedded in manifest)"

# ---------------------------------------------------------------------------
# 10. No raw logs/metrics/data dirs/key/cert/KEM/signing/API/private-identity
#     material listed by the manifest or present under the package root.
# ---------------------------------------------------------------------------
python3 - "${EXAMPLE}" <<'PY' || fail "manifest lists a forbidden private/raw artifact"
import json, re, sys
m = json.load(open(sys.argv[1]))
forbidden = re.compile(r"\.(kem\.sk\.bin|cert\.bin|key|pem|log|data|sk\.hex)$|metrics.*\.txt$|(^|/)(logs?|data|node|nodes|material)/|private.*identity", re.I)
bad = [f["relative_path"] for f in m["files"] if forbidden.search(f["relative_path"])]
assert not bad, f"forbidden entries: {bad}"
print("forbidden_entries=none")
PY
if find "${PDN}" -maxdepth 1 -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under public-devnet package root"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${EXAMPLE}" "${GUIDE}"; then
  fail "possible secret / private material found in manifest/guide"
fi
emit "committed_private_material=NONE (no keys/certs/KEM/signing/API/raw logs/metrics/data dirs/private identity listed or committed)"

# ---------------------------------------------------------------------------
# 11. ARTIFACT_INDEX.md references PACKAGE_INTEGRITY.md.
# ---------------------------------------------------------------------------
grep -qF "PACKAGE_INTEGRITY.md" "${INDEX}" || fail "ARTIFACT_INDEX.md does not reference PACKAGE_INTEGRITY.md"
emit "artifact_index_ref=OK (ARTIFACT_INDEX.md references PACKAGE_INTEGRITY.md)"

# ---------------------------------------------------------------------------
# 12. OPERATOR_VERIFICATION_MAP.md references the package integrity check.
# ---------------------------------------------------------------------------
grep -qF "PACKAGE_INTEGRITY.md" "${MAP}" \
  && grep -qi 'package integrity check' "${MAP}" \
  || fail "OPERATOR_VERIFICATION_MAP.md does not reference the package integrity check"
emit "operator_map_ref=OK (OPERATOR_VERIFICATION_MAP.md references the package integrity check)"

# ---------------------------------------------------------------------------
# 13-16. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡)"

# ---------------------------------------------------------------------------
# 17/18. Public DevNet NOT launch-ready + C4/C5 OPEN in the new docs.
# ---------------------------------------------------------------------------
grep -qi 'NOT public-DevNet launch-ready' "${GUIDE}" || fail "guide must state NOT launch-ready"
grep -qi 'C4 remains OPEN' "${GUIDE}" && grep -qi 'C5 remains OPEN' "${GUIDE}" \
  || fail "guide must state C4/C5 remain OPEN"
emit "launch_and_c4c5=OK (public DevNet NOT launch-ready; C4 OPEN; C5 OPEN)"

# ---------------------------------------------------------------------------
# 19/20/21. Non-claim grep over guide + manifest (normalized).
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
# manifest non-claims must all be false
python3 - "${EXAMPLE}" <<'PY' || fail "manifest non_claims must all be false"
import json, sys
m = json.load(open(sys.argv[1]))
assert all(v is False for v in m["non_claims"].values())
print("non_claims_all_false=OK")
PY
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim; manifest non_claims all false)"

emit ""
emit "RESULT=POSITIVE (public-DevNet package integrity manifest published + verified against the on-disk package tree and the canonical readiness matrix; every listed file present + sha256/byte_size match; no production source change; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"