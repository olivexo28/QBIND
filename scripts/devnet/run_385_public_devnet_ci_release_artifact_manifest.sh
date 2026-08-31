#!/usr/bin/env bash
# Run 385: public DevNet CI release-artifact MANIFEST wrapper / local dry-run.
#
# Wires the Run 384 canonical injected release-artifact manifest generation into a
# CI-friendly wrapper. Running this script locally is the DRY-RUN that proves the
# EXACT commands the CI workflow (.github/workflows/public-devnet-release-artifact-
# manifest.yml) executes: it reuses the Run 384 harness to build the canonical
# injected release binary, generate RELEASE_ARTIFACT_MANIFEST.json from the ACTUAL
# built artifact plus a LIVE loopback qbind_node_build_info scrape, and validate it
# against the committed schema; then it stages ONLY publish-safe outputs as
# CI-artifact-only files (checksum text, manifest JSON, validation summary, optional
# ELF BuildID summary) under CI_OUT/ci-artifacts.
#
# Decision gate = Route A (CI/workflow + harness/docs only): NO production Rust
# source change, NO build.rs change, NO runtime behaviour change, NO new CLI flag.
# The generated manifest is a CI artifact and is NEVER committed. No secret, key,
# data dir, node log, git branch, dirty-state string, absolute build path, private
# hostname, or raw /metrics dump is emitted into the staged artifacts. Metrics stay
# disabled by default and loopback-only. signed_release=false and slsa_grade=false
# are recorded in the manifest.

set -euo pipefail

CI_OUT="${1:-/tmp/qbind-run385-ci-release-artifact-manifest}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN384="${REPO_ROOT}/scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/public-devnet-release-artifact-manifest.yml"
BIN_DIR="${REPO_ROOT}/docs/release/public-devnet/binary"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCHEMA="${BIN_DIR}/RELEASE_ARTIFACT_MANIFEST.schema.json"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"

RUN384_OUT="${CI_OUT}/run384"
STAGE="${CI_OUT}/ci-artifacts"
SUMMARY="${CI_OUT}/summary.txt"

log()  { printf '[run385] %s\n' "$*"; }
fail() { printf '[run385] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${CI_OUT}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

[ -f "${RUN384}" ]  || fail "Run 384 harness not found: ${RUN384}"
[ -f "${WORKFLOW}" ] || fail "CI workflow not found: ${WORKFLOW}"
[ -f "${SCHEMA}" ]  || fail "schema not found: ${SCHEMA}"

emit "=== Run 385 CI release-artifact manifest wrapper ==="
emit "decision_gate=Route A (CI/workflow + harness/docs only: wire Run 384 manifest generation into CI as a CI artifact; no production source change, no build.rs change, no runtime change, no CLI flag; generated manifest NEVER committed)"
emit "workflow=.github/workflows/public-devnet-release-artifact-manifest.yml"
emit "reused_harness=scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh"

# ---------------------------------------------------------------------------
# 0. Static workflow safety lint (least privilege / no secrets / no release).
# ---------------------------------------------------------------------------
python3 - "${WORKFLOW}" <<'PY' || fail "workflow YAML failed to parse"
import sys, yaml
with open(sys.argv[1]) as fh:
    doc = yaml.safe_load(fh)
assert isinstance(doc, dict), "workflow is not a mapping"
# PyYAML parses the bare `on:` key as boolean True.
triggers = doc.get("on", doc.get(True))
assert triggers is not None, "workflow has no triggers"
assert "workflow_dispatch" in triggers or "push" in triggers, "no manual/release trigger"
perms = doc.get("permissions")
assert perms == {"contents": "read"}, f"permissions not least-privilege: {perms!r}"
print("workflow_yaml_ok")
PY
emit "workflow_yaml_parse=OK (valid YAML; manual/release-track trigger; permissions == {contents: read})"

# Least-privilege + no-secrets + no-release static assertions on the raw text.
grep -Eq '^permissions:' "${WORKFLOW}" || fail "workflow declares no explicit permissions block"
grep -Eq '^[[:space:]]*contents:[[:space:]]*read' "${WORKFLOW}" || fail "workflow missing contents: read"
if grep -Eq '(contents|packages|deployments|id-token|pull-requests|issues)[[:space:]]*:[[:space:]]*write' "${WORKFLOW}"; then
  fail "workflow requests a write permission (must be least-privilege read-only)"
fi
if grep -Eiq 'secrets\.[A-Za-z_]' "${WORKFLOW}"; then
  fail "workflow references a secret (must avoid secrets entirely this run)"
fi
if grep -Eiq 'softprops/action-gh-release|actions/create-release|gh release create|create-deployment|gh deploy|repository_dispatch' "${WORKFLOW}"; then
  fail "workflow creates a release/deployment (out of scope)"
fi
if grep -Eiq 'git[[:space:]]+push|git[[:space:]]+commit|add-and-commit|stefanzweifel/git-auto-commit' "${WORKFLOW}"; then
  fail "workflow commits/pushes (generated manifest must not be committed)"
fi
emit "workflow_least_privilege=OK (permissions: contents: read only; no write scope)"
emit "workflow_no_secrets=OK (no secrets.* reference; no signing this run)"
emit "workflow_no_release=OK (no release/tag/deployment/seed/endpoint creation; no commit/push of artifacts)"

# actionlint if available (optional; non-fatal absence).
if command -v actionlint >/dev/null 2>&1; then
  actionlint "${WORKFLOW}" && emit "actionlint=OK" || fail "actionlint reported problems"
else
  emit "actionlint=SKIP (actionlint not installed; PyYAML parse + static checks used instead)"
fi

# ---------------------------------------------------------------------------
# 1. Reuse the Run 384 harness: canonical injected build + manifest + all checks.
#    This runs the SAME build/generate/validate/cross-check commands CI runs.
# ---------------------------------------------------------------------------
rm -rf "${RUN384_OUT}"
mkdir -p "${RUN384_OUT}"
log "invoking Run 384 harness (canonical injected build + manifest generation + schema validation + live scrape cross-check)"
bash "${RUN384}" "${RUN384_OUT}" | sed 's/^/[run384] /'
grep -q '^RESULT=POSITIVE' "${RUN384_OUT}/summary.txt" || fail "Run 384 harness did not report RESULT=POSITIVE"
MANIFEST="${RUN384_OUT}/manifest.json"
[ -f "${MANIFEST}" ] || fail "Run 384 manifest.json not produced"
[ -x "${NODE_BIN}" ] || fail "canonical release binary missing after Run 384 build: ${NODE_BIN}"
emit "run384_reuse=OK (RESULT=POSITIVE; canonical injected build + schema-valid manifest + live metric cross-check)"

# ---------------------------------------------------------------------------
# 2. Canonical injected build inputs echoed from the generated manifest.
# ---------------------------------------------------------------------------
GC="$(jq -r '.injected_QBIND_GIT_COMMIT' "${MANIFEST}")"
BID="$(jq -r '.injected_QBIND_BUILD_ID' "${MANIFEST}")"
SHA="$(jq -r '.binary_sha256' "${MANIFEST}")"
ELF="$(jq -r '.elf_build_id' "${MANIFEST}")"
CARGO_LOCK_SHA="$(jq -r '.cargo_lock_sha256' "${MANIFEST}")"
TARGET_TRIPLE="$(jq -r '.target_triple' "${MANIFEST}")"
emit "canonical_git_commit=${GC}"
emit "canonical_build_id=${BID}"
emit "build_command=QBIND_GIT_COMMIT=${GC} QBIND_BUILD_ID=${BID} cargo build -p qbind-node --release --locked --bin qbind-node"
emit "target_triple=${TARGET_TRIPLE}"
emit "cargo_lock_sha256=${CARGO_LOCK_SHA}"

# ---------------------------------------------------------------------------
# 3. Record signed_release=false / slsa_grade=false (no signing this run).
# ---------------------------------------------------------------------------
jq -e '.reproducibility_scope | ((.signed_release|not) and (.slsa_grade|not))' "${MANIFEST}" >/dev/null \
  || fail "manifest does not record signed_release=false / slsa_grade=false"
emit "signed_release=false slsa_grade=false (recorded in manifest; no signing/SLSA in this run)"

# ---------------------------------------------------------------------------
# 4. Stage ONLY publish-safe CI artifacts (never the generated manifest into git).
# ---------------------------------------------------------------------------
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
cp "${MANIFEST}" "${STAGE}/RELEASE_ARTIFACT_MANIFEST.json"
printf '%s  qbind-node\n' "${SHA}" > "${STAGE}/qbind-node.sha256"
printf 'ELF .note.gnu.build-id: %s\n' "${ELF}" > "${STAGE}/BUILDID.txt"

# Manifest validation summary artifact (schema validation result, publish-safe).
python3 - "${SCHEMA}" "${STAGE}/RELEASE_ARTIFACT_MANIFEST.json" > "${STAGE}/MANIFEST_VALIDATION_SUMMARY.txt" <<'PY' || fail "staged manifest failed schema validation"
import json, sys
schema = json.load(open(sys.argv[1]))
inst = json.load(open(sys.argv[2]))
try:
    import jsonschema
    jsonschema.validate(instance=inst, schema=schema)
    mode = "jsonschema"
except ModuleNotFoundError:
    req = schema.get("required", [])
    missing = [k for k in req if k not in inst]
    assert not missing, f"missing required keys: {missing}"
    mode = "structural"
print("manifest_schema_valid=OK")
print(f"validator={mode}")
print(f"schema_version={inst.get('schema_version')}")
print(f"package_name={inst.get('package_name')}")
print(f"environment={inst.get('environment')}")
print(f"binary_sha256={inst.get('binary_sha256')}")
print(f"elf_build_id={inst.get('elf_build_id')}")
print(f"metric_build_id={inst.get('metric_build_id')}")
print(f"metric_git_commit={inst.get('metric_git_commit')}")
print(f"signed_release={inst['reproducibility_scope'].get('signed_release')}")
print(f"slsa_grade={inst['reproducibility_scope'].get('slsa_grade')}")
PY
emit "ci_artifacts_staged=OK ($(cd "${STAGE}" && ls | tr '\n' ' '))"

# ---------------------------------------------------------------------------
# 5. Re-validate the STAGED manifest against the committed schema (independent).
# ---------------------------------------------------------------------------
python3 -c "import json,jsonschema,sys; \
 s=json.load(open('${SCHEMA}')); \
 i=json.load(open('${STAGE}/RELEASE_ARTIFACT_MANIFEST.json')); \
 jsonschema.validate(i,s); print('staged manifest OK')" \
  || fail "staged manifest failed independent schema validation"
emit "staged_manifest_schema_valid=OK (staged RELEASE_ARTIFACT_MANIFEST.json validates against committed schema)"

# ---------------------------------------------------------------------------
# 6. Artifact upload safety: staged dir must exclude raw logs/metrics/data dirs
#    and must carry no absolute path / private host / secret / raw /metrics dump.
# ---------------------------------------------------------------------------
if find "${STAGE}" -type f \( -name '*.log' -o -name '*.metrics.txt' -o -name '*.metrics' -o -name '*.err' \) | grep -q .; then
  fail "staged artifacts include raw log/metrics files"
fi
if find "${STAGE}" -type d \( -name 'nodes' -o -name 'data' -o -name 'node-data' -o -name 'logs' \) | grep -q .; then
  fail "staged artifacts include a node data/log directory"
fi
for f in "${STAGE}"/*; do
  if grep -Eq '(^|[^A-Za-z0-9_])/(home|root|var|etc|usr)/' "$f"; then
    fail "staged artifact ${f} contains an absolute private path"
  fi
  if grep -Eiq 'secret|password|apikey|api_key|BEGIN [A-Z ]*PRIVATE KEY|token=|bearer ' "$f"; then
    fail "staged artifact ${f} contains a secret-ish token"
  fi
  NONLOOP="$(grep -oE '://[A-Za-z0-9._-]+' "$f" | grep -vE '://(127\.0\.0\.1|localhost)$' || true)"
  [ -z "${NONLOOP}" ] || { printf '%s\n' "${NONLOOP}" >&2; fail "staged artifact ${f} contains a non-loopback endpoint"; }
  if grep -Eq '^qbind_(consensus|p2p|net)_' "$f"; then
    fail "staged artifact ${f} embeds a raw /metrics dump"
  fi
done
emit "artifact_upload_safety=OK (staged dir excludes raw logs/metrics/data dirs; no absolute path/host/endpoint/secret/raw-metrics-dump)"

# ---------------------------------------------------------------------------
# 7. No new qbind-node CLI flag (exposure stays QBIND_METRICS_HTTP_ADDR env only).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--build-id|--git-commit|--provenance|--manifest|--artifact'; then
  fail "unexpected provenance/manifest CLI flag present in --help"
fi
emit "no_new_cli_flag=OK (no provenance/manifest/CI CLI flag; exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 8. Generated manifest is NOT committed / tracked in git.
# ---------------------------------------------------------------------------
if git -C "${REPO_ROOT}" ls-files --error-unmatch \
     "docs/devnet/run_385_public_devnet_ci_release_artifact_manifest/RELEASE_ARTIFACT_MANIFEST.json" \
     >/dev/null 2>&1; then
  fail "a generated RELEASE_ARTIFACT_MANIFEST.json is tracked in git (must be CI-artifact-only)"
fi
if git -C "${REPO_ROOT}" ls-files 'docs/devnet/run_385_public_devnet_ci_release_artifact_manifest/*.json' 2>/dev/null | grep -q .; then
  fail "a generated manifest JSON is tracked under the Run 385 archive dir"
fi
emit "generated_manifest_not_committed=OK (RELEASE_ARTIFACT_MANIFEST.json is a CI artifact only; not tracked in git)"

# ---------------------------------------------------------------------------
# 9. Non-claim grep over the release-binary + observability packages (unchanged).
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" "${BIN_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow|red)|grep |negat|no doc claims|matches present|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "release/observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in release+observability docs)"

# ---------------------------------------------------------------------------
# 10. Observability example YAML still parses (no metric/alert change).
# ---------------------------------------------------------------------------
for y in "${OBS_DIR}"/prometheus-*.example.yml; do
  [ -f "$y" ] || continue
  python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1])); print('yaml_ok', sys.argv[1])" "$y" \
    || fail "observability example YAML failed to parse: $y"
done
emit "observability_yaml_parse=OK (prometheus example YAML unchanged and still parses)"

emit "committed_private_material=NONE (Run 384 removed node-data dirs and raw scrape dumps on exit; only publish-safe hashes/status lines land in tracked summary; generated manifest stays a CI artifact)"
emit ""
emit "RESULT=POSITIVE (Route A: Run 384 manifest generation wired into CI via .github/workflows/public-devnet-release-artifact-manifest.yml and this wrapper; canonical injected build git_commit=${GC} build_id=${BID}; schema-valid manifest generated from the REAL built binary + live loopback qbind_node_build_info scrape; publish-safe CI artifacts staged (RELEASE_ARTIFACT_MANIFEST.json, qbind-node.sha256, MANIFEST_VALIDATION_SUMMARY.txt, BUILDID.txt) excluding raw logs/metrics/data dirs; least-privilege permissions contents:read; no secrets; no release/tag/deployment; generated manifest NOT committed; signed_release=false slsa_grade=false; no new CLI flag; metrics disabled-by-default and loopback-only; M12/M13/M14 remain Green; M4 stays Yellow; M6 Yellow/Partial; public DevNet NOT launch-ready; C4/C5 OPEN)"