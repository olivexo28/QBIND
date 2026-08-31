#!/usr/bin/env bash
# Run 386: public DevNet release SIGNING / ATTESTATION preflight (local dry-run).
#
# Decision gate = Route B. A real, secret-free signing/attestation path EXISTS —
# GitHub artifact attestation via actions/attest-build-provenance (keyless Sigstore
# over GitHub OIDC, NO repository secrets) — but it requires the elevated
# `id-token: write` + `attestations: write` permissions and can only mint / verify a
# genuine attestation inside GitHub-hosted CI. It CANNOT run in this offline sandbox
# (no OIDC issuer, no cosign, `gh attestation verify` needs a real CI-minted
# attestation), so Run 386 ships a DISABLED-BY-DEFAULT, protected signing workflow
# plus the exact operator/CI prerequisites, and keeps the release-artifact manifest
# honest: signed_release=false and slsa_grade=false remain present and true (the
# committed schema pins both to const:false). No signature/attestation is produced or
# committed in this run; a real attestation is recorded only in a SEPARATE publish-safe
# artifact file by the CI job, never by flipping those fields or committing the blob.
#
# This preflight makes NO production Rust source change, NO build.rs change, NO runtime
# change, and adds NO new qbind-node CLI flag. It:
#   * lints BOTH the existing manifest workflow (unchanged, least-privilege) and the
#     new signing workflow (disabled-by-default; only id-token+attestations writes;
#     no secrets; protected environment; no release/deploy/commit);
#   * reuses the Run 385 wrapper (which reuses the Run 384 harness) to build the
#     canonical injected artifact and generate a schema-valid manifest from the REAL
#     binary + a LIVE loopback qbind_node_build_info scrape (regression);
#   * confirms signed_release=false / slsa_grade=false and that NO signature or
#     attestation is committed;
#   * preserves the CI artifact-upload safety, no-new-CLI-flag, and non-claim checks.

set -euo pipefail

CI_OUT="${1:-/tmp/qbind-run386-ci-release-signing-attestation}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN385="${REPO_ROOT}/scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh"
RUN384="${REPO_ROOT}/scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh"
MANIFEST_WF="${REPO_ROOT}/.github/workflows/public-devnet-release-artifact-manifest.yml"
SIGN_WF="${REPO_ROOT}/.github/workflows/public-devnet-release-signing-attestation.yml"
BIN_DIR="${REPO_ROOT}/docs/release/public-devnet/binary"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
SCHEMA="${BIN_DIR}/RELEASE_ARTIFACT_MANIFEST.schema.json"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"

RUN385_OUT="${CI_OUT}/run385"
STAGE="${CI_OUT}/ci-artifacts"
SUMMARY="${CI_OUT}/summary.txt"

log()  { printf '[run386] %s\n' "$*"; }
fail() { printf '[run386] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${CI_OUT}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

[ -f "${RUN385}" ]      || fail "Run 385 wrapper not found: ${RUN385}"
[ -f "${RUN384}" ]      || fail "Run 384 harness not found: ${RUN384}"
[ -f "${MANIFEST_WF}" ] || fail "manifest workflow not found: ${MANIFEST_WF}"
[ -f "${SIGN_WF}" ]     || fail "signing workflow not found: ${SIGN_WF}"
[ -f "${SCHEMA}" ]      || fail "schema not found: ${SCHEMA}"

emit "=== Run 386 release signing/attestation preflight ==="
emit "decision_gate=Route B (secret-free GitHub artifact attestation path exists but requires elevated id-token:write + attestations:write in a protected CI environment and cannot be minted/verified in this offline sandbox; ship a disabled-by-default protected workflow + exact prerequisites; keep signed_release=false slsa_grade=false honest; no signature/attestation produced or committed)"
emit "signing_workflow=.github/workflows/public-devnet-release-signing-attestation.yml (disabled by default)"
emit "reused_manifest_workflow=.github/workflows/public-devnet-release-artifact-manifest.yml (unchanged)"
emit "reused_wrapper=scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh"

# ---------------------------------------------------------------------------
# 0. CRLF guard for the executed SHELL harnesses (bash aborts on CRLF: a
#    `set -euo pipefail\r` line fails with "set: pipefail: invalid option name").
#    YAML workflows tolerate CRLF (GitHub Actions parses them fine), so they are
#    not gated here.
# ---------------------------------------------------------------------------
for f in "${RUN384}" "${RUN385}" "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"; do
  if grep -qU $'\r' "$f" 2>/dev/null; then
    fail "$(basename "$f") has CRLF line endings; normalize to LF so CI/Linux bash can execute it"
  fi
done
emit "crlf_guard=OK (reused shell harnesses run_384/run_385 + this preflight are LF; executable on Linux/CI)"

# ---------------------------------------------------------------------------
# 1. Static safety lint of the NEW signing/attestation workflow.
# ---------------------------------------------------------------------------
python3 - "${SIGN_WF}" <<'PY' || fail "signing workflow YAML failed structural checks"
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
assert isinstance(doc, dict), "workflow is not a mapping"
# PyYAML parses the bare `on:` key as boolean True.
triggers = doc.get("on", doc.get(True))
assert triggers is not None, "workflow has no triggers"
assert set(triggers.keys()) == {"workflow_dispatch"}, f"signing workflow must be manual-only, got {list(triggers)}"
inp = (triggers["workflow_dispatch"] or {}).get("inputs", {})
assert "confirm" in inp, "missing opt-in `confirm` input"
assert str(inp["confirm"].get("default")).lower() == "no", "confirm input must default to 'no' (disabled by default)"
# Top-level least privilege.
assert doc.get("permissions") == {"contents": "read"}, f"top-level permissions not contents:read: {doc.get('permissions')!r}"
jobs = doc.get("jobs", {})
assert len(jobs) == 1, "expected exactly one job"
job = next(iter(jobs.values()))
cond = str(job.get("if", ""))
assert "confirm" in cond and "'yes'" in cond, f"job not gated on confirm == 'yes': {cond!r}"
assert job.get("environment") == "release-signing", "job must target the protected release-signing environment"
perms = job.get("permissions", {})
# Only the two writes required for keyless attestation; contents stays read.
assert perms.get("contents") == "read", "job contents permission must be read"
writes = {k for k, v in perms.items() if v == "write"}
assert writes == {"id-token", "attestations"}, f"job write scopes must be exactly id-token+attestations, got {writes}"
# Must actually use the attestation action + a verify step.
blob = open(sys.argv[1]).read()
assert "actions/attest-build-provenance@" in blob, "workflow does not use actions/attest-build-provenance"
assert "gh attestation verify" in blob, "workflow does not verify the attestation"
print("signing_workflow_ok")
PY
emit "signing_workflow_yaml=OK (manual-only; confirm defaults 'no'; job gated on confirm=='yes'; protected environment 'release-signing'; top-level permissions contents:read; job writes limited to id-token+attestations; attest-build-provenance + gh attestation verify present)"

# Raw-text assertions: no secrets, no release/deploy, no commit/push, no broad writes.
if grep -Eiq 'secrets\.[A-Za-z_]' "${SIGN_WF}"; then
  fail "signing workflow references a repository secret (keyless OIDC path must use no secrets)"
fi
if grep -Eq '(contents|packages|deployments|pull-requests|issues)[[:space:]]*:[[:space:]]*write' "${SIGN_WF}"; then
  fail "signing workflow requests a forbidden write scope (only id-token + attestations write allowed)"
fi
if grep -Eiq 'softprops/action-gh-release|actions/create-release|gh release create|create-deployment|gh deploy|repository_dispatch' "${SIGN_WF}"; then
  fail "signing workflow creates a release/deployment (out of scope)"
fi
if grep -Eiq 'git[[:space:]]+push|git[[:space:]]+commit|add-and-commit|stefanzweifel/git-auto-commit' "${SIGN_WF}"; then
  fail "signing workflow commits/pushes (must not commit signatures/attestations)"
fi
emit "signing_workflow_no_secrets=OK (no secrets.* reference; keyless Sigstore over GitHub OIDC)"
emit "signing_workflow_least_privilege=OK (only id-token:write + attestations:write elevated; contents stays read; no packages/deployments/contents write)"
emit "signing_workflow_no_release=OK (no release/tag/deployment; no commit/push of signatures/attestations)"

# ---------------------------------------------------------------------------
# 2. Re-assert the existing manifest workflow is unchanged / least-privilege.
# ---------------------------------------------------------------------------
python3 - "${MANIFEST_WF}" <<'PY' || fail "manifest workflow YAML failed checks"
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
assert doc.get("permissions") == {"contents": "read"}, "manifest workflow permissions regressed"
print("manifest_workflow_ok")
PY
if grep -Eiq 'secrets\.[A-Za-z_]' "${MANIFEST_WF}"; then fail "manifest workflow now references a secret"; fi
emit "manifest_workflow_unchanged=OK (permissions: contents: read; no secrets; Run 385 posture preserved)"

# actionlint if available (optional; non-fatal absence).
if command -v actionlint >/dev/null 2>&1; then
  actionlint "${SIGN_WF}" "${MANIFEST_WF}" && emit "actionlint=OK" || fail "actionlint reported problems"
else
  emit "actionlint=SKIP (actionlint not installed; PyYAML parse + static checks used instead)"
fi

# ---------------------------------------------------------------------------
# 3. Regression: reuse the Run 385 wrapper (build + manifest + all Run 384/385 checks).
# ---------------------------------------------------------------------------
rm -rf "${RUN385_OUT}"
mkdir -p "${RUN385_OUT}"
log "invoking Run 385 wrapper (canonical injected build + manifest + schema validation + live scrape cross-check + Run 385 safety checks)"
bash "${RUN385}" "${RUN385_OUT}" | sed 's/^/[run385] /'
grep -q '^RESULT=POSITIVE' "${RUN385_OUT}/summary.txt" || fail "Run 385 wrapper did not report RESULT=POSITIVE"
MANIFEST="${RUN385_OUT}/ci-artifacts/RELEASE_ARTIFACT_MANIFEST.json"
[ -f "${MANIFEST}" ] || fail "Run 385 did not produce RELEASE_ARTIFACT_MANIFEST.json"
[ -x "${NODE_BIN}" ] || fail "canonical release binary missing after Run 385 build: ${NODE_BIN}"
emit "run385_regression=OK (RESULT=POSITIVE; canonical injected build + schema-valid manifest + live metric cross-check preserved)"

GC="$(jq -r '.injected_QBIND_GIT_COMMIT' "${MANIFEST}")"
BID="$(jq -r '.injected_QBIND_BUILD_ID' "${MANIFEST}")"
SHA="$(jq -r '.binary_sha256' "${MANIFEST}")"
ELF="$(jq -r '.elf_build_id' "${MANIFEST}")"
emit "canonical_git_commit=${GC}"
emit "canonical_build_id=${BID}"
emit "binary_sha256=${SHA}"
emit "elf_build_id=${ELF}"

# ---------------------------------------------------------------------------
# 4. Honest manifest posture: signed_release=false / slsa_grade=false (Route B).
# ---------------------------------------------------------------------------
jq -e '.reproducibility_scope | ((.signed_release|not) and (.slsa_grade|not))' "${MANIFEST}" >/dev/null \
  || fail "manifest does not record signed_release=false / slsa_grade=false"
jq -e '.non_claims | (.no_signed_release and .no_slsa_provenance)' "${MANIFEST}" >/dev/null \
  || fail "manifest non_claims must keep no_signed_release and no_slsa_provenance true"
emit "signed_release=false slsa_grade=false (present and true; no real attestation produced/verified in this offline preflight)"

# The committed schema pins both fields to false: a real attestation must live in a
# SEPARATE artifact file, never by flipping these fields.
jq -e '.properties.reproducibility_scope.properties.signed_release.const == false and .properties.reproducibility_scope.properties.slsa_grade.const == false' "${SCHEMA}" >/dev/null \
  || fail "schema no longer pins signed_release/slsa_grade to false"
emit "schema_pins_false=OK (RELEASE_ARTIFACT_MANIFEST.schema.json keeps signed_release/slsa_grade const:false; real attestation identity goes in a separate artifact file)"

# ---------------------------------------------------------------------------
# 5. No signature / attestation / signing key material is committed to git.
# ---------------------------------------------------------------------------
SIG_TRACKED="$(git -C "${REPO_ROOT}" ls-files \
  '*.sig' '*.sigstore' '*.sigstore.json' '*.intoto.jsonl' '*.dsse' \
  '*.attestation' '*ATTESTATION_IDENTITY.txt' '*.pem' '*.key' '*.p12' 2>/dev/null || true)"
[ -z "${SIG_TRACKED}" ] || { printf '%s\n' "${SIG_TRACKED}" >&2; fail "a signature/attestation/key artifact is tracked in git"; }
emit "no_signature_committed=OK (no *.sig/*.sigstore/*.intoto.jsonl/*.dsse/ATTESTATION_IDENTITY/private-key artifact tracked in git)"

# ---------------------------------------------------------------------------
# 6. Stage ONLY publish-safe preflight artifacts (no signature blob, no manifest into git).
# ---------------------------------------------------------------------------
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
cp "${MANIFEST}" "${STAGE}/RELEASE_ARTIFACT_MANIFEST.json"
printf '%s  qbind-node\n' "${SHA}" > "${STAGE}/qbind-node.sha256"
printf 'ELF .note.gnu.build-id: %s\n' "${ELF}" > "${STAGE}/BUILDID.txt"
cat > "${STAGE}/SIGNING_PREFLIGHT.txt" <<EOF
decision_gate=Route B
signing_path=GitHub artifact attestation (actions/attest-build-provenance, keyless Sigstore over GitHub OIDC; zero repository credential material)
required_permissions=contents:read + id-token:write + attestations:write (job-scoped only)
protected_environment=release-signing (operator-configured required reviewers)
sandbox_status=UNAVAILABLE (no OIDC issuer / cosign; gh attestation verify needs a real CI-minted attestation)
signed_release=false
slsa_grade=false
verify_when_enabled=gh attestation verify target/release/qbind-node --repo <owner>/<repo>
EOF

# ---------------------------------------------------------------------------
# 7. Re-validate the staged manifest against the committed schema (independent).
# ---------------------------------------------------------------------------
python3 -c "import json,jsonschema; \
 s=json.load(open('${SCHEMA}')); \
 i=json.load(open('${STAGE}/RELEASE_ARTIFACT_MANIFEST.json')); \
 jsonschema.validate(i,s); print('staged manifest OK')" \
  || fail "staged manifest failed independent schema validation"
emit "staged_manifest_schema_valid=OK (staged RELEASE_ARTIFACT_MANIFEST.json validates against committed schema)"
emit "ci_artifacts_staged=OK ($(cd "${STAGE}" && ls | tr '\n' ' '))"

# ---------------------------------------------------------------------------
# 8. Artifact upload safety: no raw logs/metrics/data dirs, no secret/host/endpoint.
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
emit "artifact_upload_safety=OK (staged dir excludes raw logs/metrics/data dirs; no absolute path/host/endpoint/secret/raw-metrics-dump/signing-key)"

# ---------------------------------------------------------------------------
# 9. No new qbind-node CLI flag (exposure stays QBIND_METRICS_HTTP_ADDR env only).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" --help 2>&1 | grep -Eiq -- '--metrics|--observ|--scrape-|--prometheus|--telemetry|--build-info|--build-id|--git-commit|--provenance|--manifest|--artifact|--sign-release|--attest|--slsa|--sigstore|--cosign'; then
  fail "unexpected provenance/release-signing/manifest CLI flag present in --help"
fi
emit "no_new_cli_flag=OK (no provenance/release-signing/attestation/manifest CLI flag; pre-existing consensus --signer-* flags unchanged; exposure remains QBIND_METRICS_HTTP_ADDR env only)"

# ---------------------------------------------------------------------------
# 10. Non-claim grep over the release-binary + observability packages.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${OBS_DIR}" "${BIN_DIR}" 2>/dev/null | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|remains? (open|yellow|red)|grep |negat|no doc claims|matches present|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "release/observability docs contain a forbidden readiness claim"; }
emit "non_claim_check=OK (no launch-ready / M4-Green / TestNet/MainNet / C4/C5-closure claim in release+observability docs)"

# ---------------------------------------------------------------------------
# 11. Observability example YAML still parses (no metric/alert change).
# ---------------------------------------------------------------------------
for y in "${OBS_DIR}"/prometheus-*.example.yml; do
  [ -f "$y" ] || continue
  python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1])); print('yaml_ok', sys.argv[1])" "$y" \
    || fail "observability example YAML failed to parse: $y"
done
emit "observability_yaml_parse=OK (prometheus example YAML unchanged and still parses)"

emit "committed_private_material=NONE (no signature/attestation/private key committed; generated manifest stays a CI artifact; only publish-safe hashes/status lines land in the tracked summary)"
emit ""
emit "RESULT=POSITIVE (Route B: disabled-by-default protected signing/attestation workflow .github/workflows/public-devnet-release-signing-attestation.yml added with the exact operator/CI prerequisites — keyless GitHub artifact attestation over OIDC, no secrets, job-scoped id-token+attestations writes, protected release-signing environment, confirm-gated; Run 385 regression RESULT=POSITIVE with canonical injected build git_commit=${GC} build_id=${BID}, binary_sha256=${SHA}, elf_build_id=${ELF}; schema-valid manifest from the REAL binary + live loopback scrape; signed_release=false slsa_grade=false present and true; schema still pins both false; no signature/attestation/private key produced or committed; publish-safe artifacts staged excluding raw logs/metrics/data dirs; no new CLI flag; metrics disabled-by-default and loopback-only; M12/M13/M14 remain Green; M4 stays Yellow; M6 Yellow/Partial; public DevNet NOT launch-ready; C4/C5 OPEN)"
