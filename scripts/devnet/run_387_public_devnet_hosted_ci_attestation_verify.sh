#!/usr/bin/env bash
# Run 387: public DevNet HOSTED-CI keyless attestation VERIFY harness.
#
# Purpose. Encapsulate the single publish-safe verification contract for the Run 386
# signing/attestation workflow (.github/workflows/public-devnet-release-signing-
# attestation.yml): verify a REAL keyless build-provenance attestation against the
# built release binary's SHA-256 and emit ONLY a publish-safe attestation IDENTITY
# summary (never the raw attestation blob, OIDC token, or any secret).
#
# Decision gate. Route A vs Route C is determined at RUN TIME, honestly:
#   * Route A (hosted GitHub CI): a built binary exists, `gh` is installed AND
#     authenticated, and GitHub's attestation API is reachable, so `gh attestation
#     verify <binary> --repo <owner>/<repo>` runs for real. Only if that command
#     PASSES does this harness record RESULT=POSITIVE and write ATTESTATION_IDENTITY.txt.
#   * Route C (offline sandbox / no hosted CI): any prerequisite is missing (no binary,
#     no `gh` auth, no network to the attestation store, or no minted attestation), so
#     this harness records RESULT=NEGATIVE-FOR-ATTESTATION with the EXACT missing
#     prerequisite and preserves the Run 386 preflight posture. It NEVER fakes a PASS.
#
# Honesty rules (hard):
#   * signed_release and slsa_grade STAY false. This harness does not flip the
#     schema-pinned manifest fields; a real attestation identity lives in a SEPARATE
#     publish-safe artifact only.
#   * No secret, private key, OIDC token, raw attestation bundle, raw log, raw /metrics
#     dump, data dir, private hostname, git branch, dirty-state string, or absolute
#     build path is emitted. Only owner/repo (public), the binary basename, its
#     SHA-256, and OK / status lines are printed.
#   * Creates NO release, tag, deployment, seed, or endpoint. Adds NO qbind-node CLI
#     flag. Builds nothing (the canonical injected build stays the Run 385 wrapper's
#     job, reused unchanged by the Run 386 workflow).
#
# Usage:
#   scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh [BINARY_PATH] [OUT_DIR]
# Defaults: BINARY_PATH=target/release/qbind-node, OUT_DIR=/tmp/qbind-run387-hosted-ci-attestation

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY_PATH="${1:-${REPO_ROOT}/target/release/qbind-node}"
OUT_DIR="${2:-/tmp/qbind-run387-hosted-ci-attestation}"
BIN_NAME="$(basename "${BINARY_PATH}")"

mkdir -p "${OUT_DIR}"

# Resolve owner/repo in a publish-safe way (prefer GITHUB_REPOSITORY in CI; else parse
# the git remote path only — never the host/credentials portion of the URL).
resolve_repo() {
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    printf '%s' "${GITHUB_REPOSITORY}"
    return 0
  fi
  local url path
  url="$(git -C "${REPO_ROOT}" config --get remote.origin.url 2>/dev/null || true)"
  # Strip scheme://host[:port]/ and any trailing .git, keeping only <owner>/<repo>.
  path="${url#*://}"
  path="${path#*/}"
  path="${path%.git}"
  printf '%s' "${path}"
}
OWNER_REPO="$(resolve_repo)"

# Non-fatal accumulation of the honest posture.
RESULT="NEGATIVE-FOR-ATTESTATION"
ROUTE="Route C"
BLOCKER=""
BINARY_SHA256=""
VERIFY_RESULT="NOT-RUN"
GH_PRESENT="no"
GH_AUTH="no"

if command -v gh >/dev/null 2>&1; then
  GH_PRESENT="yes"
  if gh auth status >/dev/null 2>&1; then
    GH_AUTH="yes"
  fi
fi

if [ -f "${BINARY_PATH}" ]; then
  BINARY_SHA256="$(sha256sum "${BINARY_PATH}" | awk '{print $1}')"
fi

# Gate the REAL verification on all Route-A prerequisites. Missing any one keeps us on
# Route C and records the precise blocker; nothing is faked.
if [ -z "${OWNER_REPO}" ]; then
  BLOCKER="owner/repo could not be resolved (set GITHUB_REPOSITORY or a git remote)."
elif [ ! -f "${BINARY_PATH}" ]; then
  BLOCKER="release binary '${BIN_NAME}' not built (the Run 385 wrapper builds it inside the Run 386 workflow)."
elif [ "${GH_PRESENT}" != "yes" ]; then
  BLOCKER="'gh' CLI not installed; cannot run 'gh attestation verify'."
elif [ "${GH_AUTH}" != "yes" ]; then
  BLOCKER="'gh' not authenticated and no OIDC/token available in this environment; cannot reach the GitHub attestation store."
else
  # Route-A candidate: every prerequisite present. Run the REAL verification. A
  # non-zero exit (e.g. no attestation minted yet) keeps RESULT negative and records
  # the exact failure — we never treat a failed verify as success.
  if VERIFY_OUT="$(gh attestation verify "${BINARY_PATH}" \
        --repo "${OWNER_REPO}" \
        --predicate-type https://slsa.dev/provenance/v1 2>&1)"; then
    RESULT="POSITIVE"
    ROUTE="Route A"
    VERIFY_RESULT="PASS"
    # Publish-safe attestation IDENTITY only. The attestation itself lives in GitHub's
    # attestation store; no raw blob/token is written here.
    ISSUER="$(printf '%s\n' "${VERIFY_OUT}" | grep -iE 'issuer|oidc' | head -1 | sed 's/^[[:space:]]*//' || true)"
    {
      printf 'workflow=public-devnet-release-signing-attestation\n'
      printf 'attestation_repo=%s\n' "${OWNER_REPO}"
      printf 'predicate_type=https://slsa.dev/provenance/v1\n'
      printf 'binary_name=%s\n' "${BIN_NAME}"
      printf 'binary_sha256=%s\n' "${BINARY_SHA256}"
      printf 'verifier_command=gh attestation verify %s --repo %s --predicate-type https://slsa.dev/provenance/v1\n' "${BIN_NAME}" "${OWNER_REPO}"
      printf 'verification=PASS\n'
      [ -n "${ISSUER}" ] && printf 'issuer_identity=%s\n' "${ISSUER}"
      printf 'signed_release=false\n'
      printf 'slsa_grade=false\n'
    } > "${OUT_DIR}/ATTESTATION_IDENTITY.txt"
  else
    VERIFY_RESULT="FAIL"
    BLOCKER="gh attestation verify did not pass (no minted attestation for this binary, or verification failed)."
  fi
fi

# --- publish-safe summary (this is what the archive tracks) ---
{
  echo "=== Run 387 hosted-CI keyless attestation verify ==="
  echo "objective=verify a REAL keyless build-provenance attestation against the built release binary SHA-256 and record publish-safe attestation identity only"
  echo "decision_gate=${ROUTE}"
  echo "attestation_repo=${OWNER_REPO}"
  echo "binary_name=${BIN_NAME}"
  if [ -n "${BINARY_SHA256}" ]; then
    echo "binary_sha256=${BINARY_SHA256}"
  else
    echo "binary_sha256=UNAVAILABLE (binary not built in this environment)"
  fi
  echo "gh_present=${GH_PRESENT} gh_authenticated=${GH_AUTH}"
  echo "verifier_command=gh attestation verify ${BIN_NAME} --repo ${OWNER_REPO} --predicate-type https://slsa.dev/provenance/v1"
  echo "verification=${VERIFY_RESULT}"
  echo "signed_release=false slsa_grade=false (unchanged; not flipped by this harness)"
  echo "schema_pins_false=EXPECTED (RELEASE_ARTIFACT_MANIFEST.schema.json keeps signed_release/slsa_grade const:false; real attestation identity goes in a separate artifact)"
  echo "no_secret_emitted=OK (only owner/repo, binary basename, SHA-256, status lines; no token/key/raw-attestation/log/metrics/data-dir/host/abs-path)"
  echo "no_release_or_endpoint=OK (creates no release/tag/deployment/seed/endpoint; adds no CLI flag; builds nothing)"
  if [ -n "${BLOCKER}" ]; then
    echo "blocker=${BLOCKER}"
  fi
  echo ""
  if [ "${RESULT}" = "POSITIVE" ]; then
    echo "RESULT=POSITIVE (Route A: real hosted-CI keyless attestation verified against ${BIN_NAME} SHA-256 ${BINARY_SHA256}; publish-safe ATTESTATION_IDENTITY.txt written; signed_release/slsa_grade unchanged at false)"
  else
    echo "RESULT=NEGATIVE-FOR-ATTESTATION (${ROUTE}: hosted-CI attestation could not be minted/verified from this environment — ${BLOCKER:-prerequisite missing}; Run 386 preflight posture preserved; signed_release=false slsa_grade=false)"
  fi
} | tee "${OUT_DIR}/summary.txt"