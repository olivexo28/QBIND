#!/usr/bin/env bash
# Run 417: foundational runtime-security reconciliation AUDIT harness.
#
# This harness is READ-ONLY and fail-closed. It verifies the COMPLETENESS and INTERNAL
# CONSISTENCY of the Run 417 audit archive and the two canonical Run 417 records. It does NOT
# implement, prove, or bless any security fix. It never modifies production Rust, opens a port,
# publishes a seed, mutates trust/validator/epoch state, or moves a readiness item Green.
#
# The audit's SECURITY verdict is NEGATIVE (deployed consensus authentication is fail-open).
# This harness therefore separates two distinct axes and NEVER conflates them:
#   * audit-completeness (can be POSITIVE)   -> RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS
#   * runtime-security   (is NEGATIVE)       -> SECURITY_VERDICT=NEGATIVE-FOR-RUNTIME-SECURITY
# A bare "PASS" is intentionally never emitted so it cannot be misread as security readiness.
#
# It FAILS CLOSED if:
#   * a required audit artifact or canonical record is missing;
#   * any of the four security domains is absent from the findings matrix;
#   * any finding lacks a finding_classification or source_evidence;
#   * the taxonomy / severity vocabulary is missing;
#   * the summary emits generic PASS wording or omits the NEGATIVE security verdict;
#   * a Run 417 doc claims a production fix / bypass / Green move / launch-readiness / C4-C5
#     closure / TestNet-MainNet readiness / a live seed;
#   * devnet-seeds.live.json exists, the candidate is not planned/null, or the current status
#     documents do not preserve C4/C5 OPEN + public DevNet NO-GO + M4 Yellow;
#   * SHA256SUMS.txt does not cover every tracked archive file except itself and .gitignore, or
#     `sha256sum -c` fails;
#   * a secret / private-material token appears in a Run 417-authored file.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE="${REPO_ROOT}/docs/devnet/run_417_foundational_runtime_security_reconciliation"
EVIDENCE="${REPO_ROOT}/docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md"
RECON="${REPO_ROOT}/docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md"
NETDIR="${REPO_ROOT}/docs/release/public-devnet/network"
CANDIDATE="${NETDIR}/devnet-seeds.live-candidate.json"
READINESS="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
C4C5="${REPO_ROOT}/docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md"

fail() { echo "FAIL: $*" >&2; echo "RESULT=NEGATIVE-FOR-AUDIT-COMPLETENESS"; exit 1; }
ok()   { echo "  ok: $*"; }

echo "== Run 417 audit-completeness harness =="
echo "repo_root=${REPO_ROOT}"

# 1) Required artifacts must exist.
REQ_ARCHIVE=(README.md summary.txt source_trace.txt findings_matrix.txt commands.txt SHA256SUMS.txt .gitignore)
for f in "${REQ_ARCHIVE[@]}"; do
  [ -f "${ARCHIVE}/${f}" ] || fail "missing archive artifact: ${f}"
done
ok "archive artifacts present"
[ -f "${EVIDENCE}" ] || fail "missing canonical evidence record QBIND_DEVNET_EVIDENCE_RUN_417.md"
[ -f "${RECON}" ]    || fail "missing reconciliation record QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md"
ok "canonical records present"

MATRIX="${ARCHIVE}/findings_matrix.txt"
SUMMARY="${ARCHIVE}/summary.txt"

# 2) All four security domains present in the matrix.
for dom in TRANSACTION CONSENSUS PEER-IDENTITY-BINDING QUORUM-CERTIFICATE; do
  grep -q "security_domain: ${dom}" "${MATRIX}" || fail "security domain absent from matrix: ${dom}"
done
ok "all four security domains present"

# 3) Every finding has a classification and source evidence, and they are balanced.
n_findings=$(grep -c '^FINDING ' "${MATRIX}" || true)
[ "${n_findings}" -ge 8 ] || fail "expected >=8 findings, found ${n_findings}"
n_class=$(grep -c '^finding_classification: ' "${MATRIX}" || true)
n_src=$(grep -c '^source_evidence: ' "${MATRIX}" || true)
n_sev=$(grep -c '^severity: ' "${MATRIX}" || true)
[ "${n_class}" -eq "${n_findings}" ] || fail "each finding needs a finding_classification (${n_class}/${n_findings})"
[ "${n_src}" -eq "${n_findings}" ]   || fail "each finding needs source_evidence (${n_src}/${n_findings})"
[ "${n_sev}" -eq "${n_findings}" ]   || fail "each finding needs severity (${n_sev}/${n_findings})"
ok "findings=${n_findings}, all have classification/source_evidence/severity"

# 4) Taxonomy + severity vocabulary must be present.
for tok in VERIFIED-FAIL-OPEN VERIFIED-INCOMPLETE MITIGATED-BY-CURRENT-UNREACHABILITY; do
  grep -q "${tok}" "${MATRIX}" || fail "taxonomy token missing from matrix: ${tok}"
done
grep -Eq 'severity: (Critical|High|Medium|Low|Informational)' "${MATRIX}" || fail "severity vocabulary missing"
ok "taxonomy + severity vocabulary present"

# 5) Overall result must distinguish audit-completeness from security readiness (no bare PASS).
grep -q 'AUDIT-COMPLETE / NEGATIVE-FOR-RUNTIME-SECURITY' "${SUMMARY}" || fail "summary must state AUDIT-COMPLETE / NEGATIVE-FOR-RUNTIME-SECURITY"
grep -Eq 'security_verdict=NEGATIVE' "${SUMMARY}" || fail "summary must record a NEGATIVE security verdict"
if grep -Eiq '(^|[^-])RESULT=PASS|overall.?result=pass|verdict=pass\b' "${SUMMARY}"; then
  fail "generic PASS wording could be misread as security readiness"
fi
ok "overall result separates audit completeness from security verdict"

# 6) No Run 417 doc may claim a production fix / bypass / Green move / readiness overclaim.
#    The check is negation-aware: it flags only POSITIVE assertions. Lines that negate the
#    phrase (e.g. "NOT launch-ready", "remains OPEN", "no readiness item moves Green") are the
#    required current-state posture and must NOT trip the guard.
AUTHORED=("${EVIDENCE}" "${RECON}" "${ARCHIVE}/README.md" "${SUMMARY}" "${MATRIX}" "${ARCHIVE}/source_trace.txt" "${ARCHIVE}/commands.txt")
# Positive overclaim phrasings (would be false if asserted by a Run 417 audit doc):
OVERCLAIM='devnet-seeds\.live\.json (is |was )?(now )?(published|created)|(is|are|now|becomes|declared) (public devnet )?launch-?ready|LAUNCH[ =]GO\b|move[sd]? (to )?green|C4/C5 (closed|closure achieved)|(is|are|now) (testnet|mainnet)[ -]ready|authentication bypass added|fix (landed|applied|implemented|is in) (production|the deployed)'
# Negation / current-state context that legitimately co-occurs with the above tokens:
NEGATION='not |\bno |no-go|never|remains open|remain open|stays? (not|open)|absent|does not|is not|are not|no item moves|makes no|without|neither'
for f in "${AUTHORED[@]}"; do
  hits="$(grep -Ein "${OVERCLAIM}" "${f}" | grep -Eiv "${NEGATION}" || true)"
  if [ -n "${hits}" ]; then
    echo "${hits}" >&2
    fail "authored doc contains a prohibited overclaim/fix-claim: ${f}"
  fi
done
ok "no fix-claim / readiness overclaim in authored docs (negation-aware)"

# 7) Current-state protections preserved.
[ -f "${NETDIR}/devnet-seeds.live.json" ] && fail "devnet-seeds.live.json must remain absent"
ok "devnet-seeds.live.json absent"
grep -q '"status": "planned"' "${CANDIDATE}" || fail "candidate must remain status planned"
grep -q '"last_reachability_evidence": null' "${CANDIDATE}" || fail "candidate last_reachability_evidence must remain null"
ok "candidate remains planned with null reachability evidence"
grep -q 'C4' "${C4C5}" && grep -qi 'C4 remains OPEN' "${C4C5}" || fail "C4/C5 closure doc must keep C4 OPEN"
grep -qiE 'NOT launch-?ready|NO-GO' "${READINESS}" || fail "readiness matrix must preserve NOT launch-ready / NO-GO"
grep -qE 'M4 (Yellow|remains Yellow)' "${READINESS}" || fail "readiness matrix must preserve M4 Yellow"
ok "C4/C5 OPEN, M4 Yellow, public DevNet NO-GO preserved"

# 8) SHA256SUMS must cover every tracked archive file except itself and .gitignore, and verify.
mapfile -t COVERED < <(awk '{print $2}' "${ARCHIVE}/SHA256SUMS.txt" | sed 's#^\*##')
for f in README.md summary.txt source_trace.txt findings_matrix.txt commands.txt; do
  printf '%s\n' "${COVERED[@]}" | grep -qx "${f}" || fail "SHA256SUMS.txt does not cover ${f}"
done
printf '%s\n' "${COVERED[@]}" | grep -qx "SHA256SUMS.txt" && fail "SHA256SUMS.txt must not cover itself"
printf '%s\n' "${COVERED[@]}" | grep -qx ".gitignore" && fail "SHA256SUMS.txt must not cover .gitignore"
( cd "${ARCHIVE}" && sha256sum -c SHA256SUMS.txt >/dev/null ) || fail "sha256sum -c failed"
ok "SHA256SUMS covers the intended set and verifies"

# 9) Secret / private-material scan of Run 417-authored files (backstop).
SECRET_RE='BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|-----BEGIN|aws_secret_access_key|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36}'
for f in "${AUTHORED[@]}" "${ARCHIVE}/.gitignore"; do
  if grep -EqI "${SECRET_RE}" "${f}"; then fail "possible secret/private material in ${f}"; fi
done
ok "no secret/private-material tokens in authored files"

echo
echo "RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS"
echo "SECURITY_VERDICT=NEGATIVE-FOR-RUNTIME-SECURITY"
echo "note: audit completeness is NOT security readiness. Public DevNet remains NO-GO; C4/C5 OPEN; M4 Yellow."