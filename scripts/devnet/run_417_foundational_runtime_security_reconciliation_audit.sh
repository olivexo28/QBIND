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

# 10) RS1 launch-governance blocker must exist, be OPEN / launch-blocking, gate the GO rule,
#     and carry findings F1-F8 with their audited severities. This makes the harness fail closed
#     if a future edit deletes RS1, marks it closed prematurely, or lets the GO rule pass with
#     RS1 open. It NEVER moves anything Green; RS1 OPEN is the required current state.
BLOCKER="${REPO_ROOT}/docs/release/public-devnet/BLOCKER_REGISTER.md"
LAUNCH="${REPO_ROOT}/docs/release/public-devnet/LAUNCH_GO_NO_GO.md"
[ -f "${BLOCKER}" ] || fail "missing BLOCKER_REGISTER.md"
[ -f "${LAUNCH}" ]  || fail "missing LAUNCH_GO_NO_GO.md"

# These governance docs and the matrix are tracked with CRLF line endings; normalize to LF copies
# OUTSIDE the repo tree so the guard's line-anchored checks are terminator-agnostic. The tracked
# files are never modified.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/run417_rs1.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
sed 's/\r$//' "${BLOCKER}" > "${WORK}/blocker.md"
sed 's/\r$//' "${LAUNCH}"  > "${WORK}/launch.md"
sed 's/\r$//' "${MATRIX}"  > "${WORK}/matrix.txt"

# rs1_guard: returns 0 only when RS1 is present, OPEN / launch-blocking, and forces NO-GO in both
# the blocker register and the launch gate. Any relaxation (RS1 removed, marked closed, or the GO
# rule no longer requiring RS1) makes it return non-zero.
rs1_guard() {
  local blocker="$1" launch="$2"
  grep -Eq '^\| \*\*RS1\*\* \|.*\*\*OPEN / launch-blocking\*\* \|$' "${blocker}" || return 1
  grep -q 'RS1 closed' "${blocker}"                                              || return 1
  grep -Eiq 'including RS1, even if every' "${blocker}"                          || return 1
  grep -Eiq 'RS1 is closed' "${launch}"                                         || return 1
  grep -Eiq 'RS1 remaining OPEN forces NO-GO' "${launch}"                       || return 1
  return 0
}
rs1_guard "${WORK}/blocker.md" "${WORK}/launch.md" || fail "RS1 must be present, OPEN / launch-blocking, and gate the GO rule in BLOCKER_REGISTER.md + LAUNCH_GO_NO_GO.md"
ok "RS1 present, OPEN / launch-blocking, and gating the GO rule (both docs)"

# F1-F8 must all be recorded, with their audited severities, and must not be suppressed/reclassified.
for fnd in F1 F2 F3 F4 F5 F6 F7 F8; do
  grep -qx "FINDING ${fnd}" "${WORK}/matrix.txt" || fail "findings matrix missing ${fnd}"
done
severity_of() { awk -v want="FINDING $1" '$0==want{f=1} f&&/^severity: /{print $2; exit}' "${WORK}/matrix.txt"; }
for fnd in F3 F4 F6 F7; do
  [ "$(severity_of "${fnd}")" = "Critical" ] || fail "${fnd} must be recorded Critical"
done
for fnd in F5 F8; do
  [ "$(severity_of "${fnd}")" = "High" ] || fail "${fnd} must be recorded High"
done
grep -Eiq 'Do not suppress, weaken, or reclassify F1' "${WORK}/blocker.md" || fail "BLOCKER must forbid suppressing/reclassifying F1-F8"
ok "F1-F8 recorded with audited severities and non-suppression clause"

# 11) Negative self-tests: prove the RS1 guard actually fails closed. Each mutation is applied to a
#     TEMP COPY OUTSIDE the repository tree; the real tracked files are never modified. A guard that
#     still passes on a relaxed copy would be worthless, so a passing mutation aborts the harness.
# (a) RS1 blocker row deleted -> guard must fail.
grep -v '^| \*\*RS1\*\* |' "${WORK}/blocker.md" > "${WORK}/blocker_no_rs1.md"
if rs1_guard "${WORK}/blocker_no_rs1.md" "${WORK}/launch.md"; then
  fail "negative self-test failed: RS1 guard passed after deleting the RS1 blocker row"
fi
# (b) RS1 marked closed in the blocker row -> guard must fail.
sed 's#\*\*OPEN / launch-blocking\*\*#**CLOSED**#' "${WORK}/blocker.md" > "${WORK}/blocker_rs1_closed.md"
if rs1_guard "${WORK}/blocker_rs1_closed.md" "${WORK}/launch.md"; then
  fail "negative self-test failed: RS1 guard passed after marking RS1 closed"
fi
# (c) Launch GO rule no longer forces NO-GO on RS1 -> guard must fail.
sed 's#RS1 remaining OPEN forces NO-GO#RS1 is optional#' "${WORK}/launch.md" > "${WORK}/launch_no_rs1_gate.md"
if rs1_guard "${WORK}/blocker.md" "${WORK}/launch_no_rs1_gate.md"; then
  fail "negative self-test failed: RS1 guard passed after removing the RS1 NO-GO clause from the GO rule"
fi
# 12) Run 417 consistency micro-guards (final corrective pass). These fail CLOSED if the reconciled
#     model regresses. Each file is flattened to a single stream (CR stripped, newlines -> spaces) so
#     sentence-bounded ([^.]) checks are terminator- and wrap-agnostic. The tracked files are never
#     modified.
LEDGER="${REPO_ROOT}/docs/whitepaper/contradiction.md"
RUN417_TEXTS=("${EVIDENCE}" "${RECON}" "${SUMMARY}" "${READINESS}" "${LEDGER}")
for f in "${RUN417_TEXTS[@]}"; do
  [ -f "${f}" ] || fail "missing Run 417 text for consistency guard: ${f}"
  flat="$(sed 's/\r$//' "${f}" | tr '\n' ' ')"
  # (a) No text may claim F6 (peer/session binding) is a prerequisite for making cryptographic
  #     proposal/vote/QC signatures or their verification meaningful. F6 is transport-level
  #     accountability only; message-level signatures remain independently necessary.
  if printf '%s' "${flat}" | grep -Eioq 'prerequisite for (meaningful|making)[^.]{0,120}(signature|verification|proposal|vote|qc)'; then
    fail "stale F6 framing: '${f}' says F6 is a prerequisite for making cryptographic signatures/verification meaningful"
  fi
  # (b) No text may claim F1-F8 (or "these deployed-path gaps") are already fully tracked/reflected/
  #     represented by C4 and M4/M6. RS1 is the independent launch-blocking control; C4 OPEN did not
  #     independently prevent launch.
  if printf '%s' "${flat}" | grep -Eioq '(F1.{0,4}F8|F1-F8|these ([a-z -]*)?gaps|deployed-path[^.]*gaps)[^.]*already (tracked|reflected|represented|covered)[^.]*(C4|M4/M6)'; then
    fail "stale coverage framing: '${f}' says F1-F8 are already tracked/reflected/represented by C4 and M4/M6"
  fi
  if printf '%s' "${flat}" | grep -Eioq 'already (tracked|reflected|represented|covered)[^.]*C4[^.]*M4/M6'; then
    fail "stale coverage framing: '${f}' says gaps are already tracked/reflected by C4 and M4/M6"
  fi
done
ok "no stale F6-prerequisite / F1-F8-already-covered-by-C4/M4-M6 framing in Run 417 texts"

# (c/d) Findings severities must not be downgraded and the deployed findings must remain reachable.
#       F3/F4/F6/F7 = Critical + reachable; F5/F8 = High + reachable. Reachability is read from the
#       matrix and fails closed on any unreachability/mitigation marker.
reach_line() { awk -v want="FINDING $1" '$0==want{f=1} f&&/^current_reachability: /{sub(/^current_reachability: /,"");print;exit}' "${WORK}/matrix.txt"; }
is_reachable() {
  local rl; rl="$(reach_line "$1")"
  [ -n "${rl}" ] || return 1
  printf '%s' "${rl}" | grep -Eiq 'MITIGATED-BY-CURRENT-UNREACHABILITY|not reachable|unreachab|not exploitable' && return 1
  printf '%s' "${rl}" | grep -Eiq 'reachable|deployed consensus[^.]*suite 0|inbound accepts any suite' || return 1
  return 0
}
for fnd in F3 F4 F6 F7; do
  [ "$(severity_of "${fnd}")" = "Critical" ] || fail "${fnd} must remain Critical"
  is_reachable "${fnd}" || fail "${fnd} must remain reachable on the deployed path"
done
for fnd in F5 F8; do
  [ "$(severity_of "${fnd}")" = "High" ] || fail "${fnd} must remain High"
  is_reachable "${fnd}" || fail "${fnd} must remain reachable on the deployed path"
done
ok "F3/F4/F6/F7 Critical+reachable and F5/F8 High+reachable"

# (e) The FORMAL go/no-go rule section (§9) of LAUNCH_GO_NO_GO.md must still require RS1 closure and
#     keep RS1-OPEN => NO-GO. Checked against the §9 section only, not merely anywhere in the doc.
awk '/^## 9\./{f=1;print;next} f&&/^## /{f=0} f{print}' "${WORK}/launch.md" > "${WORK}/launch_sec9.md"
[ -s "${WORK}/launch_sec9.md" ] || fail "LAUNCH_GO_NO_GO.md formal go/no-go rule section (§9) not found"
sec9_guard() {
  grep -Eiq 'RS1 (is|must be) closed' "$1" || return 1
  grep -Eiq 'RS1 (remaining )?OPEN forces NO-GO' "$1" || return 1
  return 0
}
sec9_guard "${WORK}/launch_sec9.md" || fail "formal §9 GO rule must require RS1 closure and force NO-GO while RS1 is OPEN"
# Negative self-test: dropping the RS1 closure requirement from a §9 copy must trip the guard.
sed 's#RS1 is closed#every M1-M20 is Green#' "${WORK}/launch_sec9.md" > "${WORK}/launch_sec9_no_rs1.md"
if sec9_guard "${WORK}/launch_sec9_no_rs1.md"; then
  fail "negative self-test failed: §9 guard passed after removing the RS1-closure requirement"
fi
ok "formal §9 GO rule requires RS1 closure (section-scoped, with negative self-test)"

rm -rf "${WORK}"; trap - EXIT
ok "RS1 guard negative self-tests fail closed (deleted row / closed / ungated GO rule)"

echo
echo "RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS"
echo "SECURITY_VERDICT=NEGATIVE-FOR-RUNTIME-SECURITY"
echo "note: audit completeness is NOT security readiness. Public DevNet remains NO-GO; C4/C5 OPEN; M4 Yellow."