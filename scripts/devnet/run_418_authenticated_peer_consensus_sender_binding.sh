#!/usr/bin/env bash
# Run 418: authenticated KEMTLS peer -> consensus sender binding (F6) evidence harness.
#
# This harness is READ-ONLY and FAIL-CLOSED. It verifies the COMPLETENESS and INTERNAL
# CONSISTENCY of the Run 418 F6 code/test-remediation evidence set. It does NOT build, run, or
# bless the deployed release binary, open a port, publish a seed, mutate trust/validator/epoch
# state, or move a readiness item Green.
#
# Run 418 remediates F6 (transport-session-to-consensus-sender binding) in CODE and TEST only.
# The harness therefore separates two axes and NEVER conflates them:
#   * F6 code/test remediation (can be POSITIVE) -> RESULT=POSITIVE-FOR-F6-CODE-TEST-REMEDIATION
#   * launch security posture   (is UNCHANGED)   -> SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
# A bare "PASS" is intentionally never emitted so it cannot be misread as launch readiness or as
# closure of any other finding.
#
# It FAILS CLOSED if:
#   * a required Run 418 artifact or canonical record is missing;
#   * the summary omits the F6 scope guard (F6 does not close F3/F4/F5/F7/F8/RS1/C4/C5);
#   * any Run 418 doc claims F6 closes those findings, claims F5 fixed/enforced, claims a
#     release-binary evidence run, publishes a seed, moves an item Green, or asserts launch
#     readiness / C4-C5 closure / TestNet-MainNet readiness;
#   * RS1 is not present + OPEN / launch-blocking, or the launch GO rule no longer forces NO-GO
#     while RS1 is OPEN;
#   * devnet-seeds.live.json exists or the candidate is not planned/null;
#   * SHA256SUMS.txt does not cover every tracked archive file except itself and .gitignore, or
#     `sha256sum -c` fails;
#   * a secret / private-material token appears in a Run 418-authored file.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE="${REPO_ROOT}/docs/devnet/run_418_authenticated_peer_consensus_sender_binding"
EVIDENCE="${REPO_ROOT}/docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_418.md"
RECON="${REPO_ROOT}/docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md"
NETDIR="${REPO_ROOT}/docs/release/public-devnet/network"
CANDIDATE="${NETDIR}/devnet-seeds.live-candidate.json"
READINESS="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
BLOCKER="${REPO_ROOT}/docs/release/public-devnet/BLOCKER_REGISTER.md"
LAUNCH="${REPO_ROOT}/docs/release/public-devnet/LAUNCH_GO_NO_GO.md"
LEDGER="${REPO_ROOT}/docs/whitepaper/contradiction.md"
SRC="${REPO_ROOT}/crates/qbind-node/src/peer_consensus_binding.rs"
TESTS="${REPO_ROOT}/crates/qbind-node/tests/run_418_authenticated_peer_consensus_sender_binding_tests.rs"

fail() { echo "FAIL: $*" >&2; echo "RESULT=NEGATIVE-FOR-F6-CODE-TEST-REMEDIATION"; exit 1; }
ok()   { echo "  ok: $*"; }

echo "== Run 418 F6 code/test-remediation evidence harness =="
echo "repo_root=${REPO_ROOT}"

# 1) Required artifacts must exist.
REQ_ARCHIVE=(README.md summary.txt source_trace.txt commands.txt test_results.txt SHA256SUMS.txt .gitignore)
for f in "${REQ_ARCHIVE[@]}"; do
  [ -f "${ARCHIVE}/${f}" ] || fail "missing archive artifact: ${f}"
done
ok "archive artifacts present"
[ -f "${EVIDENCE}" ] || fail "missing canonical evidence record QBIND_DEVNET_EVIDENCE_RUN_418.md"
[ -f "${RECON}" ]    || fail "missing reconciliation record"
[ -f "${SRC}" ]      || fail "missing peer_consensus_binding.rs (F6 gate)"
[ -f "${TESTS}" ]    || fail "missing Run 418 acceptance test file"
ok "canonical records + F6 source + acceptance tests present"

SUMMARY="${ARCHIVE}/summary.txt"

# 2) Result axes: F6 code/test remediation POSITIVE, security posture UNCHANGED. No bare PASS.
grep -q 'harness_result=POSITIVE-FOR-F6-CODE-TEST-REMEDIATION' "${SUMMARY}" || fail "summary must record POSITIVE-FOR-F6-CODE-TEST-REMEDIATION"
grep -q 'security_posture=RS1-OPEN / PUBLIC-DEVNET-NO-GO' "${SUMMARY}" || fail "summary must record RS1-OPEN / PUBLIC-DEVNET-NO-GO posture"
if grep -Eiq '(^|[^-])RESULT=PASS|overall.?result=pass|verdict=pass\b' "${SUMMARY}"; then
  fail "generic PASS wording could be misread as launch readiness"
fi
ok "result axes present and separated (no bare PASS)"

# 3) F6 scope guard must be explicit and must NOT be relaxed.
grep -q 'f6_does_not_close=F3 F4 F5 F7 F8 RS1 C4 C5' "${SUMMARY}" || fail "summary must state F6 does not close F3/F4/F5/F7/F8/RS1/C4/C5"
grep -q 'release_binary_evidence=ABSENT' "${SUMMARY}" || fail "summary must record that release-binary evidence is ABSENT"
grep -Eiq 'f5_status=.*not claimed fixed or always enforced' "${SUMMARY}" || fail "summary must record F5 not fixed/enforced"
ok "F6 scope guard + F5 wording + release-binary-absent present"

# 4) No Run 418 doc may overclaim (F6 closes other findings / F5 fixed / release-binary evidence /
#    Green move / launch readiness / seed publish). Negation-aware: only POSITIVE assertions trip.
AUTHORED=("${EVIDENCE}" "${ARCHIVE}/README.md" "${SUMMARY}" "${ARCHIVE}/source_trace.txt" "${ARCHIVE}/commands.txt" "${ARCHIVE}/test_results.txt")
OVERCLAIM='F6 (closes|fixes|resolves) (F3|F4|F5|F7|F8|RS1|C4|C5)|RS1 (is )?(now )?(closed|resolved)|F5 (is )?(now )?(fixed|enforced|closed)|release[- ]binary evidence (captured|exists|collected)|move[sd]? (to )?green|(is|are|now) (public devnet )?launch-?ready|devnet-seeds\.live\.json (is |was )?(now )?(published|created)|C4/C5 (closed|closure achieved)'
NEGATION='not |\bno |no-go|never|remains open|remain open|does not|do not|is not|are not|without|absent|ONLY|only\b|no item moves|makes no|cannot|must not'
for f in "${AUTHORED[@]}"; do
  hits="$(grep -Ein "${OVERCLAIM}" "${f}" | grep -Eiv "${NEGATION}" || true)"
  if [ -n "${hits}" ]; then
    echo "${hits}" >&2
    fail "authored doc contains a prohibited overclaim: ${f}"
  fi
done
ok "no overclaim in authored docs (negation-aware)"

# 5) Current-state protections preserved.
[ -f "${NETDIR}/devnet-seeds.live.json" ] && fail "devnet-seeds.live.json must remain absent"
ok "devnet-seeds.live.json absent"
grep -q '"status": "planned"' "${CANDIDATE}" || fail "candidate must remain status planned"
grep -q '"last_reachability_evidence": null' "${CANDIDATE}" || fail "candidate last_reachability_evidence must remain null"
ok "candidate remains planned with null reachability evidence"

# 6) RS1 must remain OPEN / launch-blocking and gate the GO rule. These governance docs are
#    tracked with CRLF; normalize to LF copies OUTSIDE the tree so line-anchored checks are
#    terminator-agnostic. The tracked files are never modified.
[ -f "${BLOCKER}" ] || fail "missing BLOCKER_REGISTER.md"
[ -f "${LAUNCH}" ]  || fail "missing LAUNCH_GO_NO_GO.md"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/run418_rs1.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
sed 's/\r$//' "${BLOCKER}" > "${WORK}/blocker.md"
sed 's/\r$//' "${LAUNCH}"  > "${WORK}/launch.md"

rs1_guard() {
  local blocker="$1" launch="$2"
  grep -Eq '^\| \*\*RS1\*\* \|.*\*\*OPEN / launch-blocking\*\* \|$' "${blocker}" || return 1
  grep -Eiq 'RS1 remaining OPEN forces NO-GO' "${launch}" || return 1
  return 0
}
rs1_guard "${WORK}/blocker.md" "${WORK}/launch.md" || fail "RS1 must remain OPEN / launch-blocking and force NO-GO"
ok "RS1 present, OPEN / launch-blocking, gating the GO rule"

# 7) SHA256SUMS must cover every tracked archive file except itself and .gitignore, and verify.
mapfile -t COVERED < <(awk '{print $2}' "${ARCHIVE}/SHA256SUMS.txt" | sed 's#^\*##')
for f in README.md summary.txt source_trace.txt commands.txt test_results.txt; do
  printf '%s\n' "${COVERED[@]}" | grep -qx "${f}" || fail "SHA256SUMS.txt does not cover ${f}"
done
printf '%s\n' "${COVERED[@]}" | grep -qx "SHA256SUMS.txt" && fail "SHA256SUMS.txt must not cover itself"
printf '%s\n' "${COVERED[@]}" | grep -qx ".gitignore" && fail "SHA256SUMS.txt must not cover .gitignore"
( cd "${ARCHIVE}" && sha256sum -c SHA256SUMS.txt >/dev/null ) || fail "sha256sum -c failed"
ok "SHA256SUMS covers the intended set and verifies"

# 8) Secret / private-material scan of Run 418-authored files (backstop).
SECRET_RE='BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|-----BEGIN|aws_secret_access_key|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36}'
for f in "${AUTHORED[@]}" "${ARCHIVE}/.gitignore" "${EVIDENCE}"; do
  if grep -EqI "${SECRET_RE}" "${f}"; then fail "possible secret/private material in ${f}"; fi
done
ok "no secret/private-material tokens in authored files"

# 9) F6 gate + acceptance-test surface sanity (structural; does not compile/run).
grep -q 'fn authorize' "${SRC}" || fail "peer_consensus_binding.rs must define authorize"
for reason in MissingOrigin UnknownPeer UnknownValidator ClaimedSenderMismatch AmbiguousMapping; do
  grep -q "${reason}" "${SRC}" || fail "binding reject reason missing from gate: ${reason}"
done
grep -q 'run_binary_consensus_loop_with_io' "${TESTS}" || fail "acceptance tests must exercise the real consensus loop"
grep -q 'VerifiedServerIdentity' "${TESTS}" || fail "acceptance tests must exercise the verified server identity"
ok "F6 gate reasons + real-ingress/verified-identity test surface present"

# 10) Negative self-tests: prove the guards actually fail closed. Mutations are applied to TEMP
#     COPIES OUTSIDE the repository tree; the real tracked files are never modified.
# (a) RS1 blocker row deleted -> guard must fail.
grep -v '^| \*\*RS1\*\* |' "${WORK}/blocker.md" > "${WORK}/blocker_no_rs1.md"
if rs1_guard "${WORK}/blocker_no_rs1.md" "${WORK}/launch.md"; then
  fail "negative self-test failed: RS1 guard passed after deleting the RS1 blocker row"
fi
# (b) RS1 marked closed -> guard must fail.
sed 's#\*\*OPEN / launch-blocking\*\*#**CLOSED**#' "${WORK}/blocker.md" > "${WORK}/blocker_rs1_closed.md"
if rs1_guard "${WORK}/blocker_rs1_closed.md" "${WORK}/launch.md"; then
  fail "negative self-test failed: RS1 guard passed after marking RS1 closed"
fi
# (c) Launch GO rule no longer forces NO-GO on RS1 -> guard must fail.
sed 's#RS1 remaining OPEN forces NO-GO#RS1 is optional#' "${WORK}/launch.md" > "${WORK}/launch_no_rs1_gate.md"
if rs1_guard "${WORK}/blocker.md" "${WORK}/launch_no_rs1_gate.md"; then
  fail "negative self-test failed: RS1 guard passed after removing the RS1 NO-GO clause"
fi
# (d) Overclaim guard must trip on an injected fix-claim (temp copy of the summary).
sed '1a harness_injected_overclaim: RS1 is now closed and F6 fixes F5' "${SUMMARY}" > "${WORK}/summary_overclaim.txt"
if ! grep -Ein "${OVERCLAIM}" "${WORK}/summary_overclaim.txt" | grep -Eiv "${NEGATION}" >/dev/null; then
  fail "negative self-test failed: overclaim guard did not trip on an injected fix-claim"
fi
rm -rf "${WORK}"; trap - EXIT
ok "negative self-tests fail closed (RS1 deleted/closed/ungated + overclaim injection)"

echo
echo "RESULT=POSITIVE-FOR-F6-CODE-TEST-REMEDIATION"
echo "SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO"