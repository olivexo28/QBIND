#!/usr/bin/env bash
# Run 396 — Public DevNet readiness matrix canonicalization / stale-row cleanup verifier.
#
# Docs + verification harness only. This script asserts that
# docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md is INTERNALLY CONSISTENT after
# Runs 356–395: every checklist, status table, gap matrix, blocker summary, and next-run
# recommendation agrees with the canonical per-item status, and no readiness overclaim is
# introduced. It changes nothing; it only reads and greps the committed document.
#
# Exit 0 + RESULT=POSITIVE when the matrix is consistent; non-zero + RESULT=NEGATIVE otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"

FAILURES=0
CHECKS=0

pass() { printf '  [PASS] %s\n' "$1"; CHECKS=$((CHECKS + 1)); }
fail() { printf '  [FAIL] %s\n' "$1"; CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); }

# assert_absent <human description> <regex> : fails if regex matches any line in DOC.
assert_absent() {
  local desc="$1" re="$2"
  if grep -Eq "$re" "$DOC"; then
    fail "$desc (unexpected match for: $re)"
    grep -nE "$re" "$DOC" | sed 's/^/        > /'
  else
    pass "$desc"
  fi
}

# assert_present <human description> <regex> : fails if regex matches NO line in DOC.
assert_present() {
  local desc="$1" re="$2"
  if grep -Eq "$re" "$DOC"; then
    pass "$desc"
  else
    fail "$desc (expected at least one match for: $re)"
  fi
}

# assert_no_positive_claim <human description> <regex> : matches candidate lines, then drops
# lines that are negations ("no ...", "not ...", "never ...", "n't", "without"); fails if a
# genuine POSITIVE claim remains.
assert_no_positive_claim() {
  local desc="$1" re="$2" hits
  hits="$(grep -En "$re" "$DOC" | grep -Eiv 'no live|no [a-z ]*status (page|service)|no externally|no (public )?faucet|not (deployed|live|running|launched)|never |without |n.t (deployed|live)' || true)"
  if [[ -n "$hits" ]]; then
    fail "$desc"
    printf '%s\n' "$hits" | sed 's/^/        > /'
  else
    pass "$desc"
  fi
}

echo "== Run 396 readiness matrix canonicalization verifier =="
echo "Document under test: docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
echo

if [[ ! -f "$DOC" ]]; then
  echo "RESULT=NEGATIVE"
  echo "readiness criteria document not found: $DOC"
  exit 1
fi

echo "-- 1. No stale 'None shipped' row remains for S6 --"
# A stale row would be a table row (starts with '|') whose status cell is Red AND text says 'None shipped'.
assert_absent "S6/alert-rules table row is not Red+None-shipped" '^\|[^|]*(alert rule|S6)[^|]*\|[^|]*🔴[^|]*None shipped'
assert_present "S6 status row is Green in the current-status table" '^\| S6 alert rules / scrape config \| 🟢'

echo
echo "-- 2. No stale Red row remains for S1/S2/S3/S4/S6 --"
assert_present "S1 snapshot/backup/restore is Green" '^\| S1 snapshot / backup / restore \| 🟢'
assert_present "S2 data retention is Green"          '^\| S2 data retention \| 🟢'
assert_present "S3 upgrade procedure is Green"        '^\| S3 upgrade procedure \| 🟢'
assert_present "S4 rollback procedure is Green"       '^\| S4 rollback procedure \| 🟢'
assert_absent  "no S1..S4/S6 status row is Red"       '^\| S[12346][^|]*\| 🔴'

echo
echo "-- 3. No stale Yellow row remains for M5/M7..M20 (in §10 status table and §16 gap matrix) --"
# §10 current-status table: these must all be Green.
for row in \
  'M5 validator onboarding' \
  'M7 key-management' \
  'M8 trust-bundle bootstrap' \
  'M9 PQC root / signing-key guidance' \
  'M10 public P2P port posture' \
  'M11 peer admission policy' \
  'M12 abuse / DoS protections' \
  'M13 telemetry / metrics' \
  'M14 monitoring / alerting' \
  'M15 reset policy' \
  'M16 incident response' \
  'M17 public documentation' \
  'M18 user-facing disclaimers' \
  'M19 network parameter publication' \
  'M20 genesis hash publication'; do
  assert_present "§10 row Green: ${row}" "^\| ${row} \| 🟢"
done
# §16 gap matrix DevNet rows that map to Green must-haves must not be Yellow/Red.
assert_absent "§16 validator onboarding not Yellow/Red"        '^\| validator onboarding \| DevNet \| docs \| (🟡|🔴)'
assert_absent "§16 key-management not Yellow/Red"              '^\| validator key-management guidance \| DevNet \| security \| (🟡|🔴)'
assert_absent "§16 trust-bundle bootstrap not Yellow/Red"      '^\| trust-bundle bootstrap \| DevNet \| security \| (🟡|🔴)'
assert_absent "§16 PQC root/signing-key not Yellow/Red"        '^\| PQC root / signing-key guidance \| DevNet \| security \| (🟡|🔴)'
assert_absent "§16 public P2P port posture not Yellow/Red"     '^\| public P2P port posture \| DevNet \| network \| (🟡|🔴)'
assert_absent "§16 peer admission policy not Yellow/Red"       '^\| peer admission policy \| DevNet \| security \| (🟡|🔴)'
assert_absent "§16 telemetry / metrics not Yellow/Red"         '^\| telemetry / metrics \| DevNet \| observability \| (🟡|🔴)'
assert_absent "§16 monitoring / alerting not Yellow/Red"       '^\| monitoring / alerting \| DevNet \| observability \| (🟡|🔴)'
assert_absent "§16 abuse handling not Yellow/Red"              '^\| abuse handling \| DevNet \| security \| (🟡|🔴)'
assert_absent "§16 public documentation not Yellow/Red"        '^\| public documentation \| DevNet \| docs \| (🟡|🔴)'
assert_absent "§16 user-facing disclaimers not Yellow/Red"     '^\| user-facing disclaimers \| DevNet \| docs \| (🟡|🔴)'

echo
echo "-- 4. M4 remains Yellow / launch-blocking everywhere --"
assert_present "§10 M4 status row is Yellow"       '^\| M4 seed/bootnodes \| 🟡'
assert_present "§16 seed-nodes row is Yellow"       '^\| seed nodes / bootnodes \| DevNet \| network \| 🟡'
assert_absent  "§16 seed-nodes row is not Red"      '^\| seed nodes / bootnodes \| DevNet \| network \| 🔴'
assert_present "M4 described as launch blocker"     '[Ll]aunch blocker'

echo
echo "-- 5. M6 remains Yellow / Partial everywhere --"
assert_present "§10 M6 status row is Yellow"        '^\| M6 validator identity \| 🟡'
assert_present "§16 validator identity row is Yellow" '^\| validator identity \| DevNet \| security \| 🟡'
assert_present "M6 described as Yellow / Partial"   'M6 (stays|remains) Yellow/Partial|M6 .*Yellow / Partial|Yellow / Partial \(Run 358'

echo
echo "-- 6. S5 remains Yellow everywhere --"
assert_present "§10 S5 status row is Yellow"        '^\| S5 status page \| 🟡'
assert_present "§16 status page row is Yellow"       '^\| status page \| DevNet \| observability \| 🟡'
assert_absent  "S5 not marked Green in checklist"   '^- \[x\] S5\.'

echo
echo "-- 7. S7 remains Yellow everywhere --"
assert_present "§10 S7 status row is Yellow"        '^\| S7 seed-node runbook \| 🟡'
assert_present "S7 checklist item is Yellow (unchecked)" '^- \[~\] S7\.'

echo
echo "-- 8. Public DevNet remains NOT launch-ready everywhere --"
assert_present "explicit NOT launch-ready statement" 'NOT launch-ready|not launch-ready|not.*mark public DevNet ready'
assert_absent  "no positive launch-ready claim"      '[Pp]ublic DevNet is (now )?(launch-ready|ready to launch|READY)'

echo
echo "-- 9. C4/C5 remain OPEN everywhere --"
assert_present "C4 remains OPEN"                     'C4 remains \*\*OPEN\*\*|C4 .*OPEN|N5 \(C4\) OPEN'
assert_present "C5 remains OPEN"                     'C5 remains \*\*OPEN\*\*|C5 .*OPEN|N6 \(C5\) OPEN'
assert_absent  "no C4 closure claim"                 'C4 (is )?(now )?(CLOSED|closed)'
assert_absent  "no C5 closure claim"                 'C5 (is )?(now )?(CLOSED|closed)'

echo
echo "-- 10. No TestNet/MainNet readiness claim appears --"
assert_absent "no TestNet readiness claim"  '(TestNet|Test[Nn]et) is (now )?(ready|launch-ready|READY)'
assert_absent "no MainNet readiness claim"  '(MainNet|Main[Nn]et) is (now )?(ready|launch-ready|READY)'

echo
echo "-- 11. No new launch/faucet/RPC/explorer/status-service DEPLOYMENT claim appears --"
assert_absent "no faucet deployment claim"          '[Ff]aucet (is )?(now )?(deployed|live|running|launched)'
assert_absent "no RPC gateway deployment claim"     'RPC (gateway|endpoint) (is )?(now )?(deployed|live|running|launched)'
assert_absent "no explorer deployment claim"        '[Ee]xplorer (is )?(now )?(deployed|live|running|launched)'
assert_no_positive_claim "no live status-service deploy claim" 'status (page|service) (is )?(now )?(deployed|live|running|launched)'

echo
echo "-- 12. Changed files contain no secrets / raw material / absolute paths --"
CHANGED_FILES=(
  "docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
  "scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh"
  "docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_396.md"
  "docs/devnet/run_396_public_devnet_readiness_matrix_canonicalization/README.md"
  "docs/devnet/run_396_public_devnet_readiness_matrix_canonicalization/summary.txt"
)
SECRET_RE='BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN|AKIA[0-9A-Z]{16}|(api[_-]?key|secret|password|token)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9/+]{16,}'
ABS_PATH_RE='(^|[^A-Za-z0-9_./])/(home|root|Users|var|etc)/[A-Za-z0-9._-]+/'
for f in "${CHANGED_FILES[@]}"; do
  p="${REPO_ROOT}/${f}"
  [[ -f "$p" ]] || continue
  # The verifier script necessarily embeds secret-detection and abs-path REGEX literals; skip
  # scanning it against its own patterns (it is separately covered by the repo secret scanner).
  if [[ "$f" == scripts/devnet/run_396_* ]]; then
    pass "secret/abs-path self-scan skipped for the verifier script itself (${f})"
    continue
  fi
  if grep -Eqi "$SECRET_RE" "$p"; then
    fail "no secrets in ${f}"; grep -nEi "$SECRET_RE" "$p" | sed 's/^/        > /'
  else
    pass "no secrets in ${f}"
  fi
  if grep -Eq "$ABS_PATH_RE" "$p"; then
    fail "no host absolute paths in ${f}"; grep -nE "$ABS_PATH_RE" "$p" | sed 's/^/        > /'
  else
    pass "no host absolute paths in ${f}"
  fi
done

echo
echo "== Summary: ${CHECKS} checks, ${FAILURES} failure(s) =="
if [[ "$FAILURES" -eq 0 ]]; then
  echo "RESULT=POSITIVE"
  echo "VERDICT=PASS — public-DevNet readiness matrix canonicalization POSITIVE"
  exit 0
else
  echo "RESULT=NEGATIVE"
  echo "VERDICT=FAIL — readiness matrix is not internally consistent"
  exit 1
fi