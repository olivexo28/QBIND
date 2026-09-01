#!/usr/bin/env bash
# Run 402: public DevNet launch go/no-go gate + blocker register verification
# harness.
#
# This harness produces the Run 402 acceptance evidence for the public DevNet
# launch go/no-go gate package (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_402.md`,
# `docs/release/public-devnet/LAUNCH_GO_NO_GO.md`, and
# `docs/release/public-devnet/BLOCKER_REGISTER.md`). It is a DOCS + VERIFICATION
# run (Decision gate = Route B): it validates the published go/no-go gate and
# blocker register against the canonical readiness matrix. It makes NO production
# Rust source change, adds NO CLI flag, opens NO externally reachable port,
# deploys NO seed/bootnode/faucet/RPC/explorer/status page, changes NO wire
# format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  The launch go/no-go doc exists and carries the DevNet safety label.
#   2.  The blocker register exists and carries the DevNet safety label.
#   3.  The current decision is NOT launch-ready / NO-GO.
#   4.  The blocker register records the M4 / M6 / S5 / S7 blockers with
#       owner / action / evidence-needed / status columns.
#   5.  The M4 blocker is "no real external seed reachability yet".
#   6.  The M6 blocker is "live-registration half M4-gated; root
#       rotation/revocation C4/C5-deferred".
#   7.  The S5 blocker is "live status view deferred until M4/live network".
#   8.  The S7 blocker is "live seed operation deferred until M4".
#   9.  The go/no-go rule requires every must-have Green AND launch in scope.
#   10. C4/C5 are stated OPEN; no C4/C5 closure claim.
#   11. No TestNet/MainNet readiness claim; no launch/faucet/RPC/explorer/
#       status-service deployment claim; no M4/M6/S5/S7 Green claim.
#   12. Cross-links to the M4 checklist, evidence template, identity continuity,
#       rotation deferral, status decision, readiness criteria, C4/C5, and
#       contradiction ledger are present.
#   13. Non-claim grep over the two new docs passes.
#   14. No private key / KEM secret / root/signing secret / raw log / raw metrics
#       / data dir / private endpoint / absolute path is committed in the package.
#   15. Readiness matrix reconciliation: M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN;
#       public DevNet NOT launch-ready.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run402-public-devnet-launch-go-no-go-gate}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
GONOGO="${PDN}/LAUNCH_GO_NO_GO.md"
REGISTER="${PDN}/BLOCKER_REGISTER.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run402] %s\n' "$*"; }
fail() { printf '[run402] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Launch go/no-go doc exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${GONOGO}" ] || fail "launch go/no-go doc missing: LAUNCH_GO_NO_GO.md"
grep -qi 'experimental' "${GONOGO}" \
  && grep -qi 'no C4/C5 closure claim' "${GONOGO}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${GONOGO}" \
  || fail "safety label missing in LAUNCH_GO_NO_GO.md"
emit "go_no_go_doc=OK (LAUNCH_GO_NO_GO.md present, safety-labelled) sha256=$(sha256_file "${GONOGO}")"

# ---------------------------------------------------------------------------
# 2. Blocker register exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${REGISTER}" ] || fail "blocker register missing: BLOCKER_REGISTER.md"
grep -qi 'experimental' "${REGISTER}" \
  && grep -qi 'no C4/C5 closure claim' "${REGISTER}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${REGISTER}" \
  || fail "safety label missing in BLOCKER_REGISTER.md"
emit "blocker_register_doc=OK (BLOCKER_REGISTER.md present, safety-labelled) sha256=$(sha256_file "${REGISTER}")"

# ---------------------------------------------------------------------------
# 3. Current decision is NOT launch-ready / NO-GO.
# ---------------------------------------------------------------------------
grep -qi 'NO-GO' "${GONOGO}" || fail "go/no-go doc does not state NO-GO"
grep -qi 'NOT launch-ready' "${GONOGO}" || fail "go/no-go doc does not state NOT launch-ready"
emit "decision=OK (NO-GO / NOT launch-ready)"

# ---------------------------------------------------------------------------
# 4. Blocker register has owner/action/evidence-needed/status columns + rows.
# ---------------------------------------------------------------------------
grep -qi 'Owner' "${REGISTER}" \
  && grep -qi 'Action required' "${REGISTER}" \
  && grep -qi 'Evidence needed' "${REGISTER}" \
  && grep -qi 'Status' "${REGISTER}" \
  || fail "blocker register missing owner/action/evidence-needed/status columns"
for ID in M4 M6 S5 S7; do
  grep -q "| \*\*${ID}\*\*" "${REGISTER}" || fail "blocker register missing ${ID} row"
done
emit "register_columns=OK (owner/action/evidence-needed/status; M4/M6/S5/S7 rows present)"

# ---------------------------------------------------------------------------
# 5. M4 blocker: no real external seed reachability yet.
# ---------------------------------------------------------------------------
grep -qi 'No real external seed reachability yet' "${REGISTER}" \
  || fail "M4 blocker text (no real external seed reachability yet) missing"
emit "m4_blocker=OK (no real external seed reachability yet)"

# ---------------------------------------------------------------------------
# 6. M6 blocker: live-registration half M4-gated; root rotation/revocation
#    C4/C5-deferred.
# ---------------------------------------------------------------------------
grep -qi 'Live-registration half is \*\*M4-gated\*\*' "${REGISTER}" \
  && grep -qi 'C4/C5-deferred' "${REGISTER}" \
  || fail "M6 blocker text (M4-gated live half + C4/C5-deferred rotation/revocation) missing"
emit "m6_blocker=OK (live-registration half M4-gated; root rotation/revocation C4/C5-deferred)"

# ---------------------------------------------------------------------------
# 7. S5 blocker: live status view deferred until M4/live network.
# ---------------------------------------------------------------------------
grep -qi 'Live status / aggregate health view deferred until M4' "${REGISTER}" \
  || fail "S5 blocker text (live status view deferred until M4/live network) missing"
emit "s5_blocker=OK (live status view deferred until M4/live network)"

# ---------------------------------------------------------------------------
# 8. S7 blocker: live seed operation deferred until M4.
# ---------------------------------------------------------------------------
grep -qi 'Live seed operation deferred until M4' "${REGISTER}" \
  || fail "S7 blocker text (live seed operation deferred until M4) missing"
emit "s7_blocker=OK (live seed operation deferred until M4)"

# ---------------------------------------------------------------------------
# 9. Final go/no-go rule: every must-have Green AND launch explicitly in scope.
# ---------------------------------------------------------------------------
grep -qi 'every must-have' "${GONOGO}" \
  && grep -qi 'explicitly in scope' "${GONOGO}" \
  || fail "final go/no-go rule (every must-have Green AND launch in scope) missing"
emit "go_no_go_rule=OK (GO only if every must-have Green AND launch explicitly in scope; otherwise NO-GO)"

# ---------------------------------------------------------------------------
# 10. C4/C5 OPEN; no closure claim.
# ---------------------------------------------------------------------------
grep -qi 'C4 remains OPEN' "${GONOGO}" \
  && grep -qi 'C5 remains OPEN' "${GONOGO}" \
  || fail "go/no-go doc does not state C4/C5 remain OPEN"
emit "c4_c5=OK (C4 OPEN; C5 OPEN; no closure claim)"

# ---------------------------------------------------------------------------
# 11. Cross-links present in both docs (union).
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md" \
  "docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md" \
  "docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md" \
  "docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md" \
  "docs/release/public-devnet/status/STATUS_PAGE_DECISION.md" \
  "docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md" \
  "docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md" \
  "docs/whitepaper/contradiction.md" ; do
  grep -rqF "${LINK}" "${GONOGO}" "${REGISTER}" \
    || fail "go/no-go package does not cross-link ${LINK}"
done
emit "cross_links=OK (M4 checklist, evidence template, identity continuity, rotation deferral, status decision, readiness criteria, C4/C5, contradiction referenced)"

# ---------------------------------------------------------------------------
# 12. Non-claim grep over the two new docs.
#     Normalize first: strip markdown emphasis/backticks and join wrapped lines.
# ---------------------------------------------------------------------------
normalize_md() {
  sed -e 's/[`*]//g' "$1" \
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
CLAIM_HITS="$(for f in "${GONOGO}" "${REGISTER}"; do normalize_md "$f"; done \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in go/no-go package"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim)"

# ---------------------------------------------------------------------------
# 13. No private/raw artifact + no absolute path committed under the package.
# ---------------------------------------------------------------------------
if find "${PDN}" -maxdepth 1 -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under public-devnet package"
fi
# The two new docs must contain no absolute filesystem paths, private endpoints,
# or embedded secrets.
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${GONOGO}" "${REGISTER}"; then
  fail "absolute filesystem path found in go/no-go package"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${GONOGO}" "${REGISTER}"; then
  fail "possible secret / private material found in go/no-go package"
fi
emit "committed_private_material=NONE (docs only; no keys/logs/metrics/data dirs/absolute paths/private endpoints)"

# ---------------------------------------------------------------------------
# 14. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow; C4/C5 OPEN.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (public-DevNet launch go/no-go gate + blocker register published and verified against the canonical readiness matrix; no production source change; decision is NO-GO / NOT launch-ready; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"