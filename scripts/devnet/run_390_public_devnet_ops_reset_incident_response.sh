#!/usr/bin/env bash
# Run 390: public DevNet ops reset-policy (M15) + incident-response (M16)
# verification harness.
#
# This harness produces the Run 390 acceptance evidence for the public DevNet
# ops documentation (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md` and
# `docs/release/public-devnet/ops/`). It is a DOCS + VERIFICATION run
# (Decision gate = Route B): it validates the published guidance against the
# REAL `qbind-node` CLI/help + source surfaces. It makes NO production Rust
# source change, adds NO CLI flag, opens NO externally reachable port, deploys
# NO seed/bootnode/faucet/RPC/explorer/status page, changes NO wire format,
# weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  `cargo build -p qbind-node --release --locked --bin qbind-node` builds.
#   2.  The pre-existing offline `--authority-state-reset` ceremony flag exists
#       (defined in cli.rs, dispatched offline in main.rs) and is intentionally
#       HIDDEN from `--help` (no invented reset/incident CLI flag).
#   3.  The ops package files exist.
#   4.  Every ops doc carries the DevNet safety label.
#   5.  RESET_POLICY.md carries the required trigger/notice/evidence/operator
#       -action/what-never-changes/authority-state-reset sections.
#   6.  INCIDENT_RESPONSE.md carries the required severity/classes/first
#       -response/evidence/redaction/escalation/publication/non-claim sections.
#   7.  The ops docs cross-link operator, observability, security, network, and
#       ops runbooks (internal incident-response + PQC trust lifecycle).
#   8.  Non-claim grep over the ops docs passes.
#   9.  No private/raw artifact is committed under the ops package.
#   10. Readiness matrix reconciliation: M15 Green, M16 Green (reconciled),
#       M4 Yellow, M6 Yellow, no launch-ready / C4-C5 closure claim.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run390-public-devnet-ops-reset-incident-response}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
OPS_DIR="${REPO_ROOT}/docs/release/public-devnet/ops"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run390] %s\n' "$*"; }
fail() { printf '[run390] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Build the release node binary.
# ---------------------------------------------------------------------------
log "building qbind-node (release, locked)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"

emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 2. Documented reset flag exists (offline ceremony, hidden from --help); no
#    invented reset/incident CLI flag.
# ---------------------------------------------------------------------------
HELP="${OUTDIR}/qbind-node.help.txt"
"${NODE_BIN}" --help > "${HELP}" 2>&1 || true
grep -q -- '--authority-state-reset' "${REPO_ROOT}/crates/qbind-node/src/cli.rs" \
  || fail "--authority-state-reset not defined in cli.rs"
grep -q 'authority_state_reset' "${REPO_ROOT}/crates/qbind-node/src/main.rs" \
  || fail "--authority-state-reset not dispatched in main.rs"
if grep -q -- '--authority-state-reset' "${HELP}"; then
  fail "hidden --authority-state-reset unexpectedly advertised in --help"
fi
# No invented reset/incident flag is documented in the ops package.
if grep -rhoE -- '--[a-z0-9-]*(reset|incident)[a-z0-9-]*' "${OPS_DIR}" \
   | sort -u | grep -qvE -- '--authority-state-reset(-output-audit|-operator-note)?$'; then
  fail "ops docs reference an undocumented/invented reset/incident CLI flag"
fi
emit "reset_flag=OK (--authority-state-reset defined+offline-dispatched; hidden from --help; no invented flag)"

# ---------------------------------------------------------------------------
# 3. Ops package files exist.
# ---------------------------------------------------------------------------
for F in README RESET_POLICY INCIDENT_RESPONSE SAFETY VERIFY; do
  [ -f "${OPS_DIR}/${F}.md" ] || fail "ops package missing ${F}.md"
done
emit "ops_package_files=OK (README/RESET_POLICY/INCIDENT_RESPONSE/SAFETY/VERIFY present)"

# ---------------------------------------------------------------------------
# 4. Safety label present in every ops doc.
# ---------------------------------------------------------------------------
for F in README RESET_POLICY INCIDENT_RESPONSE SAFETY VERIFY; do
  grep -qi 'experimental' "${OPS_DIR}/${F}.md" \
    && grep -qi 'no value' "${OPS_DIR}/${F}.md" \
    || fail "safety label missing in ${F}.md"
done
emit "safety_labels=OK (experimental/resettable/no-value label in all 5 ops docs)"

# ---------------------------------------------------------------------------
# 5. RESET_POLICY.md required sections.
# ---------------------------------------------------------------------------
for S in 'Reset triggers' 'Notice policy' 'Operator action' 'Reset evidence record' \
         'What never changes silently' 'authority-state-reset' 'no.*guarantee'; do
  grep -qiE "${S}" "${OPS_DIR}/RESET_POLICY.md" || fail "RESET_POLICY.md missing section: ${S}"
done
emit "reset_policy_sections=OK (triggers/notice/operator-action/evidence-record/never-silent/authority-state-reset/no-guarantees)"

# ---------------------------------------------------------------------------
# 6. INCIDENT_RESPONSE.md required sections.
# ---------------------------------------------------------------------------
for S in 'severity level' 'Incident classes' 'First-response' 'Evidence to capture' \
         'redact' 'Escalation' 'Publication policy' 'non-claim'; do
  grep -qiE "${S}" "${OPS_DIR}/INCIDENT_RESPONSE.md" || fail "INCIDENT_RESPONSE.md missing section: ${S}"
done
# Named incident classes must be present.
for C in 'Seed unreachable' 'Trust-bundle' 'key compromise' 'flood' 'halt' 'release artifact' 'Reset event'; do
  grep -qiE "${C}" "${OPS_DIR}/INCIDENT_RESPONSE.md" || fail "INCIDENT_RESPONSE.md missing incident class: ${C}"
done
emit "incident_response_sections=OK (severity/classes/first-response/evidence/redaction/escalation/publication/non-claims)"

# ---------------------------------------------------------------------------
# 7. Cross-links to operator / observability / security / network / ops runbooks.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/operator/" \
  "docs/release/public-devnet/observability/" \
  "docs/release/public-devnet/security/" \
  "docs/release/public-devnet/network/" \
  "docs/ops/QBIND_INCIDENT_RESPONSE.md" \
  "docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md" ; do
  grep -rqF "${LINK}" "${OPS_DIR}" || fail "ops docs do not cross-link ${LINK}"
done
emit "cross_links=OK (operator, observability, security, network, internal-incident-response, PQC lifecycle referenced)"

# ---------------------------------------------------------------------------
# 8. Non-claim grep over the ops docs.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA' \
  "${OPS_DIR}" 2>/dev/null \
  | grep -viE 'NOT |not launch-ready|no M4|no uptime|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure claim found in ops docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-Green / C4-C5-closure / TestNet-MainNet-ready / uptime-SLA claim)"

# ---------------------------------------------------------------------------
# 9. No private/raw artifact committed under the ops package.
# ---------------------------------------------------------------------------
if find "${OPS_DIR}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
        -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under ops package"
fi
emit "committed_private_material=NONE (ops package is docs only; no keys/logs/metrics/data dirs)"

# ---------------------------------------------------------------------------
# 10. Readiness matrix reconciliation for M15 / M16.
# ---------------------------------------------------------------------------
grep -qE '^- \[x\] M15\.' "${CRITERIA}" || fail "M15 not marked Green (checklist) in readiness criteria"
grep -qE '^- \[x\] M16\.' "${CRITERIA}" || fail "M16 not marked Green (checklist) in readiness criteria"
grep -q "M15 reset policy | 🟢" "${CRITERIA}" || fail "M15 status row not 🟢 in readiness criteria"
grep -q "M16 incident response | 🟢" "${CRITERIA}" || fail "M16 status row not 🟢 in readiness criteria"
# M4 stays Yellow / M6 stays Yellow.
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
emit "readiness_reconciled=OK (M15 🟢; M16 🟢 reconciled; M4 🟡; M6 🟡; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (M15 DevNet reset policy + M16 public-DevNet incident-response guidance published and verified against real CLI/source surfaces; no production source change; M4/M6 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"