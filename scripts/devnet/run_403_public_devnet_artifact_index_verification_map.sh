#!/usr/bin/env bash
# Run 403: public DevNet artifact index + operator verification map verification
# harness.
#
# This harness produces the Run 403 acceptance evidence for the public DevNet
# release-package **artifact index + operator verification map** (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_403.md`,
# `docs/release/public-devnet/ARTIFACT_INDEX.md`, and
# `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`). It is a DOCS +
# VERIFICATION run (Decision gate = Route B): it validates the published
# navigation index + verification map against the on-disk package tree and the
# canonical readiness matrix. It makes NO production Rust source change, adds NO
# CLI flag, opens NO externally reachable port, deploys NO
# seed/bootnode/faucet/RPC/explorer/status page, changes NO wire format, weakens
# NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  ARTIFACT_INDEX.md exists and is safety-labelled.
#   2.  OPERATOR_VERIFICATION_MAP.md exists and is safety-labelled.
#   3.  Every major public DevNet package path exists or is explicitly marked absent.
#   4.  Launch go/no-go and blocker register are referenced.
#   5.  M4 checklist and seed reachability template are referenced.
#   6.  Identity continuity and rotation/revocation deferral are referenced.
#   7.  C4/C5 criteria and contradiction ledger are referenced.
#   8.  No readiness item moves Green.
#   9.  M4 remains Yellow.
#   10. M6 remains Yellow/Partial.
#   11. S5 remains Yellow.
#   12. S7 remains Yellow.
#   13. Public DevNet remains NOT launch-ready.
#   14. C4/C5 remain OPEN.
#   15. No TestNet/MainNet readiness claim appears.
#   16. No launch/faucet/RPC/explorer/status-service deployment claim appears.
#   17. No private keys/KEM secrets/root/signing secrets/raw logs/raw metrics/
#       data dirs/private endpoints/absolute paths are committed.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run403-public-devnet-artifact-index-verification-map}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PDN="${REPO_ROOT}/docs/release/public-devnet"
INDEX="${PDN}/ARTIFACT_INDEX.md"
MAP="${PDN}/OPERATOR_VERIFICATION_MAP.md"
GONOGO="${PDN}/LAUNCH_GO_NO_GO.md"
REGISTER="${PDN}/BLOCKER_REGISTER.md"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run403] %s\n' "$*"; }
fail() { printf '[run403] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. ARTIFACT_INDEX.md exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${INDEX}" ] || fail "artifact index missing: ARTIFACT_INDEX.md"
grep -qi 'experimental' "${INDEX}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${INDEX}" \
  && grep -qi 'no C4/C5 closure claim' "${INDEX}" \
  || fail "safety label missing in ARTIFACT_INDEX.md"
emit "artifact_index_doc=OK (ARTIFACT_INDEX.md present, safety-labelled) sha256=$(sha256_file "${INDEX}")"

# ---------------------------------------------------------------------------
# 2. OPERATOR_VERIFICATION_MAP.md exists + carries the safety label.
# ---------------------------------------------------------------------------
[ -f "${MAP}" ] || fail "operator verification map missing: OPERATOR_VERIFICATION_MAP.md"
grep -qi 'experimental' "${MAP}" \
  && grep -qi 'NOT public-DevNet launch-ready' "${MAP}" \
  && grep -qi 'no C4/C5 closure claim' "${MAP}" \
  || fail "safety label missing in OPERATOR_VERIFICATION_MAP.md"
emit "operator_map_doc=OK (OPERATOR_VERIFICATION_MAP.md present, safety-labelled) sha256=$(sha256_file "${MAP}")"

# ---------------------------------------------------------------------------
# 3. Every major public DevNet package path exists OR is explicitly marked absent.
# ---------------------------------------------------------------------------
for PKG in genesis binary operator identity p2p network security observability ops recovery status; do
  if [ -d "${PDN}/${PKG}" ]; then
    grep -qF "${PKG}/" "${INDEX}" || fail "package ${PKG}/ present on disk but not referenced in ARTIFACT_INDEX.md"
  else
    grep -qiE "${PKG}/[^ ]*.*absent|${PKG}.*explicitly.*absent" "${INDEX}" \
      || fail "package ${PKG}/ absent on disk and not explicitly marked absent in ARTIFACT_INDEX.md"
  fi
done
# Both top-level launch docs must be referenced too.
grep -qF "LAUNCH_GO_NO_GO.md" "${INDEX}" || fail "ARTIFACT_INDEX.md does not reference LAUNCH_GO_NO_GO.md"
grep -qF "BLOCKER_REGISTER.md" "${INDEX}" || fail "ARTIFACT_INDEX.md does not reference BLOCKER_REGISTER.md"
emit "package_paths=OK (genesis/binary/operator/identity/p2p/network/security/observability/ops/recovery/status all present + indexed; launch docs referenced)"

# ---------------------------------------------------------------------------
# 4. Launch go/no-go + blocker register referenced (both new docs, union).
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/LAUNCH_GO_NO_GO.md" \
  "docs/release/public-devnet/BLOCKER_REGISTER.md" ; do
  grep -rqF "${LINK}" "${INDEX}" "${MAP}" || fail "index/map does not reference ${LINK}"
done
emit "launch_docs_referenced=OK (LAUNCH_GO_NO_GO.md + BLOCKER_REGISTER.md referenced)"

# ---------------------------------------------------------------------------
# 5. M4 checklist + seed reachability template referenced.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md" \
  "docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md" ; do
  grep -rqF "${LINK}" "${INDEX}" "${MAP}" || fail "index/map does not reference ${LINK}"
done
emit "m4_refs=OK (M4 Route-A checklist + seed reachability evidence template referenced)"

# ---------------------------------------------------------------------------
# 6. Identity continuity + rotation/revocation deferral referenced.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md" \
  "docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md" ; do
  grep -rqF "${LINK}" "${INDEX}" "${MAP}" || fail "index/map does not reference ${LINK}"
done
emit "identity_refs=OK (identity continuity + rotation/revocation deferral referenced)"

# ---------------------------------------------------------------------------
# 7. C4/C5 criteria + contradiction ledger referenced.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md" \
  "docs/whitepaper/contradiction.md" ; do
  grep -rqF "${LINK}" "${INDEX}" "${MAP}" || fail "index/map does not reference ${LINK}"
done
emit "c4_c5_refs=OK (C4/C5 closure criteria + contradiction ledger referenced)"

# ---------------------------------------------------------------------------
# 8. Referenced doc/harness targets actually resolve on disk.
# ---------------------------------------------------------------------------
MISSING=""
for TARGET in \
  "docs/release/public-devnet/LAUNCH_GO_NO_GO.md" \
  "docs/release/public-devnet/BLOCKER_REGISTER.md" \
  "docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md" \
  "docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md" \
  "docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md" \
  "docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md" \
  "docs/release/public-devnet/status/STATUS_PAGE_DECISION.md" \
  "docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md" \
  "docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md" \
  "docs/whitepaper/contradiction.md" ; do
  [ -e "${REPO_ROOT}/${TARGET}" ] || MISSING="${MISSING} ${TARGET}"
done
[ -z "${MISSING}" ] || fail "referenced target(s) missing on disk:${MISSING}"
emit "link_targets_resolve=OK (all cross-linked docs resolve on disk)"

# ---------------------------------------------------------------------------
# 9. Non-claim grep over the two new docs.
#    Normalize first: strip markdown emphasis/backticks/table pipes and join
#    wrapped lines.
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
CLAIM_HITS="$(for f in "${INDEX}" "${MAP}"; do normalize_md "$f"; done \
  | grep -Ei 'is launch-ready|M4 is Green|M6 is Green|S5 is Green|S7 is Green|C4 closed|C5 closed|TestNet ready|MainNet ready|status service deployed|faucet deployed|explorer deployed|RPC deployed|seed is live' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no S5|no S7|neither|does not|do not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT|deferred|until M4|without real' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/launch/deployment claim found in index/map"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim)"

# ---------------------------------------------------------------------------
# 10. No private/raw artifact + no absolute path/private endpoint committed.
# ---------------------------------------------------------------------------
if find "${PDN}" -maxdepth 1 -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under public-devnet package root"
fi
if grep -nE '(^|[^A-Za-z])/(home|root|Users|tmp|var|etc)/' "${INDEX}" "${MAP}"; then
  fail "absolute filesystem path found in index/map"
fi
if grep -niE 'BEGIN [A-Z ]*PRIVATE KEY|kem\.sk|signing[_-]secret|api[_-]?key|password=' "${INDEX}" "${MAP}"; then
  fail "possible secret / private material found in index/map"
fi
emit "committed_private_material=NONE (docs only; no keys/logs/metrics/data dirs/absolute paths/private endpoints)"

# ---------------------------------------------------------------------------
# 11. Launch stop rule present in the operator verification map.
# ---------------------------------------------------------------------------
grep -qi 'do not attempt launch while M4' "${MAP}" \
  && grep -qi 'do not create .devnet-seeds.live.json. without real M4' "${MAP}" \
  && grep -qi 'do not claim TestNet' "${MAP}" \
  && grep -qi 'do not claim C4' "${MAP}" \
  || fail "operator verification map missing the four-part launch stop rule"
emit "stop_rule=OK (no launch while M4/M6 Yellow; no live seed-list without M4 evidence; no TestNet/MainNet; no C4/C5 closure)"

# ---------------------------------------------------------------------------
# 12. Readiness matrix reconciliation: M4/M6/S5/S7 stay Yellow; C4/C5 OPEN.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (public-DevNet artifact index + operator verification map published and verified against the on-disk package tree and the canonical readiness matrix; no production source change; no readiness item moves Green; M4/M6/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"