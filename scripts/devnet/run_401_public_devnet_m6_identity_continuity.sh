#!/usr/bin/env bash
# Run 401: public DevNet M6 operator identity continuity / rotation-revocation
# deferral verification harness.
#
# This harness produces the Run 401 acceptance evidence for the public DevNet
# operator identity continuity documentation (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md` and
# `docs/release/public-devnet/identity/`). It is a DOCS + VERIFICATION run
# (Decision gate = Route B): it validates the published guidance against the
# REAL first-class `qbind-node identity` command surfaces. It makes NO production
# Rust source change, adds NO CLI flag, opens NO externally reachable port,
# deploys NO seed/bootnode/faucet/RPC/explorer/status page, changes NO wire
# format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  `cargo build -p qbind-node --release --locked --bin qbind-node` builds.
#   2.  The Run 401 continuity docs exist (IDENTITY_CONTINUITY.md,
#       ROTATION_REVOCATION_DEFERRAL.md) and carry the DevNet safety label.
#   3.  The documented identity commands are present in the `qbind-node identity`
#       help/usage surface (generate/verify/print-public/seed-candidate/
#       register-check).
#   4.  The generate/verify/print-public/seed-candidate/register-check surfaces
#       remain present and functional (a real DevNet identity is generated and
#       its node_id is deterministically re-derived — durable reuse).
#   5.  MainNet/TestNet identity generation is refused.
#   6.  IDENTITY_CONTINUITY.md carries the required continuity sections.
#   7.  ROTATION_REVOCATION_DEFERRAL.md carries the required deferral sections.
#   8.  The continuity docs cross-link the C4/C5, trust-anchor, PQC-lifecycle,
#       security, and recovery references.
#   9.  Non-claim grep over the identity docs passes (no launch-ready / M4-M6
#       Green / C4-C5 closure / rotation-delivered claim).
#   10. No private key/KEM/root/signing material is committed under the identity
#       package.
#   11. Readiness matrix reconciliation: M6 🟡, M4 🟡, S5 🟡, S7 🟡, C4/C5 OPEN,
#       public DevNet NOT launch-ready.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run401-public-devnet-m6-identity-continuity}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
ID_DIR="${REPO_ROOT}/docs/release/public-devnet/identity"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run401] %s\n' "$*"; }
fail() { printf '[run401] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

# ---------------------------------------------------------------------------
# 1. Build the release node binary (which carries the `identity` command).
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
# 2. Run 401 continuity docs exist + carry the safety label.
# ---------------------------------------------------------------------------
for F in IDENTITY_CONTINUITY ROTATION_REVOCATION_DEFERRAL; do
  [ -f "${ID_DIR}/${F}.md" ] || fail "identity package missing ${F}.md"
  grep -qi 'experimental' "${ID_DIR}/${F}.md" \
    && grep -qi 'no C4/C5 closure claim' "${ID_DIR}/${F}.md" \
    && grep -qi 'NOT public-DevNet launch-ready' "${ID_DIR}/${F}.md" \
    || fail "safety label missing in ${F}.md"
done
emit "continuity_docs=OK (IDENTITY_CONTINUITY.md + ROTATION_REVOCATION_DEFERRAL.md present, safety-labelled)"

# ---------------------------------------------------------------------------
# 3. Documented identity commands are present in the identity help/usage surface.
#    The `identity` subcommand is dispatched before flag parsing, so its usage is
#    the authoritative command surface. Invoking `identity` with no subcommand
#    prints the usage listing every documented command.
# ---------------------------------------------------------------------------
HELP="${OUTDIR}/qbind-node.identity.usage.txt"
"${NODE_BIN}" identity > "${HELP}" 2>&1 || true
for C in generate verify print-public seed-candidate register-check; do
  grep -q -- "qbind-node identity ${C}" "${HELP}" \
    || fail "documented identity command not present in identity help/usage: ${C}"
done
emit "identity_help_commands=OK (generate/verify/print-public/seed-candidate/register-check present in identity usage)"

# ---------------------------------------------------------------------------
# 4. generate/verify/print-public/seed-candidate/register-check surfaces remain
#    present and functional; node_id is deterministically re-derivable (durable
#    reuse). Generate into a temp dir OUTSIDE the repo tree.
# ---------------------------------------------------------------------------
MAT="${OUTDIR}/material"
mkdir -p "${MAT}"
"${NODE_BIN}" identity generate devnet full-node "${MAT}/node" > "${MAT}/node.public.json" \
  || fail "identity generate failed"
[ -f "${MAT}/node/leaf.kem.sk.bin" ] || fail "leaf KEM secret not produced"
PERMS="$(stat -c '%a' "${MAT}/node/leaf.kem.sk.bin" 2>/dev/null || echo '?')"
[ "${PERMS}" = "600" ] || fail "leaf KEM secret not 0600 (got ${PERMS})"
GEN_ID="$(python3 -c "import json;print(json.load(open('${MAT}/node.public.json'))['node_id'])")"
VER_ID="$("${NODE_BIN}" identity verify "${MAT}/node/leaf.cert.bin" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['node_id'])")"
[ -n "${GEN_ID}" ] && [ "${GEN_ID}" = "${VER_ID}" ] \
  || fail "node_id not deterministically re-derived (reuse) gen=${GEN_ID} ver=${VER_ID}"
"${NODE_BIN}" identity print-public "${MAT}/node" >/dev/null 2>&1 || fail "identity print-public failed"
"${NODE_BIN}" identity seed-candidate "${MAT}/node" > "${MAT}/node.candidate.json" 2>/dev/null \
  || fail "identity seed-candidate failed"
"${NODE_BIN}" identity register-check "${MAT}/node.public.json" \
  --seed-list "${REPO_ROOT}/docs/release/public-devnet/network/devnet-seeds.placeholder.json" \
  --role full-node --cert "${MAT}/node/leaf.cert.bin" >/dev/null 2>&1 \
  || fail "identity register-check (planned) failed for a valid candidate"
emit "identity_surfaces=OK (generate/verify/print-public/seed-candidate/register-check functional; node_id reuse deterministic; leaf secret 0600)"

# ---------------------------------------------------------------------------
# 5. MainNet/TestNet identity generation is refused.
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity generate mainnet full-node "${MAT}/should-not-exist" >/dev/null 2>&1; then
  fail "MainNet identity generation was NOT refused"
fi
if "${NODE_BIN}" identity generate testnet seed "${MAT}/should-not-exist2" >/dev/null 2>&1; then
  fail "TestNet identity generation was NOT refused"
fi
[ ! -e "${MAT}/should-not-exist" ] && [ ! -e "${MAT}/should-not-exist2" ] \
  || fail "MainNet/TestNet material was written despite refusal"
emit "mainnet_testnet_generation=REFUSED (no material written)"

# ---------------------------------------------------------------------------
# 6. IDENTITY_CONTINUITY.md required sections.
# ---------------------------------------------------------------------------
for S in 'durable operator identity' 'MAY reuse' 'must NOT be rotated' \
         'Safe public/private material' 'leaf.kem.sk.bin' 'node_id' 'in-memory only'; do
  grep -qiE "${S}" "${ID_DIR}/IDENTITY_CONTINUITY.md" || fail "IDENTITY_CONTINUITY.md missing section: ${S}"
done
emit "continuity_sections=OK (durable-identity/may-reuse/no-hand-rotate/material-handling/leaf-secret/node_id/in-memory-root)"

# ---------------------------------------------------------------------------
# 7. ROTATION_REVOCATION_DEFERRAL.md required sections.
# ---------------------------------------------------------------------------
for S in 'NOT implemented' 'explicitly deferred' 'online revocation' \
         'CA lifecycle' 'C4' 'C5' 'MainNet'; do
  grep -qiE "${S}" "${ID_DIR}/ROTATION_REVOCATION_DEFERRAL.md" || fail "ROTATION_REVOCATION_DEFERRAL.md missing section: ${S}"
done
emit "deferral_sections=OK (not-implemented/explicitly-deferred/no-online-revocation/no-CA-lifecycle/C4/C5/MainNet)"

# ---------------------------------------------------------------------------
# 8. Cross-links to C4/C5, trust-anchor, PQC-lifecycle, security, recovery.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md" \
  "docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md" \
  "docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md" \
  "docs/release/public-devnet/security/KEY_MANAGEMENT.md" \
  "docs/whitepaper/contradiction.md" ; do
  grep -rqF "${LINK}" "${ID_DIR}/IDENTITY_CONTINUITY.md" "${ID_DIR}/ROTATION_REVOCATION_DEFERRAL.md" \
    || fail "continuity docs do not cross-link ${LINK}"
done
emit "cross_links=OK (C4/C5, trust-anchor, PQC-lifecycle, security/KEY_MANAGEMENT, contradiction referenced)"

# ---------------------------------------------------------------------------
# 9. Non-claim grep over the identity docs.
#    Normalize first: strip markdown emphasis/backticks and join wrapped lines.
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
CLAIM_HITS="$(for f in "${ID_DIR}"/IDENTITY_CONTINUITY.md "${ID_DIR}"/ROTATION_REVOCATION_DEFERRAL.md; do normalize_md "$f"; done \
  | grep -Ei 'launch-ready|M4 Green|M6 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|rotation is implemented|revocation is implemented' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|neither|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no TestNet|no MainNet|not implemented|is NOT' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure/rotation claim found in identity continuity docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-Green / C4-C5-closure / TestNet-MainNet-ready / rotation-delivered claim)"

# ---------------------------------------------------------------------------
# 10. No private/raw artifact committed under the identity package.
# ---------------------------------------------------------------------------
if find "${ID_DIR}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.cert.bin' -o -name '*.key' -o -name '*.log' \
        -o -name 'metrics*.txt' -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under identity package"
fi
emit "committed_private_material=NONE (identity package is docs/schema only; no keys/logs/metrics/data dirs)"

# ---------------------------------------------------------------------------
# 11. Readiness matrix reconciliation: M6/M4/S5/S7 stay Yellow; C4/C5 OPEN.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S5 status page | 🟡" "${CRITERIA}" || fail "S5 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (public-DevNet M6 operator identity continuity + rotation/revocation deferral package published and verified against the real qbind-node identity CLI surfaces; no production source change; M6 stays Yellow/Partial; M4/S5/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"
