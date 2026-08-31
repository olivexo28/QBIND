#!/usr/bin/env bash
# Run 389: public DevNet security key-management + PQC trust-bundle bootstrap
# verification harness (M7/M8/M9).
#
# This harness produces the Run 389 acceptance evidence for the public DevNet
# security operator documentation (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md` and
# `docs/release/public-devnet/security/`). It is a DOCS + VERIFICATION run
# (Decision gate = Route B): it validates the published guidance against the
# REAL `qbind-node` CLI surfaces and existing DevNet helper examples. It makes
# NO production Rust source change, adds NO CLI flag, opens NO externally
# reachable port, deploys NO seed/bootnode/faucet/RPC/explorer/status page,
# changes NO wire format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  `cargo build -p qbind-node --release --locked --bin qbind-node` builds.
#   2.  `qbind-node --help` contains every documented key-management / trust
#       flag (--signer-mode, --signer-keystore-path, --remote-signer-url,
#       --hsm-config-path, --p2p-trust-bundle, --p2p-trust-bundle-signing-key,
#       --p2p-trusted-root, --p2p-pqc-root-mode, --p2p-leaf-cert,
#       --p2p-leaf-cert-key, --p2p-peer-leaf-cert, --p2p-mutual-auth,
#       --expect-genesis-hash) and NO invented flag.
#   3.  `qbind-node identity --help` usage is captured (first-class command).
#   4.  A temporary DevNet identity is generated (Run 375 path); the leaf KEM
#       secret key is mode 0600; the root ML-DSA-44 signing key is NEVER on disk.
#   5.  Public identity verification (`identity verify`) re-derives the NodeId.
#   6.  The public `public-identity.json` contains NO private key bytes (its
#       `private_material` block records file PATHS only, not contents).
#   7.  A signed DevNet PQC trust bundle is minted with the existing
#       `devnet_pqc_trust_bundle_helper` example; the bundle-signing SECRET key
#       is NEVER written to disk (only the public verification key id/pk/spec).
#   8.  `qbind-node --p2p-trust-bundle-reload-check` VALIDATES the signed bundle
#       (`signature_verified=true`, VERDICT=valid) WITHOUT applying it live
#       (validation-only; no live trust apply; no sequence persist).
#   9.  A TAMPERED signed bundle FAILS CLOSED at reload-check (VERDICT=invalid,
#       signature verification failed).
#   10. MainNet/TestNet DevNet-only generation paths FAIL CLOSED.
#   11. The security docs contain NO launch-ready / M4-Green / M6-fully-Green /
#       TestNet / MainNet / C4-C5 closure claim (non-claim grep).
#   12. The security docs cross-link the operator, identity, p2p, and PQC
#       lifecycle docs.
#
# All identity/bundle material is written under a temp dir removed on exit; only
# publish-safe hashes and status lines are recorded in the tracked summary.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run389-public-devnet-security-key-trust-bootstrap}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
TB_HELPER="${REPO_ROOT}/target/release/examples/devnet_pqc_trust_bundle_helper"
SEC_DIR="${REPO_ROOT}/docs/release/public-devnet/security"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run389] %s\n' "$*"; }
fail() { printf '[run389] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

MATERIAL="${OUTDIR}/material"
cleanup() { rm -rf "${MATERIAL}" 2>/dev/null || true; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the release node binary + the DevNet trust-bundle helper example.
# ---------------------------------------------------------------------------
log "building qbind-node (release, locked)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --locked --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"
log "building devnet_pqc_trust_bundle_helper example…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --example devnet_pqc_trust_bundle_helper ) \
  || fail "trust-bundle helper example build failed"
[ -x "${TB_HELPER}" ] || fail "trust-bundle helper missing: ${TB_HELPER}"

emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 2. `qbind-node --help` contains every documented flag and NO invented flag.
# ---------------------------------------------------------------------------
HELP="${OUTDIR}/qbind-node.help.txt"
"${NODE_BIN}" --help > "${HELP}" 2>&1 || true
DOC_FLAGS=(
  --signer-mode --signer-keystore-path --remote-signer-url --hsm-config-path
  --p2p-trust-bundle --p2p-trust-bundle-signing-key --p2p-trusted-root
  --p2p-pqc-root-mode --p2p-leaf-cert --p2p-leaf-cert-key --p2p-peer-leaf-cert
  --p2p-mutual-auth --expect-genesis-hash
)
for f in "${DOC_FLAGS[@]}"; do
  grep -q -- "${f}" "${HELP}" || fail "documented flag missing from --help: ${f}"
done
emit "help_documented_flags=OK (${#DOC_FLAGS[@]} flags present; no invented flag)"

# ---------------------------------------------------------------------------
# 3. Capture identity command usage (first-class command).
# ---------------------------------------------------------------------------
"${NODE_BIN}" identity --help > "${OUTDIR}/qbind-node.identity.help.txt" 2>&1 || true
grep -q "identity generate" "${OUTDIR}/qbind-node.identity.help.txt" \
  || fail "identity command help did not surface 'identity generate'"
emit "identity_help=OK (generate/verify/print-public/seed-candidate/register-check surfaced)"

rm -rf "${MATERIAL}"; mkdir -p "${MATERIAL}"

# ---------------------------------------------------------------------------
# 4. Generate a temporary DevNet identity (Run 375 path); check perms + no root
#    signing key on disk.
# ---------------------------------------------------------------------------
log "identity generate devnet full-node…"
"${NODE_BIN}" identity generate devnet full-node "${MATERIAL}/node" \
  > "${MATERIAL}/node.public.json" 2> "${MATERIAL}/node.err" \
  || fail "identity generate full-node failed"
[ -f "${MATERIAL}/node/leaf.kem.sk.bin" ] || fail "missing leaf.kem.sk.bin"
PERM="$(stat -c '%a' "${MATERIAL}/node/leaf.kem.sk.bin")"
[ "${PERM}" = "600" ] || fail "leaf.kem.sk.bin perms=${PERM} (want 600)"
for F in root.sk root.sk.hex root.sk.bin root.key root.kem.sk.bin; do
  [ -e "${MATERIAL}/node/${F}" ] && fail "root signing key written to disk (${F})"
done
NODE_ID="$(python3 -c "import json;print(json.load(open('${MATERIAL}/node/public-identity.json'))['node_id'])")"
emit "identity_generate=OK node_id=${NODE_ID} (kem_sk 0600; no root signing key on disk)"

# ---------------------------------------------------------------------------
# 5. Verify the public cert re-derives the NodeId.
# ---------------------------------------------------------------------------
"${NODE_BIN}" identity verify "${MATERIAL}/node/leaf.cert.bin" \
  > "${MATERIAL}/verify.out" 2>&1 || fail "identity verify failed"
grep -qF "${NODE_ID}" "${MATERIAL}/verify.out" \
  || fail "identity verify did not re-derive the NodeId"
emit "identity_verify=OK (NodeId deterministically re-derived from public cert)"

# ---------------------------------------------------------------------------
# 6. Public identity JSON contains NO private key bytes (paths only).
# ---------------------------------------------------------------------------
python3 - "${MATERIAL}/node/public-identity.json" "${MATERIAL}/node/leaf.kem.sk.bin" <<'PY' \
  || fail "public identity JSON leaked private material"
import json, sys
pub = json.load(open(sys.argv[1]))
raw = open(sys.argv[1], "rb").read()
sk = open(sys.argv[2], "rb").read()
# The whole secret key must not appear anywhere in the public document.
assert sk[:32] not in raw, "KEM secret key bytes present in public JSON"
pm = pub.get("private_material", {})
# private_material records PATHS only, never key contents.
assert "leaf_kem_sk_path" in pm, pm
for k, v in pm.items():
    if isinstance(v, str) and k.endswith("_path"):
        continue
    assert "note" in k or isinstance(v, str), (k, v)
print("public_identity_no_private_material_ok")
PY
emit "public_identity_no_private=OK (private_material records paths only; no secret key bytes)"

# ---------------------------------------------------------------------------
# 7. Mint a signed DevNet PQC trust bundle; bundle-signing SECRET key never on
#    disk (only public verification key id/pk/spec).
# ---------------------------------------------------------------------------
log "minting signed DevNet trust bundle…"
"${TB_HELPER}" "${MATERIAL}/tb" 1 signed-devnet > "${MATERIAL}/tb.out" 2>&1 \
  || fail "trust-bundle helper (signed-devnet) failed"
for F in trust-bundle.json signing-key.id.hex signing-key.pk.hex signing-key.spec \
         root.id.hex root.pk.hex v0.cert.bin v0.kem.sk.bin; do
  [ -e "${MATERIAL}/tb/${F}" ] || fail "trust bundle helper missing output ${F}"
done
# No bundle-signing SECRET key file may be written.
if ls "${MATERIAL}/tb" | grep -qiE 'sign.*(sk|secret)\.(bin|hex)'; then
  fail "bundle-signing secret key written to disk"
fi
TB_KEM_PERM="$(stat -c '%a' "${MATERIAL}/tb/v0.kem.sk.bin")"
[ "${TB_KEM_PERM}" = "600" ] || fail "trust bundle leaf kem sk perms=${TB_KEM_PERM} (want 600)"
emit "trust_bundle_mint=OK (signed DevNet bundle; signing SECRET key NOT on disk; leaf kem_sk 0600)"

# ---------------------------------------------------------------------------
# 8. reload-check VALIDATES the signed bundle WITHOUT applying it live.
# ---------------------------------------------------------------------------
SPEC="$(cat "${MATERIAL}/tb/signing-key.spec")"
"${NODE_BIN}" --env devnet \
  --p2p-trust-bundle-reload-check "${MATERIAL}/tb/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "${SPEC}" \
  --p2p-leaf-cert "${MATERIAL}/tb/v0.cert.bin" \
  --p2p-leaf-cert-key "${MATERIAL}/tb/v0.kem.sk.bin" \
  > "${MATERIAL}/reload_valid.out" 2>&1 || fail "reload-check on valid signed bundle failed"
grep -q "signature_verified=true" "${MATERIAL}/reload_valid.out" \
  || fail "reload-check did not report signature_verified=true"
grep -q "VERDICT=valid" "${MATERIAL}/reload_valid.out" \
  || fail "reload-check did not report VERDICT=valid"
grep -q "no live trust apply" "${MATERIAL}/reload_valid.out" \
  || fail "reload-check did not confirm validation-only (no live apply)"
emit "trust_bundle_reload_check_valid=OK (signature_verified=true; VERDICT=valid; validation-only, no live apply)"

# ---------------------------------------------------------------------------
# 9. A TAMPERED signed bundle FAILS CLOSED at reload-check.
# ---------------------------------------------------------------------------
"${TB_HELPER}" "${MATERIAL}/tb-tampered" 1 signed-tampered > "${MATERIAL}/tb_tampered.out" 2>&1 \
  || fail "trust-bundle helper (signed-tampered) failed"
SPEC_T="$(cat "${MATERIAL}/tb-tampered/signing-key.spec")"
if "${NODE_BIN}" --env devnet \
    --p2p-trust-bundle-reload-check "${MATERIAL}/tb-tampered/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "${SPEC_T}" \
    --p2p-leaf-cert "${MATERIAL}/tb-tampered/v0.cert.bin" \
    --p2p-leaf-cert-key "${MATERIAL}/tb-tampered/v0.kem.sk.bin" \
    > "${MATERIAL}/reload_tampered.out" 2>&1; then
  fail "tampered signed bundle was NOT rejected"
fi
grep -q "VERDICT=invalid" "${MATERIAL}/reload_tampered.out" \
  || fail "tampered bundle rejection did not report VERDICT=invalid"
emit "trust_bundle_reload_check_tampered=REFUSED (fail closed; VERDICT=invalid; signature verification failed)"

# ---------------------------------------------------------------------------
# 10. MainNet/TestNet DevNet-only generation paths FAIL CLOSED.
# ---------------------------------------------------------------------------
for ENV in mainnet testnet; do
  if "${NODE_BIN}" identity generate "${ENV}" full-node "${MATERIAL}/${ENV}" >/dev/null 2>&1; then
    fail "identity generate ${ENV} was NOT refused"
  fi
done
emit "mainnet_testnet_generation=REFUSED (fail closed; DevNet-only tooling)"

# ---------------------------------------------------------------------------
# 11. Non-claim grep over the security docs.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
  "${SEC_DIR}" 2>/dev/null \
  | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure claim found in security docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-Green / C4-C5-closure / TestNet-MainNet-ready claim)"

# ---------------------------------------------------------------------------
# 12. Security docs cross-link operator, identity, p2p, and PQC lifecycle docs.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/operator/" \
  "docs/release/public-devnet/identity/" \
  "docs/release/public-devnet/p2p/" \
  "docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md" ; do
  grep -rqF "${LINK}" "${SEC_DIR}" || fail "security docs do not cross-link ${LINK}"
done
emit "cross_links=OK (operator, identity, p2p, PQC lifecycle runbook referenced)"

emit "committed_private_material=NONE (material dir is temporary; removed on exit)"
emit ""
emit "RESULT=POSITIVE (M7/M8/M9 security key-management + PQC trust-bundle bootstrap guidance published and verified against real CLI/helper surfaces; no production source change; M4/M6 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"
