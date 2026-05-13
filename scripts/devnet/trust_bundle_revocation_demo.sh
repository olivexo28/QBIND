#!/usr/bin/env bash
#
# Run 060: DevNet-ONLY demonstration of the §6.B emergency root
# revocation + §6.C variant-2 leaf revocation workflows described
# in docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md.
#
# This script is evidence/tooling only. It only invokes the existing
# `devnet_pqc_trust_bundle_helper` example with documented arguments
# and never persists any private key. It does NOT:
#   * bypass any trust-bundle check;
#   * modify any running validator state;
#   * provide production custody for any key.
#
# Usage:
#   scripts/devnet/trust_bundle_revocation_demo.sh [OUTDIR]
# Defaults:
#   OUTDIR = /tmp/qbind-run060-revocation

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run060-revocation}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[demo] OUTDIR=${OUTDIR}"
echo "[demo] REPO_ROOT=${REPO_ROOT}"
echo "[demo] This is a DevNet-ONLY rehearsal of the §6.B / §6.C workflows."
echo "[demo] It does NOT produce production-grade key material."

rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}/baseline" "${OUTDIR}/revoke_leaf_v0" "${OUTDIR}/revoke_leaf_v1"

HELPER="cargo run --quiet -p qbind-node --example devnet_pqc_trust_bundle_helper --"

cd "${REPO_ROOT}"

echo "[demo] Building devnet_pqc_trust_bundle_helper..."
cargo build --quiet -p qbind-node --example devnet_pqc_trust_bundle_helper

# Baseline: signed DevNet bundle, sequence=1. No revocations.
echo "[demo] Step 1/3: minting baseline signed bundle (sequence=1)..."
${HELPER} "${OUTDIR}/baseline" 2 signed-devnet 1
ls -1 "${OUTDIR}/baseline" | sed 's/^/[demo]     /'

# Leaf revocation v0: bundle with revoked_leaf_fingerprints[]
# carrying the fingerprint of v0's leaf cert (Run 054 helper mode).
# This rehearses §6.C variant 2 (leaf compromise suspected).
echo "[demo] Step 2/3: minting bundle that revokes v0's leaf (sequence=2)..."
${HELPER} "${OUTDIR}/revoke_leaf_v0" 2 signed-devnet-revoked-v0 2
ls -1 "${OUTDIR}/revoke_leaf_v0" | sed 's/^/[demo]     /'

# Leaf revocation v1: same shape for the other validator.
echo "[demo] Step 3/3: minting bundle that revokes v1's leaf (sequence=3)..."
${HELPER} "${OUTDIR}/revoke_leaf_v1" 2 signed-devnet-revoked-v1 3
ls -1 "${OUTDIR}/revoke_leaf_v1" | sed 's/^/[demo]     /'

# Confirm no private-key files were produced.
LEAK=$(find "${OUTDIR}" -type f \( -name 'root.sk.*' -o -name 'signing-key.sk.*' -o -name 'bundle-signing.sk.*' \) | wc -l)
if [ "${LEAK}" -ne 0 ]; then
  echo "[demo] FAIL: helper unexpectedly produced private-key file(s):" >&2
  find "${OUTDIR}" -type f \( -name 'root.sk.*' -o -name 'signing-key.sk.*' -o -name 'bundle-signing.sk.*' \) >&2
  exit 1
fi

SUMMARY="${OUTDIR}/summary.txt"
{
  echo "QBIND Run 060 DevNet revocation rehearsal"
  echo "outdir: ${OUTDIR}"
  echo
  echo "baseline (sequence=1):"
  echo "  trust-bundle.json: ${OUTDIR}/baseline/trust-bundle.json"
  echo "  signing-key.spec : $(cat ${OUTDIR}/baseline/signing-key.spec 2>/dev/null || echo '<missing>')"
  echo
  echo "revoke_leaf_v0 (sequence=2):"
  echo "  trust-bundle.json: ${OUTDIR}/revoke_leaf_v0/trust-bundle.json"
  echo "  revokes leaf fp for validator id 0; cert is still presentable by an attacker"
  echo "  but is rejected at every honest listener (Run 052 / Run 054 boundary)."
  echo
  echo "revoke_leaf_v1 (sequence=3):"
  echo "  trust-bundle.json: ${OUTDIR}/revoke_leaf_v1/trust-bundle.json"
  echo "  revokes leaf fp for validator id 1."
  echo
  echo "Operator notes:"
  echo "  * §6.B emergency ROOT revocation is policy-shaped: it would"
  echo "    require an overlap-then-revoke ordering and is not"
  echo "    rehearsable end-to-end by this helper (which mints one"
  echo "    root per bundle). This script focuses on the §6.C leaf"
  echo "    revocation flow which is reproducible with the existing"
  echo "    helper modes."
  echo "  * The Run 055 sequence-anti-rollback persistence layer"
  echo "    refuses to load any earlier-sequence bundle after the"
  echo "    revocation bundle has been persisted; this is the"
  echo "    property that prevents a rollback-style attack on a"
  echo "    fresh revocation."
  echo "  * The validator-side self-check that fails closed when the"
  echo "    validator's OWN --p2p-leaf-cert matches an active"
  echo "    revoked_leaf_fingerprints entry is NOT yet implemented"
  echo "    (Run 052/054 boundary; see runbook §10 item 4)."
  echo "    Operators MUST verify out-of-band that they are not"
  echo "    loading a revoked leaf as their own identity."
} > "${SUMMARY}"

echo "[demo] OK: rehearsal artifacts in ${OUTDIR}"
echo "[demo] Summary: ${SUMMARY}"
echo "[demo] No private-key files produced (verified)."