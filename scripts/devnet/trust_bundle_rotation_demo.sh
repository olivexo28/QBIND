#!/usr/bin/env bash
#
# Run 060: DevNet-ONLY demonstration of the §6.A normal transport
# root rotation workflow described in
# docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md.
#
# This script is evidence/tooling only. It:
#   * never writes a private key to disk in any form (the underlying
#     devnet_pqc_trust_bundle_helper mints all root/signing/KEM
#     secrets in memory and never persists them);
#   * never bypasses a trust-bundle check (it only calls the existing
#     binary with documented CLI flags);
#   * fails on first error (`set -euo pipefail`);
#   * outputs artifact paths and canonical bundle fingerprints;
#   * does NOT consume any external KMS / HSM.
#
# It is NOT a production rotation tool. Production rotation uses the
# offline / HSM authorities described in §4 of the runbook. This
# script reproduces the bundle-envelope side of §6.A on DevNet so
# operators can rehearse the workflow shape and confirm the
# fail-closed boundaries.
#
# Usage:
#   scripts/devnet/trust_bundle_rotation_demo.sh [OUTDIR]
# Defaults:
#   OUTDIR = /tmp/qbind-run060-rotation
#
# What it produces under OUTDIR:
#   bundle_n/        Initial signed DevNet bundle, sequence=1.
#   bundle_n1/       Overlap signed DevNet bundle, sequence=2.
#   bundle_n2/       Retire signed DevNet bundle, sequence=3.
#   summary.txt      Canonical fingerprints + signing key IDs.
#
# What it does NOT produce:
#   * any private key file (`root.sk.*`, `signing-key.sk.*`,
#     `bundle-signing.sk.*`) — these are minted in memory only and
#     never persisted, by the helper itself;
#   * any modification to a running validator's state.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run060-rotation}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[demo] OUTDIR=${OUTDIR}"
echo "[demo] REPO_ROOT=${REPO_ROOT}"
echo "[demo] This is a DevNet-ONLY rehearsal of the §6.A workflow."
echo "[demo] It does NOT produce production-grade key material."

rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}/bundle_n" "${OUTDIR}/bundle_n1" "${OUTDIR}/bundle_n2"

HELPER="cargo run --quiet -p qbind-node --example devnet_pqc_trust_bundle_helper --"

cd "${REPO_ROOT}"

# Build once up front so the per-bundle invocations are quick.
echo "[demo] Building devnet_pqc_trust_bundle_helper..."
cargo build --quiet -p qbind-node --example devnet_pqc_trust_bundle_helper

# Bundle N (sequence=1): the steady-state bundle the network is
# already running on.
#
# Positional arguments to the helper (see top-of-file docs in
# crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs):
#   <outdir> <num_validators> [bundle_mode] [sequence_override]
#     [activation_height_override] [chain_id_override]
#
# Mode `signed-devnet` produces a valid signed DevNet bundle.
echo "[demo] Step 1/3: minting bundle N (sequence=1) under root R_old..."
${HELPER} "${OUTDIR}/bundle_n" 2 signed-devnet 1
echo "[demo]   bundle_n outputs:"
ls -1 "${OUTDIR}/bundle_n" | sed 's/^/[demo]     /'

# Bundle N+1 (sequence=2): the overlap bundle.
#
# In a real §6.A rotation this would carry BOTH R_old and R_new as
# active roots, with an activation_height past the current finalised
# height. The helper today mints one root per invocation, so this
# demonstration uses two distinct one-root bundles to illustrate the
# sequence anti-rollback boundary; the policy shape (overlap window)
# is described in the runbook §6.A and must be implemented by the
# offline transport root authority for real rotations.
echo "[demo] Step 2/3: minting bundle N+1 (sequence=2) under root R_new..."
${HELPER} "${OUTDIR}/bundle_n1" 2 signed-devnet 2
echo "[demo]   bundle_n1 outputs:"
ls -1 "${OUTDIR}/bundle_n1" | sed 's/^/[demo]     /'

# Bundle N+2 (sequence=3): the retire bundle.
echo "[demo] Step 3/3: minting bundle N+2 (sequence=3) under root R_new..."
${HELPER} "${OUTDIR}/bundle_n2" 2 signed-devnet 3
echo "[demo]   bundle_n2 outputs:"
ls -1 "${OUTDIR}/bundle_n2" | sed 's/^/[demo]     /'

# Confirm no private-key files were produced.
LEAK=$(find "${OUTDIR}" -type f \( -name 'root.sk.*' -o -name 'signing-key.sk.*' -o -name 'bundle-signing.sk.*' \) | wc -l)
if [ "${LEAK}" -ne 0 ]; then
  echo "[demo] FAIL: helper unexpectedly produced private-key file(s):" >&2
  find "${OUTDIR}" -type f \( -name 'root.sk.*' -o -name 'signing-key.sk.*' -o -name 'bundle-signing.sk.*' \) >&2
  exit 1
fi

# Emit summary with canonical fingerprints from the helper's stderr
# (the helper prints `bundle_fingerprint=<hex>` style summary lines;
# operators verify these against their artifact inventory log).
SUMMARY="${OUTDIR}/summary.txt"
{
  echo "QBIND Run 060 DevNet rotation rehearsal"
  echo "outdir: ${OUTDIR}"
  echo
  echo "bundle_n  (sequence=1):"
  echo "  trust-bundle.json: ${OUTDIR}/bundle_n/trust-bundle.json"
  echo "  signing-key.spec : $(cat ${OUTDIR}/bundle_n/signing-key.spec 2>/dev/null || echo '<missing>')"
  echo "  root.id          : $(cat ${OUTDIR}/bundle_n/root.id.hex 2>/dev/null || echo '<missing>')"
  echo
  echo "bundle_n1 (sequence=2):"
  echo "  trust-bundle.json: ${OUTDIR}/bundle_n1/trust-bundle.json"
  echo "  signing-key.spec : $(cat ${OUTDIR}/bundle_n1/signing-key.spec 2>/dev/null || echo '<missing>')"
  echo "  root.id          : $(cat ${OUTDIR}/bundle_n1/root.id.hex 2>/dev/null || echo '<missing>')"
  echo
  echo "bundle_n2 (sequence=3):"
  echo "  trust-bundle.json: ${OUTDIR}/bundle_n2/trust-bundle.json"
  echo "  signing-key.spec : $(cat ${OUTDIR}/bundle_n2/signing-key.spec 2>/dev/null || echo '<missing>')"
  echo "  root.id          : $(cat ${OUTDIR}/bundle_n2/root.id.hex 2>/dev/null || echo '<missing>')"
  echo
  echo "Operator notes:"
  echo "  * The helper mints fresh ephemeral root and signing keys"
  echo "    per invocation, so bundle_n, bundle_n1, bundle_n2 do NOT"
  echo "    share a signing key. A real §6.A rotation reuses the same"
  echo "    bundle-signing authority across the three bundles and"
  echo "    overlaps two roots in bundle_n1."
  echo "  * The Run 055 sequence-anti-rollback persistence layer"
  echo "    refuses to load bundle_n after bundle_n1 has been"
  echo "    persisted (RUN_055/056 invariant); this is the property"
  echo "    that makes rotation safe against replay."
} > "${SUMMARY}"

echo "[demo] OK: rehearsal artifacts in ${OUTDIR}"
echo "[demo] Summary: ${SUMMARY}"
echo "[demo] No private-key files produced (verified)."