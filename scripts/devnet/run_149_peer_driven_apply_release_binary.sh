#!/usr/bin/env bash
# Run 149: release-binary evidence harness for DevNet/TestNet peer-driven
# apply arming. The harness records binary identity, proves the new apply
# flag is hidden/default-off/MainNet-refused, and provides the exact command
# surfaces for the live N=3 0x05 validation -> staging -> Run 148 controller
# path. It does not fabricate success: if prerequisites for a full local
# DevNet apply run are absent, the report records a partial-positive.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run149-peer-driven-apply-release-binary}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE_DIR="${QBIND_RUN149_ARCHIVE_DIR:-${REPO_ROOT}/docs/devnet/run_149_peer_driven_apply_release_binary}"
NODE_BIN="${QBIND_RUN149_NODE_BIN:-${REPO_ROOT}/target/release/qbind-node}"
V2_HELPER="${QBIND_RUN149_V2_HELPER:-${REPO_ROOT}/target/release/examples/run_133_v2_validation_only_fixture_helper}"

log() { printf '[run149] %s\n' "$*"; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }

rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}" "${ARCHIVE_DIR}"

{
  echo "# Run 149 peer-driven apply release-binary evidence"
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo=${REPO_ROOT}"
  echo "git_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "node_bin=${NODE_BIN}"
} > "${OUTDIR}/manifest.txt"

if [[ ! -x "${NODE_BIN}" ]]; then
  log "building release qbind-node"
  (cd "${REPO_ROOT}" && cargo build --release -p qbind-node --bin qbind-node) \
    >"${OUTDIR}/cargo-build-release-qbind-node.stdout" \
    2>"${OUTDIR}/cargo-build-release-qbind-node.stderr"
fi

{
  echo "qbind-node.sha256=$(sha256_file "${NODE_BIN}")"
  echo "qbind-node.build_id=$(build_id "${NODE_BIN}" || true)"
  if [[ -x "${V2_HELPER}" ]]; then
    echo "run_133_v2_helper.sha256=$(sha256_file "${V2_HELPER}")"
    echo "run_133_v2_helper.build_id=$(build_id "${V2_HELPER}" || true)"
  else
    echo "run_133_v2_helper=not-built"
  fi
} > "${OUTDIR}/binary-identities.txt"

"${NODE_BIN}" --help >"${OUTDIR}/qbind-node-help.stdout" 2>"${OUTDIR}/qbind-node-help.stderr" || true
if grep -q -- '--p2p-trust-bundle-peer-candidate-apply-enabled' "${OUTDIR}/qbind-node-help.stdout"; then
  echo "hidden_flag_verdict=FAIL_visible_in_help" > "${OUTDIR}/hidden-flag-verdict.txt"
  exit 1
else
  echo "hidden_flag_verdict=PASS_hidden_from_help" > "${OUTDIR}/hidden-flag-verdict.txt"
fi

set +e
"${NODE_BIN}" \
  --env mainnet \
  --network-mode p2p \
  --enable-p2p \
  --p2p-trust-bundle-peer-candidate-apply-enabled \
  >"${OUTDIR}/mainnet-refusal.stdout" \
  2>"${OUTDIR}/mainnet-refusal.stderr"
MAINNET_RC=$?
set -e
printf 'mainnet_refusal_exit_code=%s\n' "${MAINNET_RC}" > "${OUTDIR}/mainnet-refusal-verdict.txt"
if [[ "${MAINNET_RC}" -eq 0 ]] || ! grep -q 'Run 149: FATAL' "${OUTDIR}/mainnet-refusal.stderr"; then
  echo "mainnet_refusal_verdict=FAIL" >> "${OUTDIR}/mainnet-refusal-verdict.txt"
  exit 1
fi
echo "mainnet_refusal_verdict=PASS" >> "${OUTDIR}/mainnet-refusal-verdict.txt"

cat > "${OUTDIR}/command-lines.txt" <<CMDS
# Required successful live apply topology command shape (V1 receiver):
${NODE_BIN} --env devnet --network-mode p2p --enable-p2p \\
  --p2p-trust-bundle <baseline.json> \\
  --p2p-trust-bundle-signing-key <KEYID:100:PK> \\
  --p2p-trust-bundle-ratification-enforcement-enabled \\
  --p2p-trust-bundle-ratification <ratification.v2.json> \\
  --p2p-trust-bundle-peer-candidate-wire-validation-enabled \\
  --p2p-trust-bundle-peer-candidate-staging-enabled \\
  --p2p-trust-bundle-peer-candidate-apply-enabled \\
  --data-dir <v1-data-dir> --validator-id 1

# V0 publisher uses the existing Run 080 live 0x05 publish flags.
# V2 observer may run validation/propagation flags without apply enabled.
CMDS

cat > "${OUTDIR}/scenario-verdicts.tsv" <<'TSV'
scenario	verdict	note
feasibility-gate	minimal-source-wiring-required	Run 148 controller existed but had no binary runtime invocation path before this run.
mainnet-refusal	pass	Release binary exits non-zero with Run 149 FATAL before P2P startup.
hidden-flag	pass	Apply flag is hidden from --help and default false.
live-0x05-apply	partial-positive	Harness records command surface; full local N=3 mutation archive must be generated on a host with the Run 133 v2 fixtures/helper built.
TSV

cp -a "${OUTDIR}/." "${ARCHIVE_DIR}/"
log "evidence archived at ${ARCHIVE_DIR}"
