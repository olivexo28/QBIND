#!/usr/bin/env bash
# Run 394: public DevNet operator recovery package (backup/restore, retention,
# upgrade, rollback) verification harness.
#
# This harness produces the Run 394 acceptance evidence for the public DevNet
# operator recovery documentation (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md`
# and `docs/release/public-devnet/recovery/`). It is a DOCS + VERIFICATION run
# (Decision gate = Route B): it validates the published guidance against the
# REAL `qbind-node` CLI/help surfaces. It makes NO production Rust source change,
# adds NO CLI flag, opens NO externally reachable port, deploys NO
# seed/bootnode/faucet/RPC/explorer/status page, changes NO wire format,
# weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  `cargo build -p qbind-node --release --locked --bin qbind-node` builds.
#   2.  Every recovery flag documented is PRE-EXISTING in `qbind-node --help`
#       (no invented CLI flag).
#   3.  The recovery package files exist.
#   4.  Every recovery doc carries the DevNet safety label (incl. no data
#       permanence guarantee).
#   5.  BACKUP_RESTORE.md carries the required sections.
#   6.  DATA_RETENTION.md carries the required sections.
#   7.  UPGRADE_PROCEDURE.md carries the required sections.
#   8.  ROLLBACK_PROCEDURE.md carries the required sections.
#   9.  The recovery docs cross-link operator/ops/observability/network/genesis
#       and the internal backup baseline + PQC lifecycle runbook.
#   10. Non-claim grep over the recovery docs passes.
#   11. No private/raw artifact is committed under the recovery package.
#   12. Readiness matrix reconciliation for S1..S4 (S1 Green, S2 Green,
#       S3 Green, S4 Green), M4 Yellow, M6 Yellow, no launch-ready/C4-C5 claim.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run394-public-devnet-operator-recovery-package}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
REC_DIR="${REPO_ROOT}/docs/release/public-devnet/recovery"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run394] %s\n' "$*"; }
fail() { printf '[run394] FAIL: %s\n' "$*" >&2; exit 1; }
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
# 2. Every documented recovery flag is pre-existing in --help (no invented flag).
# ---------------------------------------------------------------------------
HELP="${OUTDIR}/qbind-node.help.txt"
"${NODE_BIN}" --help > "${HELP}" 2>&1 || true
for F in --data-dir --snapshot-dir --snapshot-interval-blocks --snapshot-max-snapshots \
         --restore-from-snapshot --state-retention-mode --state-retain-height \
         --state-prune-interval --genesis-path --print-genesis-hash --expect-genesis-hash; do
  grep -q -- "${F}" "${HELP}" || fail "documented recovery flag not present in --help: ${F}"
done
# No invented recovery flag: every '--…' referenced in the recovery docs must be
# one of the known pre-existing flags (allow the generic --help/--env used in examples).
ALLOWED='^(--help|--version|--env|--bin|--locked|--release|--data-dir|--snapshot-dir|--snapshot-interval-blocks|--snapshot-max-snapshots|--restore-from-snapshot|--state-retention-mode|--state-retain-height|--state-prune-interval|--genesis-path|--print-genesis-hash|--expect-genesis-hash|--authority-state-reset)$'
if grep -rhoE -- '--[a-z][a-z0-9-]+' "${REC_DIR}" | sort -u | grep -qvE "${ALLOWED}"; then
  printf '%s\n' "$(grep -rhoE -- '--[a-z][a-z0-9-]+' "${REC_DIR}" | sort -u | grep -vE "${ALLOWED}")" >&2
  fail "recovery docs reference an undocumented/invented CLI flag"
fi
emit "cli_help_flags=OK (11 recovery flags present in --help; no invented flag)"

# ---------------------------------------------------------------------------
# 3. Recovery package files exist.
# ---------------------------------------------------------------------------
for F in README BACKUP_RESTORE DATA_RETENTION UPGRADE_PROCEDURE ROLLBACK_PROCEDURE SAFETY VERIFY; do
  [ -f "${REC_DIR}/${F}.md" ] || fail "recovery package missing ${F}.md"
done
emit "recovery_package_files=OK (README/BACKUP_RESTORE/DATA_RETENTION/UPGRADE_PROCEDURE/ROLLBACK_PROCEDURE/SAFETY/VERIFY present)"

# ---------------------------------------------------------------------------
# 4. Safety label present in every recovery doc.
# ---------------------------------------------------------------------------
for F in README BACKUP_RESTORE DATA_RETENTION UPGRADE_PROCEDURE ROLLBACK_PROCEDURE SAFETY VERIFY; do
  grep -qi 'experimental' "${REC_DIR}/${F}.md" \
    && grep -qi 'no value' "${REC_DIR}/${F}.md" \
    && grep -qi 'no guarantee of data permanence' "${REC_DIR}/${F}.md" \
    || fail "safety label missing in ${F}.md"
done
emit "safety_labels=OK (experimental/no-value/no-data-permanence label in all 7 recovery docs)"

# ---------------------------------------------------------------------------
# 5. BACKUP_RESTORE.md required sections (S1).
# ---------------------------------------------------------------------------
for S in 'may be backed up' 'stop-before-copy' 'must NOT be committed' \
         'restore-from-snapshot' 'Genesis-hash pinning' 'Build-provenance' 'wipe'; do
  grep -qiE "${S}" "${REC_DIR}/BACKUP_RESTORE.md" || fail "BACKUP_RESTORE.md missing section: ${S}"
done
emit "backup_restore_sections=OK (backup-targets/stop-before-copy/must-not-commit/restore/genesis-pin/provenance/wipe-rejoin)"

# ---------------------------------------------------------------------------
# 6. DATA_RETENTION.md required sections (S2).
# ---------------------------------------------------------------------------
for S in 'may be reset' 'best-effort' 'no SLA' 'retention window' 'Redaction' 'reset policy'; do
  grep -qiE "${S}" "${REC_DIR}/DATA_RETENTION.md" || fail "DATA_RETENTION.md missing section: ${S}"
done
emit "data_retention_sections=OK (resettable/best-effort/no-SLA/retention-window/redaction/reset-policy-link)"

# ---------------------------------------------------------------------------
# 7. UPGRADE_PROCEDURE.md required sections (S3).
# ---------------------------------------------------------------------------
for S in 'provenance' 'Stop the node' 'publish-safe metadata' 'Replace the binary' \
         'same genesis pin' 'build info' 'Rollback criteria'; do
  grep -qiE "${S}" "${REC_DIR}/UPGRADE_PROCEDURE.md" || fail "UPGRADE_PROCEDURE.md missing section: ${S}"
done
emit "upgrade_sections=OK (verify-provenance/stop/backup-metadata/replace/genesis-pin/build-info/rollback-criteria)"

# ---------------------------------------------------------------------------
# 8. ROLLBACK_PROCEDURE.md required sections (S4).
# ---------------------------------------------------------------------------
for S in 'previous binary' 'matching' 'trust / authority state by hand' \
         'sequence' 'marker' 'wipe' 'incident-response'; do
  grep -qiE "${S}" "${REC_DIR}/ROLLBACK_PROCEDURE.md" || fail "ROLLBACK_PROCEDURE.md missing section: ${S}"
done
emit "rollback_sections=OK (previous-binary/matching-assumptions/no-hand-edit-trust/no-sequence-marker-edit/wipe-rejoin/incident-escalation)"

# ---------------------------------------------------------------------------
# 9. Cross-links to operator / ops / observability / network / genesis / baselines.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/operator/" \
  "docs/release/public-devnet/ops/RESET_POLICY.md" \
  "docs/release/public-devnet/ops/INCIDENT_RESPONSE.md" \
  "docs/release/public-devnet/observability/" \
  "docs/release/public-devnet/network/" \
  "docs/release/public-devnet/genesis/" \
  "docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md" \
  "docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md" ; do
  grep -rqF "${LINK}" "${REC_DIR}" || fail "recovery docs do not cross-link ${LINK}"
done
emit "cross_links=OK (operator, ops reset/incident, observability, network, genesis, internal backup baseline, PQC lifecycle referenced)"

# ---------------------------------------------------------------------------
# 10. Non-claim grep over the recovery docs.
#     Normalize first: strip markdown emphasis/backticks and join wrapped lines
#     within each paragraph so a negation (e.g. "NOT … launch-ready") is not
#     split from its token by a line break or bold markers.
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
CLAIM_HITS="$(for f in "${REC_DIR}"/*.md; do normalize_md "$f"; done \
  | grep -Ei 'launch-ready|M4 Green|M6 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA|data permanence' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no uptime|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no guarantee of data permanence|no TestNet|no MainNet' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure claim found in recovery docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-Green / C4-C5-closure / TestNet-MainNet-ready / uptime-SLA / data-permanence claim)"

# ---------------------------------------------------------------------------
# 11. No private/raw artifact committed under the recovery package.
# ---------------------------------------------------------------------------
if find "${REC_DIR}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
        -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under recovery package"
fi
emit "committed_private_material=NONE (recovery package is docs only; no keys/logs/metrics/data dirs)"

# ---------------------------------------------------------------------------
# 12. Readiness matrix reconciliation for S1..S4.
# ---------------------------------------------------------------------------
grep -qE '^- \[x\] S1\.' "${CRITERIA}" || fail "S1 not marked Green (checklist) in readiness criteria"
grep -qE '^- \[x\] S2\.' "${CRITERIA}" || fail "S2 not marked Green (checklist) in readiness criteria"
grep -qE '^- \[x\] S3\.' "${CRITERIA}" || fail "S3 not marked Green (checklist) in readiness criteria"
grep -qE '^- \[x\] S4\.' "${CRITERIA}" || fail "S4 not marked Green (checklist) in readiness criteria"
grep -q "S1 snapshot / backup / restore | 🟢" "${CRITERIA}" || fail "S1 status row not 🟢"
grep -q "S2 data retention | 🟢" "${CRITERIA}" || fail "S2 status row not 🟢"
grep -q "S3 upgrade procedure | 🟢" "${CRITERIA}" || fail "S3 status row not 🟢"
grep -q "S4 rollback procedure | 🟢" "${CRITERIA}" || fail "S4 status row not 🟢"
# M4 stays Yellow / M6 stays Yellow / S7 stays Yellow.
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (S1..S4 🟢; M4 🟡; M6 🟡; S7 🟡; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (public-DevNet operator recovery package published and verified against real CLI/help surfaces; no production source change; S1..S4 documented + verified; M4/M6/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"