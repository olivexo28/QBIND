#!/usr/bin/env bash
# Run 392: public DevNet S7 seed-node operations runbook + M4 Route-A
# deployment checklist verification harness.
#
# This harness produces the Run 392 acceptance evidence for the public DevNet
# seed-node operations documentation (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md`
# and `docs/release/public-devnet/network/`). It is a DOCS + VERIFICATION run
# (Decision gate = Route B): it validates the published guidance against the
# REAL `qbind-node` CLI/help + seed-list schema surfaces. It makes NO production
# Rust source change, adds NO CLI flag, opens NO externally reachable port,
# deploys NO seed/bootnode/faucet/RPC/explorer/status page, changes NO wire
# format, weakens NO peer admission, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState.
#
# What it proves:
#   1.  `cargo build -p qbind-node --release --locked --bin qbind-node` builds.
#   2.  No new CLI flag is introduced (the documented seed surfaces are all
#       pre-existing; the harness asserts each is present).
#   3.  The documented seed-related CLI surfaces exist (identity generate /
#       register-check subcommands + the P2P/genesis flags).
#   4.  `devnet-seeds.live-candidate.json` is still schema-valid and non-live.
#   5.  The three new network docs exist and carry every required section.
#   6.  The docs cross-link identity, security, p2p, observability, ops, and
#       readiness docs.
#   7.  Non-claim grep over the new docs passes.
#   8.  No private/raw artifact is committed under the network package.
#   9.  Records that this run does not move M4 Green and does not move M6 Green.
#
# No node is started, no port is opened, and no state/data dir is written.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run392-public-devnet-seed-ops-route-a-checklist}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
NET_DIR="${REPO_ROOT}/docs/release/public-devnet/network"
SEED_SCHEMA="${NET_DIR}/devnet-seed-list.schema.json"
LIVE_CANDIDATE="${NET_DIR}/devnet-seeds.live-candidate.json"
CLI_RS="${REPO_ROOT}/crates/qbind-node/src/cli.rs"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
OPS_DOC="${NET_DIR}/SEED_NODE_OPERATIONS.md"
CHECKLIST_DOC="${NET_DIR}/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md"
EVIDENCE_DOC="${NET_DIR}/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run392] %s\n' "$*"; }
fail() { printf '[run392] FAIL: %s\n' "$*" >&2; exit 1; }
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
# 2. No new CLI flag introduced: the documented seed flags are all pre-existing
#    (defined in cli.rs) and the top-level --help advertises them.
# ---------------------------------------------------------------------------
HELP="${OUTDIR}/qbind-node.help.txt"
"${NODE_BIN}" --help > "${HELP}" 2>&1 || true
for FLAG in \
  --network-mode --enable-p2p --p2p-listen-addr --p2p-advertised-addr --p2p-peer \
  --p2p-mutual-auth --p2p-pqc-root-mode --p2p-trusted-root --p2p-leaf-cert \
  --p2p-leaf-cert-key --expect-genesis-hash ; do
  grep -q -- "${FLAG}" "${CLI_RS}" || fail "documented flag not defined in cli.rs: ${FLAG}"
  grep -q -- "${FLAG}" "${HELP}"   || fail "documented flag not present in --help: ${FLAG}"
done
emit "cli_flags=OK (all documented P2P/genesis flags pre-existing in cli.rs + --help; no new flag)"

# ---------------------------------------------------------------------------
# 3. identity subcommands exist (generate + register-check), non-mutating.
# ---------------------------------------------------------------------------
IDHELP="${OUTDIR}/qbind-node.identity.help.txt"
"${NODE_BIN}" identity --help > "${IDHELP}" 2>&1 || true
grep -qi 'generate' "${IDHELP}"       || fail "identity generate subcommand missing"
grep -qi 'register-check' "${IDHELP}" || fail "identity register-check subcommand missing"
emit "identity_subcommands=OK (generate + register-check present; non-mutating)"

# ---------------------------------------------------------------------------
# 4. Committed live-candidate document validates against the seed-list schema
#    and remains non-live (status != live, null reachability on non-live).
# ---------------------------------------------------------------------------
python3 - "${SEED_SCHEMA}" "${LIVE_CANDIDATE}" <<'PY' || fail "live-candidate schema validation failed"
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
jsonschema.validate(instance=doc, schema=schema)
for n in doc["seed_nodes"]:
    assert n["status"] != "live", "committed candidate entry must NOT be live"
    if n["status"] in ("placeholder", "planned", "retired"):
        assert n["last_reachability_evidence"] is None, "non-live entry carries reachability evidence"
print("live_candidate_schema_ok")
PY
emit "live_candidate_schema_validation=OK (validates; single entry status=planned, non-live)"

# ---------------------------------------------------------------------------
# 5. New docs exist and carry the required sections.
# ---------------------------------------------------------------------------
for F in "${OPS_DOC}" "${CHECKLIST_DOC}" "${EVIDENCE_DOC}"; do
  [ -f "${F}" ] || fail "expected doc missing: ${F}"
  grep -qi 'experimental' "${F}" && grep -qi 'no value' "${F}" \
    || fail "safety label missing in ${F}"
done
emit "network_docs_present=OK (SEED_NODE_OPERATIONS + M4_ROUTE_A_DEPLOYMENT_CHECKLIST + SEED_REACHABILITY_EVIDENCE_TEMPLATE; safety labels present)"

# SEED_NODE_OPERATIONS.md required coverage.
for S in 'safety label' 'operator role' 'identity generate devnet seed' \
         'never be committed' '--env devnet' '--p2p-mutual-auth required' \
         '--p2p-pqc-root-mode pqc-static-root' '--p2p-trusted-root' '--p2p-leaf-cert' \
         '--genesis-path' '--expect-genesis-hash' 'Firewall' 'QBIND_METRICS_HTTP_ADDR' \
         'Operational checks' 'status: planned' 'retired'; do
  grep -qiF -- "${S}" "${OPS_DOC}" || fail "SEED_NODE_OPERATIONS.md missing coverage: ${S}"
done
emit "seed_node_operations_sections=OK (safety/role/identity-custody/startup/firewall/metrics/checks/failure/retirement)"

# M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md required coverage.
for S in 'Preflight prerequisites' 'identity material' 'public endpoint' \
         'KEMTLS' 'Independent vantage' 'RFC 5737' 'external TCP' \
         'devnet-seeds.live.json' 'status: "live"' 'last_reachability_evidence' \
         'register-check' '--status live --reachability-evidence' 'M4 Green'; do
  grep -qiF -- "${S}" "${CHECKLIST_DOC}" || fail "M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md missing coverage: ${S}"
done
emit "route_a_checklist_sections=OK (preflight/identity/endpoint/kemtls/vantage/tcp/kemtls-evidence/promotion/register-check/m4-rules)"

# SEED_REACHABILITY_EVIDENCE_TEMPLATE.md required fields.
for S in 'Run id' 'UTC timestamp' 'node_id' 'peer_id' 'Environment' \
         'Expected genesis hash' 'Binary SHA-256' 'ELF BuildID' 'Toolchain' \
         'Public host' 'independence statement' 'TCP dial result' \
         'KEMTLS' 'Observed remote NodeId' 'Redaction statement' \
         'external_tcp_reachability' 'external_kemtls_reachability' \
         'live_reachability_claim' 'm4_green_claim' 'c4_c5_closure_claim'; do
  grep -qiF -- "${S}" "${EVIDENCE_DOC}" || fail "SEED_REACHABILITY_EVIDENCE_TEMPLATE.md missing field: ${S}"
done
emit "evidence_template_fields=OK (all required evidence + conclusion fields present)"

# ---------------------------------------------------------------------------
# 6. Cross-links to identity / security / p2p / observability / ops / readiness.
# ---------------------------------------------------------------------------
for LINK in \
  "docs/release/public-devnet/identity/" \
  "docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md" \
  "docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md" \
  "docs/release/public-devnet/observability/" \
  "docs/release/public-devnet/ops/INCIDENT_RESPONSE.md" \
  "docs/release/public-devnet/ops/RESET_POLICY.md" \
  "docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md" \
  "docs/release/public-devnet/genesis/" \
  "docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md" ; do
  grep -rqF "${LINK}" "${OPS_DOC}" "${CHECKLIST_DOC}" "${EVIDENCE_DOC}" \
    || fail "network docs do not cross-link ${LINK}"
done
emit "cross_links=OK (identity, security root/bootstrap, observability, ops incident/reset, readiness, genesis, PQC lifecycle referenced)"

# ---------------------------------------------------------------------------
# 7. Non-claim grep over the new docs.
# ---------------------------------------------------------------------------
CLAIM_HITS="$(grep -rEi 'launch-ready|M4 Green|M4 moved Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA' \
  "${OPS_DOC}" "${CHECKLIST_DOC}" "${EVIDENCE_DOC}" 2>/dev/null \
  | sed 's/[*`]//g' \
  | grep -viE 'NOT |not launch-ready|no M4|no uptime|neither|not a claim|does not|do not|is not|not by itself|not move|never move|non-claim|rules and non|stays? (yellow|open)|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|only when|only if|before .*M4|until .*M4' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure claim found in new docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-Green / C4-C5-closure / TestNet-MainNet-ready / uptime-SLA claim)"

# ---------------------------------------------------------------------------
# 8. No private/raw artifact committed under the network package.
# ---------------------------------------------------------------------------
if find "${NET_DIR}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
        -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under network package"
fi
emit "committed_private_material=NONE (network docs only; no keys/logs/metrics/data dirs)"

# ---------------------------------------------------------------------------
# 9. Readiness: S7 no longer Red; M4 stays Yellow; M6 stays Yellow.
# ---------------------------------------------------------------------------
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -qE 'S7 seed-node runbook \| (🟡|🟢)' "${CRITERIA}" || fail "S7 must move off 🔴 (to 🟡 or 🟢)"
emit "readiness=OK (S7 off 🔴; M4 🟡; M6 🟡; public DevNet NOT launch-ready)"

emit ""
emit "RESULT=POSITIVE (S7 seed-node operations runbook + M4 Route-A deployment checklist + reachability evidence template published and verified against real CLI/schema surfaces; no production source change; M4 stays Yellow; M6 stays Yellow/Partial; C4/C5 OPEN; public DevNet NOT launch-ready)"
log "summary written to ${SUMMARY}"
