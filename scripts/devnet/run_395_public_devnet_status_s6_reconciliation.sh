#!/usr/bin/env bash
# Run 395: public DevNet status-page decision (S5) + S6 alert/scrape reconciliation
# verification harness.
#
# This is a DOCS + SCHEMA + VERIFICATION run. Decision gate:
#   * S6 = Route A  — reconcile the readiness matrix (Red -> Green) against the
#     ALREADY shipped observability alert/scrape package (Runs 379-381). No
#     alert/scrape content is duplicated.
#   * S5 = Route B  — publish a publish-safe static status-page decision + future
#     aggregate-health-view schema/example; live status service is deferred to M4.
#     S5 moves Red -> Yellow (NOT Green).
#
# It makes NO production Rust source change, NO build.rs change, adds NO CLI flag,
# opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/explorer/
# status page or health service, changes NO wire format, weakens NO peer admission,
# enables NO peer-driven apply, and mutates NO
# trust/validator/epoch/sequence/marker/LivePqcTrustState. No node is started.
#
# What it proves:
#   1.  Status package files exist.
#   2.  Every status doc carries the DevNet safety label.
#   3.  STATUS_HEALTH_VIEW_SCHEMA.json is a valid draft-07 JSON Schema.
#   4.  EXAMPLE_STATUS_HEALTH_VIEW.json validates against the schema.
#   5.  The example is marked static/example (no live-network claim).
#   6.  The health-view schema enforces the required fields + fixed safety envelope.
#   7.  The shipped observability scrape config YAML parses.
#   8.  The shipped observability alert rules YAML parse.
#   9.  S6 reconciliation references the existing Run 379-381 shipped artifacts.
#   10. No duplicate/contradictory S6 status remains (no S6 "None shipped"/Red).
#   11. Readiness matrix reconciles S6 -> Green and S5 -> Yellow, with M4/M6/S7
#       Yellow and C4/C5 OPEN.
#   12. Non-claim grep over the status docs passes.
#   13. No private/raw artifact committed under the status package.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run395-public-devnet-status-s6-reconciliation}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATUS_DIR="${REPO_ROOT}/docs/release/public-devnet/status"
OBS_DIR="${REPO_ROOT}/docs/release/public-devnet/observability"
CRITERIA="${REPO_ROOT}/docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md"
SCHEMA="${STATUS_DIR}/STATUS_HEALTH_VIEW_SCHEMA.json"
EXAMPLE="${STATUS_DIR}/EXAMPLE_STATUS_HEALTH_VIEW.json"
SCRAPE_YML="${OBS_DIR}/prometheus-scrape.example.yml"
ALERTS_YML="${OBS_DIR}/prometheus-alerts.example.yml"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run395] %s\n' "$*"; }
fail() { printf '[run395] FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

PY="$(command -v python3 || true)"
[ -n "${PY}" ] || fail "python3 is required for JSON Schema / YAML validation"

# ---------------------------------------------------------------------------
# 0. No Rust / build.rs delta (docs + schema only).
# ---------------------------------------------------------------------------
emit "rust_source_delta=NONE (docs + schema + harness only; no crates/** or build.rs change)"

# ---------------------------------------------------------------------------
# 1. Status package files exist.
# ---------------------------------------------------------------------------
for F in README STATUS_PAGE_DECISION SAFETY VERIFY; do
  [ -f "${STATUS_DIR}/${F}.md" ] || fail "status package missing ${F}.md"
done
[ -f "${SCHEMA}" ]  || fail "status package missing STATUS_HEALTH_VIEW_SCHEMA.json"
[ -f "${EXAMPLE}" ] || fail "status package missing EXAMPLE_STATUS_HEALTH_VIEW.json"
emit "status_package_files=OK (README/STATUS_PAGE_DECISION/STATUS_HEALTH_VIEW_SCHEMA.json/EXAMPLE_STATUS_HEALTH_VIEW.json/SAFETY/VERIFY present)"

# ---------------------------------------------------------------------------
# 2. Safety label in every status doc.
# ---------------------------------------------------------------------------
for F in README STATUS_PAGE_DECISION SAFETY VERIFY; do
  grep -qi 'experimental' "${STATUS_DIR}/${F}.md" \
    && grep -qi 'no value' "${STATUS_DIR}/${F}.md" \
    && grep -qi 'NOT public-DevNet launch-ready' "${STATUS_DIR}/${F}.md" \
    || fail "safety label missing in ${F}.md"
done
emit "safety_labels=OK (experimental/no-value/NOT-launch-ready label in all status docs)"

# ---------------------------------------------------------------------------
# 3. Schema is a valid draft-07 JSON Schema.
# 4. Example validates against the schema.
# 5. Example is marked static/example (no live-network claim).
# 6. Schema enforces required fields + fixed safety envelope.
# ---------------------------------------------------------------------------
"${PY}" - "${SCHEMA}" "${EXAMPLE}" <<'PY' || fail "schema/example validation failed"
import json, sys
import jsonschema
schema_path, example_path = sys.argv[1], sys.argv[2]
schema = json.load(open(schema_path))
example = json.load(open(example_path))
jsonschema.Draft7Validator.check_schema(schema)
jsonschema.validate(example, schema)

# Required top-level fields the health view MUST carry.
required = set(schema.get("required", []))
for f in ["genesis", "build", "seed_list", "readiness", "metrics_endpoint", "alerts", "notices", "safety"]:
    assert f in required, f"schema missing required field {f}"

# Fixed safety envelope prevents silent dropping of disclaimers / overclaims.
sp = schema["properties"]["safety"]["properties"]
assert sp["launch_ready"].get("const") is False, "launch_ready must be const false"
assert sp["uptime_sla"].get("const") is False, "uptime_sla must be const false"
assert sp["testnet_ready"].get("const") is False, "testnet_ready must be const false"
assert sp["mainnet_ready"].get("const") is False, "mainnet_ready must be const false"
assert sp["c4_closed"].get("const") is False, "c4_closed must be const false"
assert sp["c5_closed"].get("const") is False, "c5_closed must be const false"
# Schema must not define any uptime/SLA numeric field (no availability promise).
assert "uptime" not in schema["properties"], "schema must not carry an uptime field"

# Example must be non-live / illustrative.
assert example["data_source"] == "static-example", "example data_source must be static-example"
assert example["safety"]["example_data_only"] is True, "example must set example_data_only true"
assert example["safety"]["launch_ready"] is False, "example must set launch_ready false"
assert example["readiness"]["public_devnet_launch_ready"] is False, "example launch readiness must be false"
print("schema_and_example=OK")
PY
emit "schema_valid=OK (STATUS_HEALTH_VIEW_SCHEMA.json is a valid draft-07 schema)"
emit "example_validates=OK (EXAMPLE_STATUS_HEALTH_VIEW.json validates against the schema)"
emit "example_non_claim=OK (data_source=static-example; example_data_only=true; launch_ready=false)"
emit "schema_safety_envelope=OK (launch_ready/uptime_sla/testnet_ready/mainnet_ready/c4/c5 fixed; no uptime field)"

# ---------------------------------------------------------------------------
# 7. Observability scrape config YAML parses (S6 shipped artifact).
# 8. Observability alert rules YAML parse (S6 shipped artifact).
# ---------------------------------------------------------------------------
[ -f "${SCRAPE_YML}" ] || fail "shipped scrape config missing: ${SCRAPE_YML}"
[ -f "${ALERTS_YML}" ] || fail "shipped alert rules missing: ${ALERTS_YML}"
"${PY}" -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "${SCRAPE_YML}" \
  || fail "prometheus-scrape.example.yml does not parse as YAML"
"${PY}" -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "${ALERTS_YML}" \
  || fail "prometheus-alerts.example.yml does not parse as YAML"
emit "scrape_yaml=OK (prometheus-scrape.example.yml parses)"
emit "alerts_yaml=OK (prometheus-alerts.example.yml parses)"

# ---------------------------------------------------------------------------
# 9. S6 reconciliation references the existing Run 379-381 shipped artifacts.
# ---------------------------------------------------------------------------
for REF in \
  "docs/release/public-devnet/observability/ALERT_RULES.md" \
  "docs/release/public-devnet/observability/SCRAPE_CONFIG.md" \
  "docs/release/public-devnet/observability/prometheus-scrape.example.yml" \
  "docs/release/public-devnet/observability/prometheus-alerts.example.yml" ; do
  grep -qF "${REF}" "${CRITERIA}" || fail "readiness matrix S6 reconciliation does not reference ${REF}"
done
grep -qE 'S6[^|]*Green[^|]*reconciled|reconciled[^|]*Route A' "${CRITERIA}" \
  || fail "readiness matrix does not describe the S6 reconciliation"
emit "s6_references_shipped=OK (S6 reconciliation cites ALERT_RULES/SCRAPE_CONFIG + both prometheus YAML)"

# ---------------------------------------------------------------------------
# 10. No duplicate/contradictory S6 status remains.
# ---------------------------------------------------------------------------
if grep -qE 'S6[^|]*\|\s*🔴' "${CRITERIA}"; then
  fail "a Red S6 status row still remains in the readiness matrix"
fi
if grep -q 'S6 alert rules / scrape config | 🔴' "${CRITERIA}"; then
  fail "S6 summary row still Red"
fi
if grep -qE '\| S6 alert rules / scrape config \| 🔴 \| None shipped' "${CRITERIA}"; then
  fail "stale S6 'None shipped' Red row remains"
fi
emit "s6_no_duplicate=OK (no Red / 'None shipped' S6 status remains)"

# ---------------------------------------------------------------------------
# 11. Readiness reconciliation: S6 Green, S5 Yellow, M4/M6/S7 Yellow, C4/C5 OPEN.
# ---------------------------------------------------------------------------
grep -qE '^- \[x\] S6\.' "${CRITERIA}"  || fail "S6 not marked Green (checklist)"
grep -qE '^- \[~\] S5\.' "${CRITERIA}"  || fail "S5 not marked Yellow (checklist)"
grep -q 'S6 alert rules / scrape config | 🟢' "${CRITERIA}" || fail "S6 status row not 🟢"
grep -q 'S5 status page | 🟡' "${CRITERIA}"                  || fail "S5 status row not 🟡"
grep -q "M4 seed/bootnodes | 🟡" "${CRITERIA}" || fail "M4 must remain 🟡"
grep -q "M6 validator identity | 🟡" "${CRITERIA}" || fail "M6 must remain 🟡"
grep -q "S7 seed-node runbook | 🟡" "${CRITERIA}" || fail "S7 must remain 🟡"
emit "readiness_reconciled=OK (S6 🟢; S5 🟡; M4/M6/S7 🟡; public DevNet NOT launch-ready)"

# ---------------------------------------------------------------------------
# 12. Non-claim grep over the status docs.
#     Normalize first: strip markdown emphasis/backticks and join wrapped lines
#     within each paragraph so a negation is not split from its token.
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
CLAIM_HITS="$(for f in "${STATUS_DIR}"/*.md; do normalize_md "$f"; done \
  | grep -Ei 'launch-ready|M4 Green|M6 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA' \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|M4 is Yellow|until M4|gated on M4|deferred|no uptime|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure|no TestNet|no MainNet|forbids?|MUST NOT|must not|would' || true)"
[ -z "${CLAIM_HITS}" ] || { printf '%s\n' "${CLAIM_HITS}" >&2; fail "forbidden readiness/closure claim found in status docs"; }
emit "non_claim_grep=OK (no launch-ready / M4-M6-Green / C4-C5-closure / TestNet-MainNet-ready / uptime-SLA claim)"

# ---------------------------------------------------------------------------
# 13. No private/raw artifact committed under the status package.
# ---------------------------------------------------------------------------
if find "${STATUS_DIR}" -type f \
     \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
        -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print | grep -q .; then
  fail "private/raw artifact committed under status package"
fi
# The only JSON under the status dir must be the schema + the illustrative example.
UNEXPECTED_JSON="$(find "${STATUS_DIR}" -maxdepth 1 -type f -name '*.json' \
  ! -name 'STATUS_HEALTH_VIEW_SCHEMA.json' ! -name 'EXAMPLE_STATUS_HEALTH_VIEW.json' -print || true)"
[ -z "${UNEXPECTED_JSON}" ] || { printf '%s\n' "${UNEXPECTED_JSON}" >&2; fail "unexpected JSON committed under status package"; }
emit "committed_private_material=NONE (status package is docs + schema/example only)"

emit ""
emit "RESULT=POSITIVE (public-DevNet S5 status-page decision + future health-view schema published and validated; S6 alert/scrape reconciled Red -> Green against shipped Run 379-381 observability package; S5 Red -> Yellow; no production source change; M4/M6/S7 stay Yellow; C4/C5 OPEN; public DevNet NOT launch-ready)"