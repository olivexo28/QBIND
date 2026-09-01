# QBIND Public DevNet — Status / Health-View Verification (S5)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN.**

Reproducible checks for the Run 395 status package. This package is **docs + schema only**: it
starts no node, opens no port, and deploys no status service. The one-command path is the Run 395
harness:

```bash
bash scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh
```

It writes a publish-safe summary to
`docs/devnet/run_395_public_devnet_status_s6_reconciliation/summary.txt`; the canonical record is
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md`.

## Manual checks

1. **Status package files exist.**

   ```bash
   ls docs/release/public-devnet/status/
   # README.md STATUS_PAGE_DECISION.md STATUS_HEALTH_VIEW_SCHEMA.json
   # EXAMPLE_STATUS_HEALTH_VIEW.json SAFETY.md VERIFY.md
   ```

2. **Schema is a valid JSON Schema and the example validates against it.**

   ```bash
   python3 - <<'PY'
   import json, jsonschema
   s = json.load(open('docs/release/public-devnet/status/STATUS_HEALTH_VIEW_SCHEMA.json'))
   e = json.load(open('docs/release/public-devnet/status/EXAMPLE_STATUS_HEALTH_VIEW.json'))
   jsonschema.Draft7Validator.check_schema(s)
   jsonschema.validate(e, s)
   print('schema+example OK')
   PY
   ```

3. **The example is marked as static/example data (no live-network claim).**

   ```bash
   python3 -c "import json;e=json.load(open('docs/release/public-devnet/status/EXAMPLE_STATUS_HEALTH_VIEW.json'));assert e['data_source']=='static-example' and e['safety']['example_data_only'] is True and e['safety']['launch_ready'] is False;print('example non-claim OK')"
   ```

4. **The shipped observability alert/scrape YAML still parses (S6 target artifacts).**

   ```bash
   python3 -c "import yaml;yaml.safe_load(open('docs/release/public-devnet/observability/prometheus-scrape.example.yml'));print('scrape YAML OK')"
   python3 -c "import yaml;yaml.safe_load(open('docs/release/public-devnet/observability/prometheus-alerts.example.yml'));print('alerts YAML OK')"
   ```

5. **The readiness matrix reconciles S6 → Green and S5 → Yellow with no stale Red.**

   ```bash
   grep -n 'S6 alert rules / scrape config' docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
   grep -n 'S5 status page' docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
   ```

6. **Non-claim grep over the status docs passes** (no launch-ready / M4-Green / M6-Green /
   TestNet-ready / MainNet-ready / C4-C5 closure / uptime SLA claim). This is run by the harness.

## Expected

All checks pass; the schema and example validate; the observability YAML parses; the matrix shows
**S6 🟢** and **S5 🟡**; M4/M6/S7 remain Yellow; C4/C5 remain OPEN; public DevNet remains **NOT
launch-ready**.
