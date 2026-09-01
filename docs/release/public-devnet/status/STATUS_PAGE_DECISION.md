# QBIND Public DevNet — Status-Page Decision (S5, Run 395)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no TestNet readiness · no MainNet
> readiness · **C4/C5 OPEN.**

## Decision

**A live public DevNet status page / aggregate health view is deferred** until a real, externally
reachable public DevNet network exists (i.e. until **M4** is Green). A live status service that
claimed to reflect network health today would be **misleading**, because no externally reachable
seed/network is proven (M4 is Yellow/launch-blocking; see the readiness matrix).

Instead, Run 395 publishes a **publish-safe, static decision + schema package** (this document, the
`STATUS_HEALTH_VIEW_SCHEMA.json` schema, and the `EXAMPLE_STATUS_HEALTH_VIEW.json` illustrative
example) that fixes the **fields, safety envelope, and redaction rules** of a future health view.
This lets the shape be reviewed and frozen safely **before** any live deployment.

**Readiness effect:** **S5 moves Red → Yellow** — a publish-safe static decision/schema/template
lands, and a **live status service is explicitly deferred**. S5 does **not** move Green: no
externally usable status page or aggregate health view is deployed or maintained.

This follows the run's **Route B** for S5 (publish a decision + future schema, defer live
deployment) — the expected safe route while M4 is Yellow.

## Why not Route A (deploy a live status page)

Route A requires a real, externally usable status page or aggregate health view wired to live data.
That depends on a live, externally reachable network (M4). M4 is Yellow, so a "live" status view
would either be empty or would imply a reachable network that is **not proven**. Deploying it now
would be a launch/liveness overclaim, which this run must not make.

## Why not Route C (defer entirely, keep Red)

A static, clearly-labelled decision + schema is **not** a misleading launch/status claim: the schema
hard-codes a safety envelope (`launch_ready: false`, `uptime_sla: false`, `example_data_only`,
`testnet_ready: false`, `mainnet_ready: false`, `c4_closed: false`, `c5_closed: false`) and the
example is marked `data_source: static-example`. Because a publish-safe artifact can land without
overclaiming, S5 does not need to stay Red.

## What is published instead of a live page

1. **`STATUS_HEALTH_VIEW_SCHEMA.json`** — a draft-07 JSON Schema for a future aggregate health view.
   Required fields:
   - `genesis` — chain id + canonical genesis hash (the value operators verify with
     `--expect-genesis-hash`).
   - `build` — public release build info (version, short git commit, build id, env) mirroring the
     `qbind_node_build_info` labels.
   - `seed_list` — published seed-list status (`planned` / `candidate` / `live`) with counts;
     `live` requires M4 Green. Endpoints appear **only** when intentionally public.
   - `readiness` — `public_devnet_launch_ready` (fixed `false`) plus M4 / M6 color rollups.
   - `metrics_endpoint` — exposure posture (`loopback-only`, no address published) + status.
   - `alerts` — a **count-only** summary that references the shipped
     `prometheus-alerts.example.yml`; no raw alert bodies.
   - `notices` — incident / reset / maintenance summaries (redacted, publish-safe).
   The schema **forbids** uptime/SLA fields, arbitrary extra keys (`additionalProperties: false`),
   private endpoints, raw logs, raw metric dumps, secrets, data-dir paths, and absolute paths.

2. **`EXAMPLE_STATUS_HEALTH_VIEW.json`** — an illustrative instance that validates against the
   schema, with `data_source: static-example` and `example_data_only: true`. **Example data only.**

3. **Redaction & non-claim rules** — see `SAFETY.md`.

## Fields an eventual live view MUST carry

- Genesis hash (canonical, public).
- Binary build info (version / short git commit / build id / env).
- Seed-list status (planned vs live; live gated on M4).
- M4 / M6 readiness status.
- Metrics-endpoint status (loopback posture; no address).
- Alerts summary (counts referencing the shipped alert package).
- Incidents / reset notices (redacted summaries).

## S6 reconciliation (context)

The alert-rule definitions and scrape configuration that an aggregate health view would summarize
are **already shipped and verified** under **M14** (Runs 379–381):

- `docs/release/public-devnet/observability/ALERT_RULES.md`
- `docs/release/public-devnet/observability/SCRAPE_CONFIG.md`
- `docs/release/public-devnet/observability/RUNBOOK.md`
- `docs/release/public-devnet/observability/prometheus-scrape.example.yml`
- `docs/release/public-devnet/observability/prometheus-alerts.example.yml`

The readiness matrix previously kept **S6** at Red ("None shipped") while **M14** already recorded
these files as shipped and YAML-verified — a genuine internal inconsistency. Run 395 reconciles it:
**S6 moves Red → Green** citing the shipped files and the Run 379–381 harness evidence. No alert /
scrape content is duplicated. See `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## Non-claims

- No public DevNet launch. No live seed claim unless M4 is Green.
- No uptime / availability SLA. DevNet data is resettable and has no value.
- No TestNet or MainNet readiness. No C4/C5 closure.
- No trust / validator / epoch / sequence / marker / `LivePqcTrustState` change.
- The static example is **illustrative only**; it does not reflect any live network.