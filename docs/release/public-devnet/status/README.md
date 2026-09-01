# QBIND Public DevNet — Status / Health-View Package (Run 395)

> **Safety label (applies to every file in this directory):**
> **DevNet · experimental · resettable · no value · no uptime SLA · no MainNet readiness claim ·
> no TestNet readiness claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.**
>
> This is a **DevNet-only**, **docs / schema / verification-only** package. It **deploys no**
> status page, health service, seed node, bootnode, faucet, RPC gateway, or explorer, and adds
> **no** CLI flag. Nothing here is a public DevNet launch claim, a live-network claim, a TestNet
> readiness claim, or a MainNet readiness claim, and nothing here moves **M4** or **M6**. **C4 and
> C5 remain OPEN.**

This directory addresses the public DevNet should-have item **S5 — status page or aggregate health
view**. It is published under **Run 395**, **decision gate Route B**: because no live, externally
reachable network exists (M4 is Yellow), QBIND does **not** stand up a live status service. Instead
it publishes a **publish-safe status-page decision** plus the **schema, example, redaction rules,
and non-claims** for a *future* aggregate health view, so the shape is fixed and safe before any
live deployment. On this basis **S5 moves Red → Yellow** (not Green — no live status service is
deployed or maintained).

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This index, scope, and readiness statement. |
| `STATUS_PAGE_DECISION.md` | The S5 decision: why a live status page is deferred until M4 / a live network exists, and what is published instead. |
| `STATUS_HEALTH_VIEW_SCHEMA.json` | JSON Schema (draft-07) for a future aggregate health view: required fields, fixed safety envelope, redaction constraints. |
| `EXAMPLE_STATUS_HEALTH_VIEW.json` | An **illustrative, static** example instance that validates against the schema. Example data only. |
| `SAFETY.md` | Safety label, non-claims, and redaction rules for any status/health view. |
| `VERIFY.md` | Exact commands to validate the schema, the example, and the non-claims. |

## What this package is

- A **decision + schema** artifact that fixes the fields, safety envelope, and redaction rules of a
  future public DevNet aggregate health view **before** any live status service is built.
- Cross-linked to the already-shipped observability alert/scrape package
  (`docs/release/public-devnet/observability/`, S6/M14) so an eventual health view summarizes the
  **existing** metrics/alerts baseline rather than inventing a parallel one.

## What this package is NOT

- **Not** a deployed status page, uptime page, or availability dashboard.
- **Not** a live-network claim: the example carries `data_source: static-example` and
  `example_data_only: true`. A live value requires a real, externally reachable network (M4 Green),
  which does not exist yet.
- **Not** an SLO / SLA / uptime promise (the schema forbids uptime/SLA fields).
- **Not** a claim that the public DevNet is launch-ready, or that M4 or M6 is Green.

## Relationship to S6 (already shipped)

The alert-rule definitions and scrape configuration referenced by an aggregate health view are
**already shipped and verified** under M14 (Runs 379–381):
`docs/release/public-devnet/observability/ALERT_RULES.md`, `SCRAPE_CONFIG.md`, `RUNBOOK.md`,
`prometheus-scrape.example.yml`, and `prometheus-alerts.example.yml`. Run 395 reconciles the
readiness matrix so that **S6 moves Red → Green** citing those shipped files, rather than duplicating
them. See `STATUS_PAGE_DECISION.md` §S6 and
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## Cross-links

- Readiness matrix: `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- Observability (S6/M13/M14): `docs/release/public-devnet/observability/`
- Operator onboarding: `docs/release/public-devnet/operator/`
- Ops (reset / incident): `docs/release/public-devnet/ops/RESET_POLICY.md`,
  `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`
- Recovery: `docs/release/public-devnet/recovery/`
- Genesis verification: `docs/release/public-devnet/genesis/VERIFY.md`
- Evidence record: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md`
