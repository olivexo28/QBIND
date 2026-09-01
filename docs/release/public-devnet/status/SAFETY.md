# QBIND Public DevNet — Status / Health-View Safety & Redaction Rules

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN.**

This file states the non-claims and redaction rules that any QBIND public DevNet status page or
aggregate health view (see `STATUS_PAGE_DECISION.md`, `STATUS_HEALTH_VIEW_SCHEMA.json`) MUST obey.

## Mandatory labels (every rendered view)

- **DevNet-only** label, visible.
- **Experimental**, **resettable**, and **no value** (DevNet tokens/state carry no value).
- **No uptime SLA** and no availability promise.
- **Public DevNet is NOT launch-ready.**
- **No live seed claim** unless **M4** is Green.
- **No TestNet or MainNet readiness.**
- **No C4/C5 closure.**
- Any static example is **illustrative only** and does not reflect a live network.

## Required fields (semantic)

A health view carries: genesis hash; binary build info; seed-list status; M4 / M6 status; metrics
endpoint status; alerts summary; incidents / reset notices. See the schema for the exact shape.

## Redaction rules (hard requirements)

The view MUST NOT publish:

- **Private endpoints** — no internal/private seed, peer, RPC, or metrics addresses. Endpoints
  appear only when they are **intentionally public**; otherwise use counts only. Metrics stay
  **loopback-only**; no metrics address is ever published.
- **Raw logs** — no log lines, stack traces, or log file contents.
- **Raw metrics dumps** — only aggregate counts/status, never a `/metrics` scrape body.
- **Secrets** — no keys, tokens, credentials, private material, or seeds.
- **Data directories** — no `--data-dir` contents or snapshot contents.
- **Absolute paths** — repository-relative references only (`docs/...`); no host filesystem paths.

The `STATUS_HEALTH_VIEW_SCHEMA.json` enforces much of this structurally
(`additionalProperties: false`; fixed loopback exposure; `reference` restricted to `docs/...`; no
uptime/SLA field exists) but publishers remain responsible for the content of free-text `summary`
fields.

## Non-claims

Nothing in a status/health view implies that the public DevNet is launch-ready, that M4 (external
seed reachability) or M6 (validator identity) is Green, that a live seed exists, that the network is
externally joinable, or that C4/C5 are closed. It makes no TestNet or MainNet readiness claim and
mutates no trust/validator/epoch/sequence/marker/`LivePqcTrustState`.
