# QBIND Public DevNet — Ops: Reset Policy & Incident Response (Run 390)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only**, **docs / verification-only** package. It deploys **no** seed node,
> bootnode, faucet, RPC gateway, explorer, or status page, and adds **no** CLI flag. Public DevNet is
> **NOT launch-ready** (see `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`). Nothing here is
> a public DevNet launch claim, a public TestNet readiness claim, or a MainNet readiness claim. **C4
> and C5 remain OPEN.** There is **no uptime SLA and no value protection.**

This directory publishes the canonical **public DevNet operations** material for the two remaining
operator-readiness must-haves that are ops-owned:

- **M15 — DevNet reset policy** (`RESET_POLICY.md`): when and how DevNet state may be wiped, what a
  reset does and does not change, reset triggers, notice policy, operator actions, and the shape of a
  publish-safe reset evidence record.
- **M16 — DevNet incident-response process** (`INCIDENT_RESPONSE.md`): public-DevNet-scoped incident
  severity levels, incident classes, first-response steps, evidence-capture and redaction rules,
  escalation / rollback-reset decision points, publication policy, and explicit non-claims.

Both documents describe the **existing** `qbind-node` surfaces and existing ops runbooks only. Run 390
adds **no** production Rust source change and **no** invented CLI flag. The only reset-related CLI
surface referenced is the pre-existing, **hidden**, offline operator-ceremony flag
`--authority-state-reset` (Run 127); `RESET_POLICY.md` documents exactly what it does and does not
reset and makes **no** live governance / authority / C4 / C5 closure claim.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document (index, scope, cross-links, readiness statement). |
| `RESET_POLICY.md` | **M15** — DevNet reset policy: safety label, what a reset means, triggers, notice policy, operator actions, what never changes silently, reset evidence record shape, `--authority-state-reset` posture, no-guarantees statement. |
| `INCIDENT_RESPONSE.md` | **M16** — public-DevNet-scoped incident-response process: severity levels, incident classes, first-response steps, evidence/redaction rules, escalation & rollback/reset decision points, cross-links, publication policy, non-claims. |
| `SAFETY.md` | User-facing safety label / disclaimer publication for this package. |
| `VERIFY.md` | Exact copy-paste operator verification checks and expected outputs. |

## Canonical location

This is the canonical location for public DevNet **ops** (reset-policy + incident-response) operator
material. It sits alongside the operator onboarding package
(`docs/release/public-devnet/operator/`), the P2P posture package
(`docs/release/public-devnet/p2p/`), the observability package
(`docs/release/public-devnet/observability/`), and the security package
(`docs/release/public-devnet/security/`) under the shared `docs/release/public-devnet/` tree.

## Reading order

1. `SAFETY.md` — understand the experimental / resettable / no-value / no-guarantees posture first.
2. `RESET_POLICY.md` — when/how DevNet state is wiped and what an operator must do around a reset.
3. `INCIDENT_RESPONSE.md` — how DevNet incidents are classified, handled, evidenced, and published.
4. `VERIFY.md` — reproduce every CLI-surface and doc-structure check.

## Relationship to the existing internal incident-response procedure

The canonical **internal** incident-response procedure remains
`docs/ops/QBIND_INCIDENT_RESPONSE.md` (Beta / MainNet-readiness scoped: incident commanders, on-call
SRE, evidence recorders, the Beta evidence packet). That document is **not** a public status page and
was **not** written for the public DevNet audience. `INCIDENT_RESPONSE.md` in this directory is the
**public-DevNet-scoped** operator-facing subset: it references and defers to the internal procedure
for internal roles/escalation, but scopes severity, classes, evidence, redaction, and publication to
what a third-party DevNet operator needs. This is the reconciliation of the previously ambiguous M16
status (see the readiness matrix).

## Cross-links

- Operator onboarding — `docs/release/public-devnet/operator/` (`README.md`, `QUICKSTART.md`,
  `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`).
- Observability (metrics + alerting + runbook) — `docs/release/public-devnet/observability/`
  (`RUNBOOK.md`, `ALERT_RULES.md`, `METRICS.md`, `VERIFY.md`).
- Security (key-management + PQC trust bootstrap) — `docs/release/public-devnet/security/`
  (`KEY_MANAGEMENT.md`, `PQC_TRUST_BOOTSTRAP.md`, `PQC_ROOT_AND_SIGNING_KEYS.md`).
- Network / seed-list posture — `docs/release/public-devnet/network/`.
- P2P posture / admission / abuse-DoS — `docs/release/public-devnet/p2p/`.
- Internal incident-response procedure — `docs/ops/QBIND_INCIDENT_RESPONSE.md`.
- Operator drill catalog — `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md`.
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
- Trust-anchor authority model — `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
- C4/C5 closure criteria — `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`.

## Readiness track relationship

This package targets public DevNet readiness must-haves **M15** (reset policy) and **M16**
(incident-response process), tracked in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. Run 390 publishes and verifies this guidance
against the real CLI/help surfaces and existing ops runbooks (see `VERIFY.md` and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`). It does **not** move **M4** (Yellow /
launch-blocking) or **M6** (Yellow / Partial), and it does **not** close **C4** or **C5** — both
remain **OPEN**. Because at least one must-have (M4) is not Green, public DevNet is
NOT launch-ready.

## Provenance

Full provenance (git commit, artifact paths + hashes, release-binary SHA-256 / BuildID / toolchain,
CLI/help verification, ops-package structure checks, non-claim grep, readiness deltas) is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`.