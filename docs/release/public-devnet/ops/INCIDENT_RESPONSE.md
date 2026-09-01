# QBIND Public DevNet — Incident Response (M16)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document is the **public-DevNet-scoped** incident-response process for third-party DevNet
operators. It is the operator-facing subset of the canonical **internal** procedure
`docs/ops/QBIND_INCIDENT_RESPONSE.md` (Beta / MainNet-readiness scoped), which remains authoritative
for internal roles, escalation, and evidence-packet requirements. This document describes only
**existing** surfaces and adds **no** CLI flag.

---

## 1. DevNet incident severity levels

Severity is assigned independently of the incident class (§2) and may be revised during triage
(record the revision + justification). These map onto the internal Sev-0…Sev-3 scale.

| Severity | Name | Meaning (DevNet scope) | Expected posture |
|----------|------|------------------------|------------------|
| **DS-0** | Critical | Active or imminent safety / security / network-wide failure (suspected key compromise, suspected fork, confirmed exploitable defect under active discussion). | Immediate response; preserve evidence before mitigation; consider emergency reset (see `RESET_POLICY.md`); no external statement beyond the minimal incident summary. |
| **DS-1** | High | Significant impact to multiple operators or a critical function (multi-operator outage, sustained loss of monitoring, security-relevant misbehavior limited in scope). | Rapid response; evidence preserved before mitigation; publish a minimal summary; postmortem. |
| **DS-2** | Moderate | Localized / contained impact without network-wide or safety implications (single-operator defect with workaround, transient degradation). | Standard response; lightweight postmortem if recurring. |
| **DS-3** | Low | Minor or cosmetic; no operational/safety impact (doc error, benign tooling glitch). | Track and fix in normal flow. |

When uncertain about severity, **escalate** — escalation is cheap; a missed escalation is not.

---

## 2. Incident classes

| Class | Description |
|-------|-------------|
| **Seed unreachable** | Published/candidate seed or bootnode not reachable; operators cannot join / re-sync. |
| **Trust-bundle / root / signing-key mismatch** | Trust-bundle signature failure, unexpected trust root, or signing-key mismatch at load / reload-check. |
| **Suspected key compromise** | Suspected or confirmed compromise of an operator's identity key, a trust root, or a signing key. |
| **Peer flood / DoS** | Abusive connection-rate or per-peer message-rate behavior against a node's P2P surface. |
| **Chain halt / no progress** | Consensus stops advancing (committed height stalls). |
| **Bad release artifact / provenance issue** | Binary SHA / BuildID / manifest does not match the published provenance, or an unverifiable artifact is in use. |
| **Reset event** | A DevNet reset is triggered or required (see `RESET_POLICY.md`). |

---

## 3. First-response steps per class

For every class: **stabilize, preserve evidence (§4) before mutating anything, classify severity
(§1), then act.** Do not tear down state you have not yet captured.

- **Seed unreachable** — confirm from a second vantage point; check the published seed-list posture
  (`network/`); fall back to a known-good static `--p2p-peer`; capture reachability observations.
  Do **not** silently promote a seed to `status: live`.
- **Trust-bundle / root / signing-key mismatch** — do **not** apply the suspect bundle. Re-run the
  **validation-only** `--p2p-trust-bundle-reload-check` (security package) to confirm
  `VERDICT=invalid` fails closed; keep the current trusted root; escalate per the security package /
  PQC trust lifecycle runbook.
- **Suspected key compromise** — treat as **DS-0/DS-1**; stop using the affected material
  immediately; generate fresh identity material (identity/security packages); consider a
  trust-root/key-compromise **reset** (`RESET_POLICY.md` §3).
- **Peer flood / DoS** — confirm via `qbind_p2p_connection_rate_drop_total` /
  `qbind_net_per_peer_drops_total{reason="rate_limit"}` on the loopback `/metrics` endpoint; the
  connection-rate and per-peer message-rate limiters are enabled by default (see the p2p package);
  isolate the abusive peer; follow the observability runbook alert.
- **Chain halt / no progress** — check `qbind_consensus_committed_height` for a stall; capture the
  stall window; escalate; a protocol-break or unrecoverable-fork situation may require a reset.
- **Bad release artifact / provenance issue** — stop using the artifact; re-verify SHA-256 / BuildID
  against `docs/release/public-devnet/binary/`; rebuild from the published provenance.
- **Reset event** — follow `RESET_POLICY.md` operator actions (stop → back up trusted keys → wipe
  data-dir → verify genesis → restart) and record the reset evidence record (§7 of `RESET_POLICY.md`).

---

## 4. Evidence to capture

Capture enough to reconstruct the incident, using **publish-safe** values only:

- **Timestamps** — UTC, for detection, key actions, and resolution.
- **Binary SHA / BuildID / manifest** — the exact release-artifact identifiers in use
  (`docs/release/public-devnet/binary/`).
- **Metrics summaries only** — screenshots or summarized counters (e.g. the drop-counter delta), not
  raw `/metrics` dumps.
- **Relevant node IDs** — the public `node_id` / `peer_id` involved (public identifiers only).
- **Redacted config** — the relevant flags/parameters with secrets, private endpoints, private
  hostnames, and absolute build paths removed.

**Never capture into a committed record:** private keys, KEM secrets, mnemonics, credentials, tokens,
raw logs, raw metrics dumps, data directories, private endpoints, private hostnames, absolute build
paths, or branch dirty-state strings.

---

## 5. Escalation and rollback / reset decision points

- **Escalate** to the internal procedure (`docs/ops/QBIND_INCIDENT_RESPONSE.md`) for any DS-0/DS-1,
  any suspected key compromise, any suspected fork, or any confirmed exploitable defect. Internal
  roles (incident commander, evidence recorder, communications owner) and the Beta evidence packet
  are defined there.
- **Rollback / reset decision** — if the incident is a safety issue, data corruption, trust-root/key
  compromise, protocol-breaking upgrade, or unrecoverable fork, evaluate a DevNet **reset** per
  `RESET_POLICY.md` §3. Emergency resets may proceed without notice for safety (§4 of the reset
  policy); the after-the-fact UTC reset record is still required.

---

## 6. Cross-links

- Observability alerts + runbook — `docs/release/public-devnet/observability/ALERT_RULES.md`,
  `docs/release/public-devnet/observability/RUNBOOK.md` (which alert maps to which class/metric).
- Security package — `docs/release/public-devnet/security/` (key-management, PQC trust bootstrap,
  root/signing-key handling; fail-closed reload-check).
- P2P posture / abuse-DoS — `docs/release/public-devnet/p2p/` (rate-limiter posture, admission).
- Reset policy — `RESET_POLICY.md` (this package).
- Network / seed-list posture — `docs/release/public-devnet/network/`.
- Internal incident-response procedure — `docs/ops/QBIND_INCIDENT_RESPONSE.md` (authoritative for
  internal roles / escalation / evidence packet).
- Operator drill catalog — `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md`.
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.

---

## 7. Publication policy

- **Publish a minimal incident summary** for public DevNet: class, severity, UTC window, operator
  impact, operator action required, and resolution status. Reference the reset record (if any).
- **Avoid secrets / private endpoints / raw logs.** Published summaries carry only publish-safe values
  per §4. No raw logs, raw metrics dumps, private endpoints/hostnames, credentials, or keys are ever
  published or committed.

---

## 8. Explicit non-claims

This process is operator guidance for an experimental network. It provides:

- **No uptime SLA.**
- **No value protection** — DevNet state has no value and no persistence guarantee.
- **No MainNet readiness** — nothing here is a MainNet or public TestNet readiness signal; public
  DevNet is **NOT launch-ready**.
- **No C4 / C5 closure** — both remain **OPEN**.