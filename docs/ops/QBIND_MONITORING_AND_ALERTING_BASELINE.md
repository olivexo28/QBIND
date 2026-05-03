# QBIND Monitoring and Alerting Baseline

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal Monitoring and Alerting Baseline  
**Audience**: Beta coordinators, validator-candidate operators, on-call engineers / SRE, incident commanders, evidence recorders, security reviewers, and MainNet-readiness assessors

---

## 1. Purpose and Scope

This document is the **canonical internal monitoring and alerting baseline for QBIND**.

Its purpose is to define, in one place, the **minimum operational signals, alert classes, and evidence expectations** required to operate QBIND environments responsibly during Beta and to support a credible MainNet-readiness assessment later.

**What this document is:**
- The canonical internal baseline for what QBIND **must** be able to observe across DevNet, TestNet Alpha, TestNet Beta, and MainNet-readiness / cutover preparation
- A requirements/baseline document that the incident response procedure, Beta operations, and MainNet readiness assessments can all reference
- A source of structure for what evidence monitoring is expected to produce

**What this document is NOT:**
- It is **not** a dashboard implementation, dashboard catalog, or dashboard specification
- It is **not** a vendor selection, product selection, or observability stack design
- It is **not** a public status page, public uptime page, or external communications artifact
- It is **not** an SLO/SLA definition or external availability promise
- It does **not** replace the canonical incident response procedure
- It does **not** itself certify MainNet readiness, authorize launch, authorize presale, or authorize any public-sale activity

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

If any item in this baseline appears to conflict with the canonical protocol or release documents, **the canonical documents win**. This baseline only defines the minimum observability surface that QBIND operations must support.

---

## 2. Relationship to Beta Operations, Incident Response, and MainNet Readiness

This baseline is a **subordinate instrument** to the Beta plan, the Beta operator checklist, the incident response procedure, the MainNet readiness checklist, and the MainNet cutover runbook. It does not replace any of them.

| Companion document | Relationship to this baseline |
|---|---|
| `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` | Beta execution requires this baseline so that Beta produces useful, reviewable evidence rather than anecdotes. |
| `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md` | Operators rely on the signal classes defined here to fulfill their day-to-day operational and reporting duties on Beta. |
| `docs/ops/QBIND_INCIDENT_RESPONSE.md` | The incident response procedure consumes signals defined here. **This baseline defines what should be observable; incident response defines what to do when those signals indicate an incident.** |
| `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` | MainNet readiness depends on this baseline being **both defined and exercised**. A signal class that is documented here but never exercised in Beta does not satisfy readiness. |
| `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md` | The cutover runbook requires that integrity, version, and chain-identity signals from this baseline are present and trustworthy before, during, and after cutover. |

**Plain-language summary of the relationship:**

- This document is **requirements / baseline**, not an incident workflow.
- Incident response answers: *what do we do when something is wrong?*
- This baseline answers: *what must we be able to see at all, so that "wrong" is detectable and provable?*
- Beta operations need this baseline to generate the evidence the Beta plan and operator checklist call for.
- MainNet readiness later cannot be honestly concluded if the signals listed here were never present, never retained, or never exercised under realistic conditions.

---

## 3. Monitoring Principles

These principles govern every section that follows. They are intentionally short and operational.

| # | Principle | Meaning |
|---|---|---|
| 1 | **Monitor what can block safety, liveness, or launch** | Coverage is justified by risk to protocol safety, network liveness, validator/signer integrity, economic correctness, or MainNet-readiness conclusions — not by aesthetic completeness. |
| 2 | **Alerts must be actionable, not decorative** | Every alert should map to a defined responder and a defined first action. Signals that are not actionable belong in observation/evidence, not alerting. |
| 3 | **Evidence must outlive the incident** | If a signal mattered enough to alert on, the underlying evidence must be retained long enough to support postmortem, audit, and readiness review. |
| 4 | **Distinguish local from network-wide** | Observability must allow distinguishing a single-operator problem from a multi-operator or network-wide condition. Signals that cannot make this distinction are weaker and should not be relied on alone. |
| 5 | **No dependence on a single operator's anecdote** | A condition that can only be known because one operator happened to notice it is not monitored. Cross-operator or coordinator-visible signals are required for anything safety- or readiness-relevant. |
| 6 | **Signal quality matters more than dashboard count** | Fewer high-quality, well-understood signals beat many noisy or redundant ones. Noisy alerting degrades response. |
| 7 | **If a signal matters for readiness, it must be retained** | Signals referenced in the MainNet readiness checklist must be retained for the duration that supports readiness review, not just live operations. |
| 8 | **Ambiguous missing telemetry is itself a problem** | Silent monitoring is not the same as healthy operation. Loss of monitoring, gaps in signal, or "nothing reported" conditions are themselves findings, and must be observable. |
| 9 | **Launch / readiness pressure never weakens monitoring** | No timeline, milestone, or external expectation justifies disabling, deferring, or downgrading required signals. |

---

## 4. Minimum Signal Classes

QBIND monitoring must, at minimum, cover the following top-level signal classes. The remaining sections (5–10) elaborate the most important of these. Class **G** is covered by the incident response procedure.

| Class | Name | Why it matters | Example signals (illustrative, not prescriptive) |
|---|---|---|---|
| **A** | **Node and process health** | Detects local failure, exhaustion, and corruption that endanger participation and can cascade into network-wide effects. | Process up/down, restart count, CPU/memory/disk/file-descriptor pressure, storage corruption indicators, sync state, log error-rate spikes. |
| **B** | **Network and peering health** | Detects connectivity, partition, and identity-mismatch conditions that affect both local nodes and the network. | Peer count, peer churn, handshake / connection failures, latency degradation, bootstrap reachability, environment/peer-identity mismatch. |
| **C** | **Consensus and chain health** | Detects safety- and liveness-relevant conditions: stalls, divergence, abnormal commit behavior. | Commit/block progress, finality or commit lag, stalls, fork/divergence indicators, vote/proposal anomalies, epoch transitions, replay/recovery anomalies. |
| **D** | **Validator and signer health** | Detects participation, signer, and validator-set conditions that affect protocol-level correctness and operator trust. | Validator participation / missed activity, signer availability and latency, signer/key misconfiguration, jailed/excluded/below-threshold state, validator-set drift. |
| **E** | **Economics and policy observation** | Provides Beta-grade observation of fee, issuance, stake, slashing, and policy posture; supports MainNet economics finalization. | Fee flow, issuance/reward flow, stake distribution shape, slashing/evidence activity, below-minimum-stake exclusions, C3-related observation if relevant, policy/config posture mismatch. |
| **F** | **Infrastructure and artifact integrity** | Confirms that what is running is what was authorized to run, with intact artifacts and trustworthy environment. | Binary/version identity, checksum/signature verification status, config fingerprint, genesis / chain-id match, time sync health, monitoring pipeline self-health, snapshot/backup health. |
| **G** | **Incident / workflow metadata** | Connects observability to the incident response procedure: alerts opened, incidents opened, severity, ownership, and closure. | Alert→incident linkage, open incident counts by severity, time-to-acknowledge / time-to-contain (where applicable), evidence-record presence. **Authoritative definitions live in `docs/ops/QBIND_INCIDENT_RESPONSE.md`.** |

Sections 5–10 elaborate Classes A–F respectively. Class G is governed by the incident response procedure and is referenced from Sections 11 and 12 of this document.

> Signals listed below are stated at the **baseline / requirements** level. Exact metric names, exporter shapes, query languages, and storage backends are intentionally left to implementation, except where canonical QBIND documents already define a name.

---

## 5. Node and Process Health Baseline

QBIND operations must be able to observe, at minimum, the following per-node conditions:

- **Process liveness**: process up/down state for each QBIND node process and any required helper processes.
- **Restart and crash behavior**: restart count, abnormal exit indications, and rapid-restart loops.
- **Resource exhaustion risk**:
  - CPU saturation (sustained, not transient).
  - Memory pressure and OOM risk.
  - Disk usage and disk free-space trajectory (rate of growth).
  - File descriptor / handle exhaustion risk.
- **Storage health**:
  - I/O error indicators.
  - Database or chain-store corruption signals when surfaced by the node.
  - Snapshot / state directory integrity indicators where exposed.
- **Sync state and lag**:
  - Whether the node is in initial sync, catching up, or at chain tip.
  - Sync lag relative to peers / network expectation.
- **Log behavior**:
  - Error-rate spikes on a per-node basis.
  - Sudden appearance of new error classes.
  - Sustained warning floors that historically precede incidents.

**Coordinator-level expectation:** the coordinator must be able to see the node-health posture of the operator fleet in aggregate, not only via individual operator self-report.

---

## 6. Network and Peering Health Baseline

QBIND operations must be able to observe, at minimum:

- **Peer count and stability**: current peer count per node, with sufficient history to detect peer churn and sudden drops.
- **Connection / handshake failures**: failed connection attempts, handshake failures, and authentication / protocol-version negotiation failures.
- **Partition indicators**: conditions consistent with a network partition (e.g., a node or a group of nodes losing reach to a substantial fraction of the expected peer set).
- **Latency / connectivity degradation**: round-trip latency to known peers and deterioration trends.
- **Bootstrap / seed reachability**: whether documented bootstrap or seed peers are reachable from operator nodes.
- **Inbound / outbound asymmetry**: where relevant, distinguishing inbound vs. outbound connection problems (e.g., NAT, firewall, port-binding regressions).
- **Environment / peer-identity mismatches**:
  - Peers with unexpected chain-id or genesis hash.
  - Peers advertising an unexpected version or environment label.
  - Operators connecting to the wrong network.

**Coordinator-level expectation:** the coordinator must be able to detect whether peering issues are local-to-one-operator or fleet-wide. (Principle 4.)

---

## 7. Consensus and Chain-Health Baseline

This is one of the most important sections. Consensus and chain-health monitoring exists because the protocol-level **safety and liveness** conclusions of Beta and MainNet-readiness depend on it.

QBIND operations must be able to observe, at minimum:

- **Block / commit progress**:
  - Production of new blocks / commits at expected cadence.
  - Latest committed height visible per node and in aggregate.
- **Finality or commit lag**:
  - Lag between local node tip and observed network tip.
  - Lag between proposed and committed/finalized progress, where the protocol exposes this distinction.
- **Stalls**:
  - Absence of progress beyond an operationally meaningful interval.
  - Stalls at proposal, voting, or commit phases where the protocol exposes them.
- **Fork / divergence indicators**:
  - Differing committed-block hashes at the same height across operators.
  - Reorganization events and their depth.
  - Unexpected chain-tip divergence between operators that should agree.
- **Vote / proposal anomalies** (where observable):
  - Missed proposals beyond expected baseline.
  - Anomalous voting patterns (e.g., sustained absences, double-vote-shaped evidence).
- **Epoch / transition anomalies**:
  - Unexpected behavior at epoch boundaries, validator-set transitions, or parameter-update boundaries.
- **Restart / recovery anomalies**:
  - Replay anomalies after restart.
  - Recovery from a snapshot or rollback that does not converge cleanly.

**Severity floor reminder:** per the incident response procedure, any **suspected fork, suspected key compromise, or suspected protocol invariant violation** is **Sev-0 until proven otherwise**. The signals in this section must be capable of surfacing such conditions.

---

## 8. Validator and Signer Health Baseline

QBIND operations must be able to observe, at minimum:

- **Validator participation**:
  - Whether each expected validator is actively participating.
  - Missed activity (missed proposals, missed signatures, missed attestations — using whichever terms the canonical protocol report defines).
- **Signer availability**:
  - Whether the signing component for each validator is reachable and responsive.
  - Signer process health distinct from node process health, where they are separate.
- **Signer latency / failure** (where observable):
  - Time taken to sign expected messages.
  - Signing error rates, including timeouts and rejections.
- **Key / signer misconfiguration indicators**:
  - Wrong key used for an environment.
  - Mismatched signer identity vs. validator identity.
  - Repeated signing failures consistent with misconfiguration rather than transient error.
- **Validator state observations**:
  - Below-threshold / jailed / excluded / inactive states as the protocol exposes them.
  - Stake or bond changes that drop a validator out of the active set.
- **Validator-set drift**:
  - Unexpected additions or removals from the active set.
  - Set composition not matching the authorized configuration for the environment.

This section stays at monitoring-baseline level. Implementation specifics of the signer or validator stack are out of scope for this document.

---

## 9. Economics and Policy Observation Baseline

This section aligns with `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md` and `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`. Many items here are **Beta-grade observation signals** — they are intended to inform finalization, not to act as hard operational alerts that demand immediate response.

QBIND operations must be able to observe, at minimum:

- **Fee flow observations**: aggregate fee activity over time, broken down enough to support Beta evidence.
- **Issuance / reward flow observations**: issuance and reward distribution behavior consistent with the active environment's posture.
- **Stake distribution and participation shape**: distribution of stake across active validators, participation breadth, and trends over time.
- **Slashing / evidence activity**: occurrence and shape of slashing or slashing-evidence events, including absence of expected slashing pathways being exercised at all.
- **Below-minimum-stake exclusions**: validators excluded due to falling below the configured minimum, including how often and under what conditions.
- **C3-related observation (if relevant)**: any C3-related quantities the canonical protocol/economics docs expose, observed at the baseline level appropriate to the environment.
- **Policy / config posture mismatch**:
  - Wrong economics posture running in the wrong environment (e.g., MainNet-style posture observed on a TestNet, or vice versa).
  - Parameter values that disagree with the configuration authorized for the active environment.

**Classification:**

| Sub-class | Operational nature |
|---|---|
| Posture mismatch (wrong economics posture in wrong environment) | **Operational alert** — this is a configuration / safety concern. |
| Slashing / evidence activity | **Mixed** — its operational urgency depends on whether it indicates protocol misbehavior or expected exercise. |
| Fee, issuance, stake distribution, participation shape, below-minimum-stake exclusions, C3-related metrics | **Observation signals** for Beta evidence and MainNet economics finalization, not hard alerts. |

Ambiguous boundaries should default to recording observation, not paging on-call.

---

## 10. Infrastructure and Artifact Integrity Baseline

This section directly supports cutover discipline (`docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`) and version/identity guarantees referenced by readiness.

QBIND operations must be able to observe, at minimum:

- **Binary / version identity**: the version of the QBIND node binary actually running on each operator node, with sufficient detail to detect drift from the authorized release.
- **Artifact checksum / signature verification status**: whether installed artifacts match the authorized checksums / signatures for the environment, where this is part of the release process.
- **Config fingerprint**: a stable, comparable fingerprint of the operator configuration so that unexpected configuration drift is detectable.
- **Genesis / chain-id match**: confirmation that the genesis file and chain-id observed on each node match what is authorized for the environment.
- **Time sync health**: clock skew indicators across operator nodes; loss of time sync as a first-class signal.
- **Monitoring pipeline self-health** (Principle 8):
  - Health of collectors, exporters, scrapers, and storage of the monitoring pipeline itself.
  - Detection of "we stopped receiving signal X" as itself a signal.
- **Backup / snapshot health** (where relevant): success/failure and freshness of any backup or snapshot mechanisms relied on for recovery.

These signals must be observable **before, during, and after** any cutover or upgrade event.

---

## 11. Alert Severity and Routing Baseline

This baseline does **not** redefine incident severity. Incident severity is defined by `docs/ops/QBIND_INCIDENT_RESPONSE.md` (Sev-0 / Sev-1 / Sev-2 / Sev-3). This section defines a **monitoring-side urgency baseline** that maps observed signals to operational urgency and routing, and converges with the incident severity scale at the top end.

| Urgency tier | Meaning | Example signal types | Typical routing |
|---|---|---|---|
| **T0 — Informational / observe** | Baseline-of-record signal. Not paged. Retained as evidence. | Steady-state economics and participation observation; routine version-identity confirmations; routine chain-progress baselines. | Operator and coordinator visibility. No paging. Retained per Section 12. |
| **T1 — Warning / investigate** | Something is off but not actionable as an emergency. Investigation required within operating hours / next available window. | Elevated log error-rate; degraded but non-critical resource pressure; mild peering churn; minor sync lag; non-safety policy/config drift candidates. | Operator on shift; coordinator visibility. No on-call page. May be batched. |
| **T2 — Urgent / immediate operator action** | Concrete operational action required now to prevent escalation. Not yet an incident. | Resource exhaustion imminent; sustained sync lag beyond operating threshold; loss of bootstrap reachability; sustained signer latency; monitoring pipeline self-health degrading. | On-call engineer / SRE paged; coordinator notified; operator notified if external. **If conditions persist or worsen, escalate to T3 / incident.** |
| **T3 — Critical / incident-response trigger** | Conditions consistent with safety, security, network-wide, or readiness-impacting failure. Triggers the incident response procedure. | Suspected fork or chain divergence; suspected protocol invariant violation; suspected key/signer compromise; multi-operator outage; sustained loss of monitoring during operations; environment-identity / chain-id mismatch in production posture. | **Triggers `docs/ops/QBIND_INCIDENT_RESPONSE.md`.** Incident commander is assigned, evidence is preserved, severity is assigned per that procedure (Sev-0 / Sev-1 floors apply). Coordinator notified immediately. |

**Anchoring rules:**

- Any T3 condition **must** open an incident under the canonical incident response procedure. It is not closed by silencing the alert.
- Anything that the incident response procedure assigns a **Sev-0 or Sev-1 floor** to (e.g., suspected fork, suspected key compromise, suspected protocol invariant violation, anything that may impact MainNet-readiness conclusions) **must** be capable of being raised at T3 by this monitoring baseline.
- Downgrading a T3 condition is governed by the incident response procedure, not by monitoring configuration.

**Routing roles** referenced above (operator, coordinator, on-call engineer / SRE, incident commander) match the roles defined in the incident response procedure. This baseline does not introduce new roles.

---

## 12. Evidence Retention and Auditability Baseline

Monitoring evidence is the substrate that the **Beta evidence packet** and the **MainNet-readiness assessment** are built on. If the evidence is not retained, neither conclusion can be honestly reached.

Minimum expectations:

- **Metrics retention**:
  - High-resolution metrics retained long enough to support same-day and same-week incident review.
  - Down-sampled or aggregate retention long enough to support Beta-period review and MainNet-readiness review at the appropriate cadence.
- **Log retention**:
  - Operator-side and coordinator-visible logs retained long enough to support postmortem, audit, and readiness review of any incident opened during the retention window.
  - Logs supporting any open or recently-closed incident are retained at least until that incident's postmortem is closed and accepted.
- **Incident-linked snapshots**:
  - Where feasible, evidence snapshots (state, configs, logs, relevant metric windows) are captured and preserved at the time an incident is opened, not reconstructed later.
- **Traceability: alert → incident → postmortem**:
  - Every T3 alert (Section 11) must be traceable to an incident record under the incident response procedure.
  - Every incident record must be traceable to the originating alerts and underlying signals.
  - Every closed Sev-0/Sev-1 incident must be traceable to its postmortem.
- **Beta packet and readiness review**:
  - Retained evidence must be sufficient for the Beta evidence packet referenced in the Beta plan and operator checklist.
  - Retained evidence must be sufficient for MainNet-readiness review per `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`. A signal that would be required for readiness must not be lost to retention windows that are too short.
- **Cutover / upgrade context preservation**:
  - Around any cutover or upgrade window (per `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`), the immediate before/during/after evidence is preserved with context, not silently aged out.

Retention loss is itself a finding (Principle 8). A failure to retain required evidence must be recorded.

---

## 13. Environment-Specific Expectations

The strictness of this baseline scales with environment risk. The expectations below apply **in addition to** the section baselines (5–12), not as replacements.

| Environment | Coverage strictness | Posture |
|---|---|---|
| **DevNet** | Lighter, exploratory. | Node/process health and basic chain progress are required so DevNet remains useful. Other classes are encouraged but may be partial. Loss of full coverage is acceptable as long as it is known and recorded. Reference: `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`. |
| **TestNet Alpha** | Sufficient for onboarding and bug discovery. | All signal classes (A–F) must be at least partially present. Class A (node/process) and Class B (network/peering) must be reliable enough to onboard new operators. Class C (consensus/chain-health) must be reliable enough to detect chain-progress regressions. Reference: `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`. |
| **TestNet Beta** | Strong enough for evidence and stability assessment. | All signal classes (A–F) must be present, exercised, retained, and reviewable. Class C (consensus/chain-health) and Class D (validator/signer) must be coordinator-visible across the operator fleet, not just per-operator. Class F (infrastructure / artifact integrity) must be sufficient to confirm version, config, and chain identity across the fleet. Class G (incident/workflow metadata) must be wired to `docs/ops/QBIND_INCIDENT_RESPONSE.md`. Evidence retention (Section 12) must be sufficient for the Beta evidence packet. References: `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`, `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`. |
| **MainNet-readiness / cutover preparation** | Strongest. Launch-critical. | All signal classes (A–G) must be present, exercised, retained, coordinator-visible, and **demonstrated under realistic conditions in Beta** before being relied on for readiness. Class C (consensus/chain-health) and Class F (infrastructure/artifact integrity) must be capable of detecting safety, liveness, and identity failures fast enough to act on them. Monitoring pipeline self-health (Section 10, Principle 8) must be a first-class signal. Retention (Section 12) must support readiness review. References: `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`, `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`. |

This baseline does not introduce vendor-specific thresholds, vendor-specific tools, or vendor-specific configurations for any environment.

---

## 14. Explicit Gaps That This Baseline Does Not Fill

To keep boundaries clean, this document explicitly does **not**:

- Define dashboards, dashboard catalogs, or visualization specifications.
- Choose a vendor, product, SaaS, or self-hosted observability stack.
- Define exact metric names, exporter shapes, query languages, or storage backends, except where canonical QBIND documents already define them.
- Define alerting rule syntax for any specific tool.
- Replace the canonical incident response procedure (`docs/ops/QBIND_INCIDENT_RESPONSE.md`).
- Replace the Beta operator checklist (`docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`).
- Replace the MainNet cutover runbook (`docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`).
- Certify MainNet readiness by itself. Readiness is concluded only via `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`.
- Define public status-page behavior, public uptime communication, or any external-facing availability surface.
- Define SLOs, SLAs, error budgets, or external availability promises.
- Authorize launch, presale, or any public-sale activity.

When any of the items above become needed, they must be created as their own documents under the canonical structure, not retrofitted into this baseline.

---

## 15. Final Baseline Summary

QBIND monitoring and alerting must, at minimum:

1. Cover the seven signal classes (A–G) defined in Section 4, elaborated in Sections 5–10 and connected to incident workflow in Sections 11–12.
2. Distinguish local from network-wide conditions, and produce coordinator-visible posture, not just per-operator anecdote.
3. Treat consensus / chain-health (Section 7) and infrastructure / artifact integrity (Section 10) as launch-critical from Beta onward.
4. Map signals to a clear urgency tier (T0–T3, Section 11) that converges with the canonical incident severity scale at the top end and triggers the incident response procedure when appropriate.
5. Retain enough evidence (Section 12) to support the Beta evidence packet, postmortems, and MainNet-readiness review — including evidence around cutover and upgrade windows.
6. Scale strictness with environment (Section 13), with MainNet-readiness / cutover preparation requiring the strongest, demonstrated, exercised baseline.
7. Treat **loss of monitoring** itself as a signal, never as silence (Principle 8).
8. Stay within scope (Section 14): this document is the baseline, not the dashboards, not the vendor, not the incident workflow, and not a readiness certification.

This baseline is canonical. It may evolve, but it must remain consistent with the whitepaper, protocol report, release-track spec, Beta plan, operator checklist, incident response procedure, MainNet readiness checklist, and MainNet cutover runbook.