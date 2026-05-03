# QBIND Incident Response Procedure

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal Incident Response Procedure  
**Audience**: Beta coordinators, validator-candidate operators, on-call engineers / SRE, security reviewers and audit liaisons, incident commanders, evidence recorders, and internal communications owners

---

## 1. Purpose and Scope

This document is the **canonical internal incident response procedure for QBIND**.

Its sole purpose is to define, in one place, **how QBIND incidents are classified, escalated, handled, documented, and closed** during internal operations.

**What this document is:**
- The canonical internal procedure for responding to incidents during QBIND Beta operations
- A reference used during MainNet-readiness exercises to demonstrate that incident response is defined, practiced, and producing evidence
- A source of structured incident evidence that feeds the Beta evidence packet and later the MainNet readiness assessment

**What this document is NOT:**
- It is **not** a public status page, public incident page, or marketing/communications document
- It is **not** a security disclosure policy for external researchers
- It is **not** a MainNet launch authorization, presale authorization, or readiness certification
- It does **not** itself authorize resets, hard forks, network halts, public disclosures, or launches outside the documented release and readiness processes

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Beta execution posture remains governed by:**
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`
- `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`

**MainNet-readiness governance remains defined by:**
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`
- `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md`

If any item in this procedure appears to conflict with the documents above, **the canonical documents win**. This procedure only operationalizes incident handling for QBIND operations.

---

## 2. Relationship to Beta Operations and MainNet Readiness

This procedure is a **subordinate instrument** to the Beta plan, the Beta operator checklist, and the MainNet readiness checklist. It does not replace any of them.

### 2.1 Relationship to Beta operations

This procedure is the **canonical response path for incidents observed during Beta operations**. It applies to:

- Incidents reported by validator-candidate operators on Beta
- Incidents detected by Beta coordinators or internal SRE / on-call
- Incidents surfaced via audit / bounty / security review during Beta
- Incidents observed by integrators using Beta endpoints
- Incidents detected by automated monitoring in Beta

Operator-side expectations during incidents continue to be governed by:
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`
- `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`

This document defines **how the response itself is conducted**, not what operators must do day-to-day during normal Beta operations.

### 2.2 Beta evidence packet

Evidence produced under this procedure — incident records, timelines, postmortems, severity assignments, remediations, and follow-up status — feeds the **Beta evidence packet** referenced by the Beta plan and operator checklist.

A non-trivial Beta incident with no record under this procedure is, by definition, **not adequately handled** for Beta evidence purposes.

### 2.3 Relationship to MainNet readiness

`docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` requires, as a precondition to MainNet readiness, that an incident response procedure:

1. **Exists** — this document is that artifact
2. **Is canonical and internal** — this document is canonical and internal
3. **Has been exercised** — Beta incidents (and any rehearsals/drills) handled under this procedure constitute the exercise record
4. **Produces retained evidence** — this procedure mandates evidence collection and retention

This document does **not itself certify MainNet readiness**. It only provides a procedure that, when exercised and evidenced, satisfies the incident response prerequisite of the readiness checklist.

---

## 3. Incident Response Principles

The following principles govern every incident handled under this procedure.

| # | Principle | Meaning |
|---|-----------|---------|
| 1 | **Safety before speed** | A correct slow response beats a fast wrong one. Do not take destructive or networkwide actions to "move faster." |
| 2 | **Honest reporting over silent local workaround** | If something abnormal happened, it is reported. Quietly fixing a node without recording the incident is a failure of this procedure. |
| 3 | **Preserve evidence before destructive action when feasible** | Capture logs, state, and context before wiping, restarting, reformatting, or re-syncing — unless doing so is itself unsafe. |
| 4 | **Classify first, then escalate appropriately** | Decide category and severity before broadcasting widely. Misclassification causes both over- and under-response. |
| 5 | **Contain before optimize** | Stop the spread / impact first. Cleanup, refactoring, and tuning come after stabilization. |
| 6 | **Documented response over improvised heroics** | Follow this procedure even if you "know what to do." Heroics that aren't recorded leave no evidence and can't be reviewed. |
| 7 | **Launch / readiness pressure never suppresses incident handling** | No timeline, milestone, deadline, or external expectation justifies skipping incident handling, downgrading severity, or shortening review. |
| 8 | **If uncertain, escalate** | When in doubt about severity, category, or scope — escalate. Escalation is cheap; missed escalation is not. |
| 9 | **Speak inside before speaking outside** | Internal coordination and classification precede any external statement. See Section 11. |
| 10 | **Stop local experimentation when an incident is suspected** | Repeated local restarts or "let me try one more thing" without evidence and escalation is not acceptable. See Section 10. |

---

## 4. Incident Categories

Every incident is assigned **exactly one primary category** at first classification. Categories may be revised during triage; revisions must be recorded.

### 4.1 Operator issue

- **Definition**: Incident scoped to a single operator's environment, configuration, host, or process — without indication of broader protocol, network, or security impact.
- **Examples**: Local node fails to start, local disk full, local clock drift, local misconfiguration, single-node connectivity loss, local key handling mistake, single-operator process crash.
- **Typical owners / responders**: The reporting operator, on-call engineer / ops, Beta coordinator (for visibility).

### 4.2 Software defect

- **Definition**: Reproducible or strongly suspected defect in QBIND node software, tooling, or release artifacts.
- **Examples**: Node panic on otherwise-valid input, incorrect RPC behavior, tool emits wrong output, deterministic regression in a release build, unhandled error path.
- **Typical owners / responders**: On-call engineer / ops, software maintainer for the affected component, security reviewer if the defect has safety implications.

### 4.3 Protocol / safety concern

- **Definition**: Possible deviation from canonical protocol behavior, possible safety property violation, possible consensus / fork / liveness anomaly, or behavior inconsistent with the whitepaper / protocol report.
- **Examples**: Fork suspected on Beta, conflicting views across honest operators, finality anomaly, signature verification anomaly, suspected divergence from documented protocol behavior, suspected violation of a safety invariant in the M-series coverage.
- **Typical owners / responders**: Incident commander, on-call engineer / ops, security reviewer / audit liaison, Beta coordinator. Protocol/safety concerns **always** receive coordinator visibility.

### 4.4 Infrastructure issue

- **Definition**: Incident in shared infrastructure that supports operations but is not itself node software — networking, observability, CI, artifact distribution, registries, internal services.
- **Examples**: Monitoring outage, CI broken, artifact distribution broken, internal coordination services unavailable, DNS / network issue affecting multiple operators.
- **Typical owners / responders**: On-call engineer / ops, infrastructure owner, Beta coordinator if Beta operations are impacted.

### 4.5 Economics-policy issue

- **Definition**: Behavior, observation, or operator action that may conflict with the canonical Beta or MainNet economics scope, or that creates a real or perceived violation of "Beta has no MainNet rights."
- **Examples**: External claim implying Beta participation grants MainNet allocation, presale, redemption, or priority; reward / point logic behaving outside documented Beta economics scope; communication suggesting MainNet-economic value flowing from Beta activity.
- **Typical owners / responders**: Beta coordinator, communications owner, leadership / authorization role for any external statement, evidence recorder.

### 4.6 Security issue

- **Definition**: Suspected or confirmed exploitation, vulnerability, key compromise, intrusion, or abuse — including via Beta endpoints, operator hosts, or supporting infrastructure.
- **Examples**: Suspected key compromise, suspected unauthorized access to operator host or coordinator infrastructure, exploitable vulnerability disclosed by audit / bounty / external researcher, abnormal authentication patterns, supply-chain anomaly in build / release artifacts.
- **Typical owners / responders**: Incident commander, security reviewer / audit liaison, on-call engineer / ops, communications owner. Security incidents are **never** handled silently in a single operator's environment.

> **Multi-category incidents.** When an incident clearly spans more than one category (e.g., a software defect with safety implications), classify by the **highest-impact category** (typically protocol/safety or security) and record the secondary categories in the incident record.

---

## 5. Severity Levels

Severity is assigned independently of category. Severity may be revised during triage; revisions must be recorded with justification.

| Severity | Name | Meaning | Example triggers | Expected posture |
|----------|------|---------|------------------|------------------|
| **Sev-0** | Critical | Active or imminent safety, security, or networkwide failure. Beta progression and any readiness conclusions must pause. | Suspected consensus fork on Beta; suspected key compromise; confirmed exploitable vulnerability under active discussion; widespread node crash from a defect; suspected protocol invariant violation. | Immediate response. Incident commander assigned without delay. Coordinated, evidence-preserving containment. No external statement without leadership / authorization role and communications owner. Beta coordinator notified immediately. |
| **Sev-1** | High | Significant impact to operations, multiple operators, or a single critical role; or a single-operator issue with strong indication of broader risk. | Multi-operator outage on Beta; reproducible defect with potential safety implications; security-relevant misbehavior limited in scope; sustained loss of monitoring during Beta operations. | Rapid response. Incident commander assigned. Evidence preserved before mitigation. Coordinator notified promptly. Postmortem required. |
| **Sev-2** | Moderate | Localized or contained impact; service / operator degradation without networkwide or safety implications. | Single-operator software defect with workaround; transient infrastructure degradation; non-safety-relevant tool defect; isolated economics-policy concern requiring correction. | Standard response under this procedure. Coordinator visibility. Lightweight postmortem if recurring or representative. |
| **Sev-3** | Low | Minor, well-understood issue with no safety, security, networkwide, or readiness impact. | Cosmetic defect; documentation inconsistency surfaced as an incident; one-off recoverable transient with clear cause. | Tracked, recorded, classified, and closed under this procedure. May be batched in periodic reviews. |

**Severity floors.**
- Any **protocol / safety concern** is **at minimum Sev-1**.
- Any **security issue** with credible evidence is **at minimum Sev-1**.
- Any incident that may impact **MainNet-readiness conclusions** is **at minimum Sev-1**.
- Any **suspected fork, suspected key compromise, or suspected protocol invariant violation** is **Sev-0** until proven otherwise.

---

## 6. Roles and Responsibilities

These roles are operational. They are not new governance bodies. The same person may fill multiple roles in a small incident; large incidents should split them.

| Role | Responsibilities |
|------|------------------|
| **Incident Commander (IC) / Coordinator** | Owns the incident end-to-end. Sets and revises severity and category. Assigns roles. Drives the response workflow (Section 9). Decides when to escalate, contain, mitigate, recover, and close. Owns the incident record. |
| **Operator / Reporter** | Reports the incident promptly with the minimum first record (Section 7). Preserves local evidence before destructive action when feasible. Cooperates with IC. Does not perform repeated unrecorded local recovery attempts. |
| **On-call Engineer / Ops** | First-line technical responder. Performs technical triage, log collection, containment, mitigation, and recovery actions under the IC's direction. |
| **Security Reviewer / Audit Liaison** | Engaged for any security issue, any protocol/safety concern, and any incident with credible evidence of exploit or invariant violation. Owns secure handling of sensitive evidence. |
| **Communications Owner** | Owns internal status updates during the incident and is the only role that may approve any external statement, in coordination with the leadership / authorization role. Enforces communications discipline (Section 11). |
| **Evidence Recorder / Scribe** | Maintains the timestamped incident timeline, decision log, and evidence index. May be the IC for small incidents. For Sev-0 / Sev-1, a separate scribe is strongly preferred. |
| **Leadership / Authorization Role** | Engaged for incidents that may affect Beta progression, MainNet-readiness conclusions, or any external/public-facing communication. Does not bypass this procedure; provides authorization where the procedure requires it. |

> **Roles vs. people.** Role assignments are recorded in the incident record. Handovers (e.g., on-call rotation, IC change) are recorded with timestamp and reason.

---

## 7. Detection and Initial Triage

This section defines what happens **first**, in the first minutes of an incident.

### 7.1 Detection sources

Incidents may originate from any of:
- Operator report (validator-candidate operator or integrator)
- Internal monitoring / alerting
- Audit, bounty, or security-review report
- Beta coordinator observation
- User / integrator report against Beta endpoints
- Release / CI / infrastructure alarms
- External researcher report (handled per security-issue category)

### 7.2 Minimum first record

Within the first action taken on a suspected incident, the reporter or first responder records, at minimum:

- Reporter identity and role
- Detection source
- Detection timestamp (UTC)
- One-line description of observed behavior
- Affected component(s) (node, tool, infra, network, etc.)
- Affected scope as currently understood (single operator, multiple, networkwide, unknown)
- Current best guess at category (Section 4) — may be revised
- Current best guess at severity (Section 5) — may be revised
- Whether destructive action (restart, wipe, re-sync, reinstall) has already occurred

If destructive action has already occurred before the record was created, that fact is recorded explicitly. It is not concealed.

### 7.3 First classification attempt

The first responder (or IC if already assigned) attempts:
1. **Category** — using Section 4
2. **Severity** — using Section 5, including the severity floors
3. **Scope** — single operator / multiple / networkwide / unknown

If any of category, severity, or scope cannot be confidently assigned, the incident is treated at the **higher** plausible severity until clarified.

### 7.4 Immediate questions

Within initial triage, the responder attempts to answer:
- What is observed?
- When did it start (best estimate)?
- Is it ongoing?
- Is it spreading?
- Is more than one operator affected?
- Does it look like a protocol / safety concern? A security concern?
- What versions / build IDs / configs are involved?
- What has already been tried locally?

### 7.5 Evidence preservation before restart

**Before restarting, wiping, re-syncing, or reformatting** any affected node or service, the responder preserves at least:
- Recent logs (node, tool, system as relevant)
- Process / service state (where safely capturable)
- Peer / connectivity state where relevant
- Config fingerprint
- Chain context (height / view / epoch where relevant)
- Snapshot of relevant metrics / dashboards

If preservation cannot be done safely (e.g., active exploitation requires immediate isolation), the responder records **why** preservation was skipped.

### 7.6 When to stop local experimentation

Local experimentation **stops and the incident is escalated** when any of the following is true:
- The issue is not a single-operator local issue
- A protocol / safety concern is suspected
- A security concern is suspected
- A second restart did not resolve the issue
- The cause is unclear
- Any indicator suggests the issue is reproducible elsewhere

Repeated unrecorded local restarts are a violation of Principle 2 and Principle 10 (Section 3).

---

## 8. Escalation Rules

Escalation is **mandatory**, not optional, when any of the conditions below are met. Escalation is recorded in the incident record with timestamp and recipient role(s).

### 8.1 Operator must escalate immediately when

- The issue is not clearly a single-operator local issue
- A protocol / safety concern is suspected (any severity)
- A security concern is suspected (any severity)
- The issue persists after one restart
- More than one operator appears affected
- The reporter is uncertain about category, severity, or scope
- Any external statement about the incident has been or may be made

### 8.2 Becomes a protocol / safety concern when

Any of the following is observed or credibly suspected:
- Disagreement on chain state across honest operators
- Finality / liveness anomalies
- Signature, cryptographic, or M-series invariant anomalies
- Behavior inconsistent with the whitepaper or protocol report
- Behavior inconsistent with `docs/whitepaper/contradiction.md` reconciliations

Once classified protocol / safety, severity is **at least Sev-1**, and the IC, security reviewer / audit liaison, and Beta coordinator are involved.

### 8.3 Security reviewer / audit liaison must be involved when

- The category is security issue
- The category is protocol / safety concern with possible exploit implications
- Evidence is sensitive (key material, private endpoints, credentials)
- The incident originated from an audit, bounty, or external-researcher report
- Disclosure handling is required

### 8.4 Beta coordinators must be notified when

- Severity is Sev-0 or Sev-1
- More than one operator is affected
- The incident may pause Beta progression
- The incident produces evidence that belongs in the Beta evidence packet
- The incident is an economics-policy issue
- The incident may require external communication

### 8.5 Leadership / authorization role must be informed when

- The incident may affect MainNet-readiness conclusions
- The incident may pause Beta progression
- Any external / public-facing communication may be required
- The incident requires a coordinated upgrade, halt, or reset (see Section 13)

### 8.6 External / public-facing communication may be needed only when

- The incident has been internally classified, scoped, and contained or actively being contained
- The communications owner has prepared the message
- The leadership / authorization role has approved
- The message is consistent with Section 11 (no speculation, no MainNet/presale/value implications)

External communication is **never** initiated by individual operators or engineers acting alone.

---

## 9. Response Workflow

Every non-trivial incident proceeds through these stages. Stages may overlap, but none may be skipped. Each stage produces an entry in the incident record.

| # | Stage | What must happen |
|---|-------|------------------|
| 1 | **Detect** | Detection source, timestamp, one-line description, and reporter recorded (Section 7.2). |
| 2 | **Classify** | Category assigned per Section 4. Initial impact / scope estimated. |
| 3 | **Assign severity** | Severity assigned per Section 5, including severity floors. IC assigned (or confirmed) for Sev-0 / Sev-1. |
| 4 | **Preserve evidence** | Logs, state, configs, and context captured per Section 12 before destructive action when feasible. |
| 5 | **Escalate** | Required parties notified per Section 8 with timestamp and recipient. |
| 6 | **Contain** | Spread / impact stopped or bounded per Section 10. Containment actions recorded. |
| 7 | **Mitigate** | Workaround or fix applied to reduce ongoing impact, with evidence retained. |
| 8 | **Recover** | Affected nodes / services / operations restored to expected state under IC direction. |
| 9 | **Review** | Post-incident review (Section 14) for all non-trivial incidents. |
| 10 | **Close** | Closure criteria (Section 15) verified before the incident is closed. |

A timestamped entry per stage is the **minimum** record. Additional entries (decisions, role changes, severity revisions, scope changes, evidence pointers) are recorded as they occur.

---

## 10. Containment, Mitigation, and Recovery

### 10.1 Containment by category

| Category | Typical containment |
|----------|---------------------|
| Operator issue | Isolate the affected operator process / host. Stop further local mutation until evidence is preserved. |
| Software defect | Pin or roll back the affected version on impacted hosts. Avoid networkwide rollouts until reviewed. |
| Protocol / safety concern | Stop voluntary protocol-affecting actions on suspect nodes. Hold network-affecting changes pending IC and security reviewer judgment. |
| Infrastructure issue | Isolate the impaired component. Failover where pre-defined. Avoid emergency new dependencies. |
| Economics-policy issue | Halt the misaligned action / communication. Preserve the artifact (post, message, config) as evidence. Do not silently delete. |
| Security issue | Isolate suspected-compromised host, key, or credential. Rotate where the procedure for rotation is already defined. Preserve forensic state. Do not "clean up" prematurely. |

### 10.2 Isolate node/operator vs. networkwide action

- **Single-node / single-operator action** is the default response when the impact is bounded to one host or operator.
- **Coordinated multi-operator action** requires the IC, Beta coordinator, and (for security or protocol/safety) the security reviewer / audit liaison.
- **Networkwide action** (halt, coordinated upgrade, coordinated reset) requires Section 13 decision guidance and the leadership / authorization role.

Operators do **not** take networkwide-impacting action unilaterally.

### 10.3 Local vs. coordinated mitigation

Mitigation is **local** when:
- The defect / issue is bounded to one operator's environment
- A documented local workaround exists
- The local action does not affect other operators or the network

Mitigation becomes **coordinated** when:
- The same issue is observed across operators
- The mitigation requires version, configuration, or behavior changes that touch multiple operators
- The mitigation has any protocol / safety / security implication

Coordinated mitigation is run by the IC with coordinator and (where required) security reviewer involvement.

### 10.4 When recovery attempts must stop and become a broader incident

Recovery is **stopped and re-scoped** when any of the following occurs during recovery:
- Recovery does not work after a documented attempt
- Recovery surfaces new symptoms in unrelated components
- A second operator reports the same symptoms
- Evidence appears that the original classification was wrong
- A security or protocol / safety indicator emerges

The incident's category / severity are re-evaluated and the workflow returns to **Classify → Assign severity → Preserve → Escalate** before continuing.

### 10.5 Why repeated local restarts without evidence are not acceptable

A pattern of "just restart and see" without evidence preservation:
- Destroys the only record of the failure
- Hides recurring patterns from the Beta evidence packet
- Prevents accurate severity assignment
- Conceals possible protocol / safety / security signals
- Cannot be reviewed in a postmortem

Per Principle 2 and Principle 10 (Section 3), this pattern is **not acceptable** under this procedure.

---

## 11. Communications Discipline

Communications discipline is treated as a first-class part of incident response.

### 11.1 Internal vs. external

| Audience | Channel | Owner |
|----------|---------|-------|
| Incident response participants | Internal incident channel / record | Incident Commander |
| Broader internal team | Internal coordination channel | Incident Commander, with communications owner for status framing |
| Operators not directly involved | Beta coordinator-to-operator channel | Beta coordinator |
| External / public-facing | Approved channel only | Communications owner, with leadership / authorization role |

Internal updates during active Sev-0 / Sev-1 incidents are **timestamped** and recorded in the incident record.

### 11.2 No speculative public claims

External / public-facing communication during or about an incident must not:
- Speculate on root cause before the post-incident review
- Speculate on impact beyond what is internally classified
- Make commitments on remediation timing beyond what has been internally agreed
- Imply blame on external parties without evidence

### 11.3 No MainNet / presale / value implications

External communication about an incident must **never**:
- Imply MainNet launch, MainNet-readiness, or MainNet timing
- Imply allocation, presale, redemption, airdrop, priority, or other rights
- Imply token or asset value, price, or expectation of value
- Frame Beta participation as conferring MainNet-economic rights

Any such implication is itself an **economics-policy issue** under Section 4.5 and is handled as an incident under this procedure.

### 11.4 Internal timestamped updates during active incidents

For any Sev-0 or Sev-1 incident, the IC ensures internal status updates are posted at a cadence appropriate to the incident, with a minimum of:
- An update at each workflow stage transition (Section 9)
- An update on any change of category, severity, or scope
- An update on any escalation or role change

### 11.5 Who can say what externally

- Only the **communications owner** may approve external messaging
- External messaging requires the **leadership / authorization role** for any incident that may affect Beta progression, readiness conclusions, or perception of MainNet status
- Individual operators, engineers, or contributors do **not** make external statements about an active incident

### 11.6 Separation between incident handling and marketing / social posting

Marketing or social posting about QBIND **does not** substitute for incident communication. Incident communications are not marketing surfaces. Marketing/social channels are not used to issue incident updates unless the communications owner explicitly designates them as part of an approved external communication.

---

## 12. Evidence Collection and Retention

Evidence collection is **part of the response**, not a follow-up activity.

### 12.1 Minimum evidence set

For every non-trivial incident, the following is collected and recorded in the incident record:

| Item | Notes |
|------|-------|
| Timestamps | Detection, classification, severity assignment, each workflow stage, escalations, role changes |
| Versions / build IDs | Of every affected node, tool, and service |
| Logs | Relevant excerpts and pointers to full logs as retained by operator/infra |
| Metrics snapshots | Dashboards / metrics relevant to the incident window |
| Peer / connectivity state | Where relevant (consensus, networking incidents) |
| Config fingerprint | Configs in effect on affected hosts at incident time |
| Chain context | Height / view / epoch / round as relevant |
| Incident timeline | Chronological list of events, decisions, and actions |
| Attempted mitigations | What was tried, by whom, with what result |
| Outcome | Final state, residual risk, and follow-up |

### 12.2 Preserve before wipe / restart when feasible

Per Section 7.5, evidence is preserved **before** restart, wipe, re-sync, reformat, or reinstall, unless preservation itself is unsafe. Skipped preservation is recorded with reason.

### 12.3 Evidence quality

Evidence must be sufficient to support:
- Internal postmortem
- Inclusion in the **Beta evidence packet** referenced in `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` and `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`
- Later review during MainNet-readiness assessment per `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`

Evidence that does not support these uses is, by this procedure's standard, insufficient.

### 12.4 Retention

Incident records and associated evidence are retained as canonical operational artifacts. They are not deleted to "clean up" or to make readiness records look better. Retention spans:
- Beta operations (continuous)
- Through MainNet-readiness assessment
- Through any audit review for which the incident is in scope

### 12.5 Sensitive evidence

Sensitive evidence (key material, credentials, private endpoints, exploit details) is handled by the security reviewer / audit liaison. It is not posted to general internal channels, not attached to broadly accessible records, and not shared externally without the leadership / authorization role and the communications owner.

---

## 13. Reset / Upgrade / Halt Decision Guidance

This section provides **guidance**, not autonomous authorization. Resets, coordinated upgrades, halts, and any networkwide-impacting action remain governed by `docs/release/QBIND_RELEASE_TRACK_SPEC.md` and the Beta plan, and are subject to the leadership / authorization role.

### 13.1 When a restart is appropriate

A restart (single node or a small bounded set) is appropriate when:
- The issue is bounded to operator / single-host scope
- Evidence has been preserved per Section 7.5 / Section 12
- The cause is understood or clearly transient
- No protocol / safety / security indicator is present
- The action does not require coordinated multi-operator change

### 13.2 When a coordinated upgrade may be needed

A coordinated upgrade is considered when:
- A software defect is reproducible and impacts multiple operators
- A protocol / safety concern requires a corrected build
- A security issue requires a fix to be rolled out beyond a single host
- The upgrade can be staged and reviewed under the release-track spec

Coordinated upgrades are driven by the IC with coordinator and security-reviewer involvement, and authorized per the release-track spec, not by this document.

### 13.3 When resets are exceptional

A reset (network state truncation, re-genesis, or equivalent on Beta) is **exceptional** and requires:
- Explicit IC determination that no lower-impact action suffices
- Beta coordinator and leadership / authorization role involvement
- Security reviewer / audit liaison involvement where any safety / security concern exists
- A documented decision record stored with the incident
- Conformance with the Beta plan and release-track spec

A reset is **never** undertaken merely to make an incident "go away," to recover schedule, or to reduce visible incident counts.

### 13.4 When the incident must pause Beta progression or readiness conclusions

Beta progression and any in-flight MainNet-readiness conclusions are **paused** when:
- An unresolved Sev-0 incident is active
- An unresolved Sev-1 protocol / safety or security incident is active
- An incident's classification or scope is unresolved at Sev-1 or above
- Required postmortem (Section 14) for a Sev-0 / Sev-1 incident is not yet complete
- Required follow-ups for a Sev-0 / Sev-1 incident are not yet captured with owners

Resumption of Beta progression or readiness conclusions requires the IC to confirm closure criteria (Section 15) and the appropriate role (Beta coordinator and/or leadership / authorization role) to acknowledge resumption.

### 13.5 Stronger containment for protocol / safety vs. operator issues

A protocol / safety concern justifies stronger containment than a comparable operator issue, because:
- The blast radius is the network, not one operator
- Evidence loss is harder to recover
- Misclassification toward "operator issue" risks systemic harm

Where uncertain, the IC treats the incident as a protocol / safety concern until evidence supports a narrower category.

### 13.6 No autonomous launch-stage authorization

Nothing in this section authorizes:
- MainNet launch
- Presale or any external commitment
- Public claims of readiness
- Bypass of the release-track spec
- Bypass of the MainNet readiness checklist

This document provides **incident decision guidance** only.

---

## 14. Post-Incident Review Requirements

A post-incident review (postmortem) is **required** for every non-trivial incident — in particular every Sev-0, Sev-1, and Sev-2 — after stabilization.

### 14.1 Required content

Every postmortem includes, at minimum:

| Field | Description |
|-------|-------------|
| Incident ID | Stable identifier of the incident record |
| Timeline | Chronological events, decisions, and actions |
| Category | Final category per Section 4 |
| Severity | Final severity per Section 5 |
| Root cause | Confirmed root cause, or current best understanding labeled as such |
| Impact | Operators, services, network, evidence, readiness, and economics-policy implications affected |
| Evidence links | Pointers to retained evidence per Section 12 |
| Remediation | What was done, by whom, with what result |
| Follow-up owner | Named role accountable for outstanding follow-ups |
| Doc / checklist updates | Whether canonical docs, Beta operator checklist, or this procedure require updates (per their own change processes) |
| Readiness impact | Whether the incident affects MainNet-readiness assessment |

### 14.2 Timeliness

- Sev-0: postmortem started during the incident, completed promptly after stabilization
- Sev-1: postmortem completed in a defined short interval after stabilization
- Sev-2: postmortem completed before the incident is closed
- Sev-3: lightweight review; may be batched in periodic reviews

"Promptly" and "defined short interval" are operational targets owned by the Beta coordinator.

### 14.3 Postmortems are part of the canonical process

A non-trivial incident with no postmortem is, by this procedure, **not yet closed**. Postmortems feed the Beta evidence packet (Section 2.2) and are referenced during MainNet-readiness assessment (Section 2.3).

### 14.4 No-blame, evidence-driven posture

Postmortems focus on systems, evidence, and process — not on individual fault. This is a property of the procedure, not a softening of standards: weak evidence, missing escalation, or skipped preservation are recorded as procedural failures and fed back into improvements.

---

## 15. Incident Closure Criteria

An incident may be closed only when **all** of the following are true:

| # | Criterion |
|---|-----------|
| 1 | The immediate issue is stabilized — observed symptoms have stopped and are not recurring within the monitored window |
| 2 | Evidence has been collected per Section 12 |
| 3 | A follow-up owner is assigned for any open remediation work |
| 4 | Follow-up tasks are captured (with owner and tracking) |
| 5 | Required communications (internal and, where applicable, external) are completed per Section 11 |
| 6 | Unresolved risk is either remediated or **explicitly documented** in the incident record and tracked |
| 7 | The required postmortem (Section 14) is complete or, for Sev-3, the lightweight review is complete |
| 8 | For Sev-0 / Sev-1, the IC and Beta coordinator have confirmed closure |
| 9 | For incidents with readiness impact, the leadership / authorization role has acknowledged closure |
| 10 | For security and protocol / safety incidents, the security reviewer / audit liaison has acknowledged closure |

> **"It stopped happening" is not enough.** A symptom going away is **not** a closure criterion. Without classification, evidence, and follow-up, an incident is not closed under this procedure.

> **Critical / high incidents are not silently closed.** Sev-0 and Sev-1 incidents require explicit acknowledgement from the roles above and a complete postmortem. They are never closed by inactivity, time-out, or convenience.

---

## 16. What This Procedure Does Not Do

To keep boundaries clean, this procedure explicitly does **not**:

- **Replace the Beta plan.** Beta scope, posture, participants, and policy remain defined by `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`.
- **Replace the Beta operator checklist.** Operator-side day-to-day expectations remain defined by `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`.
- **Replace the MainNet readiness checklist.** Readiness criteria, evidence requirements, and gating remain defined by `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`.
- **Authorize MainNet launch.** No incident outcome under this procedure is, by itself, authorization to launch MainNet.
- **Authorize presale or public claims.** Nothing in this procedure authorizes presale, allocation, redemption, airdrop, priority, or any public claim about MainNet, value, or rights.
- **Replace external disclosure policies if and when they exist later.** Public security disclosure policy for external researchers is a separate document; if and when it is created, this procedure operates alongside it, not in place of it.
- **Eliminate the need for audits or postmortems.** Audits, security reviews, and postmortems remain required under their own canonical processes.
- **Override canonical protocol behavior.** Canonical protocol behavior remains defined by the whitepaper and the protocol report.
- **Override release sequencing.** Release sequencing remains governed by `docs/release/QBIND_RELEASE_TRACK_SPEC.md`.

---

## 17. Final Procedure Summary

QBIND incident response is governed by a single canonical internal procedure (this document), which:

1. **Defines** how incidents are detected, classified by **category** (operator / software / protocol-safety / infrastructure / economics-policy / security) and **severity** (Sev-0 through Sev-3), escalated, contained, mitigated, recovered, reviewed, and closed.
2. **Assigns** clear operational roles — Incident Commander, Operator / Reporter, On-call Engineer / Ops, Security Reviewer / Audit Liaison, Communications Owner, Evidence Recorder, and Leadership / Authorization Role — without inventing new governance bodies.
3. **Requires** evidence preservation before destructive action where feasible, a complete incident timeline, and retained evidence sufficient for postmortem, the Beta evidence packet, and MainNet-readiness assessment.
4. **Enforces** communications discipline: internal first, no speculation, no MainNet / presale / value implications, only the communications owner approves external statements, and marketing/social channels are not incident channels.
5. **Provides** decision guidance for restarts, coordinated upgrades, resets, and pausing Beta progression or readiness conclusions — without itself authorizing launch-stage actions.
6. **Mandates** postmortems for non-trivial incidents and a strict closure standard: stabilization alone is **not** closure.
7. **Supports** Beta operations and feeds MainNet-readiness assessment, while explicitly **not** replacing the Beta plan, the Beta operator checklist, the MainNet readiness checklist, the release-track spec, or canonical protocol documents.

If incident handling is ever in tension with launch pressure, marketing, optics, or schedule, **this procedure wins for the response itself**, and the canonical documents above win for protocol behavior, release sequencing, and readiness governance.