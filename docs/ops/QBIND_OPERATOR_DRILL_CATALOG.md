# QBIND Operator Drill Catalog

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal Operator Drill Catalog  
**Audience**: Beta coordinators, validator-candidate operators, on-call engineers / SRE, incident commanders, evidence recorders, monitoring owners, backup/recovery owners, cutover coordinators, MainNet-readiness reviewers

---

## 1. Purpose and Scope

This document is the **canonical internal operator drill catalog for QBIND**.

Its sole purpose is to define, in one place, the **minimum operational drills and rehearsals QBIND must run** so that incident response, recovery posture, monitoring coverage, validator/signer practice, network/peering posture, and launch-window cutover discipline are **exercised rather than assumed**.

**What this document is:**
- The canonical internal catalog of operational drills QBIND must run across environments
- A reference used during Beta operations to ensure that real procedures are rehearsed and produce evidence
- A reference used during MainNet-readiness review to demonstrate that the rehearsed posture exists, has been exercised, and has produced auditable artifacts
- A common standard for what every QBIND drill must minimally include and minimally evidence

**What this document is NOT:**
- It is **not** a training slide deck, onboarding curriculum, or HR process document
- It is **not** a vendor or tool implementation specification
- It is **not** code or configuration
- It is **not** a public operations guide or marketing document
- It is **not** a substitute for the incident response procedure, monitoring baseline, backup/recovery baseline, or MainNet cutover runbook
- It does **not** itself certify MainNet readiness or authorize launch
- It does **not** define presale, public-sale, or external communications policy

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Operational procedures rehearsed by this catalog remain defined by:**
- `docs/ops/QBIND_INCIDENT_RESPONSE.md`
- `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`
- `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`
- `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md`
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`

If any item in this catalog appears to conflict with the documents above, **the canonical documents win**. This catalog only defines the rehearsal requirements that exercise them.

---

## 2. Relationship to Beta Operations, Incident Response, Monitoring, Recovery, and Readiness

This drill catalog sits alongside the existing operational baselines and operator-facing documents. Each companion document defines **what must be true**; this catalog defines **what must be rehearsed** to know whether those things are actually true.

| Companion document | What it defines | What this catalog adds |
|---|---|---|
| `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md` | Day-to-day operator posture during Beta | Rehearsals that prove the checklist is executable, not just printable |
| `docs/ops/QBIND_INCIDENT_RESPONSE.md` | How real incidents are classified, escalated, handled, and closed | Rehearsals that prove the incident path actually works under exercise |
| `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` | What signals must be present and what alerts must fire | Rehearsals that prove monitoring is not silently broken and alerts actually reach humans |
| `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` | What must be backed up and how recovery is structured | Rehearsals that prove restores actually succeed into the correct environment |
| `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md` | How a launch window is conducted, including HOLD and ABORT | Rehearsals that prove HOLD/ABORT are socially and operationally executable |
| `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` | What must be evidenced before MainNet readiness can be claimed | Rehearsals that produce the evidence the checklist requires |

**The unifying principle:** readiness is not the existence of documents. Readiness is the **existence of documents plus evidence that the procedures in those documents have been exercised and have produced expected outcomes**. This catalog is the bridge between the two.

---

## 3. Drill Principles

The following principles apply to every drill in this catalog.

- **Drills must exercise real procedures.** A meeting that discusses a procedure is not a drill. A drill executes the procedure end-to-end against a defined scenario.
- **Drills must produce evidence, not attendance.** A drill that leaves no artifact did not happen for readiness purposes.
- **Drills must prefer realistic failure conditions.** Toy scenarios that cannot fail are not useful. Scenarios should resemble plausible operational reality.
- **Drills must preserve environment separation.** A drill must never blur DevNet, Alpha, Beta, and MainNet-readiness boundaries; environment confusion is itself a failure mode this catalog is meant to catch.
- **Drills must not create uncontrolled production-like risk.** Drills are exercises, not stunts. Destructive actions occur only in environments where destruction is acceptable.
- **Repeated unexercised procedures are a readiness gap.** If a procedure has never been drilled, treat it as unverified.
- **Failed drills are valuable evidence, not embarrassment.** A drill that surfaces a real defect is doing its job. Outcomes are recorded honestly.
- **Ambiguous drill results are findings.** "We think it worked" is a finding that requires follow-up, not a pass.
- **Drills are owned.** Every drill has a named owner accountable for scenario, execution, evidence, and follow-up.
- **Drills feed back into the canonical docs.** When a drill exposes a gap in incident response, monitoring, recovery, the operator checklist, or the cutover runbook, the gap is filed against that canonical document — not patched silently inside this catalog.

---

## 4. Drill Taxonomy

QBIND drills are organized into the following classes. Sections 6–11 elaborate the minimum required drills within each class.

| Class | Short description | Why it matters | Typical evidence produced |
|---|---|---|---|
| Incident / escalation drills | Rehearse classification, escalation, evidence preservation, communications discipline, and closure | Proves the incident response procedure is executable, not aspirational | Drill incident record, escalation timeline, postmortem-style write-up |
| Monitoring / alert drills | Exercise telemetry, alert routing, and silent-failure detection | Proves monitoring is honest and that "green" is not false-green | Alert delivery records, signal screenshots/exports, gap findings |
| Backup / restore drills | Exercise snapshot/state recovery into the correct environment | Proves recovery actually works and that backups are not stale or unrestorable | Restore log, integrity checks, environment-target verification |
| Validator / signer drills | Exercise signer outage, participation drop, exclusion, key/signer misconfig, and validator-set drift | Proves validator/signer posture under operator-level disruption | Participation snapshots, signer status logs, drift diffs |
| Network / partition drills | Exercise bootstrap reachability, peer churn, partition diagnosis, and wrong-environment connection | Proves the network posture is observable and recoverable, not fragile and silent | Peer-state snapshots, reachability checks, diagnosis notes |
| Cutover / hold / abort drills | Exercise launch-window discipline, including HOLD and ABORT | Proves launch-window decisions are socially and operationally possible | HOLD/ABORT decision records, evidence-capture artifacts, role coverage logs |
| Artifact / config integrity drills | Exercise detection of mismatched binaries, configs, genesis material, or chain identifiers | Proves that wrong-artifact and wrong-config conditions are caught before they cause harm | Hash/identity checks, mismatch detection records |
| Wrong-environment catch drills | Exercise detection of operator actions targeted at the wrong environment | Proves environment-confusion failures are caught operationally, not by luck | Catch records, near-miss logs, follow-up findings |

This taxonomy is the navigation backbone for the rest of this document.

---

## 5. Core Drill Requirements

Every drill in this catalog, regardless of class, must satisfy the following minimum cross-cutting requirements.

| Requirement | Description |
|---|---|
| Scenario definition | A written scenario describing the failure condition, trigger, and operating environment |
| Owner | A single named drill owner accountable for scenario, execution, and follow-up |
| Participants and roles | Named participants and the role each plays during the drill |
| Preconditions | State of environment, monitoring, backups, and personnel required before the drill starts |
| Success criteria | What an acceptable outcome looks like, defined before the drill runs |
| Evidence captured | Artifacts that must be retained: logs, metrics, screenshots/exports, decision records, timelines |
| Deviations recorded | Any departure from the documented procedure must be recorded, not normalized |
| Post-drill review | A short, structured review that turns observations into findings and follow-ups |
| Follow-up owner | Each finding has a named owner and a tracked follow-up item |
| Linkage to readiness | When relevant, drills are linked to the Beta evidence packet and/or the MainNet readiness checklist |

A drill that lacks any of these items is **incomplete** and does not count toward readiness evidence.

---

## 6. Incident-Response Drill Set

This set rehearses `docs/ops/QBIND_INCIDENT_RESPONSE.md`. Drills exercise the procedure itself, not roleplay.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Sev classification exercise | Operators presented with realistic conditions and asked to classify (Sev-2/Sev-1/Sev-0) per the procedure | Classifications are consistent, justified, and use the canonical definitions | Classification record with rationale per case |
| Escalation path rehearsal | The escalation path defined in the incident response procedure is walked end-to-end | Every step has a reachable, named owner; no dead ends; no "we'll figure it out" | Escalation timeline and reachability log |
| Evidence-preservation-before-restart drill | Before any restart action, required logs/state/metrics snapshots are captured | Evidence is captured before recovery actions are taken; no destructive shortcut | Pre-restart evidence bundle and timestamp |
| Communications discipline rehearsal | Internal incident comms cadence, channels, and tone are exercised | No external communications leak from drill; internal updates follow the procedure | Internal comms log; absence of external leakage |
| Incident closure / postmortem rehearsal | A drill incident is fully closed using the documented closure and postmortem flow | Closure includes findings, follow-ups, and named owners; postmortem is reviewable | Closure record and postmortem document |

Findings from this set feed directly back into the incident response procedure.

---

## 7. Monitoring / Alerting Drill Set

This set rehearses `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`. The recurring concern is that **silent monitoring failure must itself be detectable**.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Missing telemetry detection drill | A required signal is intentionally suppressed in a non-production environment | The absence of the signal is detected and surfaces as an alert/finding, not as silence | Detection record, alert artifact, time-to-detect |
| False-green pipeline failure drill | The monitoring pipeline itself is degraded (e.g., stalled scraping/forwarding) | Operators detect that "everything is green" is not trustworthy and act accordingly | Pipeline-failure detection record and operator response log |
| Peer-count / partition signal drill | A drop in peer count or partition-like condition is induced in a safe environment | Alerting fires within expected envelope; operators interpret the signal correctly | Alert record, peer-state snapshots, operator interpretation note |
| Chain-stall detection drill | A chain-stall-like condition is induced in a safe environment | Stall is detected via documented signal, not by chat reports | Detection record, signal export, time-to-detect |
| Wrong-version / wrong-chain / wrong-config signal drill | An operator/agent is presented with a node running the wrong version, wrong chain identifier, or wrong config | The mismatch is caught by documented signals before any action is taken on it | Mismatch detection record, signal export, catch confirmation |

This set proves that monitoring is honest under exercise, not just configured.

---

## 8. Backup / Restore / Recovery Drill Set

This set rehearses `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`. These drills are particularly important: a backup that has never been restored is not a backup.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Restore from snapshot drill | A snapshot is restored end-to-end in a non-production environment | Restore completes within the expected envelope and the resulting state is verified against documented integrity checks | Restore log, integrity-check output, time-to-restore |
| Restore into correct environment drill | Operator selects backup and target environment under realistic conditions | Restore targets the **correct** environment; wrong-environment selection is caught before execution | Environment-target verification record, catch evidence if applicable |
| Stale backup detection drill | An intentionally stale or incomplete backup is presented as a candidate for restore | Staleness/incompleteness is detected before restore proceeds, not after | Detection record and operator decision log |
| Host-loss / operator handoff drill | The original operator/host is treated as unavailable; a different operator must restore using documented artifacts only | Recovery succeeds using only documented procedure and stored artifacts; tribal knowledge is not required | Handoff record, restore log under handoff conditions |
| Evidence-preserving recovery drill | A recovery is performed under simulated incident conditions where pre-recovery evidence must be preserved | Pre-recovery evidence is captured before restore; recovery does not destroy diagnostic state | Pre-recovery evidence bundle, post-recovery state snapshot |

Failed drills in this set are **not** an embarrassment — they are exactly the failures this catalog exists to expose before MainNet.

---

## 9. Validator / Signer / Participation Drill Set

This set aligns with `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md` and the monitoring baseline.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Signer unavailable drill | A signer is taken offline in a safe environment | Loss of signer is detected via documented signal; operator response follows the checklist; no improvised key handling | Signer-status log, alert record, operator action log |
| Validator participation drop drill | Participation is intentionally degraded for a participant in a safe environment | Drop is observed in monitoring; cause is diagnosed via documented signals; response follows operator checklist | Participation snapshot, diagnosis note, operator response log |
| Validator below-threshold / exclusion observation drill | An operator observes another validator entering below-threshold or exclusion-relevant conditions | Operator interprets the situation per documented expectations; no unilateral, undocumented intervention | Observation record and operator decision log |
| Key / signer misconfiguration detection drill | A node is configured with a wrong/placeholder key or wrong signer identity | Misconfiguration is detected before participation begins; node is not allowed to act on the wrong identity | Detection record, configuration audit output |
| Unexpected validator-set drift drill | A drift in observed validator set vs expected validator set is induced in a safe environment | Drift is detected, diffed, and treated as an incident-worthy finding rather than ignored | Drift diff, detection record, decision log |

This set ensures validator/signer posture is rehearsed at the operator layer, not only at the protocol layer.

---

## 10. Network / Peering / Partition Drill Set

This set is practical and operational. It rehearses peering posture observable to operators.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Bootstrap reachability failure drill | Bootstrap endpoints are made unreachable from a single operator's vantage | Operator distinguishes "I can't reach bootstrap" from "bootstrap is down for everyone" before escalating | Reachability check log, diagnosis note |
| Peer churn spike drill | An induced peer churn condition is introduced in a safe environment | Operators detect churn via documented signals and follow checklist guidance | Peer-state snapshots, alert record, operator response log |
| Local-vs-network-wide diagnosis drill | Operators must distinguish whether a problem is local to their node or affects the network | Diagnosis follows documented method and reaches a defensible conclusion | Diagnosis record with evidence and conclusion |
| Partition indicator drill | A partition-like condition is induced in a safe environment | Partition indicators surface as documented; operators do not treat partition as routine churn | Partition signal record, classification record |
| Wrong-peer-identity / wrong-environment connection catch drill | An operator is presented with peer identity material from the wrong environment | The wrong-environment connection is **refused/caught**, not attempted; the catch is treated as a near-miss finding | Catch record, near-miss log, follow-up item |

This set ties directly into the wrong-environment failure modes that Section 14 calls out.

---

## 11. Cutover / Hold / Abort Drill Set

This set rehearses `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md`. The defining property of a good cutover posture is that **HOLD and ABORT are real options, not theoretical ones**.

| Drill | What is exercised | What "good" looks like | Evidence retained |
|---|---|---|---|
| Artifact mismatch causes HOLD drill | Cutover begins with a deliberately mismatched artifact (wrong hash / wrong config / wrong chain identifier) | The mismatch is detected and triggers HOLD per the runbook; cutover does not proceed | HOLD decision record, mismatch evidence, comms log |
| Missing role causes HOLD drill | A required cutover role is unavailable at gate time | HOLD is invoked; the launch window is not allowed to proceed without the role | HOLD decision record, role-coverage log |
| Late-change / "one more fix" freeze-breach drill | A late change is proposed inside the freeze window | The freeze is enforced; the change is rejected or escalated per the runbook, not silently merged | Freeze-breach attempt record, decision log |
| Cutover-step evidence capture drill | A cutover step is executed in a rehearsal environment with full evidence capture | Each step produces the evidence required by the runbook before the next step begins | Per-step evidence bundle, timestamped step log |
| ABORT decision rehearsal | Conditions worsen mid-cutover in a safe rehearsal | ABORT is invoked deliberately; rollback/hold posture is executed cleanly | ABORT decision record, rollback/hold execution log |
| Communications discipline during HOLD/ABORT drill | Internal comms during HOLD/ABORT are exercised | Comms remain internal, structured, and consistent with the runbook; no premature external statements | Internal comms log; absence of external leakage |

This set is essential for launch-quality posture and feeds directly into MainNet-readiness review.

---

## 12. Environment-Specific Expectations (DevNet / Alpha / Beta / MainNet-Readiness)

Drill rigor scales with environment. The catalog does not invent numerical schedules; it sets baseline expectations.

| Environment | Expected drill posture |
|---|---|
| **DevNet** | Lighter, ad hoc drills are acceptable. Drills here focus on shaking out scenarios, scripts, and evidence formats before they are exercised in higher environments. DevNet drill outcomes do not count toward Beta or MainNet-readiness evidence on their own. |
| **TestNet Alpha** | Basic operator response and onboarding recovery are proven. Incident classification, escalation reachability, and at least one restore drill are exercised. Evidence is recorded but not yet expected to meet full review-grade standards. |
| **TestNet Beta** | Reviewable evidence is produced across **all major drill classes** in this catalog (Sections 6–11). Drills produce artifacts suitable for inclusion in the Beta evidence packet. Findings are tracked to closure. Repeated unexercised procedures are treated as gaps. |
| **MainNet-readiness / cutover preparation** | The strongest rehearsed posture. Cutover/HOLD/ABORT drills, evidence-preserving recovery drills, and wrong-environment catch drills are all exercised under realistic conditions. Outstanding findings from earlier environments are closed or explicitly accepted. Drill evidence is referenced by the MainNet readiness checklist. |

Numerical cadences (e.g., "every N weeks") are **not** prescribed here. Cadence is owned by the operational program and is governed by the canonical readiness and release documents.

---

## 13. Drill Evidence and Recordkeeping Requirements

Every drill must produce a record containing at minimum the following fields. This aligns with incident response evidence expectations and with the monitoring and backup baselines.

| Field | Description |
|---|---|
| Scenario and objective | What scenario was rehearsed and what the drill was meant to prove |
| Drill class | Which class from Section 4 |
| Participants and roles | Named participants and the role each played |
| Date and time | Start and end timestamps |
| Environment | DevNet / Alpha / Beta / readiness rehearsal — never ambiguous |
| What was exercised | The specific documented procedure(s) being rehearsed |
| What signals were observed | Monitoring signals, alerts, peer/validator state, restore output, etc. |
| Outcome vs expected | Did the drill meet success criteria? Where did it deviate? |
| Incidents opened (if any) | Any drill incident records or near-miss logs created |
| Findings | Defects, gaps, ambiguous results — explicitly listed |
| Follow-up actions | Each finding has a named owner and a tracked item |
| Linked artifacts | Logs, metrics exports, screenshots, configs, restore outputs, decision records |
| Evidence-packet linkage | Whether the drill supports the Beta evidence packet, MainNet-readiness review, both, or neither |

Drill records are internal artifacts. They are not public material and are not distributed outside the contexts already permitted by canonical operational and readiness documents.

---

## 14. Explicit Failure Modes This Catalog Is Meant to Catch

This catalog exists because the following failure modes are realistic, recurring, and damaging. Drills are designed so these failures surface in rehearsal — not in production.

- Procedures that exist on paper but were never exercised end-to-end.
- Monitoring that appears green because the monitoring pipeline itself has silently failed.
- Telemetry gaps that are only discovered during a real incident.
- Backups that exist but cannot actually be restored, or restore into the wrong environment.
- Escalation paths whose named owners cannot in practice be reached or do not in practice know what to do.
- Incident evidence destroyed by reflexive restart before preservation.
- Cutover roles that are documented but undefined in practice when the launch window opens.
- Wrong-environment operator actions (DevNet/Alpha/Beta/MainNet confusion) that are not caught operationally.
- Wrong-artifact / wrong-chain / wrong-config conditions that pass undetected because no one rehearsed catching them.
- Validator/signer misconfigurations that act on the wrong identity because no pre-participation check was rehearsed.
- HOLD or ABORT becoming socially impossible — present on paper but unavailable in practice during a real launch window.
- Late "one more fix" changes breaking the freeze because the freeze was never tested under pressure.
- Drill outcomes recorded as "fine" with no artifacts, hiding ambiguous results.

If a drill in this catalog does not credibly threaten one or more of these failure modes, it is not a useful drill.

---

## 15. What This Catalog Does Not Decide

This catalog explicitly does **not**:

- Choose vendors, platforms, products, or specific tools.
- Replace `docs/ops/QBIND_INCIDENT_RESPONSE.md` for handling real incidents.
- Replace `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` for what monitoring must exist.
- Replace `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` for what must be backed up and how recovery is structured.
- Replace `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md` for how a launch window is conducted.
- Certify MainNet readiness on its own. Readiness is governed by `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`.
- Authorize MainNet launch, presale, public sale, distribution, or any external program.
- Define external communications policy beyond the comms-discipline posture rehearsed inside drills.
- Define training curricula, certifications, or HR/personnel processes.
- Modify canonical protocol behavior, which remains defined by the whitepaper, protocol report, M-series coverage, and contradiction document.
- Modify release sequencing, which remains governed by the release-track spec.

If any item in this catalog appears to conflict with the canonical documents above, **the canonical documents win**.

---

## 16. Final Catalog Summary

QBIND treats readiness as **exercised**, not declared. This catalog defines the minimum drills that must be run, the minimum evidence each drill must produce, and the environments in which each drill must occur with increasing rigor.

- Section 2 binds this catalog to the operator checklist, incident response, monitoring baseline, backup/recovery baseline, cutover runbook, and MainNet readiness checklist.
- Sections 3–5 define the principles, taxonomy, and core requirements every drill must satisfy.
- Sections 6–11 define the minimum drill set across incident response, monitoring, recovery, validator/signer posture, networking, and cutover discipline.
- Section 12 scales rigor across DevNet, Alpha, Beta, and MainNet-readiness.
- Section 13 fixes the evidence and recordkeeping bar.
- Section 14 names the failure modes the catalog is built to expose.
- Section 15 holds the boundaries: this catalog does not certify, authorize, or replace anything outside its scope.

The catalog succeeds when, on the day of MainNet cutover, **no procedure is being executed for the first time**.