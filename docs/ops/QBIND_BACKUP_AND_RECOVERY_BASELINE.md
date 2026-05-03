# QBIND Backup and Recovery Baseline

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal Backup and Recovery Baseline  
**Audience**: Beta coordinators, validator-candidate operators, on-call engineers / SRE, incident commanders, evidence recorders, security reviewers, audit liaisons, cutover commander, and MainNet-readiness assessors

---

## 1. Purpose and Scope

This document is the **canonical internal backup and recovery baseline for QBIND**.

Its purpose is to define, in one place:
- **what must be backed up** (or otherwise preserved) across QBIND environments,
- **what must not be backed up insecurely**,
- **how restore and recovery must be validated** before they are trusted,
- and **what evidence must exist** so that recovery posture is reviewable for Beta operations and for MainNet-readiness assessment later.

**What this document is:**
- The canonical internal baseline for backup, restore, recovery, and recovery-validation expectations across DevNet, TestNet Alpha, TestNet Beta, and MainNet-readiness / cutover preparation
- A requirements/baseline document that incident response, monitoring, cutover, Beta operator procedures, and MainNet readiness assessment can all reference
- A source of structure for what evidence the recovery posture is expected to produce

**What this document is NOT:**
- It is **not** a storage implementation, a snapshot product specification, or a backup tool design
- It is **not** a vendor selection, cloud selection, or storage-backend selection
- It is **not** a public disaster-recovery announcement, marketing artifact, or external availability promise
- It is **not** a key-management implementation specification
- It does **not** replace the canonical incident response procedure
- It does **not** replace the canonical monitoring and alerting baseline
- It does **not** replace the canonical MainNet cutover runbook
- It does **not** itself certify MainNet readiness, authorize launch, authorize presale, or authorize any public-sale activity
- It does **not** define exact RPO/RTO numerical promises beyond what canonical documents already require

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

If any item in this baseline appears to conflict with the documents above, **the canonical documents win**. This baseline only defines backup/recovery expectations and what "recoverable" must mean operationally.

---

## 2. Relationship to Incident Response, Monitoring, Cutover, and MainNet Readiness

This baseline does not stand alone. It is the recovery-posture layer that supports the rest of QBIND operations.

| Companion document | Role | Relationship to this baseline |
|---|---|---|
| `docs/ops/QBIND_INCIDENT_RESPONSE.md` | Defines how incidents are classified, escalated, handled, documented, and closed | This baseline defines what must be **recoverable** so that incident response has something credible to recover **from** and **to**. Incident response defines **what to do** when recovery is actually invoked. |
| `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` | Defines minimum signals, alert classes, and evidence expectations | This baseline relies on monitoring to make backup/restore/recovery posture **observable**, and to confirm that restored systems have been brought back into a healthy, monitored state. |
| `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md` | Defines the operational steps and controls used to execute cutover after authorization | Cutover assumes trustworthy artifacts and a credible recovery posture. This baseline is what makes that assumption defensible. |
| `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` | Defines what must be true before MainNet readiness can be claimed | Readiness later depends on backup and recovery being **documented, tested, and evidenced**. This baseline is the document that backup/recovery items in the readiness checklist refer to. |
| `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md` | Defines per-operator Beta posture | Beta operators must follow this baseline at the level appropriate to Beta, so that real recovery evidence accumulates before MainNet-readiness review. |

In short:
- **This baseline** says what "recoverable" must mean.
- **Incident response** says what to do when recovery is needed.
- **Monitoring** says how recovery posture and recovery events become visible and recordable.
- **Cutover** depends on this posture being real.
- **Readiness** later depends on this posture being documented, tested, and evidenced.

---

## 3. Backup and Recovery Principles

The following principles are non-negotiable for any QBIND environment that produces evidence intended to support Beta credibility or MainNet-readiness review.

1. **Back up only what is needed — but do not omit what is launch-critical.** Volume is not virtue, and absence is not minimalism if a launch-critical reference is missing.
2. **Recovery posture matters more than backup volume.** A small set of verified, restorable backups is worth more than a large set of unverified ones.
3. **Unverified backups do not count as backups.** If integrity has not been checked and a restore path has not been demonstrated, the artifact is an unproven file, not a backup.
4. **Destructive recovery without evidence is unacceptable.** Any recovery action that overwrites, deletes, or replaces operational state must be recorded, attributable, and reviewable.
5. **Environment separation must be preserved.** DevNet, Alpha, Beta, and MainNet-readiness data, secrets, and snapshots must not cross boundaries via backup or restore paths.
6. **Sensitive material requires stricter handling than chain data.** Signing keys, private credentials, and sensitive incident evidence are not handled like generic node files.
7. **Restore must be testable, not assumed.** "It should restore" is not a recovery posture.
8. **Recovery drills are evidence, not optional exercises.** Drills produce the records that make readiness defensible later.
9. **Conservative defaults.** When in doubt, prefer the path that preserves auditability, environment separation, and the ability to reconstruct what happened.

---

## 4. Backup Scope Taxonomy

The following taxonomy defines the major classes of QBIND data and assets relevant to backup and recovery. It is the reference used by Sections 5, 6, 10, and 11.

| # | Class | What it is | Why it matters | Backup posture |
|---|---|---|---|---|
| C1 | **Chain / state data** | Node databases, chain state, height/epoch-anchored snapshots, indexed state where applicable | Recovery of a node, catch-up time, postmortem reconstruction, audit of what the network actually saw | **Required** where the recovery model depends on it; must be tied to identifiable chain context |
| C2 | **Node configuration** | Runtime configs, network identity / chain-id references, peer/seed config, per-environment parameters | Restored nodes must come back as the right node, in the right environment, on the right network | **Required**; configuration drift is a recovery hazard |
| C3 | **Release / genesis / artifact references** | Authorized release versions, genesis references, artifact hashes, build provenance pointers | Recovery and cutover both depend on knowing exactly which authorized artifacts a node should be running | **Required**; references must match authorized versions |
| C4 | **Validator / operator metadata** | Validator roster references, operator coordination records, per-operator role assignments where relevant | Coordinated recovery, operator handoff, continuity of operational identity | **Required where operationally necessary**; sensitive subsets follow C6 rules |
| C5 | **Logs / metrics / evidence tied to incidents and readiness** | Incident records, postmortems, monitoring evidence, drill records, cutover evidence | Postmortem review, readiness review, audit, MainNet-readiness defense | **Required**; retention must support readiness review and post-cutover review |
| C6 | **Signer / key-related material** | Signing keys, key metadata, sensitive credentials, secret material | Compromise or loss has direct security and continuity consequences | **Prohibited from being backed up insecurely**; stronger controls only — see Section 6 |
| C7 | **Coordination records / runbooks / authorization or cutover artifacts** | Runbooks in use, authorization memos, cutover records, decision artifacts | Reviewability of how operations were actually conducted; cutover and readiness defense | **Required**; treated as canonical operational evidence |

A given artifact may be in scope under multiple classes; in that case the **strictest applicable** posture wins.

---

## 5. What Must Be Backed Up

At baseline, QBIND environments that are intended to produce credible evidence for Beta or MainNet-readiness must be able to preserve and recover the following categories. This section defines minimums; it does not prescribe storage mechanisms.

| Item | Class | Minimum expectation |
|---|---|---|
| Canonical genesis and release-artifact references | C3 | Identifiable, version-pinned, and tied to authorized release entries |
| Approved configuration / chain-id / network identity references | C2 | Recoverable per environment, with no cross-environment ambiguity |
| Operational records needed for incident review and readiness | C5, C7 | Preserved for the retention period implied by readiness/post-cutover review |
| Cutover records and authorization artifacts | C7 | Preserved as canonical operational evidence; not editable post-fact |
| Logs and metrics needed for postmortems and the evidence packet | C5 | Sufficient breadth and time window to reconstruct an incident or drill |
| State snapshots / database backups, where the recovery model depends on them | C1 | Tied to identifiable chain context (e.g., height/epoch/time as relevant) and verifiable for completeness |
| Validator roster / operator coordination records, where operationally necessary | C4 | Preserved at the level needed for coordinated recovery and operator handoff |
| Backup/restore and recovery-drill records themselves | C5 | Preserved as evidence that this baseline is being followed |

This list is the **floor**, not the ceiling. Specific environments may require more (see Section 10). No environment that intends to claim Beta credibility may require less.

---

## 6. What Must Not Be Backed Up Insecurely

This section is **non-negotiable**.

The following classes must **never** be backed up using the same mechanisms, retention, or access posture as generic node data:
- Signing keys (C6)
- Private credentials (C6)
- Secret material of any kind (C6)
- Sensitive incident evidence whose disclosure would itself create risk (subset of C5)

**Baseline expectations for these classes:**
- **Stronger controls.** Handling, storage, and any preservation must use stricter controls than those used for chain data, configs, or logs.
- **Access restrictions.** Access must be limited to roles that genuinely need it, and access events must be attributable.
- **Environment separation must be preserved.** Test secrets must not be commingled with MainNet-readiness or production-equivalent secrets, ever — not in storage, not in transit, not in restore targets.
- **No copy-sprawl.** Existence of additional copies must be deliberate, recorded, and minimal. "We made a backup just in case" is not acceptable for sensitive material.
- **No mixing of environments.** A backup or restore action must never cause secrets from one environment to land in another.
- **Backup existence must not become a secret-exposure risk.** If preserving sensitive material would create more risk than not preserving it, the baseline default is **do not preserve it via the generic backup path** — escalate to the controls appropriate to that class.
- **Loss vs. exposure tradeoff is explicit.** For C6, the cost of inappropriate exposure is treated as higher than the cost of having to regenerate or rotate. Recovery posture for C6 is "rotate / re-issue under controlled procedure," not "restore from generic backup."

This baseline does **not** invent specific cryptosystem or key-management tooling requirements. Where canonical documents already define such requirements, those win.

---

## 7. Backup Integrity and Verification Baseline

"We think we have backups" is not a recovery posture. The following are minimum integrity and verification expectations.

- **Identifiability.** Each backup or preserved artifact must be identifiable: what it is, what environment it belongs to, when it was produced, and what it is a backup *of*.
- **Integrity check.** Integrity must be checkable (e.g., the artifact has a verifiable representation — hash, manifest, or equivalent — that allows tampering or corruption to be detected).
- **Completeness.** Snapshot and backup completeness must be **knowable**, not assumed. A truncated snapshot must be detectable as truncated.
- **Freshness.** Stale backups are a risk. The age of a backup relative to current operational state must be knowable, and stale-but-assumed-valid backups are an explicit failure mode (Section 12).
- **Artifact reference alignment.** Any backup that references release/genesis/config artifacts must reference **authorized** versions. A backup that points at unauthorized or unrecognized artifacts is itself an issue.
- **Chain-context anchoring.** Any chain/state backup (C1) must be tied to identifiable chain context — for example, a height, epoch, or time reference appropriate to the data — so that what was captured is unambiguous.
- **Recorded verification results.** Verification outcomes (pass/fail, who, when) must be recorded. Verification that no one can later point at is not verification.

A backup that fails any of these is treated as **not a trusted backup** until remediated.

---

## 8. Restore and Recovery Validation Baseline

A backup that has never been restored is, at best, a hypothesis. This section defines what counts as meaningful restore and recovery validation.

A restore is only considered **validated** when all of the following hold:

1. **Restored data is readable and usable** — not merely "the files came back." The restored artifact functions in the form the operating role requires.
2. **Restored node behavior is correct.** A node restored from a snapshot must be able to reach the expected state, catch up appropriately, and verify chain identity for its environment.
3. **Restored configuration matches the intended environment.** A Beta restore must come up as Beta. A DevNet restore must not silently come up as anything else.
4. **Restored observability works.** Monitoring, alerting, and log emission resume in a form consistent with the monitoring baseline. A "restored" node that is invisible to monitoring is not restored.
5. **No silent environment crossing.** Restore paths must not cause data, secrets, or identity from one environment to land in another. Cross-environment restore is treated as an incident.
6. **Restore success or failure is recorded.** Each restore attempt (drill or real) produces a record: what was restored, from where, into what, by whom, with what outcome.
7. **Repeated failed restores are a serious finding.** A pattern of failed restores is not just an operational annoyance — it is a readiness-blocking signal that must be escalated under the incident response procedure.

If a restore cannot satisfy points 1–5, the underlying backup is **not yet a trusted recovery path** for the purposes of Beta evidence or MainNet-readiness defense.

---

## 9. Recovery Drill and Rehearsal Baseline

Recovery drills are how this baseline becomes real. They are also how readiness review later has anything credible to read.

**Drill classes that must be exercisable:**

| Drill | Purpose | Minimum outcome |
|---|---|---|
| Backup restore drill | Prove that a representative backup can actually be restored end-to-end | Validated restore per Section 8, with a recorded result |
| Node-from-snapshot recovery drill | Prove a node can be reconstituted from preserved state and rejoin its environment | Node reaches expected state, monitoring confirms healthy posture |
| Configuration rebuild drill | Prove that node configuration / network identity / artifact references can be reconstructed from preserved sources | Reconstructed config matches intended environment without manual guesswork |
| Operator handoff / host-loss drill | Prove that the loss of a host, an operator, or a coordination record does not break recovery posture | Handoff completes with attribution, evidence preserved, no environment crossing |
| Evidence-preserving recovery practice | Prove that performing a recovery does not destroy the evidence needed to review the recovery itself | Evidence (timestamps, attribution, outcomes) survives the recovery action |

**Posture per release stage (high level — see Section 10 for environment-specific detail):**
- Drills are **not optional** for serious environments.
- **Beta** must exercise these drills enough to **produce evidence**, not merely to demonstrate intent.
- **MainNet-readiness** later depends on those drills **existing and being reviewable** as part of readiness assessment.

A drill that produces no record produced no evidence.

---

## 10. Environment-Specific Expectations (DevNet / Alpha / Beta / MainNet-Readiness)

Recovery posture scales with stage. The following are minimum baselines per environment. Higher stages **inherit** the expectations of lower stages.

| Aspect | DevNet | TestNet Alpha | TestNet Beta | MainNet-readiness / cutover preparation |
|---|---|---|---|---|
| Backup scope coverage | Lighter; focused on what is needed to iterate | Cover C1–C3, C5 at a basic level | Cover C1–C5 and C7 at credible operator level; C6 under stricter controls | All applicable classes covered to the level required by readiness review |
| Retention | Short / pragmatic | Sufficient to reproduce recent issues | Sufficient to support Beta evidence packet and post-incident review | Sufficient to support readiness review and post-cutover review |
| Verification (Section 7) | Spot-checked | Demonstrated for representative artifacts | Routine and recorded | Routine, recorded, and reviewable as part of readiness |
| Restore validation (Section 8) | Demonstrated at least once for the recovery model in use | Prove **basic recoverability** end-to-end | Produce **credible recovery evidence**, repeatedly | **Strongest recovery confidence**, with artifact discipline matching cutover requirements |
| Drills (Section 9) | Light, ad hoc acceptable | At least one of each applicable class | Multiple instances; outcomes recorded; failures triaged | Drills exist, are reviewable, and are part of readiness defense |
| Environment separation | Enforced | Enforced | Strictly enforced; cross-environment events are incidents | Strictly enforced; any cross-environment exposure blocks readiness |
| Secrets handling (Section 6) | Stricter than C1–C5 already | Stricter than C1–C5 already | Stricter, with no copy-sprawl, no mixing | Strongest; recovery posture is rotate/re-issue under controlled procedure, not generic restore |
| Evidence retention (Section 11) | Light | Sufficient for issue review | Sufficient for Beta evidence packet | Sufficient for readiness review and post-cutover review |

Vendor specifics, storage backends, and product choices are explicitly **out of scope** for this baseline.

---

## 11. Evidence Retention and Auditability for Recovery

Recovery posture only counts if it can be reviewed later. The following are minimum evidence expectations. They align with the incident response procedure and the monitoring and alerting baseline.

At minimum, the following must be preserved for the relevant retention window:

- **Backup and restore timestamps.** When a backup was produced; when a restore was attempted; when verification was performed.
- **Source artifact / version references.** What authorized release, genesis, config, or chain context the artifact corresponds to.
- **Restore success / failure records.** Outcome, attribution (who/what role), environment, and any relevant context. Failures are recorded with the same rigor as successes.
- **Recovery drill records.** Which drill, when, by whom, against what, with what outcome, and any follow-ups generated.
- **Linkages to incidents and postmortems.** Where a backup/restore/drill is tied to an incident or postmortem, the linkage must be explicit so reviewers can trace cause and effect.
- **Retention sufficient for readiness and post-cutover review.** The window must be long enough that MainNet-readiness assessors and post-cutover reviewers can actually read the evidence in context, not just see that something existed.

Evidence that cannot be retrieved on demand is, for the purposes of this baseline, evidence that does not exist.

---

## 12. Explicit Failure Modes This Baseline Is Meant to Catch

This baseline exists, in concrete terms, to prevent the following failure modes. They are listed here so they can be referenced directly in reviews, postmortems, and readiness assessments.

1. **Backups that exist but cannot restore.** Files are present; restoration produces something that does not function as required by Section 8.
2. **Wrong-environment restore.** Data, configuration, or secrets from one environment land in another via the backup/restore path.
3. **Stale-but-assumed-valid snapshots.** A backup is treated as current when it is not, leading to recovery to an outdated or inconsistent state.
4. **Missing evidence after recovery.** A recovery action took place, but no usable record of *what* was recovered, *from* where, *by* whom, with *what* outcome remains.
5. **Key or secret exposure via sloppy backup practice.** Sensitive material (C6) is treated like generic node data, copies sprawl, or test/production boundaries are blurred.
6. **Cutover relying on unrecoverable state assumptions.** Cutover proceeds on the assumption that a particular state, artifact, or configuration is recoverable, when in fact it has never been verified or drilled.
7. **Unverified backups treated as verified.** Integrity, completeness, or freshness was never actually checked, but is assumed in operational decisions.
8. **Drills with no record.** Drills happened — no one can prove what was tested, what passed, what failed, or what was changed in response.
9. **Recovery that destroys its own evidence.** The recovery action itself wipes out logs, timestamps, or attribution needed to review whether the recovery was correct.
10. **Repeated failed restores not escalated.** A pattern of restore failures is treated as routine noise rather than as a readiness-blocking signal.

If any of these are observed in a QBIND environment intended to produce Beta evidence or MainNet-readiness evidence, they are treated as findings under this baseline, escalated under the incident response procedure where appropriate, and remediated before the relevant evidence is claimed.

---

## 13. What This Baseline Does Not Decide

This baseline is deliberately bounded. It does **not**:

- **Choose vendors or tools.** No cloud provider, snapshot product, backup product, key-management product, or storage backend is mandated or implied.
- **Replace incident response.** `docs/ops/QBIND_INCIDENT_RESPONSE.md` remains the canonical document for handling incidents, including incidents that involve recovery.
- **Replace the monitoring and alerting baseline.** `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` remains the canonical document for what must be observable.
- **Replace the cutover runbook.** `docs/ops/QBIND_MAINNET_CUTOVER_RUNBOOK.md` remains the canonical document for executing cutover after authorization.
- **Authorize launch.** Nothing in this document constitutes MainNet authorization, presale authorization, public-sale authorization, or any external commitment.
- **Define public disaster-recovery messaging.** External communications, status pages, or DR marketing artifacts are out of scope.
- **Define exact RPO/RTO promises.** Beyond what canonical documents already require, this baseline does not invent numerical recovery-time or recovery-point promises.
- **Define cryptographic key-management implementation in full detail.** Where canonical documents define key-management requirements, those win; this baseline only states that C6 material must not be backed up insecurely.

Anything outside these boundaries is handled by the appropriate canonical document, not by this baseline.

---

## 14. Final Baseline Summary

QBIND backup and recovery posture, at baseline, must satisfy all of the following:

- **Defined scope.** The taxonomy in Section 4 is used; what is in scope and what is not is explicit per environment.
- **Required preservation.** The minimums in Section 5 are met for the environment in question.
- **Strict handling of sensitive material.** Section 6 is honored without exception. C6 material is never treated as generic node data.
- **Verifiable backups.** Section 7 is honored: identifiable, integrity-checkable, completeness-knowable, freshness-knowable, artifact-aligned, chain-context-anchored, and with recorded verification results.
- **Validated restores.** Section 8 is honored: restores are demonstrated, not assumed, and validation outcomes are recorded.
- **Real drills.** Section 9 is honored: drill classes are exercisable; Beta produces evidence; MainNet-readiness has reviewable drill history.
- **Stage-appropriate posture.** Section 10 expectations are met for the current environment, and higher stages inherit lower-stage expectations.
- **Reviewable evidence.** Section 11 retention and auditability is met, in alignment with incident response and monitoring.
- **Failure modes prevented.** The Section 12 list is treated as a concrete checklist of things this baseline exists to prevent.
- **Boundaries respected.** This baseline does not exceed Section 13. Where canonical documents apply, they win.

When all of the above are true for a QBIND environment, that environment can credibly say its backup and recovery posture is **defined, tested, evidenced, and reviewable** — which is the bar Beta operations must meet now and the bar MainNet-readiness assessment will require later.

Until all of the above are true, the environment's recovery posture is, by this baseline, **not yet sufficient** — regardless of how many backup files exist.