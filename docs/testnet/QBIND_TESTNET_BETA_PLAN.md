# QBIND TestNet Beta Plan

**Version**: 1.0
**Date**: 2026-05-01
**Status**: Canonical Internal Plan — TestNet Beta
**Audience**: Core team, validator-candidate operators, integrators, auditors, security researchers, internal Beta coordinators

---

## Document Purpose

This document is the **canonical internal plan for QBIND TestNet Beta**.

It defines:

- Beta scope, objectives, and intended participants
- Beta network posture and feature/policy expectations
- Validator participation model for Beta
- Operational, observability, incident, upgrade, and reset policy
- Security and audit expectations during Beta
- Economics dry-run posture during Beta
- Beta success criteria and Beta → MainNet readiness gates
- What Beta explicitly does **not** promise

This document does **NOT**:

- Finalize MainNet schedule, scope, or commitments
- Finalize tokenomics, issuance, fee policy, validator rewards, or distribution
- Authorize, schedule, price, or imply any presale, airdrop, or token sale
- Set public marketing timelines or launch announcements
- Imply economic value of Beta participation
- Override canonical protocol behavior or release sequencing

**Canonical protocol behavior remains defined by:**

- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**

- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Beta economics posture is governed by:**

- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`

If any guidance in this Beta plan appears to conflict with the whitepaper, protocol report, release-track spec, or Beta economics scope, **the canonical documents win**. This plan only operationalizes those documents for the Beta stage.

---

## 1. Purpose and Scope

### 1.1 Purpose

TestNet Beta is the **broader-public, economics dry-run stage** of QBIND. Its purpose is to:

- Validate broader-public participation under controlled but wider exposure than Alpha.
- Exercise draft economics mechanisms live as defined in `QBIND_BETA_ECONOMICS_SCOPE.md`, producing decision-grade evidence for MainNet economics finalization.
- Validate that QBIND can be operated under a **near-production posture** by validator candidates, integrators, and the core team.
- Build the operational, security, and economics evidence base required to begin MainNet readiness work.

Beta is **not** a launch stage, **not** a marketing milestone, and **not** an economics finalization stage. Beta is an **evidence stage** with stronger discipline and broader exposure than Alpha.

### 1.2 In Scope

- A broader-public, single canonical Beta network operated under disciplined coordination.
- Onboarding of validator-candidate operators preparing for MainNet.
- Onboarding of external developers, integrators, security researchers, and community testers.
- Live exercise of the draft economics mechanisms scoped by `QBIND_BETA_ECONOMICS_SCOPE.md`.
- Realistic operational rehearsal of MainNet-style operations: change management, upgrades, incident response, observability, communications.
- Completion or near-completion of independent security review activity.
- Generation of the evidence required to evaluate Beta → MainNet readiness gates.

### 1.3 Out of Scope

- MainNet timing commitments, scheduling, or public launch announcements.
- Final tokenomics, issuance schedule, fee policy, validator reward policy, or distribution.
- Presale, airdrop, allocation, redemption rights, or any token distribution mechanism.
- Real economic value, pricing, valuation, or marketing claims.
- Production-grade SLAs, permanence guarantees, or irrevocable state preservation.
- Automatic progression to MainNet on the basis of Beta operating successfully.

### 1.4 Relationship to Other Documents

This plan operationalizes, for Beta:

- The release sequencing in `docs/release/QBIND_RELEASE_TRACK_SPEC.md`.
- The Beta economics scope in `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`.
- The Alpha plan in `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md` (as the prior stage whose exit gates feed Beta entry).
- The DevNet posture in `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` (as the long-running internal posture preserved alongside Beta).

This plan does not substitute for the whitepaper, protocol report, M-series coverage, contradiction tracker, or economics design draft.

---

## 2. Relationship to the Release Track

Per `docs/release/QBIND_RELEASE_TRACK_SPEC.md`, the canonical sequence is:

> **DevNet → TestNet Alpha → TestNet Beta → MainNet**

Within that sequence:

- **DevNet** is internal and non-public; protocol bring-up, regression coverage, no economic intent.
- **TestNet Alpha** is the first controlled public-facing stage; bug-discovery and adversarial testing under controlled validator exposure; **no economics**.
- **TestNet Beta** is the **broader-public, economics dry-run stage**; more stable, more disciplined, and operationally closer to MainNet, while still explicitly **non-MainNet**.
- **MainNet** is the only stage with finalized economics, real economic value, and production commitments.

Beta is therefore positioned as:

- The **final evidence stage before MainNet finalization work** can be undertaken on the basis of real network behavior.
- More stable and more disciplined than Alpha — Beta is not a bug-discovery free-for-all, and resets are exceptional.
- The stage that produces the operational, security, and economics evidence required to consider MainNet readiness gates.
- Explicitly **not** automatic MainNet. A successful Beta is a **necessary but not sufficient** condition for MainNet.

MainNet still requires, after Beta:

- Independent finalization of economics, governed by a separate document (see Section 16).
- Independent confirmation of MainNet readiness against the readiness checklist (see Section 16).
- Explicit MainNet authorization that is **not** implied by Beta operating successfully.

Beta is a **release-stage observation window**, not a MainNet promise.

---

## 3. Beta Objectives

Beta exists to produce specific, observable evidence. Its objectives are:

1. **Validate broader public participation** — confirm that a wider, less-curated population of validators, integrators, and testers can operate against QBIND without producing systemic instability.
2. **Validate the economics dry-run** — exercise the draft monetary family, issuance posture, fee-policy family, validator reward flow, minimum stake posture, slashing behavior, and C3 posture defined in `QBIND_BETA_ECONOMICS_SCOPE.md`, and collect the evidence specified there.
3. **Validate near-production operator discipline** — confirm that validator candidates can sustain the uptime, key-hygiene, monitoring, and responsiveness expected of MainNet-class operators.
4. **Validate upgrade and governance procedures** — exercise the documented change-management and upgrade flow under Beta-level rigor, including coordinated upgrades and emergency procedures.
5. **Validate that MainNet readiness work can begin from real Beta evidence** — demonstrate that the artefacts produced during Beta (incident records, uptime data, economics observations, audit findings) are sufficient to ground a serious MainNet readiness assessment.
6. **Validate the security posture** — confirm that no critical or high security issues remain open, that audit and bug-bounty activity has been completed or substantially advanced, and that the contradiction tracker has been reviewed.
7. **Validate observability and incident discipline** — confirm that the network can be observed, diagnosed, and recovered with the rigor a MainNet-planning conversation requires.

Beta is not a launch party. None of these objectives imply, schedule, or authorize MainNet. They define what evidence Beta must produce so that MainNet planning can be grounded in fact rather than aspiration.

---

## 4. Intended Participants

Beta is **broader than Alpha but not identical to MainNet**. The release-track spec governs: broader public exposure is permitted at Beta, but MainNet remains the only production network.

Intended participant categories:

### 4.1 Core Team

- Owns coordination, change management, observability, incident response, communications, and the post-Beta evidence packet.

### 4.2 Validator Candidates

- Operators who intend to participate in MainNet validation.
- Onboarded under published Beta validator requirements (Section 7).
- Expected to operate with near-production discipline.

### 4.3 External Developers and Integrators

- Application developers, tooling developers, RPC consumers, indexer/explorer operators.
- Permitted to interact with Beta as a realistic integration target, with the explicit understanding that Beta state, parameters, and asset are **not** MainNet.

### 4.4 Auditors and Security Researchers

- Independent audit firms continuing or completing engagements begun during Alpha.
- Bug-bounty researchers operating under a published scope.
- Reviewers of the contradiction tracker and protocol report.

### 4.5 Community Testers

- Non-validator participants exercising end-user flows: clients, wallets, RPC, integration paths.
- Permitted under an open or near-open participation posture, subject to Beta terms (no economic value, no MainNet implication).

### 4.6 Posture

- **Open public participation, or near-open participation**, depending on coordination needs.
- Validator participation may be subject to published requirements without being closed.
- All participants must understand that Beta is non-MainNet and produces no economic value, allocation, redemption, or MainNet rights.

---

## 5. Beta Network Posture

Beta operates under a **stability-first, non-MainNet** posture.

### 5.1 Network Identity

- A single canonical Beta network, with a clearly distinct chain identifier from any prior DevNet, Alpha, or future MainNet network.
- Beta test asset is clearly labelled as a Beta test asset; it is not the MainNet asset and carries no MainNet branding, claim, or redemption right.

### 5.2 Stability Expectations

- **Much higher stability expectations than Alpha.** Beta is not a bug-discovery stage.
- Resets are **exceptional and reluctant**, not routine (see Section 10).
- Beta is operated as a sustained network, not a series of short-lived experiments.

### 5.3 Economic Value

- Beta has **no economic value**. Beta test asset is non-monetary, non-transferable to any production system, and carries no MainNet allocation or redemption right.
- All economics behaviour observed during Beta is **draft, evidence-only**, per `QBIND_BETA_ECONOMICS_SCOPE.md`.

### 5.4 Operational Discipline

- Stronger operational discipline than Alpha: monitoring, on-call, change management, and incident response are run as a near-production rehearsal.
- Communications about Beta are accurate, conservative, and explicitly non-MainNet.

### 5.5 Realism Without Overclaim

- Beta is a realistic rehearsal for MainNet operations.
- Beta is **not** MainNet, **does not** imply MainNet, and **does not** confer MainNet rights or obligations.
- All public-facing material about Beta must preserve this distinction.

---

## 6. Feature and Policy Expectations

This section translates the release-track spec and Beta economics scope into Beta-stage policy. Each item is a **release-stage policy choice for the Beta stage**, not a MainNet commitment.

### 6.1 Networking

- **Full P2P required.** No fall-back to single-node or simplified topologies.
- Realistic topology with multiple geographically distributed validators and full node connectivity expectations.

### 6.2 Storage

- **RocksDB required** as the canonical storage backend for Beta operators.
- Operators are expected to follow documented backup, snapshot, and recovery procedures.

### 6.3 Slashing

- **Slashing operates in EnforceAll posture** (the release-stage default), covering O1–O5 offences as defined in the protocol report and M-series coverage.
- Slashing parameters used during Beta are draft Beta policy and may differ from MainNet finalization.

### 6.4 Economics

- The economics dry-run is **enabled** according to `QBIND_BETA_ECONOMICS_SCOPE.md`.
- Issuance posture, fee policy family, validator reward flow, minimum stake posture, and C3 posture operate under draft Beta parameters.
- These are **release-stage policy choices for evidence collection only**, not MainNet commitments.

### 6.5 Key Handling

- Key-handling expectations are **stronger than Alpha**: documented operator key hygiene, separated signing keys, secure storage practices, and rotation procedures.
- Beta does not yet require the full set of MainNet key-handling controls (e.g. final HSM/KMS posture), but Beta operators should be on a realistic path to MainNet-grade practice.
- Beta avoids **overcommitting** key-handling guarantees beyond what canonical MainNet requirements will eventually specify.

### 6.6 Permanence

- **No production-grade permanence promises.** Beta state is not guaranteed to be preserved indefinitely or migrated to MainNet.
- Beta upgrades and operational changes may produce incompatibilities; participants must accept that the network is non-final.

### 6.7 Governance and Upgrades

- Documented governance and upgrade processes are exercised at Beta-level rigor (Section 8 and Section 10).
- Emergency upgrade paths exist but are explicitly distinguished from routine upgrades.

---

## 7. Validator Participation Model

Beta validator participation is **broader and more demanding** than Alpha.

### 7.1 Posture

- **Open or near-open participation**, subject to clear, published Beta validator requirements.
- MainNet-candidate validators are explicitly encouraged to participate under MainNet-rehearsal posture.

### 7.2 Requirements

Published requirements for Beta validators include:

- Acceptance of published Beta terms (non-MainNet, no economic value, no MainNet rights).
- Documented operator identity sufficient for coordination and incident response.
- Hardware/network baseline consistent with the protocol report.
- Adherence to published key hygiene and operational practices.
- Commitment to upgrade and incident-response responsiveness within published windows.

### 7.3 Stake Posture

- A **draft minimum stake** is applied per `QBIND_BETA_ECONOMICS_SCOPE.md`.
- Minimum stake is denominated in Beta test asset and carries no economic value.
- The minimum stake is a **draft Beta policy**; the MainNet minimum stake remains undecided and is not implied by the Beta value.

### 7.4 Operational Expectations

Beta validators are expected to demonstrate:

- High uptime (Beta target uptime is published; see Section 9 and Section 14).
- Disciplined key handling.
- Responsiveness to coordination and incident channels.
- Adherence to upgrade procedures and timelines.
- Honest, prompt incident reporting.

### 7.5 Evidence-Driven Observation

- Validator behaviour is observed as **evidence**, not graded for prizes.
- Observed behaviour feeds the Beta evidence packet (Section 14) and informs MainNet validator-policy finalization. It does **not** automatically translate into MainNet allocation, slot reservation, or preferential rights.

### 7.6 Demand on Operators

Beta is **substantially more demanding than Alpha**:

- Stability over experimentation.
- Discipline over speed.
- Coordination over independence.
- Honest reporting over silent failure.

Operators not prepared to meet this posture should not validate during Beta.

---

## 8. Operational Model

Beta is run closer to production than Alpha, while still acknowledging Beta is not MainNet.

### 8.1 Coordination Ownership

- The **core team owns Beta coordination**: scheduling, change management, incident command, communications, and the Beta evidence packet.
- A designated Beta coordinator and on-call rotation are maintained throughout Beta.

### 8.2 Operational Discipline

- Documented runbooks for routine operations, upgrades, and incident response.
- Documented on-call posture with defined response-time expectations.
- Documented communication channels for operators, integrators, auditors, and the public.

### 8.3 Change Management

- All non-emergency network-level changes follow a documented change-management process: proposal, review, scheduling, notice, execution, post-change review.
- Emergency changes are permitted but distinctly classified, justified, and recorded.

### 8.4 Maintenance Windows

- Routine maintenance is performed during published maintenance windows where feasible.
- Maintenance windows are announced with sufficient operator notice consistent with the change-management process.

### 8.5 Upgrade Handling

- Coordinated upgrades follow the documented upgrade process.
- Upgrade dry-runs may be performed prior to network-wide rollout where appropriate.
- Upgrade outcomes are recorded in the Beta evidence packet (Section 9 and Section 14).

### 8.6 Incident Triage

- Incidents are classified, triaged, and tracked from detection through resolution and post-incident review.
- Incident records are part of the Beta evidence packet and feed Beta → MainNet readiness assessment.
- The incident classification scheme distinguishes operator issues, software defects, protocol/safety concerns, infrastructure issues, and economics-policy issues (Section 10).

### 8.7 Communication Expectations

- Internal: operator and validator coordination channels, on-call channels, audit and security channels.
- External: status communications appropriate to a non-MainNet but broader-public network.
- All external communications preserve the Beta-is-not-MainNet distinction and avoid implying economic value, MainNet timing, or distribution rights.

### 8.8 Posture vs MainNet

- Beta operations are a **rehearsal** for MainNet operations. Gaps observed during Beta operations feed the MainNet readiness checklist and operational hardening work; they do not, in themselves, mean Beta has failed.

---

## 9. Observability, Metrics, and Reporting

Beta observability is **stronger than Alpha** and forms the substrate of the Beta evidence packet.

### 9.1 Required Visibility

At minimum, Beta must continuously surface:

- **Node health**: process state, version, resource usage, sync status.
- **Peer and connectivity health**: peer counts, peer churn, partition signals, latency distributions.
- **Commit and finality progress**: block production cadence, finality lag, missed slots, fork events.
- **Validator participation and churn**: active set, joins/exits, missed signing, rotation events.
- **Slashing and evidence events**: O1–O5 offence detection, slashing actions taken.
- **Economics metrics** (per `QBIND_BETA_ECONOMICS_SCOPE.md`): issuance behaviour, fee flow, validator reward flow, stake distribution, C3 posture observations.
- **Incident frequency and categorisation**: counts and durations by category (Section 10).
- **Upgrade outcomes**: planned vs actual, completion rate, rollback events.
- **Restart and recovery results**: recovery time, success rate, residual issues.

### 9.2 Reporting

- Periodic internal reports summarise the above for the Beta evidence packet.
- Auditor- and security-researcher-facing reporting is provided as required by their engagement scope.
- Public-facing status communications are appropriate to a broader-public non-MainNet network, with clear non-MainNet language.

### 9.3 Public-Facing Status

- A public-facing status surface is appropriate during Beta where it improves operator and integrator coordination.
- Public status surfaces must not imply MainNet, economic value, or distribution rights.

### 9.4 Evidence Discipline

- All metrics are recorded with timestamps, network version, and surrounding operational context.
- Observations from Beta are treated as **evidence**, not as MainNet parameter commitments.

---

## 10. Incident, Upgrade, and Reset Policy

This section is operationally serious.

### 10.1 Resets

- **Beta resets are exceptional, not routine.**
- Resets require **substantial advance notice** to operators, integrators, and the broader Beta participant base, except in emergencies where notice is impossible.
- Resets must be recorded with: cause, classification, decision rationale, communications timeline, and post-reset review.
- **Repeated resets are a direct MainNet-readiness warning.** Repeated or unexplained resets pause any MainNet-readiness conclusions.

### 10.2 Upgrades

- All upgrades follow the documented upgrade process.
- Routine upgrades are coordinated and rehearsed where appropriate.
- Emergency upgrades are explicitly classified and recorded as such.
- Upgrade outcomes (success, partial success, rollback) are part of the Beta evidence packet.

### 10.3 Incident Classification

Incidents are classified into at least the following categories:

1. **Operator issue** — caused by an individual operator's configuration, environment, or process.
2. **Software defect** — caused by a defect in the QBIND implementation.
3. **Protocol or safety concern** — touches consensus, slashing, finality, or security invariants defined in the protocol report and contradiction tracker.
4. **Infrastructure issue** — caused by underlying networking, hosting, or storage infrastructure rather than QBIND itself.
5. **Economics-policy issue** — caused by, or surfacing concerns in, the draft Beta economics policy (issuance, fees, rewards, slashing-economics, minimum stake, C3 posture). Economics-policy issues feed `QBIND_BETA_ECONOMICS_SCOPE.md` evidence and the eventual MainNet economics finalization.

### 10.4 Severity and Response

- Each incident is assigned a severity level and routed to the appropriate response posture.
- Critical-severity incidents trigger incident-command procedures and immediate communications.
- Post-incident review is mandatory for moderate-or-higher incidents.

### 10.5 Effect on MainNet Readiness

- **Serious incidents pause MainNet-readiness conclusions** until they are understood, resolved, and reviewed.
- Unresolved critical or high incidents, repeated resets, or unresolved protocol/safety concerns are direct blockers to Beta → MainNet readiness gates (Section 14).
- Incident records are part of the Beta evidence packet and are visible to the MainNet readiness assessment.

### 10.6 Honest Reporting

- Honest, prompt incident reporting is required. Silent failures, undisclosed issues, or post-hoc rationalisation are considered Beta-discipline failures and are themselves a MainNet-readiness signal.

---

## 11. Security and Audit Expectations During Beta

Beta is the stage at which security review is **completed or substantially advanced**, and through which security evidence is gathered for MainNet.

### 11.1 Independent Security Audit

- Independent security audit activity continues from Alpha or is initiated and completed during Beta.
- Audit findings are tracked openly; **no silent waiving of critical or high findings is permitted**.
- Critical or high findings must be resolved (or formally accepted with a documented, reviewable rationale that is not equivalent to silent waiver) before MainNet readiness can be considered satisfied (Section 14).

### 11.2 Bug Bounty

- Bug-bounty activity operates against Beta under a published scope.
- Bounty findings are triaged and resolved through the same incident and audit pipelines.

### 11.3 Contradiction Tracker

- The contradiction tracker (`docs/whitepaper/contradiction.md`) is reviewed during Beta.
- Any new contradictions surfaced by Beta evidence are recorded and addressed before MainNet readiness can be considered.

### 11.4 Governance and Upgrade Process Testing

- Governance and upgrade processes are exercised under Beta conditions, including coordinated upgrades and at least one rehearsed emergency-class procedure.
- Process gaps are recorded as Beta evidence and addressed prior to MainNet readiness conclusion.

### 11.5 MainNet-Readiness Evidence Gathering

- Security evidence collected during Beta is structured for use in the Beta → MainNet readiness assessment (Section 14).
- Security review explicitly connects to readiness: an audit incomplete at the end of Beta, or with unresolved critical/high findings, blocks readiness conclusion regardless of operational performance.

---

## 12. Economics Dry-Run Posture

This section aligns directly with `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`. Where this section and that document differ, the Beta economics scope governs.

### 12.1 Beta as the Economics Dry-Run Stage

- Beta is the **economics dry-run** stage of QBIND.
- Beta is the first stage in which economic mechanisms are exercised live in a way capable of producing decision-grade evidence.

### 12.2 Draft, Non-Final Economics

- All economics parameters used during Beta are **draft**.
- Beta-observed parameters are **not** MainNet commitments and **do not** imply that the same values will appear at MainNet.
- Beta does not finalize tokenomics, issuance numbers, fee ratios, validator reward ratios, genesis supply, allocation, or distribution.

### 12.3 What Beta Must Simulate

Per `QBIND_BETA_ECONOMICS_SCOPE.md`, Beta must exercise the chosen:

- **Monetary family** (issuance/supply behaviour family).
- **Issuance posture** (how new units enter circulation, if any).
- **Fee-policy family** (transaction-fee model under a draft policy).
- **Validator reward flow** (how rewards are computed, distributed, and constrained).
- **Minimum stake posture** (draft minimum stake for Beta validator participation).
- **Slashing behaviour** (economic effect of slashing under EnforceAll).
- **C3 posture** (per `QBIND_BETA_ECONOMICS_SCOPE.md`).

### 12.4 Evidence, Not Commitments

- Observations from Beta are **evidence**, not commitments.
- Evidence is structured for use in the future MainNet economics finalization document (see Section 16).
- "It worked in Beta" is **not** the same as "it is the MainNet parameter".

### 12.5 Test Asset Discipline

- Beta test asset is **clearly labelled as Beta test asset**.
- Beta test asset must remain visibly separate from any MainNet asset branding, identifier, or claim.
- Beta test asset confers **no** MainNet allocation, redemption right, presale eligibility, or economic value.
- Communications about Beta must not blur the line between Beta test asset and any future MainNet asset.

### 12.6 Discipline Boundary

- Beta does **not** authorize, schedule, or imply any presale, airdrop, public sale, valuation, or pricing.
- Beta does **not** create distribution rights of any kind.
- Beta participation does **not** constitute investment, and no part of this plan should be read as investment material.

---

## 13. Beta Success Criteria

Beta success is measured **before** MainNet readiness is even discussed. "Beta ran" is not the same as "Beta succeeded".

A Beta is considered successful when, at minimum:

1. **Stable broader-public operation** — the Beta network sustained broader-public participation without systemic instability for the planned Beta stability window.
2. **Economics dry-run produced interpretable evidence** — `QBIND_BETA_ECONOMICS_SCOPE.md` evidence requirements were met, with interpretable, decision-grade observations.
3. **Upgrade process worked** — at least the planned coordinated upgrade(s) and rehearsed emergency-class procedure(s) completed with documented outcomes.
4. **No critical/high unresolved issues remain** — security audit, bug-bounty, and contradiction tracker activity left no critical or high issue silently open.
5. **Operators sustained MainNet-like posture** — validator candidates demonstrated near-production discipline in uptime, key handling, and responsiveness for the relevant window.
6. **Observability sufficient for MainNet readiness assessment** — the observability and evidence packet are strong enough that a serious MainNet readiness assessment is grounded in fact.
7. **Operational discipline sustained** — change management, incident response, and communications operated as documented throughout the Beta stability window.

Falling short of any of these does not in itself mean Beta has "failed"; it means Beta has **not yet** reached the posture from which MainNet readiness can be evaluated. Beta is extended, not skipped.

---

## 14. Beta → MainNet Readiness Gates

These gates align tightly with `docs/release/QBIND_RELEASE_TRACK_SPEC.md` and `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`. They are operationalized here for the Beta stage.

A Beta → MainNet readiness conclusion requires **all** of the following:

- [ ] **Security audit complete** with no critical or high findings open. Any formally accepted lower-severity findings carry a documented, reviewable rationale (no silent waiver).
- [ ] **Sustained stable operation** under realistic Beta load over the planned Beta stability window, demonstrated by the evidence packet.
- [ ] **Uptime target achieved** — 95% or better uptime sustained over the relevant Beta stability period (final stretch), as defined by Beta observability records.
- [ ] **No resets during the relevant final stretch** of Beta. Repeated or final-stretch resets restart the readiness clock.
- [ ] **Economics dry-run completed** per `QBIND_BETA_ECONOMICS_SCOPE.md`, with required evidence collected, recorded, and interpretable.
- [ ] **Governance and upgrade process tested** — at least one coordinated upgrade and one rehearsed emergency-class procedure completed with documented outcomes and post-event reviews.
- [ ] **Incident response and monitoring production-capable** — incident classification, response, post-incident review, and observability are at a level sufficient to plan MainNet operations against.
- [ ] **No unresolved protocol/safety concerns** — the contradiction tracker is reviewed; no protocol or safety concerns remain open.
- [ ] **MainNet economics finalization can proceed from Beta evidence** — the evidence base is sufficient for the MainNet economics finalization document (Section 16) to be authored on real data, not aspiration.
- [ ] **Beta evidence packet assembled** — operational, security, and economics evidence is collected into a coherent, reviewable evidence packet supporting the readiness conclusion.

These gates are **necessary but not sufficient** for MainNet authorization. MainNet still requires:

- Independent MainNet readiness confirmation per the release-track spec.
- Independent finalization of MainNet economics.
- Explicit MainNet authorization, which is **not** implied by satisfying Beta gates.

---

## 15. What Beta Explicitly Does Not Promise

Beta operating, even operating successfully, does **NOT** promise:

- **A MainNet date.** No MainNet timing is implied, scheduled, or committed by Beta.
- **Final tokenomics.** No issuance, fee, reward, allocation, or distribution numbers observed during Beta are MainNet commitments.
- **Presale timing or eligibility.** No presale is authorized, scheduled, or implied. Beta participation does not create presale rights.
- **MainNet allocation or redemption rights.** Beta test asset, Beta participation, and Beta validator behaviour do **not** confer MainNet allocation, slot reservation, redemption, or preferential rights.
- **Production-grade permanence.** Beta state is not guaranteed to persist indefinitely or migrate to MainNet.
- **Automatic progression to MainNet.** Beta success is necessary but not sufficient for MainNet. MainNet requires separate readiness confirmation, separate economics finalization, and explicit MainNet authorization.
- **Investment, valuation, or pricing.** Nothing in Beta constitutes investment material or any pricing or valuation claim.

This list is strict on purpose. Confusion at the Beta → MainNet boundary is a known failure mode for projects of this kind, and QBIND will not produce that confusion.

---

## 16. Immediate Follow-Up Documents

Beta planning implies, but does not author, the following follow-up canonical documents. They are listed here so that Beta planners and reviewers know what is expected next; they are **not created by this plan**:

- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` — operationalization of Beta → MainNet readiness gates as a reviewable checklist for the MainNet authorization decision.
- `docs/economics/QBIND_MAINNET_ECONOMICS_FINALIZATION.md` — the document in which MainNet economics is finalized on the basis of Beta evidence and the tokenomics decision framework.
- `docs/testnet/QBIND_TESTNET_BETA_OPERATOR_CHECKLIST.md` — the operator-facing checklist that turns this plan's expectations into concrete validator-candidate operational steps.
- `docs/ops/QBIND_INCIDENT_RESPONSE.md` — the canonical incident-response procedure document referenced by Beta operations and required for MainNet operational readiness.

These documents are out of scope for this plan and will be authored separately.

---

## 17. Final Plan Summary

- TestNet Beta is the **broader-public, economics dry-run stage** in the canonical sequence DevNet → TestNet Alpha → TestNet Beta → MainNet.
- Beta is **more stable, more disciplined, and operationally closer to MainNet than Alpha**, while remaining explicitly non-MainNet.
- Beta exercises the **draft economics scope** defined in `QBIND_BETA_ECONOMICS_SCOPE.md` strictly as evidence; Beta does **not** finalize tokenomics, presale, pricing, allocation, or distribution.
- Beta requires near-production operator discipline, strong observability, conservative reset and upgrade policy, and honest incident reporting.
- Beta produces an **evidence packet** — operational, security, and economics — that is the substrate for MainNet readiness assessment and MainNet economics finalization.
- Beta success is **necessary but not sufficient** for MainNet. MainNet requires separate readiness confirmation, separate economics finalization, and explicit authorization.
- Beta does **not** promise a MainNet date, final tokenomics, presale, allocation, redemption rights, production-grade permanence, or automatic progression.
- Canonical protocol behaviour remains defined by the whitepaper, protocol report, M-series coverage, and contradiction tracker. Release sequencing remains governed by the release-track spec. Beta economics posture remains governed by the Beta economics scope. This plan only operationalizes those documents for the Beta stage.