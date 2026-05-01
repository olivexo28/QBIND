# QBIND TestNet Alpha Plan

**Version**: 1.0
**Date**: 2026-05-01
**Status**: Canonical Internal Plan — TestNet Alpha
**Audience**: Core team, invited validators, auditors, technical collaborators

---

## Document Purpose

This document is the **canonical internal plan for QBIND TestNet Alpha**.

It defines:

- Alpha scope and objectives
- Intended participants
- Operational posture and feature/policy expectations
- Validator onboarding model
- Observability, incident, and reset policy
- Security review expectations during Alpha
- Economics posture during Alpha
- Alpha success criteria and Alpha → Beta exit gates

This document does **NOT**:

- Finalize MainNet commitments, schedule, or readiness
- Finalize tokenomics, inflation, fee model, or distribution
- Authorize or define presale mechanics
- Set public marketing timelines or launch announcements
- Override canonical protocol behavior or release sequencing

**Canonical protocol behavior remains defined by:**

- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**

- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

If any guidance in this Alpha plan appears to conflict with the whitepaper, protocol report, or release-track spec, **the canonical documents win**. This plan only operationalizes those documents for the Alpha stage.

---

## 1. Purpose and Scope

### 1.1 Purpose

TestNet Alpha is the **first real-world public-facing QBIND network**. Its purpose is to expose the implementation, operator workflows, and validator onboarding model to controlled external participation, in order to:

- Surface real-world failure modes that DevNet cannot reproduce
- Validate that external validators can independently bring up and operate nodes
- Exercise consensus, slashing, and recovery behavior under adversarial conditions
- Build the operational evidence required to consider Beta planning grounded

Alpha is a **bug-discovery and adversarial-testing stage**. It is explicitly not a stability showcase, not a production environment, and not an economics validation stage.

### 1.2 In Scope

- Bring-up of a public-reachable Alpha network operated by the core team
- Onboarding of a controlled set of external validators
- Adversarial testing of consensus, slashing (O1–O5), and recovery
- External security review activity (audit initiation, researcher engagement)
- Operational rigor sufficient to expose, document, and triage incidents
- Refinement of operator and onboarding documentation

### 1.3 Out of Scope

- Permissionless public participation
- Final tokenomics, fee, or inflation parameter decisions
- Real economic value, presale, or any token distribution
- MainNet timing commitments or public launch announcements
- Production-grade SLAs or uptime guarantees
- Long-term state preservation across the entire Alpha period

### 1.4 Relationship to Other Documents

| Document | Role for Alpha |
|----------|----------------|
| `QBIND_WHITEPAPER.md` | Canonical protocol behavior |
| `QBIND_PROTOCOL_REPORT.md` | Implementation/spec gap status |
| `QBIND_M_SERIES_COVERAGE.md` | Mitigation index referenced for Alpha readiness |
| `QBIND_RELEASE_TRACK_SPEC.md` | Authoritative on stage scope and exit criteria |
| `QBIND_DEVNET_OPERATIONAL_GUIDE.md` | Source of operational practices to extend into Alpha |
| `QBIND_ECONOMICS_DESIGN_DRAFT.md` | Draft only — not committed during Alpha |
| `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md` | Framework only — no Alpha commitments |
| `contradiction.md` | Tracker reviewed throughout Alpha; no silent waivers |

---

## 2. Relationship to the Release Track

### 2.1 Position in the Release Sequence

Per the canonical release-track specification:

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

Alpha sits between DevNet (internal) and Beta (broader public, economics dry-run, mainnet rehearsal). Alpha **cannot be skipped** to reach Beta faster.

### 2.2 What Alpha Is in Release Terms

- The **first public-facing network**
- **Controlled public exposure**, not broad public openness
- A **bug-discovery and adversarial-testing stage**
- A network where operational discipline is real, but resets and breaking changes are still permitted with notice
- A **prerequisite** for any consideration of Beta

### 2.3 What Alpha Is Not in Release Terms

- Not Beta. Beta is the later **economics dry-run / mainnet-rehearsal stage**, with broader public participation and stricter reset policies.
- Not MainNet. MainNet is production with real economic value.
- Not an open permissionless launch.
- Not a marketing milestone.

### 2.4 Stage Comparison (operational lens)

| Attribute | DevNet | TestNet Alpha | TestNet Beta | MainNet v0 |
|-----------|--------|---------------|--------------|------------|
| Audience | Internal team | Invited externals + core | Open public | Permissionless |
| Reset policy | Routine, unannounced ok | With notice (typically 48h planned, 24h emergency) | Exceptional, ≥7-day notice | No resets |
| Stability bar | Best-effort | Higher than DevNet, lower than Beta | Mainnet rehearsal | Production |
| Economics | None | Test tokens only, exploratory | Test tokens, dry-run | Real value |
| Slashing default | RecordOnly / dev-set | `EnforceCritical` (policy choice) | `EnforceAll` (policy choice) | `EnforceAll` |
| Persistence | RocksDB available | RocksDB required | RocksDB required | RocksDB required |
| Networking | LocalMesh / limited P2P | Full P2P | Full P2P | Full P2P |

This table operationalizes the release-track spec; it does not replace it.

---

## 3. Alpha Objectives

Alpha pursues a deliberately narrow set of objectives. Anything not listed here is either out of scope or belongs to Beta.

### 3.1 Primary Objectives

1. **Validate external validator onboarding.** Demonstrate that a documented, repeatable onboarding flow allows non-core operators to bring up an Alpha validator using only released artifacts and operator documentation.
2. **Validate network operation with non-core participants.** Confirm the network remains live and recovers correctly when participants the core team does not directly control are part of the validator set.
3. **Surface operational failures before Beta.** Use real public exposure to elicit failure modes that DevNet cannot reproduce: peer churn, adversarial peers, real network conditions, mixed operator skill levels, unexpected configurations.
4. **Test slashing and consensus behavior under controlled adversarial conditions.** Drive O1–O5 evidence paths through scripted and unscripted adversarial scenarios within a controlled cohort, and confirm that the configured Alpha enforcement mode behaves as specified.
5. **Gather stability and observability evidence.** Produce baseline measurements of commit progress, peer health, restart/recovery behavior, and incident frequency that can ground Beta planning.
6. **Refine operator procedures and documentation.** Use feedback from external onboarding to harden runbooks, onboarding checklists, and incident playbooks.

### 3.2 Explicitly Not Alpha Objectives

The following objectives belong to Beta or later and are **not** Alpha success criteria:

- Final economics or tokenomics validation
- Hybrid burn/proposer-reward fee dry-run as an economics decision
- Permissionless validator set growth
- Production-grade uptime
- Full O1–O5 enforcement as a release-stage default (Beta concern)
- Cross-chain, bridging, or ecosystem application onboarding at scale
- Any presale-related signal or messaging

---

## 4. Intended Participants

Alpha is **controlled public participation**. Participation is by invitation, not by self-service signup.

### 4.1 Participant Categories

| Category | Role in Alpha |
|----------|---------------|
| Core team | Operate seed validators, coordinate the network, run incident response, maintain documentation |
| Invited external validators | Run independent validators using released artifacts; primary source of Alpha-specific evidence |
| Auditors / security reviewers | Conduct external security review and adversarial testing; coordinate disclosure with the core team |
| Selected technical collaborators | Targeted partners providing infrastructure or operational feedback (e.g., monitoring, key handling) |
| A small number of external developers | Optional. Invited for application-layer feedback on transaction submission, observability, and operator-side APIs |

### 4.2 Participation Constraints

- Participation is **invite-and-approval based**. There is no public open enrollment for Alpha.
- All participants must accept the Alpha posture explicitly: no economic value, possible resets, no production guarantees.
- Participant identity must be known to the core team to a degree sufficient for coordination, incident communication, and disclosure handling.
- Participation can be revoked if a participant materially destabilizes the network outside agreed adversarial scope.

### 4.3 What Alpha Is Not, in Participant Terms

- Not permissionless.
- Not first-come, first-served.
- Not marketed as a public registration event.
- Not a community testnet in the Beta sense.

---

## 5. Alpha Network Posture

This section defines Alpha's operational character.

### 5.1 Public-Facing but Controlled

- Alpha endpoints (validator peers, RPC endpoints if exposed, telemetry sinks) are **reachable from the public internet** so that real-world conditions are exercised.
- However, the **validator set is closed**. Genesis is published, but only invited validators are configured into the active set.
- RPC and observability endpoints, if publicly exposed, are clearly labeled as Alpha and may be rate-limited, restarted, or rotated without notice.

### 5.2 Resets and State Persistence

- Alpha **may reset**. Resets are not routine like in DevNet, but they are explicitly permitted.
- Planned resets require **advance notice** to participants in line with the release-track spec (typically 48 hours for planned resets, with shorter timelines acceptable for emergencies).
- State permanence across Alpha is **not promised**. Operators must not depend on any Alpha state surviving beyond a given Alpha generation.

### 5.3 No Economic Value

- Alpha tokens have **no economic value** of any kind.
- Alpha participation does not entitle anyone to any future MainNet allocation, presale slot, or token claim.
- No token sale, allocation, or distribution mechanism is run on Alpha.

### 5.4 Stability Posture

- Stability expectations are **higher than DevNet**: networks should generally stay live across days, not just hours; restarts should be coordinated; incidents should be tracked.
- Stability expectations are **lower than Beta**: extended stalls, breaking changes with notice, and reset cycles remain acceptable.
- The network exists to **expose real-world failures**. A long, smooth Alpha with no incidents is not the goal; a long Alpha with incidents that are visible, triaged, and resolved is.

### 5.5 Not Production

Alpha is explicitly **not production**. There is no production SLA, no uptime guarantee, no commitment to backwards compatibility of state, and no finality of any value attached to Alpha state.

---

## 6. Feature and Policy Expectations

This section converts the release-track spec into Alpha-specific operational policy. It does not redefine protocol behavior.

### 6.1 Networking and Persistence

- **Full P2P networking is required.** LocalMesh is not used in Alpha.
- **RocksDB persistence is required.** Ephemeral or in-memory persistence is not used.
- Bootstrap peers are published and maintained by the core team.

### 6.2 Gas and Fees

- Gas accounting **may be enabled** for mechanism testing of execution and metering.
- Fee/burn/reward routing **may be enabled** for functional correctness, but **economics remain non-final and exploratory**. No conclusion about MainNet economics is drawn from Alpha behavior.
- All tokens used in fee mechanisms are test tokens with no value.

### 6.3 Slashing

- Slashing is a **release-stage policy choice**, not an implementation limitation. The protocol implementation supports the full O1–O5 slashing surface.
- Alpha's likely default is **`EnforceCritical`**: critical safety offenses (consistent with O1/O2 in the M-series coverage) are enforced; lower-severity offenses may be **recorded only**, with enforcement deferred as a release-policy decision.
- `EnforceCritical` is chosen for Alpha because:
  - It exercises evidence pipelines and slashing logic end-to-end.
  - It avoids penalizing external validators for non-safety-critical issues that may stem from operational immaturity rather than malicious behavior.
  - It is conservative relative to Beta, where `EnforceAll` is expected.
- Specific parameter values (penalty amounts, evidence windows) are not committed in this plan; they follow canonical protocol documentation and Alpha release notes.

### 6.4 Key Handling

- Key handling for Alpha is **stronger than DevNet**:
  - Validator signing keys must be protected by at least an encrypted on-disk store and access-controlled host.
  - Operators are expected to follow basic operational hygiene (no shared keys across operators, no committing keys to source control, no copying validator keys between hosts without rotation).
- Key handling for Alpha is **not yet MainNet-grade**:
  - HSM use is **encouraged but not mandated** in Alpha.
  - Threshold or multi-sig validator signing is not assumed.
- Operators should treat Alpha keys as throwaway: they must not be reused for any other QBIND network or for any non-QBIND system.

### 6.5 Permanence Assumptions

- No operator, participant, or external party should assume MainNet-grade permanence of any Alpha-era state, configuration, or address.
- Genesis may change between Alpha generations.
- Chain ID, network ID, and other identifiers used in Alpha must be distinct from any MainNet identifiers.

### 6.6 No Inferred Values

This plan does not invent specific numeric parameter values (block times, fee constants, slashing magnitudes, stake floors). Where canonical documents provide values, those apply. Where they do not, values are set by Alpha release notes at bring-up time and are not promoted by this plan to canonical status.

---

## 7. Validator Onboarding Model

Alpha onboarding is **controlled, structured, and documented**. It is not permissionless self-service.

### 7.1 Invitation and Approval

- Candidate validators are identified by the core team based on technical capability, alignment with Alpha objectives, and the desired diversity of the validator set.
- Each candidate is formally invited and must explicitly accept the Alpha terms (no economic value, reset risk, no production guarantees, communication expectations).
- The core team approves participation before any validator key is included in the configuration.

### 7.2 Identity and Communication

- Each validator must have at least one identified primary contact reachable through an agreed channel.
- Contacts must be reachable in incident-response time windows (defined in the operational model).
- Pseudonymous participation is acceptable when the pseudonym is durable, contactable, and consistent across communications and validator operations.

### 7.3 Configuration Distribution

- Genesis, chain ID, network parameters, bootstrap peer list, and required binaries/artifacts are distributed by the core team through documented channels.
- All distributed artifacts must be verifiable (checksums and signatures as canonicalized in operator documentation).
- Operators must not run modified protocol binaries on Alpha unless explicitly coordinated with the core team for testing purposes.

### 7.4 Key and Signer Expectations

- Each validator is responsible for generating and protecting its own validator key material.
- Validator keys must be unique to Alpha; reuse from DevNet or any other context is prohibited.
- Operators confirm key handling expectations (Section 6.4) before being marked onboarded.

### 7.5 Peer and Bootstrap Coordination

- Onboarded validators connect via the published bootstrap peers and announce their endpoint to the core team.
- Peer-list updates, address changes, and rotation are coordinated through the operational channels.
- Validators that cannot maintain reachable, well-behaved peering may be administratively removed from the active set.

### 7.6 Onboarding Completion Criteria

A validator is considered **successfully onboarded** when all of the following are demonstrated:

- Validator binary built or installed from approved artifacts and verified.
- Genesis, chain ID, and configuration match the published Alpha values.
- Validator key generated, protected per Alpha key handling expectations, and registered with the core team.
- Validator successfully connects to bootstrap peers and reaches a healthy peer count.
- Validator participates in consensus across at least one full epoch boundary without administrative intervention.
- Validator operator demonstrates ability to receive and act on operational notices within the agreed window.

Onboarding is not "the validator started a process"; it is "the validator is operating as an accountable participant."

---

## 8. Operational Model

Alpha must be operated with discipline that reflects its role as a public-facing, controlled network.

### 8.1 Coordination Ownership

- The core team **operates Alpha** end-to-end: bring-up, monitoring, incident response, communication, and shutdown/reset cycles.
- A named Alpha coordinator (rotating among core team members as needed) is responsible for the live network at any given time.
- External validators participate operationally but are not responsible for whole-network coordination.

### 8.2 Maintenance and Change Discipline

- Configuration changes, binary updates, and parameter changes are **planned, communicated, and recorded**.
- Unannounced production-style changes are not permitted on Alpha.
- Routine maintenance windows are communicated to participants in advance.
- Emergency changes (in response to live incidents) are permitted but must be documented after the fact, including rationale and impact.

### 8.3 Upgrade and Change Communication

- A single canonical communication channel (documented at bring-up time) is used for:
  - Planned upgrade announcements
  - Emergency notices
  - Reset notices
  - Incident updates
- Operators are expected to monitor this channel during Alpha.

### 8.4 Validator Issue Triage

- Operators report issues to the core team via the agreed channel with sufficient context (logs, configuration excerpts, observed behavior).
- The core team performs initial triage, classifies the issue (Section 10.5), and tracks it to resolution or known-issues status.
- Validators must not unilaterally apply unreviewed patches to protocol binaries on Alpha.

### 8.5 Operational Rigor Relative to DevNet

Compared to DevNet, Alpha requires:

- Tracked, not ad-hoc, incidents
- Communicated, not silent, restarts and resets
- Documented, not implicit, configuration changes
- Real-time, not best-effort, monitoring during active testing periods
- A real triage path for external participants

It does **not** yet require:

- Formal on-call rotations to MainNet standard
- Council-driven change control
- Multi-sig operational gating
- 24/7 production-grade staffing

---

## 9. Observability, Metrics, and Reporting

Alpha must be observable enough that failures can be **explained**, not just observed.

### 9.1 Observability Categories

The following categories must be visible during Alpha. Specific dashboards and tools are defined operationally and are not canonicalized here.

- **Node health**: process liveness, resource usage, version information, configuration fingerprint.
- **Peer and connectivity**: peer count, peer churn, handshake success rate, observed network partitions.
- **Commit progress**: block/round/view progression, finality latency, observed stalls.
- **Stalls, forks, and incidents**: detection of stalled consensus, view-change storms, divergent forks, and any safety-relevant anomalies.
- **Validator onboarding outcomes**: successful onboardings, failed onboardings, root cause categories.
- **Restart and recovery outcomes**: planned restarts, crash restarts, time-to-rejoin, state-sync outcomes.
- **Slashing and evidence events**: evidence detected, evidence processed, slashing actions taken under the configured Alpha enforcement mode.
- **Workload and throughput observations**: basic transaction throughput, mempool depth, gas usage patterns. These are observations, not benchmarks for Beta entry.

### 9.2 Reporting Cadence

- A periodic Alpha status summary (cadence defined operationally) is produced for participants, covering:
  - Network state and recent incidents
  - Notable observability findings
  - Upcoming planned changes or resets
  - Any participant actions required
- A running Alpha incident log is maintained.

### 9.3 What Alpha Observability Is Not

- Alpha observability is **not** a productized monitoring stack. It is the minimum required to explain network behavior.
- Public real-time dashboards may exist but are not promised.
- Metrics retention is not committed across resets.

---

## 10. Incident and Reset Policy

Alpha takes incidents seriously and resets carefully. This is one of the strongest distinctions between DevNet and Alpha.

### 10.1 Resets

- Alpha **may reset**, but resets are **not routine**.
- Planned resets require advance notice to participants per the release-track spec.
- Emergency resets (driven by safety, security, or unrecoverable state issues) are permitted with shorter notice but must be documented after the fact.
- Resets must include a written rationale and a post-reset summary.

### 10.2 Incident Documentation

- Every notable incident is documented with:
  - Detection time and source
  - Symptoms and observed scope
  - Initial classification (Section 10.5)
  - Mitigation taken
  - Root cause (when known)
  - Outcome and follow-up actions
- Incident records are retained across resets.

### 10.3 Pause and Progression Hold

- Critical issues found during Alpha can **pause Alpha-internal progression** (further onboardings, further adversarial campaigns) until they are understood.
- Critical issues from Alpha can **block Alpha → Beta progression** (Section 14).
- Repeated unresolved instability is itself a reason to **stay in Alpha** rather than push toward Beta.

### 10.4 Resets Are Not Routine

Unlike DevNet — where resets are an expected part of iteration — Alpha resets must be justified, communicated, and reflected upon. A high reset rate is a signal that Alpha is not yet ready to advance toward Beta.

### 10.5 Incident Classification

Each incident is classified into at least one of the following categories. A single incident may fall under more than one.

| Category | Description | Typical Response |
|----------|-------------|------------------|
| **Operator error** | Misconfiguration, mishandled keys, incorrect upgrade procedure, etc., on a participant's side | Document, improve onboarding/runbook, support operator recovery |
| **Software defect** | Bug in protocol implementation, node binary, tooling, or auxiliary services | File issue, triage severity, patch via coordinated upgrade |
| **Protocol or safety concern** | Behavior implicating consensus safety, slashing correctness, evidence handling, or other safety-critical surface | Highest priority; may pause progression; coordinate with security review |
| **Infrastructure issue** | Failures in hosting, network, observability, or other non-protocol infrastructure | Restore service, document, harden infrastructure as feasible |

Misclassification is itself a follow-up action: incidents may be reclassified as understanding improves.

---

## 11. Security Review Expectations During Alpha

Alpha is the stage at which **external security work begins in earnest**.

### 11.1 External Review and Audit Initiation

- External security review or audit activity is initiated at or before Alpha bring-up.
- Auditor scope, access, and reporting expectations are agreed in writing.
- Audit findings feed directly into Alpha → Beta exit gates (Section 14).

### 11.2 Adversarial Testing

- Alpha must include a deliberate adversarial testing period.
- Per the release-track spec (§6.2), the dedicated adversarial testing period is expected to span **≥2 weeks** before Alpha → Beta progression is considered.
- Adversarial testing exercises consensus, slashing (O1–O5 evidence paths), DoS resistance, evidence handling, and recovery.
- Adversarial testing is coordinated with the core team to avoid unbounded disruption while still exercising failure modes.

### 11.3 Contradiction Tracker Review

- The contradiction tracker (`docs/whitepaper/contradiction.md`) is reviewed during Alpha against observed behavior.
- New contradictions surfaced during Alpha must be added to the tracker, not silently waived.
- Existing intentionally-open items are revisited in light of Alpha evidence.

### 11.4 Issue Triage Discipline

- Security-relevant issues are tracked separately from general issues, with explicit severity classification.
- Critical and high-severity issues are not closed without an explicit, documented decision.
- No silent waiving of critical issues is permitted, regardless of release schedule pressure.

### 11.5 Alignment

This section is operationalization, not redefinition. Where it appears to conflict with the release-track spec or protocol report, those documents win.

---

## 12. Economics Posture During Alpha

This section is intentionally restrictive.

### 12.1 Alpha Is Not the Tokenomics Stage

- Alpha is **not** the stage at which final tokenomics are decided.
- Alpha **does not** validate inflation rates, reward curves, presale parameters, or distribution mechanisms.
- Beta is the **economics dry-run** stage, per the release-track spec.

### 12.2 Test Tokens Only

- All tokens visible on Alpha are **test tokens**.
- Test tokens have **no economic value**, no off-network exchange, and no claim on any future asset.
- Any communication that implies otherwise is out of scope and contrary to this plan.

### 12.3 Fee and Gas Behavior

- Fee and gas mechanisms **may be enabled** for functional correctness testing.
- Their behavior on Alpha is **not** a commitment to MainNet economics.
- Observed fee dynamics on Alpha are observations, not decisions.

### 12.4 Exploratory, Not Final

- Economics design remains exploratory throughout Alpha.
- Draft economics documents (e.g., `QBIND_ECONOMICS_DESIGN_DRAFT.md`, `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`) remain drafts during Alpha.
- A draft suitable for Beta dry-run is required as part of the Alpha → Beta exit gates (Section 14), but Alpha itself does not commit to it.

### 12.5 No Presale, No Value Messaging

- Alpha is **not** used for presale, allocation signaling, or any value-related messaging.
- Alpha participation is not compensated with any token, allocation, or claim.
- External communications about Alpha must avoid language that could imply economic value or imminent token availability.

This posture matters: Alpha's credibility depends on being clearly non-economic.

---

## 13. Alpha Success Criteria

This section defines what it means for **Alpha itself** to be considered successful, independent of the formal Alpha → Beta exit gates in Section 14. Alpha success is a precondition for taking exit gates seriously.

Alpha is internally considered successful when:

1. **External validators can onboard and stay online.** Multiple independent operators have completed the onboarding flow (Section 7.6) and have remained operational across upgrades and incidents.
2. **No unresolved critical consensus or security issues remain.** Any critical issues encountered have either been resolved or are explicitly accepted with documented rationale (and acceptance does not include silently waiving safety concerns).
3. **Restart and recovery behavior is understood.** Crash restart, planned restart, and resync paths have been exercised at least once for each significant scenario, and the outcomes are documented.
4. **Observability is good enough to explain failures.** When something goes wrong on Alpha, the core team and external operators can explain *why* using available metrics, logs, and incident records — not just observe that it happened.
5. **Operator documentation is usable.** External operators report that the documentation, runbooks, and onboarding instructions are sufficient for independent bring-up; corrections are folded back into the documents.
6. **Beta planning is grounded in observed behavior.** Decisions about Beta scope, posture, and economics dry-run scope are demonstrably informed by Alpha evidence — not by assumptions.

A "smooth" Alpha that did not exercise failure paths is not a successful Alpha.

---

## 14. Alpha → Beta Exit Gates

The authoritative Alpha → Beta exit criteria are defined in `QBIND_RELEASE_TRACK_SPEC.md` §6.2. This section restates them in checklist form for Alpha execution and **does not introduce new gates**.

### 14.1 Required Exit Criteria

- [ ] **External validators**: ≥3 external validators successfully onboarded (per Section 7.6) and operating
- [ ] **Adversarial testing period completed**: dedicated adversarial testing period executed and findings documented (release-track spec contemplates ≥2 weeks)
- [ ] **No unresolved critical security issues from Alpha**
- [ ] **Performance baseline documented**: TPS and finality latency observations captured per release-track spec
- [ ] **Slashing validation completed**: slashing penalties verified to fire correctly under adversarial conditions, consistent with the configured Alpha enforcement mode
- [ ] **Audit / external review activity underway**: external security audit initiated with initial feedback incorporated
- [ ] **Operational stability materially improved**: stability targets per release-track spec achieved over the final stretch of Alpha
- [ ] **Draft economics ready for Beta**: draft economics document ready for Beta dry-run (per release-track spec)

### 14.2 Required Documentation Artifacts

- [ ] Alpha post-mortem with lessons learned documented
- [ ] Beta operational guide drafted
- [ ] Economics design draft updated for Beta testing
- [ ] Bug tracking and triage process operationalized

### 14.3 Decision Authority

Alpha → Beta progression is, per the release-track spec, made by the development team with external auditor input. This plan does not change that.

### 14.4 Conflict Rule

If anything in Section 14 appears inconsistent with the release-track spec, the release-track spec wins.

---

## 15. What Alpha Explicitly Does Not Promise

Alpha does **not** promise any of the following. External communications must not imply otherwise.

- **No economic finality.** Alpha tokens have no value and confer no claim.
- **No long-term state permanence.** State may not survive resets; resets are permitted with notice.
- **No final tokenomics.** Inflation, fees, rewards, and distribution remain unsettled.
- **No MainNet timeline.** Alpha does not establish or imply any MainNet date.
- **No presale timing.** Alpha is not associated with presale, and presale is not in scope for Alpha.
- **No open public permissionless participation.** Alpha is invite-and-approval based.
- **No production uptime guarantees.** Alpha is not production and offers no SLA.
- **No commitment to any specific Alpha duration.** Alpha continues until exit criteria are met, not until a calendar date.
- **No commitment that any artifact, identifier, or address used in Alpha will exist on Beta or MainNet.**

This list is non-exhaustive. Where anything in this plan could be read as a stronger commitment than the release-track spec, the release-track spec wins.

---

## 16. Immediate Follow-Up Documents

The following documents are implied by Alpha planning. They are **not** created by this plan; they are the next logical canonical artifacts.

| Document | Path | Purpose |
|----------|------|---------|
| TestNet Beta Plan | `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` | Canonical internal plan for the broader-public, economics dry-run stage |
| Beta Economics Scope | `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md` | Defines the scope and parameters of the Beta economics dry-run |
| MainNet Readiness Checklist | `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` | Detailed checklist for MainNet entry validation |
| Alpha Operator / Onboarding Checklist (optional) | `docs/testnet/QBIND_TESTNET_ALPHA_OPERATOR_CHECKLIST.md` | Concrete operator-facing checklist derived from this plan, if useful |

These are recommendations, not commitments to specific filenames or schedules.

---

## 17. Final Plan Summary

TestNet Alpha is the first real-world public QBIND network. Its purpose is to expose the implementation, the operator workflow, and the validator onboarding model to controlled external participation, in order to discover failures that DevNet cannot reveal and to ground Beta planning in evidence.

**Alpha is:**

- The first public-facing network in the canonical sequence DevNet → TestNet Alpha → TestNet Beta → MainNet v0
- Controlled public, invite-and-approval based, with full P2P and RocksDB persistence
- A bug-discovery and adversarial-testing stage, with `EnforceCritical` as the likely slashing default and the full O1–O5 surface available in the implementation
- Operationally more disciplined than DevNet (tracked incidents, communicated changes, real triage), but not yet at Beta-rehearsal or MainNet-production rigor
- Non-economic: test tokens only, no value, no presale, no allocation signaling

**Alpha is not:**

- Beta, MainNet, or a launch
- Permissionless or open-enrollment
- A tokenomics decision stage
- A marketing or value-messaging surface

**Alpha advances toward Beta only when:**

- ≥3 external validators have successfully onboarded and operated
- A dedicated adversarial testing period has been completed
- No unresolved critical security issues from Alpha remain
- Performance baselines, slashing validation, and audit initiation are in place
- Operational stability has materially improved
- A draft economics document is ready for Beta dry-run

Until those conditions are demonstrably met, Alpha continues. Calendar pressure is not an Alpha exit criterion.

The canonical protocol behavior remains defined by the whitepaper and protocol report. The canonical release sequencing remains defined by the release-track spec. This document is the canonical **execution plan** for Alpha within those constraints, and nothing more.