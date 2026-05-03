# QBIND MainNet Readiness Checklist

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal MainNet Readiness Gatekeeping Document

---

## 1. Purpose and Scope

This document is the **canonical internal MainNet readiness checklist** for QBIND. Its sole purpose is to define the evidence and conditions that must be satisfied before MainNet may even be **considered** for authorization.

**What this document is:**
- A strict internal gatekeeping checklist
- A reviewable artifact used to assess whether MainNet readiness is plausibly satisfied
- A blocker list that prevents premature MainNet launch

**What this document is NOT:**
- It is **not** the MainNet launch announcement
- It is **not** a public communications document
- It is **not** the final tokenomics document
- It is **not** a presale authorization, and does not imply one
- It does **not** itself authorize MainNet launch
- It does **not** finalize economics, fees, supply, allocations, or pricing
- It does **not** replace independent audits, the release-track spec, or any explicit authorization step

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md` — Authoritative technical specification
- `docs/protocol/QBIND_PROTOCOL_REPORT.md` — Protocol gaps and implementation status
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md` — Risk mitigation audit index

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

This checklist is a **subordinate** instrument to those documents and must remain consistent with them. If a conflict is discovered, the canonical documents above govern, and this checklist must be reconciled.

---

## 2. Relationship to the Release Track

The QBIND release sequence is:

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

This checklist applies to the transition from **TestNet Beta → MainNet v0**.

- **DevNet, Alpha, and Beta** are evidence-producing stages. Their plans are defined in `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`, `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`, and `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`.
- **TestNet Beta** is the final evidence stage before MainNet readiness is assessed. Its purpose includes broader exposure and economics dry-run as scoped in `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`.
- **MainNet readiness** is a **separate decision** taken after Beta. It is **not** automatic progression from Beta.
- **MainNet authorization** is a further, distinct step beyond readiness assessment, and is governed by the release-track spec, not by this checklist.

> **Beta success is necessary but not sufficient.**

A clean Beta does not, by itself, satisfy MainNet readiness. Even if Beta exit criteria are met, every applicable item in this checklist must be independently satisfied, and explicit authorization must still be obtained.

---

## 3. Readiness Philosophy

The internal principles governing this checklist are intentionally strict:

- **No launch under unresolved critical or high security findings.**
- **No launch on incomplete evidence.** Missing evidence is treated as a failed item, not a neutral one.
- **No silent waiving of gates.** Any deviation must be explicitly documented, attributed, and reviewed.
- **Evidence over schedule pressure.** Calendar dates do not override checklist items.
- **Launch delay is acceptable. Unsafe launch is not.**
- **Readiness is a reviewable decision, not a vibe.** Each item must be backed by attached evidence.
- **Conservatism by default.** When in doubt, the item fails.
- **Canonical documents govern.** This checklist cannot expand scope, soften gates, or override the release-track spec.

---

## 4. Required Evidence Inputs

Readiness review depends on, at minimum, the following documents and evidence sources existing and being current. This checklist does not produce these artifacts; it depends on them.

**Canonical baseline documents:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md` (contradiction tracker)
- `docs/protocol/QBIND_NEXT_STEP_DECISION_MEMO.md`

**Stage planning documents:**
- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`
- `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`

**Economics documents:**
- `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`
- `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`
- A final MainNet economics finalization document (must exist before MainNet consideration; this checklist does not create it)

**Operational and security evidence:**
- Beta evidence packet covering operational, security, and economics observations
- Independent security audit outputs (full reports, not summaries)
- Bug bounty outputs as required by the release-track spec
- Incident logs, post-mortems, and remediation status from DevNet, Alpha, and Beta

If any of the above are missing, outdated relative to the candidate MainNet build, or inconsistent with one another, the corresponding checklist items below must fail.

---

## 5. Security Readiness Checklist

This section is one of the strongest gates. Any single failure here blocks MainNet readiness.

- [ ] Independent security audit of the candidate MainNet build is **complete**, not in progress.
- [ ] **Zero unresolved critical findings** from the audit.
- [ ] **Zero unresolved high findings** from the audit.
- [ ] Bug bounty program has been active and/or completed as required by the release-track spec.
- [ ] No bug bounty submissions remain in unresolved critical or high status.
- [ ] Contradiction tracker (`docs/whitepaper/contradiction.md`) has been reviewed against the candidate MainNet build.
- [ ] **No open critical safety contradictions** in the contradiction tracker.
- [ ] No unresolved protocol or safety concerns flagged in the protocol report or M-series coverage.
- [ ] No silent waivers. Every accepted finding has an explicit, dated, attributed acceptance entry.
- [ ] Any accepted medium or low issues are documented with rationale and explicit non-blocker justification.
- [ ] No regressions introduced after the audit cut without re-review.
- [ ] Cryptographic, consensus, and key-handling components have not changed materially since audit without re-review.

---

## 6. Protocol and Documentation Readiness Checklist

- [ ] All canonical documents in the baseline set are present, versioned, and dated.
- [ ] Canonical documents are **internally consistent enough for MainNet**, with no known unreconciled material conflicts.
- [ ] Release-track spec, Beta plan, and economics documents align on stage definitions and exit criteria.
- [ ] No known doc-level contradictions remain that would impair launch decision-making.
- [ ] Operator-facing documentation exists for every role required to run a MainNet validator or core operator function.
- [ ] Incident response procedures are documented and accessible to on-call operators.
- [ ] Upgrade, rollback, and emergency-halt procedures are documented.
- [ ] A MainNet **economics finalization document** exists prior to MainNet consideration. (This checklist does not create it; it must already exist.)
- [ ] No checklist item, plan, or operational doc depends on deleted or superseded legacy documents.
- [ ] All references in canonical docs resolve to current, authoritative sources.

---

## 7. Operational Readiness Checklist

- [ ] Sustained Beta stability evidence exists across the final Beta stretch defined by the release-track spec.
- [ ] Target uptime evidence exists and meets or exceeds the Beta exit criteria.
- [ ] **No unplanned chain resets** in the relevant final Beta stretch.
- [ ] Incident response procedures have been **exercised**, not merely written, with at least one documented dry-run or real incident handled to closure.
- [ ] Monitoring and alerting coverage is sufficient for MainNet operations (consensus health, peer count, finality, resource exhaustion, key-signing anomalies, and equivalent signals).
- [ ] On-call rotation, paging, and escalation paths are defined and operational.
- [ ] Upgrade and rollback procedures have been **tested**, not only documented.
- [ ] Backup and recovery expectations are documented for validators and core operators.
- [ ] No repeated unresolved operational failures across Beta.
- [ ] No recurring class of incident remains without root-cause analysis and remediation.
- [ ] Coordination posture (communications channels, decision logs, change-management) is in place and exercised.

---

## 8. Economics and Tokenomics Readiness Checklist

This section is strict and intentionally avoids stating any final numbers. Final values are defined elsewhere; this checklist only verifies that the finalization has occurred.

- [ ] A MainNet **economics finalization document** exists and supersedes draft economics for MainNet purposes.
- [ ] The final **monetary-model family** has been chosen and recorded.
- [ ] The final **fee-policy family** has been chosen and recorded.
- [ ] The final **minimum stake** has been chosen and recorded.
- [ ] The final **genesis supply** has been chosen and recorded.
- [ ] The final **allocation categories** have been defined and recorded.
- [ ] The decision on **whether C3 exists in MainNet v0** has been made and recorded.
- [ ] Beta economics evidence (per `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`) was **actually used** to inform and justify the final decisions, with traceable rationale.
- [ ] **No Beta draft parameter** is being treated as a MainNet final value without explicit post-Beta finalization.
- [ ] **No presale is implied or authorized** by omission, by document phrasing, or by external messaging tied to this checklist.
- [ ] No economics decision is left "to be decided after launch" if it is required for MainNet v0 to function safely.
- [ ] Final economics decisions are consistent with the release-track spec and tokenomics decision framework.

This checklist does not enumerate, propose, or endorse any specific final economic values.

---

## 9. Governance and Upgrade Readiness Checklist

- [ ] The MainNet **upgrade process** is documented (proposal, review, activation, rollback).
- [ ] The MainNet **governance process** is documented to a level sufficient for MainNet v0, consistent with the release-track spec.
- [ ] Council, multisig, or other authorization bodies referenced by canonical docs are **defined and operational** to the extent the release-track spec requires for MainNet v0.
- [ ] Emergency procedures (halt, patch, key compromise response) are documented.
- [ ] Role ownership is unambiguous: every authorization step has a clearly identified accountable role.
- [ ] **No ambiguity about who can authorize what.** Any "TBD" authority is a blocker.
- [ ] Governance and upgrade documentation is consistent with Beta planning documents and does not contradict the release-track spec.
- [ ] No governance authority is invented in this checklist beyond what existing canonical docs support.

---

## 10. Validator and Participation Readiness Checklist

This section addresses readiness, not public recruitment.

- [ ] MainNet **validator requirements** are defined (hardware, software, network, security expectations).
- [ ] Validator **onboarding expectations** are documented sufficiently for MainNet planning.
- [ ] Validator **key-handling expectations** are defined to a strength appropriate for MainNet (generation, custody, rotation, and compromise response).
- [ ] Beta produced sufficient **operator maturity** evidence: external operators ran nodes, handled upgrades, and managed incidents at a level commensurate with MainNet expectations.
- [ ] **No hidden dependence on core-team-only operation.** MainNet must not silently rely on the core team to operate critical validator capacity.
- [ ] **Minimum stake / participation rules** are documented to a level sufficient for MainNet consideration.
- [ ] Slashing, jailing, and exit conditions are documented.
- [ ] Participation documentation is consistent with the release-track spec and Beta plan.

---

## 11. Communications and External-Expectation Readiness Checklist

- [ ] External messaging (where it exists) **does not overpromise** features, dates, returns, or rights.
- [ ] **MainNet asset naming and distinction from test assets** is defined and unambiguous.
- [ ] No lingering ambiguity between Beta-stage claims and MainNet claims in any external surface.
- [ ] **No implied redemption, allocation, or presale rights** arising from DevNet, Alpha, or Beta participation.
- [ ] **Launch communications are explicitly separated** from this readiness review. Readiness review does not author launch comms; launch comms do not pre-empt readiness review.
- [ ] No document in the canonical set reads, even accidentally, like a sale promise or investment offer.
- [ ] References to economics in any external-facing material are consistent with finalized economics, not with drafts.
- [ ] If any external surface is inconsistent with canonical docs, that inconsistency is treated as a blocker until reconciled.

---

## 12. Explicit MainNet Blockers

Any of the following automatically prevents MainNet readiness from being considered satisfied. This list is intentionally blunt.

- Any unresolved **critical** or **high** security finding (audit or bounty).
- Audit incomplete, in progress, or scoped to a build that does not match the MainNet candidate.
- **Missing economics finalization document** at MainNet consideration time.
- Unresolved **critical** item in the contradiction tracker.
- Repeated **Beta resets** in the final stretch defined by the release-track spec.
- Insufficient uptime or stability evidence relative to Beta exit criteria.
- **No explicit authorization body or process** identified for MainNet launch.
- Unresolved asset naming or communications ambiguity between test assets and MainNet assets.
- Any presale-related confusion contaminating MainNet readiness discussion, including implied presale via omission.
- Any silent waiver of any item in this checklist.
- Material protocol changes after audit cut without re-review.
- Any "TBD" governance authority required for MainNet v0 operation.

---

## 13. Readiness Review Process

This checklist is used as follows:

1. **Reviewers.** The checklist is reviewed by the roles identified in the release-track spec for stage-transition assessment. This document does not invent new governance bodies.
2. **Evidence attachment.** Each item must be backed by attached or cited evidence (audit reports, Beta evidence packet sections, finalization documents, incident logs, etc.). Citation is required; assertion alone is insufficient.
3. **Item status.** Each item is marked exactly one of:
   - `pass` — evidence reviewed and item satisfied
   - `fail` — evidence reviewed and item not satisfied
   - `not-yet-reviewed` — treated as a blocker until reviewed
4. **Unresolved items.** Any `fail` or `not-yet-reviewed` item remains a blocker unless explicitly documented, dated, attributed, and justified as a non-blocker by the appropriate authority. Silent waivers are prohibited.
5. **Re-review on change.** Any material change to the candidate MainNet build, economics finalization, or operational posture triggers re-review of affected items.
6. **Separation from authorization.** Even when **all** items pass, **MainNet authorization is a separate decision** governed by the release-track spec. Passing this checklist is necessary, not sufficient, and not equivalent to authorization.
7. **Record retention.** The completed checklist, evidence references, and any documented waivers are retained as part of the MainNet readiness record.

---

## 14. What This Checklist Does Not Do

To prevent scope creep and misuse, this checklist explicitly does **not**:

- Launch MainNet.
- Set or imply public dates.
- Finalize economics, fees, supply, allocations, or any monetary parameter.
- Authorize, schedule, structure, or imply a presale.
- Replace independent audit reports.
- Replace the release-track spec, whitepaper, protocol report, or M-series coverage.
- Replace the explicit authorization step required for MainNet launch.
- Define governance bodies beyond what existing canonical docs already define.
- Constitute an offer, solicitation, or commitment of any kind.

---

## 15. Final Readiness Summary

MainNet readiness for QBIND requires **converging evidence** across:

- **Security** — independent audit complete, no unresolved critical/high findings, contradiction tracker clean on safety-critical items.
- **Operations** — sustained Beta stability, exercised incident response, tested upgrade/rollback, real on-call posture.
- **Economics** — a MainNet economics finalization document exists, with final monetary model, fee policy, minimum stake, genesis supply, allocation categories, and the C3 decision recorded; no Beta draft treated as final by default.
- **Governance** — documented upgrade and governance processes, defined authorization bodies, unambiguous role ownership.
- **Communications** — clean external messaging, unambiguous asset naming, no implied presale, launch comms separated from readiness review.

**Beta success alone is not enough.** Every applicable item in this checklist must be independently satisfied with attached evidence, and explicit MainNet authorization remains a separate decision governed by the release-track spec.

> **Launch delay is acceptable. Unsafe launch is not.**