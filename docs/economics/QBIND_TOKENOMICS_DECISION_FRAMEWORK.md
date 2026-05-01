# QBIND Tokenomics Decision Framework

**Version**: 1.0
**Date**: 2026-05-01
**Status**: Internal Decision Framework (Non-Final)

---

> **This document is a decision framework, not a finalized tokenomics specification.**
>
> - Its purpose is to **narrow open economics choices into explicit decision points** before TestNet Beta and before MainNet.
> - It does **NOT** create public commitments, pricing, sale promises, valuations, or legal/financial representations of any kind.
> - It does **NOT** authorize, schedule, price, or imply any presale, public sale, airdrop, or token distribution.
> - It does **NOT** assign final numeric parameters to monetary model, fee policy, supply, or allocation.
> - Canonical protocol behavior remains defined by:
>   - `docs/whitepaper/QBIND_WHITEPAPER.md`
>   - `docs/protocol/QBIND_PROTOCOL_REPORT.md`
>   - `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
>   - `docs/whitepaper/contradiction.md`
>   - `docs/protocol/QBIND_LEGACY_SYNTHESIS.md`
> - Release sequencing is governed by `docs/release/QBIND_RELEASE_TRACK_SPEC.md` and operational posture by `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`.
> - Economics design space is documented in `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`. This document does **not** repeat that design space; it converts it into a sequence of decisions.

---

## 1. Purpose and Scope

### 1.1 Purpose

QBIND has reached a point where:

- Release-track sequencing is defined.
- DevNet operational posture is defined.
- The economics **design space** has been drafted.
- Tokenomics is **not** finalized.
- Presale is **not** the next step.

What is missing is not more design exploration — it is **decision discipline**: an explicit, ordered list of which economics questions must be answered, when, with what level of finality, and against which constraints.

This document provides that decision discipline. It is the bridge between "we have explored the design space" and "we are ready to scope TestNet Beta as an economics dry-run, and later, finalize MainNet economics."

### 1.2 What This Document Is

- A **decision framework** that enumerates open tokenomics questions.
- A **sequencing** of those decisions across pre-Beta, in-Beta, and pre-MainNet phases.
- A statement of **decision principles** that govern how those decisions should be made.
- A list of **preconditions** that must be satisfied before downstream activities (notably presale planning) become reasonable to discuss.

### 1.3 What This Document Is NOT

- Not a finalized tokenomics specification.
- Not a public, marketing, or investor-facing document.
- Not a presale, distribution, or token-listing commitment.
- Not a legal, regulatory, or financial representation.
- Not a replacement for canonical protocol documentation.
- Not a numeric-parameter sheet (no final supply, rate, or split numbers are committed here).

### 1.4 Audience

Internal: protocol engineers, economics working group, governance reviewers, and auditors. External communications about tokenomics must remain governed by canonical documents and any future, separately authorized public materials — not by this framework.

---

## 2. Relationship to the Release Track and Economics Draft

This document sits at the intersection of three existing canonical documents:

| Source | Provides | This Document Adds |
|---|---|---|
| `QBIND_RELEASE_TRACK_SPEC.md` | Release sequencing (DevNet → TestNet → TestNet Beta → MainNet) | Maps each economics decision to a release-track gate |
| `QBIND_DEVNET_OPERATIONAL_GUIDE.md` | Operational posture for non-MainNet networks | Identifies which decisions Beta must enable |
| `QBIND_ECONOMICS_DESIGN_DRAFT.md` | Design space for monetary model, fees, validator rewards, C3, slashing | Converts the design space into a decision tree with phase-bound deadlines |

This document **does not modify or supersede** any of the above. It is strictly a planning artifact layered on top of them.

---

## 3. Current Decision Status

This section reflects only what current canonical documents support. It is a snapshot, not a commitment.

### 3.1 Already Decided / Sufficiently Settled

- **Release sequencing**: DevNet → TestNet → TestNet Beta → MainNet, governed by the release-track spec.
- **DevNet/TestNet/MainNet posture**: non-MainNet environments carry no economic value; MainNet is the only environment where economic finalization applies.
- **Slashing model O1–O5**: defined and governance-bounded in the protocol report and economics draft; slashing exists as a deterrent mechanism.
- **Gas / fee machinery**: exists functionally in the protocol; fee *collection* is operative, even though fee *policy* is not finalized.
- **Reporter rewards (C3)**: explicitly **open** — slashing exists, but rewarding the reporter does not yet have a finalized model.
- **Final tokenomics**: **not yet decided**.
- **Presale**: **not authorized**, not scheduled, not priced.

### 3.2 Still Not Decided

- **Monetary model family** (fixed, fixed + reward pool, bounded inflation, hybrid).
- **Whether TestNet Beta simulates active issuance** or only fee flow.
- **Whether TestNet Beta includes reporter rewards** or defers C3.
- **Fee policy direction** (burn-only, proposer-only, or split).
- **Genesis supply magnitude**.
- **Genesis allocation structure** (validator/security, treasury, foundation/team, ecosystem, optional investor).
- **Test-asset naming policy** (whether DevNet/TestNet assets carry distinct names/symbols and exclusionary language).
- **Presale timing**, eligibility, structure, and authorization — all undecided and out of scope here.

### 3.3 Out of Scope for This Document

- Numeric finalization of any parameter.
- Legal/regulatory classification of any future asset.
- Any external commitments of any kind.

---

## 4. Decision Principles

Decisions taken under this framework should follow these principles. They are intentionally conservative.

1. **Safety first, optimization later.** Choose the option that is *sufficient* for protocol safety and operator clarity before optimizing for elegance, yield, or narrative.
2. **Reversible Beta beats irreversible MainNet.** Prefer Beta-time decisions that can be revised with evidence over MainNet-time commitments that cannot.
3. **No public expectations on internal test parameters.** Beta numbers are diagnostic, not promissory. Communications must reinforce this.
4. **Do not finalize what Beta can still invalidate.** If a decision depends on participation rates, fee volume, or reporter behavior we have not yet observed, defer finalization.
5. **Do not couple presale planning to unresolved economics.** Presale planning is downstream of tokenomics finalization, not parallel to it.
6. **Prefer explicit deferral to implicit ambiguity.** If a decision is being deferred, name it as deferred and assign it a phase, rather than leaving it silently open.
7. **Test assets are not MainNet assets.** Naming, UI, and communications must structurally enforce this separation.
8. **Conservatism on irreversibility.** Genesis allocation, monetary model, and fee policy are high-irreversibility decisions; treat them with stricter evidence requirements than Beta-tunable parameters.

---

## 5. Decisions Required Before TestNet Beta

TestNet Beta is intended to function as an economics dry-run. For it to provide meaningful evidence, the following must be decided before Beta scope is frozen.

| # | Decision | Why Beta Needs It | Acceptable Options | Current Recommended Default | Reversible Before MainNet? |
|---|---|---|---|---|---|
| 5.1 | Monetary-model **family** Beta will simulate | Beta cannot generate validator-economics evidence without a chosen family | Fixed / Fixed+Pool / Bounded Inflation / Hybrid | Bounded Inflation **or** Hybrid (do not hard-lock) | Yes |
| 5.2 | Whether Beta includes **active issuance** or only fee simulation | Determines whether Beta produces issuance-rate evidence at all | Issuance on / Issuance off (fee-only) | Issuance on, with conservative draft rate parameters | Yes |
| 5.3 | Whether Beta includes **reporter rewards (C3)** | Determines whether C3 can be evaluated empirically before MainNet | Include C3 / Defer C3 to post-Beta | Include a minimal, bounded C3 simulation if implementation cost is acceptable; otherwise defer | Yes |
| 5.4 | Draft **minimum stake target** for Beta | Validator entry, slashing magnitude, and security-budget framing all depend on this | Low / Medium / High draft tier | Conservative-medium draft, calibrated to deterrence not yield | Yes |
| 5.5 | **Fee policy family** Beta tests | Determines whether burn vs proposer-share evidence is collected | Burn-only / Proposer-only / Split | Split (burn + proposer share) at conservative draft ratio | Yes |
| 5.6 | **Metrics** Beta must collect | Without this, Beta cannot inform MainNet finalization | Validator participation, slashing frequency by class, fee volume, issuance rate, reporter activity (if 5.3=include), economic deterrent effectiveness | All of the above at minimum | N/A (instrumentation) |

All Beta-time numeric values chosen for these decisions are **draft parameters**, not commitments.

---

## 6. Decisions That May Be Deferred Until After TestNet Beta

These decisions should *not* be locked before Beta. They are evidence-bound: locking them earlier would require Beta to validate parameters chosen without Beta data.

- **Exact MainNet issuance rate / schedule.** Requires Beta data on validator participation and effective security budget.
- **Exact final burn/reward split.** Requires Beta data on fee volume distribution and validator profitability.
- **Exact team / foundation / investor allocation percentages.** Should be fixed only when governance posture and v0 categories are confirmed.
- **Final reporter reward magnitudes.** Requires Beta evidence on collusion risk and reporter participation, *if* C3 is included in Beta.
- **Final genesis supply number.** May remain placeholder during Beta provided Beta uses a clearly internal, non-promissory value and communications reinforce its non-public nature.
- **Final UX / wallet denomination conventions.** Can follow once supply magnitude is chosen.

Each of these can be assigned a Beta-derived evidence requirement before being closed.

---

## 7. Decisions That Must Be Finalized Before MainNet

The following must be closed before MainNet genesis. This is a hard checklist.

- [ ] **Final monetary model** (family + parameters).
- [ ] **Final fee policy** (burn / proposer / split + ratio).
- [ ] **Final minimum stake** for MainNet validators.
- [ ] **Final genesis supply** (numeric).
- [ ] **Final genesis allocation categories** (which categories exist; their relative bounds).
- [ ] **Whether reporter rewards exist in v0**, and if so, which model.
- [ ] **Final naming and communication distinction** between any test assets and the MainNet asset.
- [ ] **Treasury / community / foundation policy at genesis** (governance authority, vesting if any, transparency posture).
- [ ] **Slashing parameters** confirmed against Beta evidence (within the existing O1–O5 framework).
- [ ] **Documented justification** for each of the above tied to Beta evidence or explicit governance reasoning.

Nothing on this list is satisfied today.

---

## 8. Monetary Model Decision Framework

This section converts the design-space discussion in the economics draft into a comparative decision view. It does **not** select a final family.

| Family | Pros | Risks | PQC Cost-Profile Compatibility | Beta Simulation Suitability | MainNet Operational Difficulty | Recommendation Status |
|---|---|---|---|---|---|---|
| **Fixed supply** | Simple narrative; bounded total; minimal governance surface | Security budget collapses if fee volume is low; long-tail validator incentive risk | Weak — PQC tx costs may suppress fee volume early, undermining sole-fee security | Easy to simulate; little issuance logic | Low operational complexity; high *security-budget* risk | **Viable but not preferred** for a PQC-first chain |
| **Fixed supply + reward pool** | Bounded total; provides early validator subsidy | Pool exhaustion creates a future cliff; pool sizing is itself a hard decision | Moderate — postpones rather than solves the fee-volume problem | Moderate; requires pool accounting | Medium; cliff handling needs governance | **Viable** as a transitional structure |
| **Bounded inflation** | Continuous, predictable security budget; well-understood; tunable via governance | Requires explicit upper bound and governance discipline; dilution narrative | Strong — decouples security budget from early fee volume | Good; produces clean issuance metrics | Medium; requires bounded-rate governance | **Preferred candidate** |
| **Hybrid (fee-offset issuance)** | Self-balancing: issuance reduces as fees grow; aligns with maturity curve | Highest implementation complexity; harder to communicate; parameter-sensitive | Strong — explicitly designed for low-early-fee regimes | Good *if* implementation is ready; otherwise risky | Medium-high; requires careful parameterization | **Preferred candidate (co-equal with bounded inflation)** |

**Current direction (non-binding):** Bounded inflation **or** hybrid fee-offset issuance. Numeric parameters are intentionally not committed here. Fixed supply variants are not preferred for a PQC-first chain whose early fee volume cannot be assumed.

---

## 9. Fee Policy Decision Framework

| Policy | Anti-Spam Quality | Validator Incentive Quality | Complexity | Beta Suitability | Depends on Unvalidated Assumptions? |
|---|---|---|---|---|---|
| **Burn-only** | Strong (cost is purely a sink) | Weak — validators capture nothing from fees | Low | Easy; clean fee-burn metric | Assumes issuance fully covers validator income |
| **Proposer-only** | Adequate | Strong direct incentive, but uneven across validators (proposer luck) | Low–medium | Easy; produces proposer-skew data | Assumes fee volume is high enough to matter |
| **Split (burn + proposer/validator share)** | Strong | Balanced — incentive plus sink | Medium (ratio governance) | Best for evidence collection | Ratio needs Beta data to tune |

**Draft recommendation (non-final):** Beta should test a **split** policy at a conservative draft ratio. The split allows simultaneous observation of burn pressure and validator income, which is required to inform MainNet finalization. Burn-only and proposer-only remain viable fallbacks; both are inferior for evidence collection during Beta.

This is a recommendation, not a final policy.

---

## 10. Validator Reward Decision Framework

| Source | Behavior in Low-Activity Networks | Alignment with Security-Budget Reasoning | Fit for Early-Stage QBIND Economics | Beta Suitability |
|---|---|---|---|---|
| **Fees only** | Poor — validator income collapses with low traffic | Weak — security budget is a function of usage, not threat | Poor for an early PQC chain where fee volume is unproven | Useful only as a contrast scenario |
| **Issuance only** | Stable | Strong — security budget is independent of usage | Strong fit for early stage | Required to evaluate baseline |
| **Both (issuance + fees)** | Stable, with upside as usage grows | Strongest — combines floor (issuance) with growth (fees) | Strong fit; matches likely chosen monetary family | Preferred for Beta |
| **Pre-allocated pool** | Stable until depletion | Conditional — strong while funded, weak after | Acceptable as transitional scaffold | Useful as a comparator, not as primary |

**Principle:** Early QBIND security must not depend on optimistic fee volume. Validator economics at MainNet v0 must be solvent under a low-activity scenario. Therefore the validator reward source must include a non-fee component (issuance or pool) at v0, with fees as additive rather than load-bearing.

---

## 11. Reporter Rewards (C3) Decision Framework

C3 — the question of how a reporter of an O-class violation is rewarded — is the most evidence-thin economics question. The decision tree is:

| Option | Incentive Strength | Abuse / Collusion Risk | Implementation & Accounting Complexity | Needs Beta Testing? | In Scope for MainNet v0? |
|---|---|---|---|---|---|
| **A. No reporter rewards in v0** | Weak (relies on protocol-aligned actors) | Lowest | Lowest | No (null hypothesis) | Possible — defensible if Beta evidence is insufficient |
| **B. Rewards from slashed amount** | Strong | High — direct incentive to fabricate or coordinate reports | Medium — requires careful accounting around slashing flow and remainder routing | Yes — must observe behavior under controlled conditions | Conditional on Beta evidence |
| **C. Rewards from separate pool / treasury** | Moderate–strong | Medium — decoupled from slashing reduces but does not eliminate collusion | Medium — requires pool sizing and governance | Yes | Conditional on Beta evidence and pool funding decision |
| **D. Deferred / challenge-window rewards** | Moderate, with strong abuse resistance | Lowest among reward options — challenge window deters fabrication | Highest — requires challenge mechanics, dispute resolution, and timing parameters | Yes — and most expensive to test | Unlikely for v0; candidate for v1 |

**Two explicit questions:**

1. *Should Beta simulate reporter rewards?*
   **Recommended path:** Yes, **if** a minimal, bounded variant of Option B or C can be implemented at acceptable cost. The purpose of Beta is to generate the evidence MainNet finalization requires; deferring C3 entirely from Beta means MainNet v0 will almost certainly ship without reporter rewards.
2. *Or should Beta defer C3 and MainNet v0 launch without reporter rewards (Option A)?*
   **Acceptable fallback:** Yes, if implementation cost is non-trivial. Option A is a defensible v0 posture provided slashing remains operative and governance remains the path to introduce C3 in v1.

**Recommended path (non-final):** Default toward Option A for MainNet v0 *unless* Beta produces clean evidence supporting Option B or C. Do not commit to D for v0.

---

## 12. Test Asset vs MainNet Asset Naming and Communication

This section is intentionally stronger than the economics draft on this point.

### 12.1 The Decision Surface

- Should DevNet and TestNet (including TestNet Beta) assets carry **distinct names and symbols** from the MainNet asset (e.g., `dQBIND` for DevNet, `tQBIND` for TestNet)?
- Must UI, RPC responses, block explorers, and documentation **explicitly state** that test assets have **no value** and **no claim** on any MainNet asset?
- Must communications about test environments **explicitly reject** any redemption, conversion, migration, swap, or airdrop implication toward MainNet?

### 12.2 Required Posture

- Test assets **must not** imply any present or future claim on the MainNet asset, **unless** such a claim is **separately, formally, and explicitly** decided through governance and documented in canonical materials. No such decision exists today.
- This is simultaneously a **communications discipline** issue and a **risk-control** issue. Ambiguity here creates regulatory and reputational risk regardless of intent.
- Internal documents, including this one, must not be cited as evidence of any such claim.

### 12.3 Recommended Direction (non-final)

1. Adopt **distinct symbols** for non-MainNet environments. Recommended convention: `dQBIND` (DevNet), `tQBIND` (TestNet, including TestNet Beta). MainNet retains whatever final symbol is decided at MainNet finalization (not committed here).
2. Require **explicit no-value language** in UI, faucets, explorer headers, and any test-environment documentation: test assets carry no economic value, no claim on MainNet, and no convertibility.
3. Require **negative framing**: communications must not merely omit a redemption claim; they must affirmatively reject one.
4. Centralize this language so it is consistent across all surfaces.

This recommendation is a candidate for adoption in pre-Beta planning.

---

## 13. Genesis Supply and Allocation Decision Framework

This section structures the open decisions. It does **not** pick numeric values, since none are canonically established.

### 13.1 Genesis Supply Magnitude

| Scale | Trade-offs |
|---|---|
| **Small supply** | Higher per-unit value optics; risk of denomination/UX awkwardness for everyday fees; psychologically inflates per-unit volatility |
| **Medium supply** | Balanced denomination ergonomics; conventional in modern L1s; usually best UX trade-off |
| **Large supply** | Comfortable subdivision and fee denomination; risk of "low unit price" optics that may distort external perception |

**Decision posture:** Choose magnitude based on denomination ergonomics and validator/staking arithmetic, *not* on market optics. Defer to MainNet finalization.

### 13.2 Allocation Categories

For each candidate category, the open questions are: should it exist in v0, what risks does it introduce, and what should be deferred.

| Category | Why It May Exist | Risks Introduced | Must Exist in v0? | Defer Until Later? |
|---|---|---|---|---|
| **Validator / security budget reserve** | Provides early validator subsidy and bootstraps security budget | Concentration of supply; governance over disbursement | Likely yes — required to bootstrap security if monetary model relies on a pool component | Sizing can be deferred until Beta evidence |
| **Treasury / community reserve** | Funds protocol-level public goods; governance-disbursed | Centralization of decision power; misuse risk | Recommended yes | Disbursement policy can be deferred |
| **Foundation / team reserve** | Funds long-term protocol stewardship | Optics and centralization risk; vesting requirements | Conditional — depends on entity structure | Vesting and governance details deferable, but its **existence** must be decided pre-MainNet |
| **Ecosystem / developer reserve** | Funds integrators, tooling, audits | Disbursement abuse risk | Recommended yes | Disbursement policy deferable |
| **Investor reserve (optional)** | Funds early development if external funding is structured | Highest regulatory and communications risk; coupling to presale | **Only if separately authorized** under legal review; not assumed | Entirely deferred; not assumed by this framework |

This framework treats categories as **structural placeholders**, not commitments. Whether a category exists, and at what bound, is a MainNet finalization decision. Numeric percentages are explicitly out of scope here.

### 13.3 Governance Posture

Whichever categories exist, each must have, before MainNet:
- A defined custodian / authority.
- A defined disbursement rule or governance process.
- A defined transparency posture.

Categories without these are not v0-ready.

---

## 14. Presale Readiness Preconditions

This section is strict by design.

Presale planning **shall remain blocked** until **all** of the following are true:

1. The release-track spec exists. ✅ (`docs/release/QBIND_RELEASE_TRACK_SPEC.md`)
2. The economics design draft exists. ✅ (`docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`)
3. The tokenomics decision framework exists. ✅ (this document)
4. Beta economics scope has been chosen and frozen. ❌ (pending)
5. At least some Beta validation evidence is available. ❌ (pending)
6. A separate legal / regulatory review has been performed and recorded. ❌ (pending; explicitly out of scope of engineering and economics documents)
7. Genesis supply, allocation categories, and v0 reporter-reward posture are finalized per Section 7. ❌ (pending)
8. A separate, formally authorized presale specification exists. ❌ (does not exist; not produced here)

Until **all** of the above are satisfied:

- This framework **does not authorize** a presale.
- This framework **does not** define presale terms, eligibility, pricing, vesting, or jurisdictions.
- No statement in this document may be cited as authorization, intent, or commitment to conduct a presale.
- This framework only defines **when presale planning may become reasonable to begin** — not when a presale itself may occur.

---

## 15. Recommended Order of Decisions

The following is the recommended decision sequence. It is concrete and ordered.

### Phase 1 — Before TestNet Beta scope freeze

1. Choose **monetary-model family** for Beta simulation (Section 5.1, Section 8). Default direction: bounded inflation or hybrid; do not lock numerics.
2. Choose **Beta fee-policy family** (Section 5.5, Section 9). Default direction: split, conservative ratio.
3. Decide whether **Beta simulates active issuance** or fee-only (Section 5.2). Default direction: issuance on.
4. Decide whether **C3 (reporter rewards) is in or out for Beta** (Section 5.3, Section 11). Default direction: include a minimal bounded variant if implementation cost is acceptable; otherwise defer.
5. Choose **draft test-asset naming policy** (Section 12). Default direction: `dQBIND` / `tQBIND` with explicit no-value, no-claim language.
6. Choose **draft minimum stake target** for Beta (Section 5.4).
7. Define the **Beta metrics set** (Section 5.6).

### Phase 2 — During TestNet Beta

8. Collect economics metrics per Section 5.6.
9. Evaluate validator participation, fee volume distribution, slashing frequency, and (if applicable) reporter behavior.
10. Revise draft parameters in response to evidence; document each revision.

### Phase 3 — Before MainNet

11. Finalize **monetary model** (family + parameters), per Section 7.
12. Finalize **fee policy**, per Section 7.
13. Finalize **minimum stake** for MainNet, per Section 7.
14. Finalize **genesis supply**, per Sections 7 and 13.1.
15. Finalize **genesis allocation categories** and their bounds, per Sections 7 and 13.2.
16. Decide whether **reporter rewards exist in v0**, per Sections 7 and 11.
17. Finalize **MainNet asset naming and the test-vs-MainNet communications boundary**, per Sections 7 and 12.
18. Decide whether **presale planning may begin**, contingent on all preconditions in Section 14.

No phase may be skipped. Phase 3 may not begin while Phase 2 evidence is incomplete on a decision that depends on it.

---

## 16. Final Decision Summary

A condensed view of where this framework leaves each open question.

| # | Question | Phase Bound | Current Recommended Direction (Non-Final) |
|---|---|---|---|
| 1 | Monetary-model family | Pre-Beta (family); Pre-MainNet (parameters) | Bounded inflation or hybrid fee-offset issuance |
| 2 | Beta issuance simulation | Pre-Beta | On, with conservative draft rate |
| 3 | Fee policy | Pre-Beta (family); Pre-MainNet (final) | Split (burn + proposer/validator share), conservative draft ratio |
| 4 | Validator reward source | Pre-MainNet | Issuance + fees (fees additive, not load-bearing) |
| 5 | Reporter rewards (C3) in Beta | Pre-Beta | Include minimal bounded variant if cost is acceptable; else defer |
| 6 | Reporter rewards (C3) in MainNet v0 | Pre-MainNet | Default to **none in v0** (Option A) unless Beta evidence supports B or C |
| 7 | Test-asset naming & communication | Pre-Beta | Distinct symbols (`dQBIND` / `tQBIND`) + explicit no-value, no-claim language |
| 8 | Minimum stake | Pre-Beta (draft); Pre-MainNet (final) | Conservative-medium draft; calibrated to deterrence |
| 9 | Genesis supply magnitude | Pre-MainNet | Choose for ergonomics, not optics; not committed here |
| 10 | Genesis allocation categories | Pre-MainNet | Existence per Section 13.2; bounds per finalization |
| 11 | Treasury / foundation / ecosystem governance | Pre-MainNet | Each existing category must have custodian, disbursement rule, transparency posture |
| 12 | Investor reserve | Pre-MainNet **and** legal review | Not assumed; only with separate authorization |
| 13 | Presale planning | Section 14 preconditions | **Not authorized.** Planning blocked until all preconditions are met |

This summary is internal and non-binding. It does not replace any canonical document and does not commit QBIND to any of the listed directions.

---

**End of QBIND Tokenomics Decision Framework v1.0.**