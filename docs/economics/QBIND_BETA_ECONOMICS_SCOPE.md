# QBIND Beta Economics Scope

**Version**: 1.0
**Date**: 2026-05-01
**Status**: Internal Beta Economics Scope (Non-Final)

---

> **This document is the canonical internal Beta economics scope, not finalized MainNet tokenomics.**
>
> - Its purpose is to define **exactly what economics-related mechanisms, policies, and measurements TestNet Beta is intended to exercise**.
> - It does **NOT** finalize MainNet tokenomics, issuance numbers, fee ratios, genesis supply, allocation, or distribution.
> - It does **NOT** authorize, schedule, price, or imply any presale, public sale, airdrop, or token distribution.
> - It does **NOT** constitute marketing, investment, pricing, or valuation material.
> - It is **operationally concrete** enough to guide Beta planning, but every economic parameter herein is **draft** and exists for evidence collection only.
> - Canonical protocol behavior remains defined by:
>   - `docs/whitepaper/QBIND_WHITEPAPER.md`
>   - `docs/protocol/QBIND_PROTOCOL_REPORT.md`
>   - `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
>   - `docs/whitepaper/contradiction.md`
> - Release sequencing remains governed by `docs/release/QBIND_RELEASE_TRACK_SPEC.md`.
> - Economics design space is defined by `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`.
> - Tokenomics decision sequencing is defined by `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`.
> - This document does not repeat those documents; it converts them into a Beta-scoped, observable test plan.

---

## 1. Purpose and Scope

### 1.1 Purpose

QBIND has reached a point where:

- The release track defines TestNet Beta as the **economics dry-run** stage.
- The economics design space has been drafted.
- The tokenomics decision framework has been drafted.
- Alpha posture is technical, not economic.
- MainNet economics must be finalized **after** Beta, not during it.

What is missing is a concrete, internal definition of **what Beta will and will not simulate economically**. Without that, Beta will either drift into informal economics testing (producing weak evidence) or be treated as a tokenomics finalization stage (which it is not).

This document provides that definition.

### 1.2 What This Document Is

- The canonical internal **Beta economics scope**.
- A definition of **what Beta will simulate**, **what Beta will not finalize**, and **what evidence Beta must produce**.
- An input to Beta planning, Beta operator instructions, and post-Beta MainNet economics finalization.

### 1.3 What This Document Is NOT

- Not final MainNet tokenomics.
- Not presale planning.
- Not pricing, valuation, allocation, or distribution policy.
- Not a marketing document.
- Not a substitute for the whitepaper or protocol report.
- Not a commitment that Beta-observed parameters will become MainNet parameters.

### 1.4 Audience

- Internal Beta planners.
- Validator-operator coordinators.
- Authors of the eventual MainNet economics finalization document.
- Reviewers checking that Beta is being run as an evidence stage, not as a tokenomics launch.

---

## 2. Relationship to the Release Track

Per `docs/release/QBIND_RELEASE_TRACK_SPEC.md`:

- **DevNet** is for protocol bring-up, not economics.
- **TestNet Alpha** is for technical validator operation under controlled conditions, not economics finalization.
- **TestNet Beta** is the **economics dry-run** stage: the first stage in which economic mechanisms are exercised live in a way that can produce decision-grade evidence.
- **MainNet** is where economics is finalized and committed.

This document scopes **only** the Beta stage. It does not redefine Alpha (which is governed by `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`) and does not pre-empt MainNet finalization.

Beta is therefore positioned as:

- The **first** stage where economic behavior is observed under a real workload with real validator participation.
- The **last** stage before MainNet economics must be finalized.
- An **evidence-collection** stage, not a commitment stage.

---

## 3. Current Baseline

The following baseline is supported by the existing canonical documents and is the only baseline this document assumes:

- An **economics design draft** exists (`QBIND_ECONOMICS_DESIGN_DRAFT.md`), enumerating monetary-model families, fee-policy families, validator-reward flow options, minimum-stake postures, slashing economics, and reporter-reward (C3) options.
- A **tokenomics decision framework** exists (`QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`), sequencing tokenomics decisions across pre-Beta, in-Beta, and pre-MainNet phases.
- The **release track** designates Beta as the economics dry-run stage.
- **Alpha** is not the final tokenomics stage and is not expected to produce economic evidence at decision-grade.
- **MainNet economics must be finalized later**, not during Beta.
- **C3 (reporter rewards)** is still an open question: presence, shape, and bounding are not decided.
- **Gas / fee machinery** and **slashing enforcement** exist technically in the protocol baseline; Beta does not introduce these mechanisms, it exercises them economically.

Nothing beyond this baseline is assumed. Any parameter or policy not listed here is treated as undecided.

---

## 4. Why Beta Needs an Economics Scope

Beta cannot "figure economics out organically." A defined scope is required for several practical reasons:

1. **Evidence requires controlled choices.** Without an explicit selection of monetary family, fee family, validator-reward flow, minimum stake posture, slashing posture, and C3 posture, Beta cannot generate evidence that is comparable across runs or actionable for MainNet finalization.
2. **Drift risk.** An undefined Beta will drift toward whatever defaults happen to be in code, which biases evidence toward implementation convenience rather than design intent.
3. **Misuse risk.** An undefined Beta is more easily misread externally as a soft tokenomics launch. An explicit scope makes it clear that Beta parameters are draft and bounded.
4. **Internal draft parameters are not public commitments.** A scope document distinguishes "this is what Beta is exercising" from "this is what MainNet will be," which protects the project from inadvertent commitment.
5. **Beta is for testing mechanisms and behavior, not promising MainNet numbers.** The scope must make this distinction structurally, not just rhetorically.
6. **Decision-grade input for MainNet finalization.** MainNet economics finalization will need observed evidence on validator behavior, fee behavior, slashing deterrence, and C3 necessity. Beta is the only stage positioned to produce that evidence; an undefined Beta will fail to produce it.

The Beta economics scope therefore exists to make Beta an instrument of **decision**, not an instrument of **announcement**.

---

## 5. Beta Economics Objectives

Beta has the following concrete economic objectives. Each is an observation objective; none is a finalization objective.

1. **Test the chosen monetary-model family** under live, multi-operator conditions, using draft parameters.
2. **Observe validator participation** (joining, staying, exiting) under the chosen draft validator-reward flow.
3. **Observe fee behavior** under realistic, non-synthetic workload, including fee distribution between burn and reward (or other split components in the chosen family).
4. **Observe slashing deterrence and recovery** under enforced slashing, including the economic behavior of validators that fall below minimum stake.
5. **Collect evidence on whether C3 (reporter rewards) is necessary in MainNet v0**, by either simulating a bounded reporter reward or deliberately deferring it and measuring evidence-reporting activity in its absence.
6. **Stress the minimum-stake posture** for centralization risk vs. exclusionary risk.
7. **Gather evidence to finalize MainNet economics later**, not now.
8. **Surface operator-reported economics pain points** that are not visible from chain data alone.

Beta does **not** itself finalize economics. Beta is a precondition for finalization.

---

## 6. What Beta Will Simulate

This is the operationally concrete section. Each subsection states (a) what Beta should simulate, (b) what decision Beta is intended to inform, and (c) what remains provisional.

### 6.1 Monetary Model Family

- **Beta should simulate**: a **bounded inflation** model, or a **hybrid fee-offset issuance** model, drawn from the families documented in the economics design draft.
- **Decision Beta informs**: which monetary-model family is operationally sustainable under live conditions and validator participation.
- **Provisional**: exact issuance rates, exact bounding curves, exact fee-offset thresholds, and the final family choice for MainNet are all **draft** and **non-committal**.

Beta does not pick a final family. Beta picks a family **for evidence collection**. Multiple Beta phases may use different families if needed.

### 6.2 Issuance Behavior

- **Beta should simulate**: **active issuance**, with conservative draft parameters.
- **Decision Beta informs**: whether issuance-supported security budget is viable under low-activity and high-activity conditions, and how validator participation responds to active issuance.
- **Provisional**: issuance rates, decay schedules, issuance caps, and any issuance-fee interaction.

Issuance must be **on** during Beta because MainNet may rely on issuance-supported security, especially in low-fee periods. A fees-only Beta would silently assume MainNet will always have sufficient fee revenue, which is not yet evidenced.

### 6.3 Fee Policy Family

- **Beta should simulate**: a **split** fee-policy family (burn + reward), drawn from the fee-policy families in the economics design draft.
- **Decision Beta informs**: whether a split fee policy produces sane anti-spam behavior, sane validator incentives, and no obvious distortions; and what a defensible MainNet ratio range looks like.
- **Provisional**: the exact burn/reward ratio, any tier structure, any priority-fee mechanics, and the final fee-policy family for MainNet.

Beta does **not** lock a final ratio. Ratios chosen for Beta are observation inputs.

### 6.4 Validator Reward Flow

- **Beta should simulate**: **issuance + fees** as the validator reward source.
- **Decision Beta informs**: whether validator participation is sustained under a combined reward flow, and how participation degrades under low-fee conditions.
- **Provisional**: split between issuance share and fee share, performance-conditioned reward scaling, and any validator-class differentiation.

A fees-only assumption is not safe. Under low-activity conditions, fees-only would understate the security budget and bias Beta toward an unrealistic MainNet picture. Beta must therefore include issuance in the reward flow.

### 6.5 Minimum Stake Posture

- **Beta should simulate**: a **conservative-medium** draft minimum stake — high enough to be security-relevant, low enough not to be obviously exclusionary.
- **Decision Beta informs**: whether the minimum stake threshold is too high (centralizing), too low (insecure), or plausible.
- **Provisional**: the exact MainNet minimum stake number is **not** set here unless it has already been canonically defined elsewhere; any number used in Beta is draft.

Beta is the stage where stake thresholds are validated against live participation patterns and centralization risk indicators. Beta is not the stage where the MainNet number is committed.

### 6.6 Slashing Economics

- **Beta should simulate**: **enforced slashing** under the canonical slashing schedule structure, observing deterrence, validator churn, recovery behavior, and below-threshold consequences.
- **Decision Beta informs**: whether slashing magnitudes deter misbehavior without producing pathological churn or unrecoverable validator states.
- **Provisional**: tuning of slashing magnitudes within the canonical schedule structure.

Beta does **not** change canonical offense definitions. Beta does **not** invent new slashing categories. Beta exercises the existing slashing economics under live conditions.

### 6.7 Reporter Rewards (C3)

C3 must be handled explicitly. Two Beta-scope paths exist:

- **Path A — Minimal bounded reporter rewards**: simulate C3 with a small, capped reporter reward, sufficient to observe whether evidence-reporting activity changes meaningfully when a reward exists.
- **Path B — Deliberate deferral**: run Beta **without** reporter rewards, and measure whether evidence-reporting activity is materially suppressed in the absence of a reward.

**Recommended Beta default**: **Path B (deferral)** as the primary Beta posture, with the option to perform a bounded Path A sub-phase if Path B suggests material suppression of evidence reporting. This recommendation is **Beta policy only** and is not a MainNet commitment.

Beta must answer: **is C3 necessary in MainNet v0?** That answer is not assumed in advance.

### 6.8 Test Asset Naming and Communication

This section is strict.

- The Beta test asset **must use a distinct symbol and naming** from any intended MainNet asset.
- All Beta communications **must explicitly state**: no value, no claim, no redemption, no convertibility, no implied future allocation.
- Beta economic observations **are not public promises**, and must not be presented as pricing, valuation, distribution, or allocation guidance.
- No Beta artifact, dashboard, status page, or operator communication may use language that suggests Beta participation will translate into MainNet allocation, presale eligibility, or any economic right.

This is not a marketing constraint; it is an integrity constraint on the evidence Beta produces.

---

## 7. What Beta Will Explicitly Not Finalize

Beta will **not** finalize, and must not be presented as finalizing, any of the following:

- Final MainNet issuance numbers, schedules, or caps.
- Final burn/reward ratio or final fee-policy family selection for MainNet.
- Final genesis supply.
- Final allocation categories and percentages.
- Final validator reward flow shape for MainNet.
- Final minimum stake number for MainNet.
- Final slashing magnitudes for MainNet.
- Final C3 inclusion/exclusion decision for MainNet (Beta produces evidence; the decision is made afterward in the MainNet finalization document).
- Presale posture, presale authorization, presale pricing, or presale eligibility.
- Public sale, listing, exchange, or distribution strategy.
- Any price, valuation, or market-cap assumption.
- Any legal, regulatory, jurisdictional, or compliance commitment.

A clean way to think about this: Beta's job is to make these decisions **possible later**, not to make them.

---

## 8. Metrics Beta Must Collect

Beta is required to collect, at minimum, the following metrics. These are not "nice to have"; they are the basis for MainNet finalization evidence.

1. **Validator participation and churn**: validator set size over time, joins, exits, and time-in-set distributions.
2. **Fee volume and distribution**: total fees paid, fees burned vs. fees rewarded (under the chosen split family), per-block fee variance, and fee-per-transaction distributions.
3. **Issuance volume**: total issued under the chosen draft parameters, issuance per epoch/period, and issuance vs. fee share of validator rewards.
4. **Staking participation**: total stake, active stake, stake distribution across validators, and changes in stake over time.
5. **Slashing events and post-slash outcomes**: number and category of slashings, validator state after slashing, recovery vs. permanent exit, and downstream effect on validator-set composition.
6. **Below-minimum-stake exclusions**: how often validators fall below minimum stake, why, and what happens after.
7. **Evidence reporting activity**: number and quality of reports, whether under Path A (with bounded reward) or Path B (without reward), so that the C3 necessity question can be evaluated.
8. **Workload and throughput context**: transactions per period, block fullness, and load patterns sufficient to interpret fee and issuance numbers in context.
9. **Operator-reported economics pain points**: structured, qualitative reports from validator operators on incentives, friction, and surprises that chain data alone will not surface.

Metrics not collected at Beta cannot be invented at MainNet finalization. The collection plan must therefore be in place before Beta launch, not after.

---

## 9. Beta Evaluation Questions

Beta is a decision instrument. Its results must be readable as answers to specific questions, not as a free-form report.

1. Does the chosen monetary-model family appear operationally sustainable under live conditions and realistic workload variation?
2. Are validators remaining online and participating under the chosen draft validator-reward flow, including during low-fee periods?
3. Does the chosen fee-policy family produce sane anti-spam behavior without obvious distortions (e.g., extreme fee volatility, validator-side gaming, user-side avoidance)?
4. Is the draft minimum stake too high (centralization, exclusionary), too low (insecure, easily attacked), or still plausible?
5. Does enforced slashing deter misbehavior without producing pathological churn or unrecoverable validator states?
6. Does the absence (or bounded presence) of reporter rewards materially affect evidence-reporting activity? In other words, **is C3 necessary in MainNet v0?**
7. Are there economics-related operational pain points (validator UX, accounting, fee predictability) that must be addressed before MainNet finalization?
8. Are the Beta-observed patterns stable enough across the Beta period to be treated as evidence, or is more observation needed before MainNet finalization?

Each question should have an explicit, written answer at Beta exit, even if the answer is "insufficient evidence."

---

## 10. Beta Exit-Relevant Economics Evidence

At Beta exit, the following evidence artifacts should exist. None of these are final answers; all of them are inputs to MainNet finalization.

- **Validator-economics observations**: a usable summary of validator participation, churn, and reward-flow behavior under the chosen draft parameters.
- **Draft fee-policy tuning inputs**: observed fee distributions, observed effects of the chosen split family, and a defensible range (not a point) for MainNet fee-policy parameters.
- **Centralization-risk observations**: stake distribution patterns, minimum-stake exclusion patterns, and validator concentration indicators.
- **Slashing deterrence observations**: number and category of slashings, deterrence evidence, churn evidence, and recovery evidence.
- **C3 recommendation**: an evidenced recommendation on whether reporter rewards should exist in MainNet v0, derived from Path A and/or Path B observation.
- **Issuance observations**: how active issuance interacted with fee revenue, and whether the security budget held up under low-activity conditions.
- **Operator-reported economics pain points**: a structured list, not anecdotal.

These artifacts feed directly into the MainNet economics finalization document. Beta exit is therefore tied to economics finalization readiness, not just to technical stability.

---

## 11. Risks of Misusing Beta Economics Results

The following misuses must be actively prevented. These are not theoretical risks; they are predictable.

1. **Treating draft Beta parameters as public promises.** Any quoted Beta parameter (issuance rate, fee ratio, minimum stake, slashing magnitude) is draft and exists for observation. It must not be quoted externally as a MainNet parameter or as a commitment.
2. **Treating test token behavior as price discovery.** The Beta test asset has no value, no claim, and no redemption. Any "price" or "valuation" derived from Beta activity is meaningless and must not be cited.
3. **Overfitting MainNet economics to short Beta observations.** Beta is finite. Patterns observed over a short Beta window may not reflect long-run MainNet behavior. MainNet finalization must treat Beta evidence as **directional**, not **definitive**.
4. **Assuming Beta participation equals MainNet participation.** Beta participants are a self-selected, possibly incentivized, possibly experimental cohort. Their behavior is not a one-to-one predictor of MainNet behavior.
5. **Leaking presale expectations from Beta activity.** Beta participation must not be presented, internally or externally, as conferring presale eligibility, allocation, discount, priority, or any economic right.
6. **Confusing "Beta exercised mechanism X" with "MainNet will use mechanism X."** Beta is allowed (and encouraged) to exercise mechanisms that may be revised or rejected before MainNet.
7. **Treating absence of evidence as evidence.** If Beta does not collect a metric, MainNet finalization cannot rely on it. Missing metrics must be acknowledged as gaps, not assumed to be benign.

The defensive posture here is deliberate. The cost of misuse is asymmetric: misuse compromises the project's integrity; conservatism does not.

---

## 12. Recommended Beta Economics Defaults

The following are **recommended Beta defaults**, expressed as Beta policy. They are **not** MainNet commitments.

| Area | Recommended Beta Default |
| --- | --- |
| Monetary model family | Bounded inflation **or** hybrid fee-offset issuance (one chosen for the Beta phase) |
| Issuance | **On**, with conservative draft parameters |
| Fee policy family | **Split** (burn + reward), draft ratio |
| Validator reward flow | **Issuance + fees** (not fees-only) |
| Minimum stake posture | Conservative-medium draft, security-relevant but not obviously exclusionary |
| Slashing | Enforced, under the canonical slashing schedule structure, with magnitudes drawn from draft |
| C3 (reporter rewards) | **Path B (deferral)** as primary; bounded Path A sub-phase only if Path B suggests material suppression of evidence reporting |
| Test asset naming | Distinct symbol from any intended MainNet asset; explicit no-value / no-claim / no-redemption language in all communications |
| Public posture | Internal evidence collection; no pricing, valuation, allocation, or presale language |

Each row is **draft** and **observation-oriented**. Each row is the most operationally useful single statement of Beta posture in this document.

---

## 13. Follow-Up Decisions After Beta

Beta is not the end of economics work; it is the precondition for the next set of decisions. Beta evidence should enable, in order:

1. **Finalize MainNet monetary model** (family and parameters), informed by §6.1, §6.2, §10.
2. **Finalize MainNet fee policy** (family and ratio range), informed by §6.3, §10.
3. **Finalize MainNet validator reward flow**, informed by §6.4, §10.
4. **Finalize MainNet minimum stake**, informed by §6.5, §10.
5. **Finalize MainNet slashing magnitudes** within the canonical schedule structure, informed by §6.6, §10.
6. **Decide whether reporter rewards (C3) exist in MainNet v0**, informed by §6.7, §10.
7. **Finalize genesis supply and allocation categories**, in the dedicated MainNet economics finalization document — **not** here and **not** during Beta.
8. **Determine whether presale planning may even begin**, only after the above finalization preconditions are met. Beta does not authorize this discussion; it only makes it eventually possible.

Each of these decisions belongs to a downstream document. None of them is made by this scope or by Beta itself.

---

## 14. Final Scope Summary

- Beta is the **economics dry-run** stage, governed by the release track.
- Beta will simulate a **defined** monetary model family, **active** issuance, a **split** fee policy family, **issuance + fees** validator rewards, a **conservative-medium** draft minimum stake, **enforced** slashing under the canonical schedule structure, and a **deliberately scoped** C3 posture (default: deferral).
- Beta will use a **distinct** test asset symbol with explicit no-value language.
- Beta will **not** finalize MainNet issuance, fee ratios, supply, allocation, presale, pricing, or distribution.
- Beta will **collect specific metrics** sufficient to answer specific evaluation questions and to produce specific exit-relevant evidence artifacts.
- Beta evidence will feed directly into MainNet economics finalization, which is performed afterward and elsewhere.
- All Beta parameters are **draft**, **internal**, and **non-committal**.
- All Beta communications must structurally prevent misuse of Beta as a tokenomics launch.

This document is the canonical internal definition of that scope.