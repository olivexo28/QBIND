# QBIND MainNet Economics Finalization

**Version**: 1.0
**Date**: 2026-05-03
**Status**: Canonical Internal MainNet Economics Finalization Document (MainNet v0)

---

> **This document is the canonical internal MainNet economics finalization record for QBIND MainNet v0.**
>
> - Its purpose is to record the final economics decisions required before MainNet authorization can be considered.
> - It does **NOT** itself authorize MainNet launch.
> - It does **NOT** authorize any presale, pricing, sale structure, vesting, or external sale commitment.
> - It does **NOT** constitute marketing, investment, valuation, or pricing material.
> - Canonical protocol behavior remains defined by:
>   - `docs/whitepaper/QBIND_WHITEPAPER.md`
>   - `docs/protocol/QBIND_PROTOCOL_REPORT.md`
>   - `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
>   - `docs/whitepaper/contradiction.md`
> - Release sequencing remains governed by `docs/release/QBIND_RELEASE_TRACK_SPEC.md`.
> - Readiness gating remains governed by `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`.
> - Beta economics scope remains governed by `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`.
> - Tokenomics decision sequencing remains governed by `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`.
> - Economics design space is documented in `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`.

---

## 1. Purpose and Scope

### 1.1 Purpose

QBIND has reached a point where:

- Release sequencing is defined.
- Alpha and Beta plans exist.
- The Beta economics scope exists and positions Beta as the economics dry-run / evidence-collection stage.
- The MainNet readiness checklist explicitly requires a MainNet economics finalization document **before** MainNet may be considered for authorization.

This document is that required finalization record. It converts the prior draft economics materials, the tokenomics decision framework, and the Beta evidence posture into a single canonical internal record of what is **finalized for MainNet v0** and what remains future-governance territory.

### 1.2 What This Document Is

- The canonical internal **MainNet v0 economics finalization** record.
- A reviewable artifact that the MainNet readiness checklist (§8) depends on.
- A traceability layer from canonical economics decisions back to Beta evidence and decision-framework reasoning.
- A statement of which categories of economics parameters are finalized at the family level, which require explicit numeric values before MainNet authorization, and which remain future-governance.

### 1.3 What This Document Is NOT

- Not the MainNet launch authorization. Authorization remains a separate, explicit step under the release-track spec.
- Not the readiness assessment itself. Readiness is governed by the readiness checklist.
- Not a public tokenomics or marketing whitepaper.
- Not a presale authorization, pricing document, or distribution commitment.
- Not a substitute for the whitepaper or protocol report.
- Not a vehicle for inventing final numeric parameters that are not supported by prior canonical materials. Where numeric values are not yet decided, this document marks them as `REQUIRED FINAL VALUE` and treats them as authorization blockers.

### 1.4 Audience

- Internal protocol engineers, economics working group, governance reviewers.
- Authors and reviewers of the MainNet readiness assessment.
- Operators who require an internal, authoritative reference for MainNet v0 economic posture.

---

## 2. Relationship to the Release Track and MainNet Readiness

The QBIND release sequence is:

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

Per `docs/release/QBIND_RELEASE_TRACK_SPEC.md` and `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`:

- **DevNet** is for protocol bring-up; not an economics stage.
- **TestNet Alpha** is technical validator operation; not an economics stage.
- **TestNet Beta** is the **economics dry-run / evidence stage**. All Beta economic parameters are draft and exist for evidence collection. Beta does not finalize MainNet economics.
- **MainNet v0** is where economics is finalized and committed.

This document is the bridge between Beta-as-evidence and MainNet-as-commitment. Specifically:

- Beta is treated here as the **economics evidence stage** that informs the decisions recorded below.
- This document is **required** by the MainNet readiness checklist (§8 of that checklist) before MainNet may be considered.
- This document is **necessary but not sufficient** for MainNet launch:
  - A complete and filled-in version of this document is a precondition for MainNet readiness assessment.
  - MainNet readiness assessment is a precondition for MainNet authorization consideration.
  - MainNet authorization remains a separate, explicit step governed by the release-track spec.
- This document **does not** loosen, override, or substitute for any item in the readiness checklist. Where this document and the checklist overlap, the checklist remains the gating instrument.

> **Beta success is necessary but not sufficient for MainNet.** Likewise, the existence of this finalization document is necessary but not sufficient for MainNet authorization.

This document remains aligned with, and subordinate to:

- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md` (evidence stage scope)
- `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md` (decision sequencing and principles)
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` (gating)
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md` (release sequencing)

If a conflict is discovered, the canonical documents above govern, and this document must be reconciled.

---

## 3. Inputs Used for Finalization

The decisions in §5 must be traceable to one or more of the following inputs. Decisions that cannot be traced to any of these inputs are not eligible for finalization in this document.

**Economics inputs:**

- `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md` — design space (monetary-model families, fee-policy families, validator-reward flow options, minimum-stake postures, slashing economics, C3 options).
- `docs/economics/QBIND_TOKENOMICS_DECISION_FRAMEWORK.md` — decision principles and sequencing.
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md` — what Beta is required to simulate, measure, and produce as evidence.

**Beta evidence inputs (used as cited; collected per the Beta plan and Beta economics scope):**

- The Beta evidence packet, comprising:
  - Validator-economics observations (participation, churn, reward-flow behavior).
  - Fee-policy observations (split behavior, fee distributions, anti-spam behavior).
  - Issuance observations (issuance vs. fee share of validator rewards under varying activity).
  - Minimum-stake observations (centralization vs. exclusionary risk indicators).
  - Slashing observations (deterrence, churn, recovery, below-threshold consequences).
  - C3 (reporter rewards) observations under Path A and/or Path B per `QBIND_BETA_ECONOMICS_SCOPE.md` §6.7.
  - Operator-reported economics pain points.
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` — Beta operational plan that produced the above evidence.

**Release and readiness inputs:**

- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md`

**Protocol-canonical inputs (used where economics decisions touch protocol behavior):**

- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

Each subsection of §5 is required to cite the specific input(s) used. Decisions that rely on Beta evidence must reference the corresponding Beta scope section (e.g., §6.x of `QBIND_BETA_ECONOMICS_SCOPE.md`). Decisions that rely on framework reasoning must reference the relevant section of `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`. Decisions that rely on protocol-canonical structure (e.g., slashing offense classes O1–O5) must reference the canonical protocol documents.

---

## 4. Finalization Philosophy

The principles governing this finalization are deliberately conservative:

1. **Traceability over taste.** Every final v0 decision must be traceable to (a) Beta evidence, (b) explicit decision-framework reasoning, or (c) canonical protocol structure. Decisions traceable only to convenience or unstated preference are not eligible.
2. **No finalization by omission.** A topic is finalized only when this document explicitly records a decision. Silence on a MainNet-critical economics topic does **not** count as finalization, and does not satisfy the readiness checklist.
3. **No automatic promotion of Beta drafts.** A draft parameter value used during Beta is **not** promoted to MainNet final by virtue of having been used in Beta. Promotion requires explicit adoption recorded in this document, with rationale.
4. **Simplicity preferred where evidence is mixed.** Where Beta evidence is ambiguous or inconclusive, the simpler family-level choice is preferred over a more complex, less-validated mechanism. Complexity that Beta did not validate is rejected for v0.
5. **Family-level finalization is mandatory; numeric finalization is mandatory before authorization.** This document must finalize the family-level choice for every required topic. Where a numeric value is not yet decided in canonical materials, this document marks it as `REQUIRED FINAL VALUE` and treats MainNet authorization as blocked until that value is filled.
6. **Future-governance hooks are acceptable; unresolved MainNet-critical economics are not.** Items the readiness checklist requires finalized for v0 cannot be deferred to "post-launch governance." Items that are genuinely future-governance territory (e.g., parameter tuning ranges within governance bounds) may be deferred and recorded in §7.
7. **Conservatism over optimism.** Where doubt exists, the more conservative choice is taken. Launch delay is acceptable. Unsafe or under-evidenced launch is not.
8. **No backdoor authorization.** This document must not, by phrasing or omission, imply MainNet authorization, presale authorization, pricing, valuation, or any external commitment. Such authorizations require separate, explicit instruments outside this document.

These principles bind every subsection of §5.

---

## 5. Finalized MainNet v0 Decisions

This section is the core of the document.

For each subsection, the following structure is used:

- **Final v0 decision** — the family-level (and where available, numeric) finalization for MainNet v0.
- **Rationale** — why this is the finalized choice.
- **Inputs cited** — Beta scope section, decision-framework reference, design-draft reference, or protocol-canonical reference.
- **Future-governance scope** — what may be adjusted by governance after v0 (if any).
- **Required final values** — explicit `REQUIRED FINAL VALUE` placeholders that must be filled before MainNet authorization, where applicable.

A consolidated list of all `REQUIRED FINAL VALUE` placeholders is summarized in §10.

### 5.1 Final Monetary-Model Family

- **Final v0 decision (family):** **Bounded inflation**, with explicit support for fee-offset interaction in the validator-reward flow (§5.3). The family is "bounded inflation" rather than "fixed supply," "fixed supply + reward pool," or pure "hybrid fee-offset issuance."
- **Rationale:**
  - The Beta economics scope mandates **active issuance** during Beta because a fees-only model would silently assume MainNet always has sufficient fee revenue, which is not yet evidenced (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.2).
  - The Beta scope further recommends, as Beta posture, either **bounded inflation** or **hybrid fee-offset issuance** drawn from the design draft (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.1, §12).
  - Of those two, **bounded inflation** is the simpler, more readily validated family. Per §4 principle 4 ("simplicity preferred where evidence is mixed"), the simpler family is selected for v0 unless Beta evidence affirmatively requires the more complex hybrid form. Fee-offset interaction may still be expressed inside the bounded-inflation family via §5.3 without elevating "hybrid fee-offset issuance" itself to the family-level choice.
  - A pure fixed-supply or fixed-supply + reward-pool model is rejected for v0 because it cannot guarantee a security budget under low-fee conditions, which Beta cannot rule out.
- **Inputs cited:** `QBIND_ECONOMICS_DESIGN_DRAFT.md` (monetary-model families), `QBIND_BETA_ECONOMICS_SCOPE.md` §6.1–§6.2, §12; `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md` (decision principles); Beta evidence packet (issuance observations, validator participation under low-fee conditions).
- **Future-governance scope:** Numeric tuning of issuance rate, decay schedule, and bounding curve **within** the bounded-inflation family is governance-adjustable post-v0 within bounds defined at MainNet authorization. Switching to a different monetary-model family is **not** in-scope for governance and would require a future MainNet revision.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 issuance rate parameters (rate, basis period).`
  - `REQUIRED FINAL VALUE — v0 issuance bounding curve (cap, decay schedule if any).`
  - `REQUIRED FINAL VALUE — governance bounds within which post-v0 issuance tuning is permitted.`

### 5.2 Final Fee-Policy Family

- **Final v0 decision (family):** **Split burn/reward** fee policy. This is the family choice; the exact ratio is a required final value below.
- **Rationale:**
  - The Beta scope mandates simulating a **split** fee-policy family (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.3, §12) so that anti-spam behavior, validator incentives, and burn/reward dynamics can be observed.
  - "Burn-only" is rejected for v0 because it removes fee-driven validator incentive entirely, increasing dependence on issuance for security budget under variable activity.
  - "Proposer-only" is rejected for v0 because it removes the deflationary/disinflationary anchor and increases sensitivity to fee-driven validator gaming.
  - **Split burn/reward** retains both an anti-spam/burn anchor and a validator incentive component, and is the family Beta is required to exercise. Choosing it for v0 is the conservative, evidence-aligned choice.
- **Inputs cited:** `QBIND_ECONOMICS_DESIGN_DRAFT.md` (fee-policy families); `QBIND_BETA_ECONOMICS_SCOPE.md` §6.3, §12; Beta evidence packet (fee distribution, anti-spam observations).
- **Future-governance scope:** The burn/reward ratio is permitted to be governance-adjustable within an explicit bounded range fixed at MainNet authorization. The family itself (split burn/reward) is **not** governance-adjustable in v0; switching family would require a future MainNet revision.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 burn share (percentage of fees burned).`
  - `REQUIRED FINAL VALUE — v0 reward share (percentage of fees rewarded to validators).`
  - `REQUIRED FINAL VALUE — governance bounds within which post-v0 ratio tuning is permitted.`
  - `REQUIRED FINAL VALUE — v0 priority/tier mechanics, if any (otherwise explicitly recorded as "none in v0").`

### 5.3 Final Validator Reward Flow

- **Final v0 decision:** **Issuance + fees**. Validator rewards in MainNet v0 are sourced from **both** bounded issuance (§5.1) and the reward share of fees (§5.2). No separate reward-pool drawdown mechanism is introduced in v0.
- **Rationale:**
  - The Beta scope mandates **issuance + fees** as the validator reward source and explicitly rejects fees-only as biasing observation toward an unrealistic MainNet picture (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.4).
  - Issuance-only (with no fee-derived reward) would remove the user-side incentive pressure that fee participation creates and would conflict with §5.2.
  - A separate reward-pool drawdown mechanism is rejected for v0 under §4 principle 4: it adds complexity Beta did not validate, and it duplicates issuance with weaker bounding properties.
  - The chosen flow is internally consistent with §5.1 (bounded inflation) and §5.2 (split burn/reward), and is the structure Beta exercises.
- **Inputs cited:** `QBIND_ECONOMICS_DESIGN_DRAFT.md` (validator reward flow options); `QBIND_BETA_ECONOMICS_SCOPE.md` §6.4, §12; Beta evidence packet (validator participation, low-fee period observations).
- **Future-governance scope:** The relative weighting of the issuance and fee components within validator reward computation may be governance-adjustable within explicit bounds fixed at MainNet authorization. Performance-conditioned reward scaling and validator-class differentiation are **not** introduced in v0 and are future-governance items (see §7).
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 split between issuance share and fee share of validator rewards (or formula).`
  - `REQUIRED FINAL VALUE — governance bounds for adjusting that split post-v0.`

### 5.4 Final Minimum Stake Policy

- **Final v0 decision:**
  - MainNet v0 **has** a minimum stake policy. Existence is finalized and not optional.
  - The minimum stake is a **fixed v0 number** at genesis, with governance authority to adjust it post-v0 within explicit bounds set at MainNet authorization.
  - Validators falling below the minimum stake are subject to the canonical below-threshold consequences as exercised in Beta (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.5–§6.6, metric §8.6).
- **Rationale:**
  - The Beta scope explicitly stresses minimum-stake posture against centralization risk and exclusionary risk and treats minimum stake as a required mechanism (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.5).
  - Leaving the existence of minimum stake undecided is excluded by §4 principle 2 ("no finalization by omission").
  - Fixing a v0 number with bounded governance adjustment is consistent with §4 principle 5 (family/structure final, numeric value bounded) and with the readiness checklist requirement that the final minimum stake be chosen and recorded.
- **Inputs cited:** `QBIND_BETA_ECONOMICS_SCOPE.md` §6.5; `QBIND_ECONOMICS_DESIGN_DRAFT.md` (minimum-stake postures); `QBIND_MAINNET_READINESS_CHECKLIST.md` §8; Beta evidence packet (stake distribution, below-minimum exclusions).
- **Future-governance scope:** Adjustment of the minimum stake within explicit bounds, post-v0, is governance-adjustable. Removal of the minimum stake mechanism itself is **not** governance-adjustable in v0.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 minimum stake (numeric, in MainNet asset units).`
  - `REQUIRED FINAL VALUE — governance bounds (lower/upper) within which post-v0 adjustment is permitted.`

### 5.5 Final Slashing Economics Posture

> This subsection does **not** redefine offense classes. Offense classes O1–O5 are canonical (see `QBIND_ECONOMICS_DESIGN_DRAFT.md` §97, §111–§116; whitepaper §12.2). They are referenced here, not authored here.

- **Final v0 decision:**
  - MainNet v0 posture is **EnforceAll** over the canonical **O1–O5** offense structure. All five offense classes are economically enforced in v0.
  - Slashing in MainNet v0 is real economic deterrence, not draft Beta policy. Slashing magnitudes and jail durations are governance-controlled within an explicit schedule structure fixed at MainNet authorization, consistent with the canonical schedule structure exercised under Beta.
  - Below-threshold consequences for validators that fall below the minimum stake (§5.4) are enforced.
- **Rationale:**
  - The economics design draft already records **EnforceAll** with full O1–O5 enforcement as the MainNet posture, in contrast to weaker (e.g., EnforceCritical) postures used at earlier stages (`QBIND_ECONOMICS_DESIGN_DRAFT.md` §247, §271, §295).
  - The Beta scope requires enforced slashing under the canonical schedule structure, with magnitudes drawn from draft, and explicitly states that Beta does not change canonical offense definitions or invent new categories (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.6).
  - MainNet must treat slashing as real economic deterrence, not draft policy, per §4 principle 7 (conservatism) and the readiness checklist (no draft Beta parameter treated as final without explicit adoption).
- **Inputs cited:** `QBIND_ECONOMICS_DESIGN_DRAFT.md` (slashing schedule structure, EnforceAll posture); `QBIND_BETA_ECONOMICS_SCOPE.md` §6.6; `QBIND_WHITEPAPER.md` §12.2 (canonical offense classes); Beta evidence packet (slashing events, deterrence, churn, recovery).
- **Future-governance scope:** Tuning of slashing magnitudes and jail durations within the canonical O1–O5 schedule structure is governance-controlled within explicit bounds fixed at MainNet authorization. Adding, removing, or redefining offense classes is **not** governance-adjustable; it would require a protocol-canonical revision.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 slashing magnitudes (basis points) per offense class O1–O5.`
  - `REQUIRED FINAL VALUE — v0 jail durations per offense class O1–O5.`
  - `REQUIRED FINAL VALUE — governance bounds for adjusting magnitudes and durations post-v0.`

### 5.6 Final C3 (Reporter Rewards) Posture for MainNet v0

- **Final v0 decision:** **No reporter rewards (C3) in MainNet v0.** MainNet v0 ships **without** C3.
- **Rationale:**
  - The Beta scope is explicit that C3 must be handled with a clear answer post-Beta, that the recommended Beta default is **Path B (deferral)** as primary, and that bounded Path A is invoked only if Path B suggests material suppression of evidence reporting (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.7, §12).
  - The Beta scope further requires Beta to answer, post-evidence, "is C3 necessary in MainNet v0?" — and §4 principle 4 ("simplicity preferred where evidence is mixed") and principle 7 (conservatism) require defaulting to exclusion unless Beta evidence affirmatively justifies inclusion.
  - Excluding C3 from v0 is consistent with conservative MainNet posture, avoids introducing a reward surface that has not been demonstrated necessary, and matches the readiness checklist requirement that the C3 decision be explicitly recorded.
  - This decision does **not** preclude future C3 introduction. C3 may be reintroduced via governance/protocol revision post-v0 if evidence later supports it (see §7).
- **Inputs cited:** `QBIND_BETA_ECONOMICS_SCOPE.md` §6.7, §10, §12; Beta evidence packet (evidence-reporting activity under Path A and/or Path B); `QBIND_ECONOMICS_DESIGN_DRAFT.md` (C3 options); `QBIND_MAINNET_READINESS_CHECKLIST.md` §8.
- **Future-governance scope:** Future introduction of bounded reporter rewards is **out of scope for v0** but is recognized as a candidate future-governance item, contingent on additional evidence (see §7). v0 does not pre-commit to such introduction.
- **Required final values:** None for v0 (C3 is excluded). Explicitly recorded as "no reporter rewards in v0."

### 5.7 Final Test-Asset vs MainNet-Asset Distinction

- **Final v0 decision:**
  - MainNet asset naming is **distinct and authoritative**. The MainNet asset symbol and name used at v0 genesis are the only canonical MainNet asset identifiers.
  - Test assets used in DevNet, Alpha, and Beta:
    - have **no value**, **no claim**, **no redemption**, **no convertibility**, and **no allocation right**;
    - **do not** confer any right to MainNet allocation, presale eligibility, distribution, discount, or priority;
    - **must** use a symbol distinct from the MainNet asset symbol;
    - **must not** be referred to in any communication in a way that suggests future convertibility into MainNet asset.
  - All internal and external communications about MainNet must preserve this distinction. Any communication that conflates test-asset participation with MainNet rights is a launch-safety violation.
- **Rationale:**
  - The Beta scope already requires distinct test-asset naming and explicit no-value / no-claim / no-redemption language (`QBIND_BETA_ECONOMICS_SCOPE.md` §6.8, §11.2, §11.5, §12). This subsection promotes that posture from a Beta constraint to a canonical MainNet-launch-safety constraint.
  - Without this distinction, test-period activity could be misread as conferring MainNet economic rights, which is excluded by the readiness checklist (§8) and by §8 of this document.
- **Inputs cited:** `QBIND_BETA_ECONOMICS_SCOPE.md` §6.8, §11; `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md` (decision principles); `QBIND_MAINNET_READINESS_CHECKLIST.md` §8.
- **Future-governance scope:** None. This distinction is not governance-adjustable; weakening it would constitute a launch-safety regression.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 MainNet asset symbol.`
  - `REQUIRED FINAL VALUE — v0 MainNet asset name.`
  - `REQUIRED FINAL VALUE — confirmation that the v0 MainNet asset symbol and name are distinct from any test-asset symbol used in DevNet/Alpha/Beta.`

### 5.8 Final Genesis Supply Decision

- **Final v0 decision:**
  - MainNet v0 genesis supply is a **fixed, finalized numeric value at genesis**, expressed in MainNet asset units.
  - Genesis supply is **not** a draft value. It is required to be canonically determined before MainNet authorization is considered.
  - Post-genesis supply evolution is governed by the bounded-inflation monetary model (§5.1) within governance bounds.
- **Rationale:**
  - The Beta scope explicitly states that genesis supply is **not** finalized by Beta and must be finalized in the dedicated MainNet economics finalization document — i.e., here (`QBIND_BETA_ECONOMICS_SCOPE.md` §7, §13.7).
  - The readiness checklist requires that the final genesis supply be chosen and recorded (`QBIND_MAINNET_READINESS_CHECKLIST.md` §8).
  - Per §4 principle 2 ("no finalization by omission"), this document must record an explicit value or explicit `REQUIRED FINAL VALUE` placeholder; it cannot be left implicit.
- **Inputs cited:** `QBIND_BETA_ECONOMICS_SCOPE.md` §7, §13.7; `QBIND_MAINNET_READINESS_CHECKLIST.md` §8; `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`; `QBIND_ECONOMICS_DESIGN_DRAFT.md`.
- **Future-governance scope:** Post-genesis supply trajectory is governed by §5.1 (bounded inflation, governance-adjustable within bounds). The genesis number itself is **not** governance-adjustable post-genesis; it is fixed at v0.
- **Required final value (blocks authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 genesis supply (numeric, in MainNet asset units).`
  - **MainNet authorization cannot proceed until this value is filled.** This is recorded explicitly because no canonical material currently supports a single, evidenced numeric value, and §4 principle 2 forbids handwaving.

### 5.9 Final Genesis Allocation Categories

- **Final v0 decision (categories that exist):**
  - **Validator / security reserve** — exists in v0. Purpose: validator-security-aligned allocation supporting initial security budget and staking.
  - **Treasury / community reserve** — exists in v0. Purpose: protocol-level treasury for non-discretionary infrastructure and community-aligned uses, governance-controlled within the bounds set at MainNet authorization.
  - **Foundation / team reserve** — exists in v0. Purpose: project continuity allocation, subject to vesting/lock-up parameters defined at MainNet authorization.
  - **Ecosystem / developer reserve** — exists in v0. Purpose: ecosystem and developer support, governance-controlled.
- **Final v0 decision (categories that do NOT exist in v0):**
  - **Investor reserve / presale reserve** — **does not exist** in v0 by virtue of this document. No investor reserve, presale reserve, or sale-allocated category is introduced into v0 genesis allocation by this finalization. (See §8: presale and external-sale boundary.) Introduction of any such category in the future would require a separate, explicit, externally authorized instrument outside the scope of this document.
  - **Airdrop reserve / public-distribution reserve** — not introduced in v0 by this document.
  - **Liquidity / market-making reserve** — not introduced in v0 by this document.
- **Rationale:**
  - The Beta scope explicitly forbids finalizing allocation in Beta and forbids implying presale eligibility from Beta participation (`QBIND_BETA_ECONOMICS_SCOPE.md` §7, §11.5).
  - The readiness checklist requires explicit allocation categories to be defined, while strictly forbidding presale implication (`QBIND_MAINNET_READINESS_CHECKLIST.md` §8).
  - Per §4 principle 2 and principle 8, both **which categories exist** and **which do not** are recorded explicitly here. Silence is not finalization.
  - Per §8, the existence of a category is **not** sale authorization, and the explicit non-existence of an investor / presale reserve in v0 is the conservative default consistent with the absence of any presale authorization.
- **Inputs cited:** `QBIND_BETA_ECONOMICS_SCOPE.md` §7, §11.5; `QBIND_MAINNET_READINESS_CHECKLIST.md` §8; `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`; `QBIND_ECONOMICS_DESIGN_DRAFT.md`.
- **Future-governance scope:** Within the categories that **exist** in v0, parameter-level adjustments (e.g., disbursement schedules from the treasury reserve, ecosystem-grant policies) may be governance-controlled within bounds fixed at MainNet authorization. Adding new top-level genesis categories — including any investor / sale / airdrop / liquidity category — is **not** governance-adjustable in v0 and would require a separate, externally authorized instrument.
- **Required final values (block authorization until filled):**
  - `REQUIRED FINAL VALUE — v0 percentage allocation for validator / security reserve.`
  - `REQUIRED FINAL VALUE — v0 percentage allocation for treasury / community reserve.`
  - `REQUIRED FINAL VALUE — v0 percentage allocation for foundation / team reserve, including vesting/lock-up parameters.`
  - `REQUIRED FINAL VALUE — v0 percentage allocation for ecosystem / developer reserve.`
  - `REQUIRED FINAL VALUE — confirmation that the above sum equals the v0 genesis supply (§5.8) and that no other genesis category is introduced.`

---

## 6. Beta-Evidence Traceability

Each finalized decision in §5 is required to be traceable to (a) Beta evidence, (b) decision-framework reasoning, and/or (c) canonical protocol structure. The matrix below records that traceability and the strength of evidence backing for each.

Backing categories:
- **Strong** — Beta evidence directly supports the v0 decision under multiple metrics.
- **Partial** — Beta evidence is consistent with the decision but not by itself decisive; framework reasoning supplies the remainder.
- **Governance-judgment** — the decision is made under §4 principles (e.g., conservatism, simplicity) where Beta evidence alone is mixed or insufficient. This is permitted but must be acknowledged.
- **Canonical-structural** — the decision flows from canonical protocol structure (e.g., O1–O5 offense classes) and is not dependent on Beta evidence in the family-level sense.

| §5 Decision | Beta Scope Section(s) | Beta Evidence Type | Framework Reference | Backing |
| --- | --- | --- | --- | --- |
| 5.1 Monetary-model family (bounded inflation) | `QBIND_BETA_ECONOMICS_SCOPE.md` §6.1, §6.2, §10, §12 | Issuance observations; validator participation under low-fee conditions; security-budget viability | `QBIND_TOKENOMICS_DECISION_FRAMEWORK.md`; `QBIND_ECONOMICS_DESIGN_DRAFT.md` (monetary-model families) | Partial (Beta confirms active issuance is required; family choice within "issuance-bearing" is governance-judgment under §4 principle 4) |
| 5.2 Fee-policy family (split burn/reward) | §6.3, §10, §12 | Fee distributions; anti-spam behavior; per-block fee variance | Design draft (fee-policy families) | Strong (Beta exercises split family directly) |
| 5.3 Validator reward flow (issuance + fees) | §6.4, §10, §12 | Validator participation; reward-flow behavior; low-fee period observations | Design draft (validator-reward flow options) | Strong (Beta is required to use issuance + fees and produced corresponding evidence) |
| 5.4 Minimum stake policy (exists; fixed v0; bounded governance adjustment) | §6.5, §10 | Stake distribution; minimum-stake exclusions; centralization indicators | Design draft (minimum-stake postures); readiness checklist §8 | Partial (existence and family clear; numeric value is `REQUIRED FINAL VALUE`) |
| 5.5 Slashing posture (EnforceAll over canonical O1–O5) | §6.6, §10 | Slashing events, deterrence, churn, recovery | Design draft §247/§271/§295 (EnforceAll); whitepaper §12.2 (canonical O1–O5) | Canonical-structural (O1–O5) + Strong (EnforceAll posture) |
| 5.6 C3 posture (no reporter rewards in v0) | §6.7, §10, §12 | Evidence-reporting activity under Path A and/or Path B | Decision framework; §4 principles 4 & 7 | Partial-to-Governance-judgment (Beta posture is Path B by default; v0 exclusion follows from §4 unless Beta affirmatively required inclusion) |
| 5.7 Test-asset vs MainNet-asset distinction | §6.8, §11.2, §11.5, §12 | Communications integrity posture | Readiness checklist §8 | Canonical-structural (launch-safety constraint) |
| 5.8 Genesis supply (fixed at genesis; numeric is `REQUIRED FINAL VALUE`) | §7, §13.7 | (Beta does not finalize) | Readiness checklist §8 | Governance-judgment for the structural decision; numeric remains required |
| 5.9 Genesis allocation categories (categories finalized; percentages `REQUIRED FINAL VALUE`; no investor/presale/airdrop/liquidity category in v0) | §7, §11.5 | (Beta does not finalize) | Readiness checklist §8; §8 of this document | Governance-judgment (categories) under §4 principles 2 and 8 |

This matrix is the structural defense against "we decided because it felt right." Any future revision of §5 must update this matrix consistently.

---

## 7. Explicit Non-Final / Future-Governance Items

The following items are **not** finalized in v0 by this document and are recognized as future-governance territory. None of these items is a MainNet readiness blocker, because none is required by the readiness checklist for v0.

1. **Numeric tuning within bounded-inflation parameters** (§5.1) — issuance rate adjustments, decay-curve adjustments, within governance bounds set at MainNet authorization.
2. **Burn/reward ratio tuning** within the split family (§5.2), within governance bounds set at MainNet authorization.
3. **Validator reward-split tuning** between issuance share and fee share (§5.3), within governance bounds.
4. **Minimum-stake adjustment** (§5.4), within governance bounds.
5. **Slashing magnitude and jail-duration tuning** within the canonical O1–O5 schedule structure (§5.5), within governance bounds. Offense-class definitions are **not** governance-adjustable.
6. **Future C3 introduction** (§5.6). v0 ships without C3. A future evidence-backed governance/protocol revision may introduce bounded reporter rewards. This is explicitly **not** a v0 commitment and **not** a v0 readiness gate.
7. **Performance-conditioned reward scaling and validator-class differentiation** (§5.3). Not introduced in v0. Future-governance candidate.
8. **Treasury-policy refinement** within the existing treasury / community reserve (§5.9), within governance bounds.
9. **Ecosystem-grant policy** within the existing ecosystem / developer reserve (§5.9).
10. **Operator-facing economics UX improvements** identified by Beta operator-reported pain points (`QBIND_BETA_ECONOMICS_SCOPE.md` §10, §8.9), where they do not require protocol-canonical change.

This section must **not** reopen any item the readiness checklist requires finalized for v0. Specifically, monetary-model family, fee-policy family, validator reward flow, minimum-stake existence, slashing posture, C3 v0 inclusion/exclusion, test-asset vs MainNet-asset distinction, genesis supply, and the existence/non-existence of genesis allocation categories are **finalized in §5** and are **not** future-governance territory.

---

## 8. Presale and External-Sale Boundary

This section is strict.

- **This document does NOT authorize presale.** Presale is not authorized, scheduled, priced, structured, vested, or implied by this document. The existence of this document, of MainNet readiness, or of MainNet authorization does not, by itself, authorize presale.
- **This document does NOT define price, sale structure, vesting for investors, or exchange strategy.** No price, valuation, market-cap assumption, listing, exchange, distribution, or sale schedule is created by this document.
- **No investor / presale reserve exists in v0** (§5.9). The explicit non-existence of such a category is the conservative default. Future creation of any sale-related allocation requires a separate, explicit, externally authorized instrument outside the scope of this document.
- **Presence of any allocation category does not authorize a sale of that category.** For example, the existence of the foundation / team reserve, treasury / community reserve, or ecosystem / developer reserve in §5.9 does **not** authorize external sale of any portion of those reserves. Such external sale would require separate authorization.
- **Beta participation, DevNet/Alpha/Beta test-asset holdings, and any internal economics observation do NOT confer presale eligibility, allocation rights, discounts, or priority.** This is consistent with `QBIND_BETA_ECONOMICS_SCOPE.md` §6.8, §11.2, §11.5.
- **Separate legal, regulatory, jurisdictional, and compliance review is required** for any sale-related planning, including but not limited to presale, public sale, listing, exchange relationship, market-making relationship, or any external distribution. This document is silent on that review and does not substitute for it.
- **External communications about MainNet must not present this document as a sale authorization** or as a basis for any pricing, valuation, or distribution claim. This document is internal.

This section is the structural firewall between MainNet economics finalization and any sale-related activity. A future sale-related authorization, if and when it occurs, must be a separate instrument and must be explicit. Until such an instrument exists, the answer is "no."

---

## 9. MainNet Economics Readiness Statement

- **Economics are finalized enough for MainNet readiness assessment only if all `REQUIRED FINAL VALUE` placeholders in this document are filled** with explicit, canonical numeric values, and only if §5 family-level decisions remain consistent with all canonical inputs cited.
- **If any `REQUIRED FINAL VALUE` placeholder remains unfilled** — for example, the v0 genesis supply (§5.8), the v0 burn/reward ratio (§5.2), the v0 minimum stake (§5.4), the v0 slashing magnitudes/jail durations (§5.5), the v0 allocation percentages (§5.9), or the v0 MainNet asset symbol/name (§5.7) — **MainNet economics readiness is NOT satisfied**, and the corresponding readiness checklist items in `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` §8 must be marked failing.
- **This document is one required input** to the MainNet readiness assessment. It is **not** the readiness assessment, and it is **not** MainNet authorization.
- **MainNet authorization remains a separate, explicit step** governed by the release-track spec and dependent on a successful readiness assessment that includes — but is not limited to — a complete and filled-in version of this document.
- **Filling a `REQUIRED FINAL VALUE` placeholder requires** (a) the value to be supported by a citable input per §3, (b) the rationale to be recorded in §5 alongside the value, and (c) §6 to be updated so traceability remains coherent.
- **No item finalized in §5 may be silently reopened.** Any change requires explicit revision of this document with version increment, and may trigger re-review of the readiness checklist per its §11/§12.

---

## 10. Final Summary

**Finalized for MainNet v0 (family-level / structural):**

- Monetary-model family: **bounded inflation** (§5.1).
- Fee-policy family: **split burn/reward** (§5.2).
- Validator reward flow: **issuance + fees** (§5.3).
- Minimum stake policy: **exists**, fixed at v0, bounded governance adjustment thereafter (§5.4).
- Slashing posture: **EnforceAll** over canonical **O1–O5** offense classes; magnitudes/durations governance-controlled within a fixed schedule structure (§5.5).
- C3 (reporter rewards) v0 posture: **not included in v0** (§5.6).
- Test-asset vs MainNet-asset distinction: **distinct, authoritative MainNet asset; test assets confer no rights** (§5.7).
- Genesis supply: **fixed at genesis**, structurally finalized (§5.8); numeric value remains a `REQUIRED FINAL VALUE`.
- Genesis allocation categories that **exist** in v0: validator/security reserve, treasury/community reserve, foundation/team reserve, ecosystem/developer reserve (§5.9).
- Genesis allocation categories that **do not exist** in v0: investor/presale reserve, airdrop/public-distribution reserve, liquidity/market-making reserve (§5.9).

**Future-governance (deferred from v0; not readiness blockers):**

- Numeric tuning within bounded-inflation parameters (§7.1).
- Burn/reward ratio tuning within the split family (§7.2).
- Validator reward-split tuning (§7.3).
- Minimum-stake adjustment within bounds (§7.4).
- Slashing-magnitude/jail-duration tuning within the canonical schedule structure (§7.5).
- Future C3 introduction, contingent on additional evidence (§7.6).
- Performance-conditioned reward scaling and validator-class differentiation (§7.7).
- Treasury-policy and ecosystem-grant refinements within existing categories (§7.8–§7.9).

**Blocked until explicit values are filled (MainNet authorization cannot proceed until each is recorded with rationale and citation, per §9):**

- v0 issuance rate parameters and bounding curve (§5.1).
- v0 burn/reward shares and any priority/tier mechanics (§5.2).
- v0 issuance/fee split for validator rewards and governance bounds (§5.3).
- v0 minimum stake numeric value and governance bounds (§5.4).
- v0 slashing magnitudes and jail durations per O1–O5 and governance bounds (§5.5).
- v0 MainNet asset symbol and name, with confirmation of distinctness from test assets (§5.7).
- v0 genesis supply numeric value (§5.8).
- v0 allocation percentages per existing category, and confirmation that the sum equals genesis supply with no additional categories (§5.9).

**Standing position of this document:**

- This document does **not** authorize MainNet launch.
- This document does **not** authorize presale, pricing, sale structure, vesting, or any external sale.
- This document is one required input to the MainNet readiness checklist.
- Unsafe ambiguity is not acceptable: every required v0 economic decision is either finalized here, or marked as a blocking `REQUIRED FINAL VALUE` that prevents MainNet authorization until filled.