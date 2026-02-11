# QBIND Tokenomics Input Sheet

**Purpose**: Internal design worksheet for the protocol team  
**Status**: Template (no final parameters)  
**Date**: 2026-02-11

---

## Table of Contents

- [PART 1 – Design Space Overview](#part-1--design-space-overview)
  - [1.1 What Is Already Decided](#11-what-is-already-decided)
  - [1.2 Open Design Dimensions](#12-open-design-dimensions)
- [PART 2 – Parameter Template](#part-2--parameter-template)
  - [2.1 Supply Parameters](#21-supply-parameters)
  - [2.2 Initial Distribution Categories](#22-initial-distribution-categories)
  - [2.3 Vesting Schedules](#23-vesting-schedules)
  - [2.4 Inflation & PQC Cost Parameters](#24-inflation--pqc-cost-parameters)
  - [2.5 Fee Distribution Parameters](#25-fee-distribution-parameters)
  - [2.6 Staking Parameters](#26-staking-parameters)
  - [2.7 Treasury & Safety Funds](#27-treasury--safety-funds)
- [Appendix: Example Configurations](#appendix-example-configurations)

---

# PART 1 – Design Space Overview

This section summarizes what is established in the current protocol design and identifies the open dimensions requiring team decisions.

---

## 1.1 What Is Already Decided

The following elements are defined in the whitepaper and monetary policy design documents.

### 1.1.1 PQC-Adjusted Inflation Phases

QBIND operates a three-phase monetary policy that accounts for post-quantum cryptography costs:

| Phase | Time Window | Base R_target | PQC-Adjusted Range | Inflation Floor |
| :--- | :--- | :--- | :--- | :--- |
| **Bootstrap** | Years 0–3 | 5.0% (classical) | 7.5%–9.0% annual | None (0%) |
| **Transition** | Years 3–7 | 4.0% (classical) | 6.0%–7.5% annual | None (0%) |
| **Mature** | Year 7+ | 3.0% (classical) | 4.0%–5.5% annual | 1.0%–2.0% |

**PQC Premium Formula** (established):
```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

Where β factors compensate validators for PQC operational costs:
- `β_compute ≈ 0.20–0.35` (ML-DSA-44 ~5–10× ECDSA verification cost)
- `β_bandwidth ≈ 0.10–0.20` (2,420-byte signatures vs 64-byte)
- `β_storage ≈ 0.05–0.10` (1,312-byte public keys vs 32-byte)

**Phase Transition Gates** (established):
- Time gates: Epochs encoded at genesis (cannot be accelerated without meeting economic readiness)
- Economic gates: Fee coverage ratio, staking participation, fee volatility thresholds

### 1.1.2 Fee Burn / Proposer Reward Split

The hybrid fee distribution model (T193) is fixed:

| Component | Share | Recipient | Supply Impact |
| :--- | :--- | :--- | :--- |
| **Burn** | 50% | Destroyed | Deflationary |
| **Proposer Reward** | 50% | Block proposer | Redistribution |

This split is hard-coded for MainNet v0. Governance adjustability is deferred to v1+.

### 1.1.3 Seigniorage Distribution (Design-Level)

New token issuance from inflation is distributed:

| Recipient | MainNet v0 Default | Bounds |
| :--- | :--- | :--- |
| **Active Validators** | 82% | [75%, 90%] |
| **Treasury** | 12% | [5%, 20%] |
| **Insurance Reserve** | 4% | — |
| **Community Fund** | 2% | — |

### 1.1.4 Security-Budget Philosophy

Core principles:
1. **Inflation exists to fund security**: Target inflation is computed to ensure validators receive adequate compensation for operational costs + staked capital return.
2. **PQC cost acknowledgment**: Higher computational costs of ML-DSA-44 are explicitly factored into security budgets.
3. **Progressive fee-funding**: As adoption grows, transaction fees increasingly cover the security budget, reducing reliance on inflation.
4. **Smooth transitions**: No abrupt parameter changes; EMA smoothing and rate limiters prevent volatility.

### 1.1.5 EMA-Based Fee Smoothing

Fee input to the inflation formula is smoothed to resist manipulation:

```
EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}
```

Phase-specific λ values:
- Bootstrap: 0.05–0.10 (faster response)
- Transition: 0.02–0.05 (balanced)
- Mature: 0.01–0.02 (maximum stability)

### 1.1.6 Rate-of-Change Limiters

Per-epoch caps prevent sudden inflation changes regardless of fee fluctuations:
- Maximum inflation increase: Capped per epoch
- Maximum inflation decrease: Capped per epoch

---

## 1.2 Open Design Dimensions

The following dimensions are **not yet finalized** and require team decisions before public documentation.

### 1.2.1 Total Supply vs. Uncapped Supply

**Decision required**: Does QBIND have a fixed total supply cap, or is it uncapped with ongoing inflation?

| Option | Description | Tradeoffs |
| :--- | :--- | :--- |
| **Fixed cap** | Hard maximum supply (e.g., 1B, 10B QBIND) | Scarcity narrative; may require fee-only security in long term; limits flexibility |
| **Uncapped with floor** | No hard cap; inflation floor ensures perpetual minimal issuance | Perpetual validator incentives; no "final supply" narrative; long-term dilution |
| **Soft cap** | Theoretical max if inflation hits floor indefinitely | Combines elements; complex to communicate |

**Current design implication**: The mature-phase inflation floor (1–2%) implies ongoing issuance, suggesting uncapped or soft-cap models.

### 1.2.2 Initial Distribution Categories

**Decision required**: How is the genesis supply allocated?

Typical categories to consider:

| Category | Purpose | Typical Range |
| :--- | :--- | :--- |
| **Team & Founders** | Incentivize core contributors | 10%–20% |
| **Investors (Seed/Private)** | Early funding | 10%–25% |
| **Foundation/Treasury** | Long-term development, grants, ecosystem | 15%–30% |
| **Community/Ecosystem** | Airdrops, liquidity mining, grants | 10%–25% |
| **Validator Incentives** | Genesis staking rewards, early validator programs | 5%–15% |
| **Testnet/Airdrop** | Reward testnet participants | 1%–5% |
| **Reserve/Future Use** | Strategic flexibility | 5%–15% |

**Note**: Categories and percentages interact with vesting schedules.

### 1.2.3 Vesting and Lockup Options

**Decision required**: What vesting structures apply to each category?

Key dimensions:
- **Cliff duration**: Time before any tokens vest (e.g., 6 months, 1 year)
- **Linear vesting period**: Duration over which tokens vest after cliff (e.g., 2–4 years)
- **Lockup period**: Additional holding requirement post-vesting
- **Category-specific schedules**: Team vs investor vs community may differ

Typical structures:
- Team: 1-year cliff, 3-year linear vesting (4-year total)
- Investors: 6-month cliff, 2-year linear vesting
- Community: Immediate or short lockup with gradual release
- Treasury: Controlled release via governance

### 1.2.4 Staking Incentives: Real Yield vs. Pure Dilution

**Decision required**: How do staking rewards relate to overall supply dynamics?

| Approach | Description | Implications |
| :--- | :--- | :--- |
| **Pure dilution** | Inflation rewards paid to stakers, diluting non-stakers | Higher nominal APY; encourages staking participation |
| **Real yield** | Rewards funded primarily by fees, minimal dilution | Lower nominal APY; more sustainable; requires high network usage |
| **Hybrid** | Bootstrap with dilution, transition to fee-based | Phased approach; complexity in communication |

**Current design implication**: The three-phase model is inherently hybrid—bootstrap emphasizes dilution, mature phase targets fee-funded security.

**Related question**: What target staking participation rate? (Affects APY calculations)

### 1.2.5 Treasury Structure and Runway Planning

**Decision required**: How is the treasury funded and governed?

Key questions:
- **Initial treasury allocation**: What percentage at genesis?
- **Ongoing treasury funding**: Seigniorage share (currently 12%)?
- **Runway target**: How many years of development/grants should treasury cover?
- **Governance model**: Multisig, on-chain voting, council?
- **Spending categories**: Core development, grants, security audits, marketing?

### 1.2.6 Slashing Insurance / Safety Funds

**Decision required**: How are slashing victims and network emergencies funded?

Key questions:
- **Insurance reserve size**: What percentage of seigniorage (currently 4%)?
- **Coverage scope**: Slashing victim compensation, protocol bugs, black swan events?
- **Reserve target**: Minimum balance before reducing contributions?
- **Distribution mechanism**: Automatic vs governance-approved claims?

---

# PART 2 – Parameter Template

This section provides structured templates for tokenomics parameters. All values are placeholders or examples—**none are final**.

---

## 2.1 Supply Parameters

### Template

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Genesis supply** | `___` QBIND | Total tokens at network launch |
| **Supply model** | `[ ] Fixed cap / [ ] Uncapped / [ ] Soft cap` | — |
| **Hard cap (if fixed)** | `___` QBIND | Maximum total supply ever |
| **Circulating at genesis** | `___` QBIND | Unlocked, liquid tokens at launch |
| **Circulating %** | `___`% | Circulating / Genesis |

### Acceptable Ranges & Tradeoffs

| Parameter | Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Genesis supply** | 100M–10B (typical) | Larger supply → lower unit price → lower barrier for small stakers | Perception only; no technical impact |
| **Circulating at genesis** | 5%–30% of genesis | Higher → more price volatility early | Higher → wider distribution potential |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: Conservative Launch**
| Parameter | Value |
| :--- | :--- |
| Genesis supply | 1,000,000,000 QBIND |
| Supply model | Uncapped with inflation floor |
| Circulating at genesis | 100,000,000 QBIND (10%) |

**Example B: Larger Initial Supply**
| Parameter | Value |
| :--- | :--- |
| Genesis supply | 10,000,000,000 QBIND |
| Supply model | Soft cap (theoretical max ~15B after 50 years) |
| Circulating at genesis | 500,000,000 QBIND (5%) |

---

## 2.2 Initial Distribution Categories

### Template

| Category | % of Genesis | Absolute Amount | Purpose |
| :--- | :--- | :--- | :--- |
| **Team & Founders** | `___`% | `___` QBIND | Core contributor incentives |
| **Investors (Seed)** | `___`% | `___` QBIND | Early-stage funding |
| **Investors (Private/Strategic)** | `___`% | `___` QBIND | Later-stage funding |
| **Foundation/Treasury** | `___`% | `___` QBIND | Long-term development |
| **Community/Ecosystem** | `___`% | `___` QBIND | Grants, liquidity, partnerships |
| **Validator Incentives** | `___`% | `___` QBIND | Genesis staking, early validator programs |
| **Testnet Rewards/Airdrops** | `___`% | `___` QBIND | Community engagement |
| **Reserve/Future Use** | `___`% | `___` QBIND | Strategic flexibility |
| **TOTAL** | **100%** | — | — |

### Acceptable Ranges & Tradeoffs

| Category | Typical Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Team & Founders** | 10%–20% | High team stake → strong incentive alignment | High % + short vesting → centralization risk |
| **Investors** | 15%–30% combined | — | High % to few investors → concentration risk |
| **Foundation/Treasury** | 15%–30% | Larger treasury → more runway, flexibility | Foundation-controlled stake → centralization |
| **Community/Ecosystem** | 10%–25% | — | Wider distribution → better decentralization |
| **Validator Incentives** | 5%–15% | Dedicated validator pool → early security | — |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: Community-Focused**
| Category | % | Absolute (1B genesis) |
| :--- | :--- | :--- |
| Team & Founders | 15% | 150,000,000 QBIND |
| Investors (Seed + Private) | 18% | 180,000,000 QBIND |
| Foundation/Treasury | 20% | 200,000,000 QBIND |
| Community/Ecosystem | 25% | 250,000,000 QBIND |
| Validator Incentives | 10% | 100,000,000 QBIND |
| Testnet/Airdrops | 5% | 50,000,000 QBIND |
| Reserve | 7% | 70,000,000 QBIND |
| **TOTAL** | **100%** | **1,000,000,000 QBIND** |

**Example B: Development-Focused**
| Category | % | Absolute (1B genesis) |
| :--- | :--- | :--- |
| Team & Founders | 18% | 180,000,000 QBIND |
| Investors (Seed + Private) | 22% | 220,000,000 QBIND |
| Foundation/Treasury | 25% | 250,000,000 QBIND |
| Community/Ecosystem | 15% | 150,000,000 QBIND |
| Validator Incentives | 8% | 80,000,000 QBIND |
| Testnet/Airdrops | 2% | 20,000,000 QBIND |
| Reserve | 10% | 100,000,000 QBIND |
| **TOTAL** | **100%** | **1,000,000,000 QBIND** |

---

## 2.3 Vesting Schedules

### Template

| Category | Cliff (months) | Linear Vesting (months) | Total Duration | Lockup Post-Vest | TGE Unlock |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Team & Founders** | `___` | `___` | `___` | `___` | `___`% |
| **Investors (Seed)** | `___` | `___` | `___` | `___` | `___`% |
| **Investors (Private)** | `___` | `___` | `___` | `___` | `___`% |
| **Foundation/Treasury** | `___` | `___` | `___` | `___` | `___`% |
| **Community/Ecosystem** | `___` | `___` | `___` | `___` | `___`% |
| **Validator Incentives** | `___` | `___` | `___` | `___` | `___`% |
| **Testnet/Airdrops** | `___` | `___` | `___` | `___` | `___`% |

### Acceptable Ranges & Tradeoffs

| Parameter | Typical Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Team cliff** | 6–18 months | Longer cliff → stronger long-term alignment | — |
| **Team vesting** | 24–48 months | Longer vesting → sustained contribution incentive | — |
| **Investor cliff** | 6–12 months | — | Shorter → earlier liquidity pressure |
| **Investor vesting** | 18–36 months | — | Longer → reduced dump risk |
| **TGE unlock (team/investors)** | 0%–10% | Lower → less early selling | Higher → more immediate liquidity |
| **Community TGE unlock** | 10%–100% | — | Higher → wider early distribution |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: Conservative Vesting**
| Category | Cliff | Vesting | Total | Post-Vest Lock | TGE Unlock |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Team & Founders | 12 mo | 36 mo | 48 mo | None | 0% |
| Investors (Seed) | 6 mo | 24 mo | 30 mo | None | 0% |
| Investors (Private) | 6 mo | 18 mo | 24 mo | None | 5% |
| Foundation/Treasury | N/A | Governance-controlled | — | — | 10% |
| Community/Ecosystem | None | 24 mo | 24 mo | None | 20% |
| Validator Incentives | None | 12 mo | 12 mo | None | 50% |
| Testnet/Airdrops | None | None | Immediate | None | 100% |

**Example B: Balanced Vesting**
| Category | Cliff | Vesting | Total | Post-Vest Lock | TGE Unlock |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Team & Founders | 12 mo | 24 mo | 36 mo | 6 mo | 0% |
| Investors (Seed) | 6 mo | 18 mo | 24 mo | None | 5% |
| Investors (Private) | 3 mo | 18 mo | 21 mo | None | 10% |
| Foundation/Treasury | N/A | Governance-controlled | — | — | 5% |
| Community/Ecosystem | None | 18 mo | 18 mo | None | 25% |
| Validator Incentives | None | 6 mo | 6 mo | None | 75% |
| Testnet/Airdrops | None | None | Immediate | None | 100% |

---

## 2.4 Inflation & PQC Cost Parameters

### Template (Per Phase)

| Parameter | Bootstrap (Yr 0–3) | Transition (Yr 3–7) | Mature (Yr 7+) |
| :--- | :--- | :--- | :--- |
| **R_target_classical** | `___`% | `___`% | `___`% |
| **β_compute** | `___` | `___` | `___` |
| **β_bandwidth** | `___` | `___` | `___` |
| **β_storage** | `___` | `___` | `___` |
| **R_target_PQC (computed)** | `___`% | `___`% | `___`% |
| **r_floor** | `___`% | `___`% | `___`% |
| **α (fee sensitivity)** | `___` | `___` | `___` |
| **λ (EMA smoothing)** | `___` | `___` | `___` |
| **Max Δr per epoch** | `___`% | `___`% | `___`% |

### Acceptable Ranges & Tradeoffs

| Parameter | Range | Security Tradeoff | Notes |
| :--- | :--- | :--- | :--- |
| **R_target_classical** | 3%–7% | Higher → better validator compensation; higher dilution | Set per whitepaper guidance |
| **β_compute** | 0.15–0.50 | Higher → more PQC cost compensation | Calibrated via T198 benchmarks |
| **β_bandwidth** | 0.05–0.30 | Higher → more bandwidth cost compensation | Moderated, not raw ratio |
| **β_storage** | 0.03–0.20 | Higher → more storage cost compensation | Moderated, not raw ratio |
| **r_floor (mature)** | 1%–2% | Higher → guaranteed validator income; perpetual dilution | Only active in mature phase |
| **α (fee sensitivity)** | 0.3–1.5 | Higher → faster inflation reduction as fees grow | Bounded by design |
| **λ (EMA smoothing)** | 0.005–0.15 | Higher → faster response to fee changes | Phase-dependent |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: Conservative PQC Compensation**
| Parameter | Bootstrap | Transition | Mature |
| :--- | :--- | :--- | :--- |
| R_target_classical | 5.0% | 4.0% | 3.0% |
| β_compute | 0.30 | 0.30 | 0.30 |
| β_bandwidth | 0.15 | 0.15 | 0.15 |
| β_storage | 0.10 | 0.10 | 0.10 |
| **R_target_PQC** | **7.75%** | **6.20%** | **4.65%** |
| r_floor | 0% | 0% | 1.5% |
| α | 0.4 | 0.9 | 1.0 |
| λ | 0.08 | 0.03 | 0.015 |
| Max Δr/epoch | 0.5% | 0.5% | 0.25% |

**Example B: Higher Security Budget**
| Parameter | Bootstrap | Transition | Mature |
| :--- | :--- | :--- | :--- |
| R_target_classical | 6.0% | 5.0% | 4.0% |
| β_compute | 0.35 | 0.35 | 0.35 |
| β_bandwidth | 0.18 | 0.18 | 0.18 |
| β_storage | 0.12 | 0.12 | 0.12 |
| **R_target_PQC** | **9.90%** | **8.25%** | **6.60%** |
| r_floor | 0% | 0% | 2.0% |
| α | 0.35 | 0.85 | 1.1 |
| λ | 0.10 | 0.04 | 0.02 |
| Max Δr/epoch | 0.5% | 0.4% | 0.2% |

---

## 2.5 Fee Distribution Parameters

### Template

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Burn ratio** | `___`% | Percentage of fees burned |
| **Proposer reward ratio** | `___`% | Percentage to block proposer |
| **Treasury fee share** | `___`% | (If applicable) Fee share to treasury |
| **Fee burn governance-adjustable** | `[ ] Yes / [ ] No` | Can governance change the split? |

### Acceptable Ranges & Tradeoffs

| Parameter | Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Burn ratio** | 30%–70% | Higher burn → more deflation; less direct validator reward | — |
| **Proposer reward** | 30%–70% | Higher → more direct validator incentive; less deflation | Higher → larger validators benefit more |

### Current Design (Fixed for MainNet v0)

| Parameter | Value | Status |
| :--- | :--- | :--- |
| Burn ratio | 50% | Hard-coded (T193) |
| Proposer reward | 50% | Hard-coded (T193) |
| Treasury fee share | 0% | Fees go to burn + proposer only |
| Governance-adjustable | No | Deferred to v1+ |

---

## 2.6 Staking Parameters

### Template

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Target staking participation** | `___`% of total supply | Desired stake ratio |
| **Minimum stake (validator)** | `___` QBIND | Minimum to run a validator |
| **Minimum stake (delegator)** | `___` QBIND | Minimum to delegate |
| **Unbonding period** | `___` days/epochs | Time to withdraw staked tokens |
| **Slashing max (critical offense)** | `___`% of stake | Maximum slashable for O1/O2 |
| **Slashing max (medium offense)** | `___`% of stake | Maximum slashable for O3/O5 |
| **Reward compounding** | `[ ] Auto / [ ] Manual / [ ] Claimable` | How rewards are handled |

### Acceptable Ranges & Tradeoffs

| Parameter | Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Target stake %** | 30%–70% | Higher → more economic security; higher opportunity cost | — |
| **Min validator stake** | 10K–1M QBIND (varies by supply) | Higher → fewer validators, more professional operators | Lower → more accessible, more decentralized |
| **Unbonding period** | 7–28 days | Longer → better security (can slash after misbehavior detected) | Longer → worse liquidity for stakers |
| **Slashing (critical)** | 5%–15% | Higher → stronger deterrent | — |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: High Security Focus**
| Parameter | Value |
| :--- | :--- |
| Target staking participation | 60% |
| Minimum stake (validator) | 100,000 QBIND |
| Minimum stake (delegator) | 100 QBIND |
| Unbonding period | 21 days |
| Slashing max (critical) | 10% |
| Slashing max (medium) | 3% |
| Reward compounding | Auto |

**Example B: Accessibility Focus**
| Parameter | Value |
| :--- | :--- |
| Target staking participation | 45% |
| Minimum stake (validator) | 32,000 QBIND |
| Minimum stake (delegator) | 10 QBIND |
| Unbonding period | 14 days |
| Slashing max (critical) | 5% |
| Slashing max (medium) | 1% |
| Reward compounding | Claimable |

---

## 2.7 Treasury & Safety Funds

### Template

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Treasury initial allocation** | `___`% of genesis | Percentage at launch |
| **Treasury seigniorage share** | `___`% | Ongoing funding from inflation |
| **Treasury governance model** | `[ ] Multisig / [ ] On-chain vote / [ ] Council` | Control mechanism |
| **Treasury runway target** | `___` years | Planned operational runway |
| **Insurance reserve seigniorage share** | `___`% | Ongoing funding from inflation |
| **Insurance reserve minimum balance** | `___` QBIND | Target floor |
| **Community fund seigniorage share** | `___`% | Ongoing funding from inflation |

### Acceptable Ranges & Tradeoffs

| Parameter | Range | Security Tradeoff | Decentralization Tradeoff |
| :--- | :--- | :--- | :--- |
| **Treasury initial %** | 15%–30% | Larger → more development capacity | Larger → more foundation control |
| **Treasury seigniorage %** | 5%–20% | Higher → sustained development funding | Higher → less to validators |
| **Insurance reserve %** | 2%–8% | Higher → better victim compensation coverage | — |
| **Runway target** | 3–10 years | Longer → more certainty; requires larger allocation | — |

### Example Configurations

> ⚠️ **Examples, not final**

**Example A: Conservative Treasury**
| Parameter | Value |
| :--- | :--- |
| Treasury initial allocation | 20% |
| Treasury seigniorage share | 12% |
| Treasury governance model | Multisig (5-of-7 initially, on-chain vote later) |
| Treasury runway target | 5 years |
| Insurance reserve seigniorage share | 4% |
| Insurance reserve minimum balance | 10,000,000 QBIND |
| Community fund seigniorage share | 2% |

**Example B: Community-Governed Treasury**
| Parameter | Value |
| :--- | :--- |
| Treasury initial allocation | 15% |
| Treasury seigniorage share | 10% |
| Treasury governance model | On-chain vote (stake-weighted) |
| Treasury runway target | 7 years |
| Insurance reserve seigniorage share | 5% |
| Insurance reserve minimum balance | 25,000,000 QBIND |
| Community fund seigniorage share | 5% |

---

# Appendix: Example Configurations

This appendix presents two complete example configurations combining all parameters. **These are illustrative only—not recommendations or final values.**

## Example Configuration A: "Conservative Launch"

### Philosophy
- Moderate initial supply with conservative circulating percentage
- Longer vesting for insiders
- Higher security budget (PQC-compensated)
- Professional validator requirements

### Summary

| Dimension | Configuration |
| :--- | :--- |
| **Genesis Supply** | 1,000,000,000 QBIND |
| **Supply Model** | Uncapped with 1.5% mature floor |
| **Circulating at Genesis** | ~10% |
| **Team/Founders** | 15%, 12-month cliff, 36-month vest |
| **Investors** | 18%, 6-month cliff, 24-month vest |
| **Treasury** | 20%, governance-controlled |
| **Community** | 25%, 24-month release |
| **Bootstrap Inflation** | ~7.75% PQC-adjusted |
| **Fee Split** | 50% burn / 50% proposer |
| **Target Stake** | 60% |
| **Min Validator Stake** | 100,000 QBIND |

## Example Configuration B: "Community-First Launch"

### Philosophy
- Larger initial supply for lower unit price accessibility
- More aggressive community distribution
- Shorter vesting for community allocations
- Lower validator barriers

### Summary

| Dimension | Configuration |
| :--- | :--- |
| **Genesis Supply** | 10,000,000,000 QBIND |
| **Supply Model** | Soft cap (theoretical ~15B after 50 years) |
| **Circulating at Genesis** | ~8% |
| **Team/Founders** | 12%, 12-month cliff, 24-month vest |
| **Investors** | 15%, 6-month cliff, 18-month vest |
| **Treasury** | 18%, governance-controlled |
| **Community** | 30%, 12-month release, 25% TGE |
| **Bootstrap Inflation** | ~8.5% PQC-adjusted |
| **Fee Split** | 50% burn / 50% proposer |
| **Target Stake** | 50% |
| **Min Validator Stake** | 32,000 QBIND |

---

## Next Steps

1. **Team discussion**: Review open design dimensions (§1.2) and select preferred approaches
2. **Fill in templates**: Use Part 2 templates to document final decisions
3. **Model scenarios**: Run tokenomics simulations with selected parameters
4. **External review**: Consider economic audit of final parameters
5. **Update whitepaper**: Feed finalized parameters back into public documentation

---

*Document Version: 1.0*  
*Last Updated: 2026-02-11*