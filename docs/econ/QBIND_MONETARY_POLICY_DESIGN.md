# QBIND Monetary Policy & Monetary Engine v1 Design

**Task**: T194  
**Status**: Design Specification  
**Date**: 2026-02-04

---

## Table of Contents

1. [Objectives & Constraints](#1-objectives--constraints)
2. [Phase Model (Bootstrap / Transition / Mature)](#2-phase-model-bootstrap--transition--mature)
3. [Inflation & Security Budget Formula](#3-inflation--security-budget-formula)
4. [Seigniorage Allocation & Fee Distribution](#4-seigniorage-allocation--fee-distribution)
5. [Parameter Classes: Hard-Coded, Governance-Tunable, Future](#5-parameter-classes-hard-coded-governance-tunable-future)
6. [Phase-Specific Behavior Summary](#6-phase-specific-behavior-summary)
7. [Implementation Roadmap (T195+)](#7-implementation-roadmap-t195)
8. [Related Documents](#8-related-documents)

---

## 1. Objectives & Constraints

### 1.1 Goals

The QBIND monetary policy is designed around the following high-level objectives:

| Goal | Description |
| :--- | :--- |
| **Security-Budget-Driven Inflation** | Inflation exists to fund a target security budget sufficient to protect the network against economic attacks. |
| **PQC-Only Validator Stack** | All validators use ML-DSA-44 (signatures) and ML-KEM-768 (key exchange). Higher computational costs of PQC must be accounted for in security budget targets. |
| **Long-Term Validator Sustainability** | Validators must receive adequate rewards to cover hardware, bandwidth, and operational costs despite higher PQC overhead compared to classical chains. |
| **Smooth, Predictable Monetary Behavior** | Inflation and fee dynamics must change gradually, avoiding wild swings that could destabilize the ecosystem. |
| **Fee-Based Security Funding Over Time** | As network adoption grows, transaction fees should increasingly cover the security budget, reducing reliance on inflation. |

### 1.2 Constraints

| Constraint | Rationale |
| :--- | :--- |
| **No Off-Chain Discretion for Core Rules** | Monetary policy parameters must be deterministically computed on-chain or set via transparent governance. No central authority can unilaterally adjust rates. |
| **PQC Cryptography Only** | No classical signature schemes permitted. All cost models assume ML-DSA-44 signature verification (~5–10× classical ECDSA cost). |
| **Forward Compatibility with Oracles and AI** | The design must accommodate Phase 2 (oracle-assisted parameter hints) and Phase 3 (AI-based monitoring) without requiring core formula changes. |
| **No Dependency on Future Features** | MainNet v0 monetary policy must function without oracles, AI monitoring, or governance upgrade mechanisms beyond basic parameter adjustment. |
| **Alignment with Fee Distribution (T193)** | The monetary engine must integrate cleanly with the hybrid fee distribution model (burn + proposer reward) established in T193. |

### 1.3 Design Principles

1. **Security First**: The primary purpose of inflation is to fund network security. All other considerations are secondary.

2. **Smooth Transitions**: Phase transitions and parameter changes use time-based gates and EMA smoothing to prevent abrupt shifts.

3. **Conservative Defaults**: Hard-coded parameters err on the side of higher security budgets and lower inflation floors.

4. **Governance as Override, Not Driver**: Governance can adjust parameters within bounds, but the core formula operates autonomously.

5. **Transparency**: All parameters, formulas, and state transitions are documented and auditable on-chain.

---

## 2. Phase Model (Bootstrap / Transition / Mature)

### 2.1 Phase Enum Definition

The monetary policy operates across three distinct phases:

```
enum MonetaryPhase {
    Bootstrap,    // Phase 1: Network establishment (years 0–3)
    Transition,   // Phase 2: Growth and stabilization (years 3–7)
    Mature,       // Phase 3: Long-term operation (year 7+)
}
```

Each phase has distinct characteristics for inflation targets, fee offsets, and governance flexibility.

### 2.2 Phase Characteristics

#### 2.2.1 Bootstrap Phase (Years 0–3)

**Purpose**: Establish network security during initial low-usage period.

| Aspect | Bootstrap Configuration |
| :--- | :--- |
| **Time Window** | Epochs 0 to ~157,680 (assuming 10-minute epochs, ~3 years) |
| **R_target** | Higher (~8–9% annual, PQC-adjusted) |
| **Fee Offset** | Limited (α_bootstrap ≈ 0.3–0.5) to prevent instability from volatile early fees |
| **Inflation Floor** | None (r_floor = 0%) |
| **EMA Horizon** | Shorter (λ ≈ 0.05–0.10) for faster response to early fee patterns |
| **Governance** | Minimal adjustments allowed; focus on stability |

**Rationale**: Early network has few transactions and uncertain fee revenue. A higher inflation target ensures adequate security budget regardless of fee income. Limited fee-offset prevents wild inflation swings from early adoption spikes.

#### 2.2.2 Transition Phase (Years 3–7)

**Purpose**: Gradually shift from inflation-funded to fee-funded security.

| Aspect | Transition Configuration |
| :--- | :--- |
| **Time Window** | Epochs ~157,680 to ~368,280 (years 3–7) |
| **R_target** | Moderate (~6–7% annual, PQC-adjusted) |
| **Fee Offset** | Full sensitivity (α_transition ≈ 0.8–1.0) |
| **Inflation Floor** | None (r_floor = 0%) |
| **EMA Horizon** | Medium (λ ≈ 0.02–0.05) for balanced smoothing |
| **Governance** | Parameter tuning allowed within bounds |

**Rationale**: Network has established usage patterns. Fee-offset becomes fully active, allowing inflation to decrease as fees grow. Governance can fine-tune parameters based on observed behavior.

#### 2.2.3 Mature Phase (Year 7+)

**Purpose**: Long-term sustainable operation with minimal inflation.

| Aspect | Mature Configuration |
| :--- | :--- |
| **Time Window** | Epochs ~368,280+ (year 7 onwards) |
| **R_target** | Lower (~4–5% annual, PQC-adjusted) |
| **Fee Offset** | Full sensitivity (α_mature ≈ 1.0) |
| **Inflation Floor** | Active (r_floor = 1–2% annual) |
| **EMA Horizon** | Longer (λ ≈ 0.01–0.02) for maximum stability |
| **Governance** | Full parameter governance; oracle hints available (Phase 2+) |

**Rationale**: Mature network should be primarily fee-funded. A small inflation floor ensures validators always receive some new issuance even if fees fully cover security budget—this provides a buffer against fee volatility and maintains staking incentives.

### 2.3 Phase Transition Criteria

Phase transitions require both **time gates** (necessary condition) and **economic readiness gates** (sufficient condition).

#### 2.3.1 Time Gates

Time gates prevent premature transitions regardless of economic metrics:

| Transition | Minimum Time | Expressed As |
| :--- | :--- | :--- |
| Bootstrap → Transition | 3 years | `current_epoch >= EPOCH_TRANSITION_START` |
| Transition → Mature | 7 years from genesis | `current_epoch >= EPOCH_MATURE_START` |

**Note**: Time is expressed in epochs, not wall-clock time, to ensure deterministic transitions.

#### 2.3.2 Economic Readiness Gates

Economic gates ensure the network is ready for reduced inflation:

| Metric | Bootstrap → Transition | Transition → Mature |
| :--- | :--- | :--- |
| **Fee Coverage Ratio** | `EMA_fees / target_security_budget >= 0.20` | `EMA_fees / target_security_budget >= 0.50` |
| **Staking Participation** | `staked_supply / circulating_supply >= 0.30` | `staked_supply / circulating_supply >= 0.40` |
| **Fee Volatility** | `stddev(fees_30d) / mean(fees_30d) <= 2.0` | `stddev(fees_30d) / mean(fees_30d) <= 1.5` |

**Fee Coverage Ratio**: Measures how much of the target security budget is covered by fee revenue. Higher values indicate reduced reliance on inflation.

**Staking Participation**: Measures network commitment and security backing. Higher participation indicates mature staking ecosystem.

**Fee Volatility**: Measures stability of fee revenue. Lower volatility indicates predictable transaction demand.

#### 2.3.3 Governance Override Model

Governance can influence phase transitions under strict conditions:

| Action | Requirements | Mechanism |
| :--- | :--- | :--- |
| **Delay Transition** | Simple majority vote | Extend current phase by up to 1 year |
| **Advance Transition (Cautious)** | 2/3 supermajority + 30-day timelock | Requires all economic gates met |
| **Emergency Rollback** | 3/4 supermajority + 7-day timelock | Return to previous phase for max 6 months |

**Note**: Governance cannot skip phases or force transitions without meeting economic gates.

### 2.4 Phase State Machine

The following state machine formally defines phase transitions:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Phase Transition State Machine                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐     time >= EPOCH_TRANSITION_START     ┌────────────┐         │
│  │          │     AND fee_coverage >= 0.20           │            │         │
│  │ Bootstrap│ ─────────────────────────────────────▶ │ Transition │         │
│  │          │     AND stake_ratio >= 0.30            │            │         │
│  └──────────┘     AND fee_volatility <= 2.0          └────────────┘         │
│       │                                                    │                 │
│       │                                                    │                 │
│       │  (Governance delay: extend up to 1 year)          │                 │
│       │                                                    │                 │
│       └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐           │                 │
│                                                 │           │                 │
│                                                 │           │                 │
│                                                 ▼           │                 │
│                                          ┌──────────┐       │                 │
│                                          │  Delay   │◀─ ─ ─ ┘                 │
│                                          │  Buffer  │                        │
│                                          └──────────┘                        │
│                                                                              │
│                     time >= EPOCH_MATURE_START       ┌─────────┐            │
│  ┌────────────┐     AND fee_coverage >= 0.50         │         │            │
│  │            │ ────────────────────────────────────▶│  Mature │            │
│  │ Transition │     AND stake_ratio >= 0.40          │         │            │
│  │            │     AND fee_volatility <= 1.5        └─────────┘            │
│  └────────────┘                                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.5 Phase Transition Summary Table

| State | Guards (All Must Be True) | Transition Actions |
| :--- | :--- | :--- |
| **Bootstrap → Transition** | `epoch >= EPOCH_TRANSITION_START` ∧ `fee_coverage >= 0.20` ∧ `stake_ratio >= 0.30` ∧ `fee_volatility <= 2.0` | Update phase enum; adjust α, λ, R_target |
| **Transition → Mature** | `epoch >= EPOCH_MATURE_START` ∧ `fee_coverage >= 0.50` ∧ `stake_ratio >= 0.40` ∧ `fee_volatility <= 1.5` | Update phase enum; activate inflation floor; adjust α, λ, R_target |
| **Governance Delay** | Vote passes ∧ `current_phase != Mature` | Extend phase deadline by voted duration |
| **Governance Advance** | 2/3 supermajority ∧ all economic gates met ∧ timelock elapsed | Trigger transition immediately |

---

## 3. Inflation & Security Budget Formula

### 3.1 Security Budget Concept

The **security budget** represents the total economic value that must be distributed to validators per year to ensure adequate network security. This budget must be sufficient to:

1. Cover validator operational costs (hardware, bandwidth, storage)
2. Provide economic return on staked capital
3. Create attack resistance by making 1/3+ stake acquisition prohibitively expensive

### 3.2 PQC-Adjusted Target Rate

#### 3.2.1 Classical Baseline

Start with a classical security target rate that would apply to a traditional PoS chain:

```
R_target_classical = 5.0%  (annual, relative to staked supply)
```

This represents a baseline return that makes staking economically attractive while limiting inflation.

#### 3.2.2 PQC Premium Factors

QBIND uses PQC-only cryptography, which incurs higher costs:

| Factor | Symbol | Description | Expected Range |
| :--- | :--- | :--- | :--- |
| **Compute Premium** | β_compute | Higher CPU cost for ML-DSA-44 verification (~5–10× ECDSA) | 0.20–0.35 |
| **Bandwidth Premium** | β_bandwidth | Larger signature sizes (ML-DSA-44: 2,420 bytes vs ECDSA: 65 bytes) | 0.10–0.20 |
| **Storage Premium** | β_storage | Larger keys and state (ML-DSA-44 pubkey: 1,312 bytes) | 0.05–0.10 |

**Combined Premium**: β_total = β_compute + β_bandwidth + β_storage ≈ 0.35–0.65

#### 3.2.3 PQC-Adjusted Target Formula

```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

**Example Calculation**:
```
R_target_PQC = 5.0% × (1 + 0.30 + 0.15 + 0.10)
             = 5.0% × 1.55
             = 7.75% (annual)
```

For MainNet v0, the expected range is **7.5%–9.0%** annual target rate in the Bootstrap phase.

### 3.3 EMA-Based Fee Smoothing

#### 3.3.1 Why EMA Smoothing

Instantaneous fee revenue is highly volatile:
- Transaction bursts cause fee spikes
- Network quiet periods cause fee drops
- Attack attempts could manipulate short-term fees

EMA smoothing provides:
- Stable, predictable fee input to inflation formula
- Resistance to manipulation via short-term fee spikes
- Gradual response to genuine long-term fee trends

#### 3.3.2 EMA Formula

```
EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}
```

Where:
- `fees_t` = Total fees collected in epoch t
- `λ` = Smoothing factor (0 < λ < 1)
- Higher λ = faster response to recent fees
- Lower λ = more smoothing, slower response

#### 3.3.3 Phase-Specific EMA Parameters

| Phase | λ (Smoothing Factor) | Effective Lookback | Rationale |
| :--- | :--- | :--- | :--- |
| Bootstrap | 0.05–0.10 | ~10–20 epochs | Faster response to establish fee baseline |
| Transition | 0.02–0.05 | ~20–50 epochs | Balanced response during growth |
| Mature | 0.01–0.02 | ~50–100 epochs | Maximum smoothing for stability |

**Effective Lookback**: Approximate number of epochs where EMA retains significant weight from past values.

### 3.4 Inflation Rate Formula

#### 3.4.1 Core Formula

The inflation rate at epoch t is:

```
r_inf(t) = max(r_floor(phase), R_target(phase) - α × (EMA_fees_t / S_t))
```

Where:
- `r_floor(phase)` = Inflation floor for current phase
- `R_target(phase)` = PQC-adjusted target rate for current phase
- `α` = Fee-offset sensitivity parameter
- `EMA_fees_t` = EMA-smoothed fee revenue at epoch t
- `S_t` = Total staked supply at epoch t

#### 3.4.2 Component Breakdown

**Inflation Floor** (`r_floor`):
- Bootstrap: 0% (no floor)
- Transition: 0% (no floor)
- Mature: 1–2% (active floor)

The floor ensures validators always receive some inflation even if fees fully cover the security budget. This provides:
- Buffer against fee volatility
- Continuous staking incentive
- Predictable minimum validator income

**Fee-Offset Term** (`α × EMA_fees_t / S_t`):
- Represents how much fee revenue reduces required inflation
- Scaled by staked supply to normalize across different stake levels
- α controls sensitivity: higher α = stronger fee impact

#### 3.4.3 Parameter Constraints and Guardrails

| Parameter | Hard Constraint | Rationale |
| :--- | :--- | :--- |
| `r_inf(t)` | ≥ 0% | No deflation from the inflation formula |
| `r_inf(t)` | ≤ R_target_max = 12% | Cap prevents runaway inflation from bugs |
| Fee-offset rate | Δr/epoch ≤ 0.5% | Limits how fast fees can reduce inflation |
| α | 0.3 ≤ α ≤ 1.5 | Bounds fee sensitivity within safe range |

**Rate of Change Cap**: Even if EMA_fees changes dramatically, inflation cannot drop by more than 0.5% per epoch. This prevents manipulation via temporary fee spikes.

### 3.5 Worked Example

**Scenario**: Year 2 of Bootstrap phase

Given:
- `R_target(Bootstrap)` = 8.0% annual
- `r_floor(Bootstrap)` = 0%
- `α` = 0.4
- `EMA_fees_t` = 50,000 QBIND per epoch
- `S_t` = 10,000,000 QBIND staked
- Epochs per year = 52,560 (10-minute epochs)

**Calculate fee-offset term**:
```
fee_offset = α × (EMA_fees_t / S_t) × epochs_per_year
           = 0.4 × (50,000 / 10,000,000) × 52,560
           = 0.4 × 0.005 × 52,560
           = 0.4 × 262.8
           = 105.12  (annualized as percentage of stake)
           ≈ 1.05% annual
```

**Calculate inflation rate**:
```
r_inf = max(0%, 8.0% - 1.05%)
      = max(0%, 6.95%)
      = 6.95% annual
```

**Interpretation**: With moderate fee revenue, inflation is reduced from 8.0% target to 6.95% actual. The security budget is funded 13% by fees and 87% by inflation.

---

## 4. Seigniorage Allocation & Fee Distribution

### 4.1 Security Budget Sources

The total security budget comes from two sources:

| Source | Description | Supply Impact |
| :--- | :--- | :--- |
| **Inflation (Seigniorage)** | New token issuance distributed to validators | Increases total supply |
| **Transaction Fees** | Fees paid by users for transaction inclusion | No supply change (redistribution) |

### 4.2 Inflation Issuance Per Epoch

New issuance per epoch is calculated as:

```
issuance_epoch = r_inf × S_t / epochs_per_year
```

Where:
- `r_inf` = Current inflation rate (annual, from §3.4)
- `S_t` = Total staked supply
- `epochs_per_year` = 52,560 (assuming 10-minute epochs)

### 4.3 Seigniorage Split (Design Level)

New issuance is distributed among multiple recipients:

| Recipient | Share | Purpose |
| :--- | :--- | :--- |
| **Active Validators** | 80–85% | Direct security incentive |
| **Treasury** | 10–15% | Protocol development, grants |
| **Insurance Reserve** | 3–5% | Slashing compensation, emergency fund |
| **Community Fund** | 2–5% | Ecosystem development, airdrops |

**MainNet v0 Default Split**:
```
validators_share  = 82%
treasury_share    = 12%
insurance_share   = 4%
community_share   = 2%
```

**Note**: Treasury governance mechanics are outside the scope of this document. This design only positions how treasury/insurance/community slices fit into the overall budget.

### 4.4 Fee Distribution (Reference: T193)

As established in T193, transaction fees are distributed using a hybrid model:

| Component | Share | Recipient | Supply Impact |
| :--- | :--- | :--- | :--- |
| **Burn** | 50% | Destroyed | Deflationary |
| **Proposer Reward** | 50% | Block proposer | Redistribution |

**Reference**: [QBIND_GAS_AND_FEES_DESIGN.md §5](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) for fee distribution implementation details.

### 4.5 Interaction Between Burned Fees and Inflation

Burned fees have a dual effect:

1. **Direct Deflation**: Burned fees reduce total supply, creating deflationary pressure
2. **Indirect Inflation Reduction**: Fees (including burned portion) feed into EMA_fees, reducing required inflation via the fee-offset term

**Net Supply Change Per Epoch**:
```
net_supply_change = issuance_epoch - burned_fees_epoch
```

In high-usage scenarios, the network can become deflationary if:
```
burned_fees_epoch > issuance_epoch
```

This occurs when fee revenue is sufficiently high and the inflation floor is low.

### 4.6 Value Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Security Budget Value Flows                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐                                                        │
│  │   INFLATION      │                                                        │
│  │   (New Issuance) │                                                        │
│  │   r_inf × S_t    │                                                        │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌────────────────────────────────────────────────────────┐                  │
│  │                   SEIGNIORAGE SPLIT                     │                  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │                  │
│  │  │Validators│ │ Treasury │ │Insurance │ │Community │   │                  │
│  │  │   82%    │ │   12%    │ │    4%    │ │    2%    │   │                  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │                  │
│  └───────┼────────────┼────────────┼────────────┼─────────┘                  │
│          │            │            │            │                            │
│          ▼            ▼            ▼            ▼                            │
│    ┌──────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐                       │
│    │Validator │  │Treasury │  │Insurance│  │Community│                       │
│    │  APY     │  │ Account │  │ Reserve │  │  Fund   │                       │
│    └──────────┘  └─────────┘  └─────────┘  └─────────┘                       │
│          ▲                                                                   │
│          │                                                                   │
│  ┌───────┴───────┐                                                           │
│  │               │                                                           │
│  │  ┌─────────┐  │  ┌─────────┐                                              │
│  │  │Proposer │  │  │  Burn   │                                              │
│  │  │Reward   │  │  │(Supply ↓)│                                             │
│  │  │  50%    │  │  │  50%    │                                              │
│  │  └────┬────┘  │  └────┬────┘                                              │
│  │       │       │       │                                                   │
│  │  ┌────┴───────┴───────┴────┐                                              │
│  │  │      FEE SPLIT          │                                              │
│  │  │   (T193 Hybrid Model)   │                                              │
│  │  └────────────┬────────────┘                                              │
│  │               │                                                           │
│  │  ┌────────────┴────────────┐                                              │
│  │  │    TRANSACTION FEES     │                                              │
│  │  │    (User Payments)      │                                              │
│  │  └─────────────────────────┘                                              │
│  │                                                                           │
│  └───────────────────────────────────────────────────────────────────────────┘
│                                                                              │
│  Legend:                                                                     │
│    ──▶  Value flow (increases recipient balance)                            │
│    ↓    Supply reduction (burn)                                             │
│    ↑    Supply increase (inflation)                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.7 Validator APY Calculation

Total validator APY combines inflation rewards and proposer fee rewards:

```
validator_APY = (inflation_rewards + proposer_fee_rewards) / staked_amount

Where:
  inflation_rewards = r_inf × validators_share × (validator_stake / total_stake)
  proposer_fee_rewards = EMA_fees × proposer_share × (validator_blocks / total_blocks)
```

**Note**: Proposer fee rewards are not equally distributed—they depend on block proposal frequency, which correlates with stake weight in most PoS systems.

---

## 5. Parameter Classes: Hard-Coded, Governance-Tunable, Future

### 5.1 Hard-Coded Parameters (MainNet v0)

These parameters are fixed at genesis and require a hard fork or major governance act to change:

| Parameter | Value | Rationale |
| :--- | :--- | :--- |
| `EPOCH_TRANSITION_START` | 157,680 (~3 years) | Minimum Bootstrap duration |
| `EPOCH_MATURE_START` | 368,280 (~7 years) | Minimum time to Mature phase |
| `R_TARGET_MAX` | 12% annual | Hard cap on inflation |
| `R_FLOOR_MATURE_MIN` | 1% annual | Minimum inflation floor in Mature |
| `R_FLOOR_MATURE_MAX` | 2% annual | Maximum inflation floor in Mature |
| `VALIDATORS_SHARE_MIN` | 75% | Minimum validator seigniorage share |
| `VALIDATORS_SHARE_MAX` | 90% | Maximum validator seigniorage share |
| `FEE_BURN_RATIO` | 50% (5000 bps) | Fee burn percentage (T193) |
| `FEE_PROPOSER_RATIO` | 50% (5000 bps) | Fee proposer reward percentage (T193) |

### 5.2 Governance-Tunable Parameters (Within Bounds)

These parameters can be adjusted by governance within predefined bounds:

| Parameter | Default | Bounds | Adjustment Frequency |
| :--- | :--- | :--- | :--- |
| `R_target_classical` | 5.0% | [3.0%, 7.0%] | Per-epoch (with rate limits) |
| `β_compute` | 0.30 | [0.15, 0.50] | Quarterly recalibration |
| `β_bandwidth` | 0.15 | [0.05, 0.30] | Quarterly recalibration |
| `β_storage` | 0.10 | [0.03, 0.20] | Quarterly recalibration |
| `α` (fee sensitivity) | 0.5 | [0.3, 1.5] | Per-epoch (with rate limits) |
| `λ` (EMA smoothing) | Phase-dependent | [0.005, 0.15] | Per-epoch (with rate limits) |
| `validators_share` | 82% | [75%, 90%] | Epoch boundary only |
| `treasury_share` | 12% | [5%, 20%] | Epoch boundary only |
| `r_floor` (Mature) | 1.5% | [1.0%, 2.0%] | Epoch boundary only |

**Rate Limits**: Parameters can change by at most:
- `R_target`: ±0.25% per epoch
- `α`: ±0.05 per epoch
- `λ`: ±0.005 per epoch

### 5.3 Reserved for Future Phases

These parameters or mechanisms are not implemented in MainNet v0 but are anticipated:

| Parameter/Mechanism | Target Phase | Description |
| :--- | :--- | :--- |
| **Oracle Cost Indices** | Phase 2 (Oracles) | Hardware, electricity, bandwidth price feeds as hints for β recalibration |
| **Dynamic β Adjustment** | Phase 2 (Oracles) | Automatic PQC premium recalibration based on oracle data |
| **AI-Based Monitoring** | Phase 3 (AI) | Advisory alerts for parameter drift, anomaly detection |
| **Cross-Shard Fee Routing** | MainNet v2+ | Fee distribution across multiple shards |
| **Dynamic Fee Burn Ratio** | MainNet v1+ | Governance-adjustable burn/proposer split |
| **Validator Performance Weighting** | MainNet v1+ | Adjust rewards based on uptime, latency metrics |

### 5.4 Parameter Classification Summary Table

| Parameter | Class | MainNet v0 Behavior |
| :--- | :--- | :--- |
| Phase time gates | Hard-coded | Fixed epoch numbers |
| Economic readiness thresholds | Hard-coded | Fixed percentage thresholds |
| R_target per phase | Governance-tunable | Adjustable within [3%, 7%] |
| β coefficients | Governance-tunable | Quarterly recalibration allowed |
| α (fee sensitivity) | Governance-tunable | Adjustable within [0.3, 1.5] |
| λ (EMA smoothing) | Governance-tunable | Adjustable within [0.005, 0.15] |
| Seigniorage split | Governance-tunable | Adjustable within bounds |
| Fee burn/proposer ratio | Hard-coded | 50/50 fixed (T193) |
| Oracle hints | Reserved | Not available in v0 |
| AI monitoring | Reserved | Not available in v0 |

---

## 6. Phase-Specific Behavior Summary

This section provides a "cheat sheet" of expected values and behaviors for operators and economists.

### 6.1 Bootstrap Phase (Years 0–3)

| Parameter | Expected Range | Notes |
| :--- | :--- | :--- |
| **R_target** | 7.5%–9.0% annual | PQC-adjusted; higher to ensure security |
| **α (fee sensitivity)** | 0.3–0.5 | Limited; prevents instability from volatile early fees |
| **λ (EMA smoothing)** | 0.05–0.10 | Shorter lookback; faster adaptation |
| **Inflation Floor** | 0% | Not active |
| **Fee-Offset Active** | Yes (limited) | Reduced sensitivity |
| **Economic Gates Enforced** | No (entry) / Yes (exit) | Transition requires meeting gates |

**Operator Guidance**:
- Expect relatively stable, higher inflation during Bootstrap
- Fee revenue will have limited impact on inflation
- Focus on validator uptime and stake accumulation

### 6.2 Transition Phase (Years 3–7)

| Parameter | Expected Range | Notes |
| :--- | :--- | :--- |
| **R_target** | 6.0%–7.5% annual | Reduced target; growing fee coverage |
| **α (fee sensitivity)** | 0.8–1.0 | Full sensitivity; fees meaningfully reduce inflation |
| **λ (EMA smoothing)** | 0.02–0.05 | Medium lookback; balanced response |
| **Inflation Floor** | 0% | Not active |
| **Fee-Offset Active** | Yes (full) | Full sensitivity enabled |
| **Economic Gates Enforced** | Yes (entry and exit) | All transitions gated |

**Operator Guidance**:
- Inflation will decrease as fee revenue grows
- Monitor fee coverage ratio for phase transition readiness
- Governance may adjust parameters based on observed behavior

### 6.3 Mature Phase (Year 7+)

| Parameter | Expected Range | Notes |
| :--- | :--- | :--- |
| **R_target** | 4.0%–5.5% annual | Lower target; fee-funded security |
| **α (fee sensitivity)** | 1.0–1.2 | Full sensitivity |
| **λ (EMA smoothing)** | 0.01–0.02 | Longer lookback; maximum stability |
| **Inflation Floor** | 1.0%–2.0% | Active; ensures minimum validator income |
| **Fee-Offset Active** | Yes (full) | Full sensitivity; capped by floor |
| **Economic Gates Enforced** | N/A (terminal phase) | No further transitions |

**Operator Guidance**:
- Inflation may approach or hit the floor if fee revenue is high
- Validator income increasingly comes from proposer fee rewards
- Long-term stability is the priority; expect minimal parameter changes

### 6.4 Summary Table

| Phase | R_target | α | λ | r_floor | Fee-Offset | Gates |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Bootstrap** | 7.5–9.0% | 0.3–0.5 | 0.05–0.10 | 0% | Limited | Exit only |
| **Transition** | 6.0–7.5% | 0.8–1.0 | 0.02–0.05 | 0% | Full | Entry + Exit |
| **Mature** | 4.0–5.5% | 1.0–1.2 | 0.01–0.02 | 1–2% | Full (floored) | N/A |

---

## 7. Implementation Roadmap (T195+)

This section outlines the implementation tasks required to bring the monetary policy design to life. Task IDs beyond T195 are indicative; exact numbering will be finalized during planning.

### 7.1 Task Groups Overview

| Task Group | Description | Dependencies |
| :--- | :--- | :--- |
| **T195–T197** | Monetary module skeleton | T194 (this design) |
| **T198** | PQC cost benchmarking | T195 |
| **T199–T201** | On-chain implementation | T197, T198 |
| **T202–T205** | EMA/smoothing implementation | T199 |
| **T210+** | Treasury governance | T201 |

### 7.2 T195–T197: Monetary Module Skeleton

**Scope**: Create the Rust module structure for monetary policy without active behavior.

| Task | Deliverable | Acceptance |
| :--- | :--- | :--- |
| **T195** | `MonetaryPolicy` struct with phase enum | Compiles; unit tests for phase detection |
| **T196** | Parameter registry (read-only constants) | All hard-coded params accessible |
| **T197** | Design validation harness | Property tests for formula correctness |

**Code Location**: `crates/qbind-monetary/` (new crate)

**Key Structs**:
```rust
// Indicative structure (not final)
pub enum MonetaryPhase { Bootstrap, Transition, Mature }

pub struct MonetaryParams {
    pub r_target: FixedPoint,
    pub alpha: FixedPoint,
    pub lambda: FixedPoint,
    pub r_floor: FixedPoint,
    pub validators_share: u16,  // basis points
    // ...
}

pub struct MonetaryState {
    pub current_phase: MonetaryPhase,
    pub ema_fees: u128,
    pub last_transition_epoch: u64,
    // ...
}
```

### 7.3 T198: PQC Cost Benchmarking & β Calibration

**Scope**: Benchmark actual PQC costs and calibrate β coefficients.

| Deliverable | Description |
| :--- | :--- |
| **ML-DSA-44 verification benchmarks** | Measure actual verification time on reference hardware |
| **Signature size impact analysis** | Quantify bandwidth cost per transaction |
| **State size impact analysis** | Quantify storage cost per account |
| **β calibration report** | Recommended β_compute, β_bandwidth, β_storage values |

**Output**: Concrete β values for MainNet v0 genesis parameters.

### 7.4 T199–T201: On-Chain Implementation

**Scope**: Wire monetary policy into the reward distribution system.

| Task | Deliverable | Acceptance | Status |
| :--- | :--- | :--- | :--- |
| **T199** | Inflation calculation per epoch | Correct r_inf values in test scenarios | ✅ **Implemented** |
| **T200** | Seigniorage distribution to validators | Rewards credited correctly | ⏳ Pending |
| **T201** | Treasury/insurance/community routing | Funds routed to designated accounts | ⏳ Pending |

**T199 Implementation Notes** (2026-02-04):
- Epoch-level, consensus-tracked monetary state added (`MonetaryEpochState`)
- Deterministic `compute_epoch_state()` function bridges epoch inputs to T195 monetary engine
- Epoch boundary detection via `epoch_for_height()` and `is_epoch_boundary()` helpers
- MonetaryMode semantics integrated (Off/Shadow/Active)
- Metrics extended with epoch-level gauges and counters
- Seigniorage application remains pending (T200/T201)

**Integration Points**:
- Execution engine: Distribute rewards at epoch boundaries
- State persistence: Track EMA_fees, current phase
- Consensus: Phase transitions at commit time

### 7.5 T202–T205: EMA/Smoothing Implementation

**Scope**: Implement EMA-based fee smoothing and rate limiters.

| Task | Deliverable | Acceptance |
| :--- | :--- | :--- |
| **T202** | EMA_fees calculation | Correct EMA values with configurable λ |
| **T203** | Rate-of-change limiters | Inflation changes capped per epoch |
| **T204** | Phase transition logic | Automatic transitions when gates met |
| **T205** | Economic metric tracking | Fee coverage, stake ratio, volatility metrics |

### 7.6 T210+: Treasury Governance

**Scope**: Implement treasury governance mechanics (out of T194 scope).

| Task | Deliverable | Notes |
| :--- | :--- | :--- |
| **T210** | Treasury account structure | Basic treasury fund management |
| **T211** | Governance proposal system | On-chain parameter change proposals |
| **T212** | Voting mechanics | Stake-weighted voting for proposals |
| **T213** | Timelock enforcement | Delayed execution of approved changes |

**Note**: Treasury governance is positioned in this design but not detailed. See future design documents for full specification.

### 7.7 Implementation Timeline (Indicative)

```
                         MainNet v0 Launch
                               │
  ├────────┼────────┼────────┼─┴──────┼────────┼────────┼────────►
  T194     T195-197  T198     T199-201  T202-205  Audit   Launch
  Design   Skeleton  Bench    Core      EMA/     Review
           (2 wks)   (1 wk)   (3 wks)   Smooth
                                        (2 wks)
```

---

### 7.6 Implementation Status

**Current Status** (as of T203):

| Task | Component | Status | Notes |
| :--- | :--- | :--- | :--- |
| **T194** | Design Specification | ✅ Complete | This document |
| **T195** | Monetary Engine Core | ✅ Complete | `qbind-ledger::monetary_engine` |
| **T196** | Telemetry & Shadow Mode | ✅ Complete | `qbind-node::monetary_telemetry` |
| **T197** | Seigniorage Accounting | ✅ Complete | `qbind-ledger::monetary_engine` |
| **T199** | Epoch Monetary State | ✅ Complete | `qbind-ledger::monetary_state` |
| **T200** | Validator Seigniorage | ✅ Complete | `qbind-ledger::monetary_state` |
| **T201** | Seigniorage Application | ✅ Complete | `qbind-ledger::monetary_state` |
| **T202** | EMA Fee Smoothing | ✅ Complete | `qbind-ledger::monetary_state` |
| **T203** | Rate-of-Change Limiters | ✅ Complete | `qbind-ledger::monetary_state` |

**What's Implemented** (T195–T203):

- `MonetaryPhase` enum (Bootstrap, Transition, Mature)
- `PhaseParameters` with target rates, floors, caps, EMA lambda (T202), max_delta (T203)
- `MonetaryEngineConfig` with PQC premium factors and validation
- `compute_monetary_decision()` pure function
- `PhaseTransitionRecommendation` heuristics
- `MonetaryTelemetry` node-level service for shadow mode
- `MonetaryMetrics` Prometheus gauges for observability
- **T202**: `ema_step()` helper for per-epoch fee smoothing
- **T202**: `ema_lambda_bps` in PhaseParameters (Bootstrap: 700, Transition: 300, Mature: 150)
- **T202**: `ema_fees_per_epoch` field in MonetaryEpochState
- **T202**: `compute_ema_fee_revenue()` for EMA-based annual fee computation
- **T202**: `smoothed_annual_fee_revenue` now uses EMA-smoothed fees
- **T203**: `max_delta_r_inf_per_epoch_bps` in PhaseParameters (Bootstrap: 25, Transition: 10, Mature: 5)
- **T203**: `clamp_inflation_rate_change()` helper for rate-of-change limiting
- **T203**: `prev_r_inf_annual_bps` field in MonetaryEpochInputs
- **T203**: Rate clamping applied in `compute_epoch_state()` after floor/cap

**EMA Fee Smoothing** (T202):

The consensus-level monetary pipeline now uses EMA-based fee smoothing:
- Epoch 0 initializes EMA to raw fees
- Subsequent epochs apply: `EMA_t = λ × fees_t + (1 - λ) × EMA_{t-1}`
- Phase-dependent λ values provide faster response in Bootstrap, maximum stability in Mature
- This prevents inflation rate spikes from short-term fee volatility

**Rate-of-Change Limiting** (T203):

The monetary engine enforces maximum epoch-to-epoch changes in the annual inflation rate:

- **Formula**: `r_inf_final = clamp(r_bounded, r_prev ± max_delta)`
- **Order of operations**: 
  1. Compute unclamped rate (T195 with fees, EMA, PQC premiums)
  2. Apply floor/cap bounds
  3. Apply Δ-limit relative to previous epoch's final rate
- **Phase-specific limits** (in basis points per epoch):
  - Bootstrap: 25 bps (0.25% max change) — faster response during establishment
  - Transition: 10 bps (0.10% max change) — balanced response during growth
  - Mature: 5 bps (0.05% max change) — maximum stability for long-term operation
- **Epoch 0 behavior**: No clamping applied when no previous rate exists
- **Rationale**: Prevents abrupt shocks to validator economics, ensures predictable rate transitions across phase changes

**Shadow Mode** (T196):

The telemetry module computes and exposes what the monetary engine *would* do under current workloads, without:
- Modifying validator rewards
- Actual mint/burn operations
- Supply changes

This allows operators to observe the computed inflation rate and phase recommendations in metrics/logs before production wiring is enabled.

**Code Locations**:
- Engine: `crates/qbind-ledger/src/monetary_engine.rs`
- State: `crates/qbind-ledger/src/monetary_state.rs`
- Telemetry: `crates/qbind-node/src/monetary_telemetry.rs`
- Metrics: `crates/qbind-node/src/metrics.rs` (MonetaryMetrics)
- Tests: `crates/qbind-ledger/tests/` (T195–T203 test files)

---

## 8. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet v0 architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk tracker |
| **Gas and Fees Design** | [QBIND_GAS_AND_FEES_DESIGN.md](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) | Gas model and fee distribution (T167, T193) |
| **TestNet Beta Spec** | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | TestNet Beta architecture |
| **TestNet Beta Audit** | [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md) | Beta risk tracker |
| **DevNet v0 Freeze** | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet baseline |
| **DAG Consensus Coupling** | [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](../mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) | DAG–HotStuff coupling (T188) |
| **Parallel Execution Design** | [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) | Stage A/B parallelism |

---

## Appendix A: Glossary

| Term | Definition |
| :--- | :--- |
| **Security Budget** | Total economic value distributed to validators per year to ensure network security |
| **Seigniorage** | New token issuance (inflation) distributed as rewards |
| **R_target** | Target annual return rate for stakers, including PQC premium |
| **r_inf** | Actual inflation rate after fee-offset adjustments |
| **r_floor** | Minimum inflation rate regardless of fee revenue |
| **α (alpha)** | Fee-offset sensitivity parameter |
| **λ (lambda)** | EMA smoothing factor |
| **β (beta)** | PQC premium factors (compute, bandwidth, storage) |
| **EMA** | Exponential Moving Average |
| **Fee Coverage Ratio** | Ratio of fee revenue to target security budget |
| **Stake Ratio** | Ratio of staked supply to circulating supply |

## Appendix B: Formula Reference

### Inflation Rate Formula
```
r_inf(t) = max(r_floor(phase), R_target(phase) - α × (EMA_fees_t / S_t))
```

### PQC-Adjusted Target
```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

### EMA Smoothing
```
EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}
```

### Issuance Per Epoch
```
issuance_epoch = r_inf × S_t / epochs_per_year
```

### Net Supply Change
```
net_supply_change = issuance_epoch - burned_fees_epoch
```

---

*End of Document*