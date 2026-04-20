# QBIND Economics Design Draft

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Draft Economics Design Document

---

> **This is a draft economics design document.**
>
> - It is intended to guide TestNet Beta economic dry-run planning and MainNet economics finalization.
> - It does **NOT** finalize tokenomics, presale mechanics, or public distribution commitments.
> - Canonical protocol behavior remains defined by `docs/whitepaper/QBIND_WHITEPAPER.md` and `docs/protocol/QBIND_PROTOCOL_REPORT.md`.
> - This document will evolve through TestNet Beta validation before any economics become final.

---

## 1. Purpose and Scope

This document provides a technical economics design framework for QBIND's progression from DevNet through MainNet. It serves as the internal reference for economics decisions that must be made before and during TestNet Beta validation.

### 1.1 What This Document Is

- A technical draft for economics design decisions
- The foundation for TestNet Beta economics dry-run planning
- A framework for MainNet economics finalization
- An internal reference for the development team and auditors

### 1.2 What This Document Is NOT

- A finalized tokenomics specification
- A presale or distribution commitment
- A marketing or investor document
- A legal or financial guarantee
- A replacement for canonical protocol documentation

### 1.3 Document Scope

This draft addresses:

1. Economics design principles aligned with QBIND's protocol philosophy
2. Environment-specific economic posture (DevNet → TestNet → MainNet)
3. Design space exploration for monetary model, fee model, and validator economics
4. Slashing and economic deterrence within the existing canonical framework
5. Reporter rewards (C3) design options and open questions
6. Explicit enumeration of undecided tokenomics questions
7. TestNet Beta validation requirements for economics

---

## 2. Relationship to the Release Track

This document aligns with the canonical release-track specification (`docs/release/QBIND_RELEASE_TRACK_SPEC.md`).

### 2.1 Release Sequence

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

### 2.2 Economics Timing per Release-Track Spec

| Milestone | Tokenomics Status | Rationale |
|-----------|-------------------|-----------|
| DevNet | ❌ Not Required | DevNet uses test tokens with no economics |
| TestNet Alpha | ❌ Not Required | Alpha tests protocol mechanics, not economics |
| TestNet Beta | ⚠️ **Draft Required** | Beta should dry-run economic parameters |
| MainNet | ✅ **Finalized Required** | MainNet commits to real economic value |

### 2.3 Current Stage

Per the release-track spec, QBIND is currently preparing for the DevNet → TestNet Alpha transition. This economics design draft exists to:

1. Establish the economic design framework before TestNet Beta
2. Enable economics dry-run planning during TestNet Beta
3. Provide sufficient lead time for economic parameter validation

### 2.4 Presale Is NOT the Next Step

Per the release-track spec and decision memo:

> "Presale planning is NOT the next step."

Economics design should proceed independently of presale considerations. This document does not create presale commitments or authorize presale planning.

---

## 3. Current Economics Baseline

This section summarizes the current canonical economics state based on existing documentation.

### 3.1 Protocol Economics Implementation Status

| Component | Status | Reference |
|-----------|--------|-----------|
| Gas/fee machinery | ✅ Functional | M18 gas accounting specification |
| Slashing O1–O5 | ✅ Implemented and enforced | M9/M11, whitepaper Section 12.2 |
| Governance slashing parameters | ✅ Wired | M14, `SlashingPenaltySchedule` in `ParamRegistry` |
| Minimum stake enforcement | ✅ Implemented | M2.1–M2.4, epoch boundary filtering |
| Reporter rewards | ⚠️ Not implemented | C3 intentionally open |
| Tokenomics | ❌ Not finalized | Intentionally deferred |
| Inflation model | ❌ Not finalized | Requires release context |
| Fee policy | ❌ Not finalized | Functional plumbing exists, policy not decided |

### 3.2 What Exists (Canonical)

From the current canonical documentation:

1. **Gas Accounting (M18)**: Formal gas model with deterministic metering, overflow protection, and atomicity guarantees. Gas is functional for correctness testing.

2. **Slashing Penalties (M9/M11/M14/M17)**: Full O1–O5 penalty schedule implemented:
   - O1 (Double-signing): 750 bps (7.5%) slash + 10 epoch jail
   - O2 (Invalid proposer signature): 500 bps (5%) + 5 epoch jail
   - O3 (Invalid vote): 300 bps (3%) + 3 epoch jail
   - O4 (Censorship): 200 bps (2%) + 2 epoch jail
   - O5 (Availability): 100 bps (1%) + 1 epoch jail

3. **Governance Wiring (M14)**: `SlashingPenaltySchedule` stored in `ParamRegistry` with epoch-boundary activation semantics.

4. **Evidence Hardening (M15)**: Hardened evidence ingestion pipeline with 8-step verification ordering, validator-only reporter gating, per-block caps, age bounds, and size limits.

### 3.3 What Is Intentionally Open

Per the contradiction tracker (`docs/whitepaper/contradiction.md`):

- **C3 (Reporter Rewards)**: `reporter_reward_bps` parameter exists but no code distributes rewards. Evidence reporting has no monetary incentive mechanism. This is documented as future economics work, not a safety gap.

### 3.4 What Is Not Yet Decided

The following are explicitly undecided in current canonical documentation:

- Total genesis supply
- Inflation rate or model
- Staking yield targets
- Fee burn vs proposer reward split (plumbing exists, policy not decided)
- Reporter reward funding source
- Treasury/community allocations
- Validator reward sources

---

## 4. Economics Design Principles

The following principles guide QBIND's economics design, consistent with the protocol's overall philosophy of security and correctness over speed.

### 4.1 Security Budget Before Speculative Growth

Economic parameters must first satisfy the security budget—the minimum compensation required to incentivize honest validator participation and secure the network against attack. Speculation about token price appreciation or network growth should not substitute for a sustainable security budget.

**Implication**: Validator rewards must cover operational costs even at conservative network utilization assumptions.

### 4.2 Operational Realism Over Headline Numbers

Economic parameters should be grounded in realistic operational costs and network utilization estimates. Avoid parameters that only make sense under optimistic adoption scenarios.

**Implication**: Fee assumptions should not depend on high transaction volumes that may not materialize.

### 4.3 Simplicity Before Complex Token Engineering

Prefer simple, well-understood economic mechanisms over novel or complex token engineering. Complexity increases attack surface, implementation risk, and auditing difficulty.

**Implication**: Start with straightforward inflation and fee models; introduce complexity only when demonstrated necessary.

### 4.4 No Dependence on Unrealistic Fee Assumptions

Do not design validator economics that require sustained high fee revenue to cover the security budget. Fee revenue is variable and may be near zero in early network operation.

**Implication**: The security budget should be fundable through issuance alone, with fees providing supplementary value.

### 4.5 Testability Before Finalization

Economics must be testable in TestNet Beta before MainNet finalization. Parameters that cannot be observed, measured, or validated under test conditions should not be finalized.

**Implication**: TestNet Beta must simulate economics with observable metrics and adjustable parameters.

### 4.6 Support Decentralization, Not Accidental Centralization

Staking and validator economics must not create accidental centralization pressures through:
- Minimum stake thresholds that exclude smaller validators
- Hardware requirements that favor well-capitalized operators
- Slashing parameters that disproportionately punish smaller stakes

**Implication**: Economic parameters should be evaluated for centralization risk before finalization.

### 4.7 Avoid Locking Numbers Too Early

Premature commitment to specific parameters reduces flexibility to respond to TestNet Beta observations. Keep parameters adjustable until validated.

**Implication**: This document proposes design directions, not final numbers.

### 4.8 PQC Cost Awareness

QBIND's post-quantum cryptography (ML-DSA-44) imposes higher computational, bandwidth, and storage costs than classical alternatives. Economics must account for the "PQC premium":

- ML-DSA-44 signature verification: ~5–10× classical ECDSA verification cost
- Signature size: 2,420 bytes (vs 64 bytes for ECDSA)
- Public key size: 1,312 bytes (vs 32 bytes for ECDSA)

**Implication**: Validator economics must reflect PQC overhead rather than copying classical L1 assumptions blindly.

---

## 5. Environment-Specific Economic Posture

Each release environment has a distinct economic posture reflecting its purpose and maturity.

### 5.1 DevNet

**Purpose**: Internal controlled integration testing

**Economic Posture**:
- Economics are **not final** and **not meaningful**
- Test tokens only—no economic value whatsoever
- Permissive, low-friction operation to facilitate rapid iteration
- No value assumptions should be made

**Feature Settings**:

| Feature | Setting | Rationale |
|---------|---------|-----------|
| Gas | Disabled or free-tier | No economics testing needed |
| Fees | None | Development convenience |
| Slashing | RecordOnly or EnforceCritical | Configurable for testing needs |
| Minimum Stake | May be relaxed | Internal validators only |
| Inflation | None | No economics simulation |

**Key Point**: DevNet economics should not be analyzed for economic validity. Any numeric parameters present are for functional testing only.

---

### 5.2 TestNet Alpha

**Purpose**: First public-facing network with controlled exposure

**Economic Posture**:
- Still **no real value**—test tokens only
- Fees/gas may be active for **functional testing**
- Economics remain **exploratory, not final**
- Protocol mechanics testing takes priority over economic validation

**Feature Settings**:

| Feature | Setting | Rationale |
|---------|---------|-----------|
| Gas | Enabled (test tokens) | Functional correctness testing |
| Fees | Enabled (test tokens) | Mechanism correctness testing |
| Slashing | EnforceCritical | O1/O2 enforced, O3–O5 may be recorded only |
| Minimum Stake | Test values | Not economically final |
| Inflation | Not active | Deferred to Beta |

**Key Point**: Alpha validates that economic *mechanisms* work correctly. It does not validate whether economic *parameters* are appropriate for MainNet.

---

### 5.3 TestNet Beta

**Purpose**: Economics dry-run environment and MainNet rehearsal

**Economic Posture**:
- **Economics dry-run environment**
- Should test draft fee/inflation/staking logic
- Still **no real value**—test tokens only
- Parameter behavior **matters here**—this is where economics are validated

**Feature Settings**:

| Feature | Setting | Rationale |
|---------|---------|-----------|
| Gas | Enabled (hybrid model) | Full economics testing |
| Fees | Burn + proposer reward | Validate fee flow mechanics |
| Slashing | EnforceAll | All O1–O5 enforced |
| Minimum Stake | Draft MainNet values | Validate threshold appropriateness |
| Inflation | Draft issuance model | Validate sustainability |

**Key Point**: TestNet Beta is where economics are validated through observation. Issues discovered here should feed back into parameter adjustment before MainNet finalization.

---

### 5.4 MainNet v0

**Purpose**: Production network with real economic value

**Economic Posture**:
- **Finalized economics required** before launch
- Real value assumptions begin
- Stricter security budget reasoning required
- No experimental shortcuts permitted

**Feature Settings**:

| Feature | Setting | Rationale |
|---------|---------|-----------|
| Gas | Enforced (economically calibrated) | Production gas pricing |
| Fees | Final burn/reward split | Production fee policy |
| Slashing | EnforceAll (mandatory, no override) | Full economic deterrence |
| Minimum Stake | Final value | Production validator threshold |
| Inflation | Final issuance model | Production security budget |

**Key Point**: MainNet economics must be finalized based on TestNet Beta validation. Untested parameters should not proceed to MainNet.

---

### 5.5 Summary: Test Environments Can Simulate Economics Without Creating Commitments

Test environments (DevNet, Alpha, Beta) can simulate economics without creating binding economic commitments because:

1. Test tokens have no economic value
2. Parameters may be adjusted between resets
3. Observed behavior informs parameter adjustment
4. No external parties have staked real value

This separation is intentional and essential for safe economics development.

---

## 6. Monetary Model Design Space

This section explores design options for QBIND's monetary model. **No option is finalized**—this section lays out the design space.

### 6.1 Option A: Fixed Supply / No Ongoing Inflation

**Description**: Total supply is fixed at genesis. No new tokens are ever minted. Validator rewards come entirely from transaction fees.

**Characteristics**:
- Supply: Fixed at genesis (e.g., 1 billion tokens)
- Ongoing issuance: None
- Validator rewards: 100% fee-dependent

**Security Implications**:
- ⚠️ **Security budget risk**: If fee revenue is low, validator incentives may be insufficient to secure the network
- ⚠️ **Bootstrap problem**: New networks with low activity may have near-zero validator revenue
- ✅ **No dilution**: Token holders are not diluted over time

**Validator Incentive Implications**:
- Validators must rely entirely on fees, which may be volatile
- Early network operation may be economically challenging

**Simplicity vs Flexibility**:
- ✅ Simple: No issuance logic, no inflation calculations
- ⚠️ Inflexible: Cannot adjust security budget after genesis

**PQC Relevance**:
- PQC validators have higher operational costs; fee-only model may be insufficient to cover PQC premium

**Verdict**: High risk for early network operation when fees are uncertain. May be viable for mature networks with sustained fee revenue.

---

### 6.2 Option B: Fixed Supply + Pre-Allocated Rewards Pool

**Description**: Total supply is fixed at genesis, but a portion is reserved for validator rewards distributed over time. No new tokens are minted; rewards come from a pre-allocated pool.

**Characteristics**:
- Supply: Fixed at genesis with explicit rewards allocation
- Ongoing issuance: None (distribution from pool)
- Validator rewards: Pool drawdown + fees

**Security Implications**:
- ✅ **Predictable security budget** for reward pool duration
- ⚠️ **Pool exhaustion risk**: What happens when pool is depleted?
- ✅ **No supply expansion**: Total supply never increases

**Validator Incentive Implications**:
- Rewards are predictable during pool lifetime
- Transition to fee-only model is eventual and requires planning

**Simplicity vs Flexibility**:
- ✅ Moderately simple: Distribution schedule is predetermined
- ⚠️ Requires pool sizing decisions at genesis
- ⚠️ Inflexible: Cannot extend rewards without governance intervention

**PQC Relevance**:
- Pool must be sized to account for PQC operational costs over distribution period

**Verdict**: More conservative than ongoing inflation; requires careful pool sizing and transition planning.

---

### 6.3 Option C: Bounded Ongoing Inflation / Security-Budget-Driven Issuance

**Description**: Ongoing inflation with governance-adjustable parameters. New tokens are minted to fund the security budget, with bounded maximum rates.

**Characteristics**:
- Supply: Starts at genesis, grows with inflation
- Ongoing issuance: Yes, bounded (e.g., max 10% annual)
- Validator rewards: Issuance + fees

**Security Implications**:
- ✅ **Sustainable security budget**: Can always fund validator incentives
- ✅ **Responsive**: Parameters can adjust to network needs
- ⚠️ **Dilution**: Token holders are diluted over time

**Validator Incentive Implications**:
- Validators have reliable issuance-based income
- Fee revenue supplements but is not required for basic security

**Simplicity vs Flexibility**:
- ⚠️ More complex: Requires inflation logic, governance for parameter adjustment
- ✅ Flexible: Can respond to changing network conditions

**PQC Relevance**:
- Can explicitly include PQC premium in issuance calculations
- Security budget formula can account for higher validator costs

**Verdict**: Most flexible for long-term operation; requires governance maturity for parameter management.

---

### 6.4 Option D: Hybrid Model (Fees Offset Issuance Over Time)

**Description**: Ongoing inflation funds the security budget, but fee revenue reduces or offsets issuance. As network matures and fees grow, effective inflation decreases.

**Characteristics**:
- Supply: Starts at genesis, growth depends on fee offset
- Ongoing issuance: Yes, reduced by fee contribution
- Validator rewards: Issuance (net of offset) + fees

**Security Implications**:
- ✅ **Sustainable security budget** regardless of fee levels
- ✅ **Natural transition**: Network evolves from issuance-heavy to fee-heavy
- ⚠️ **Complexity**: Fee offset calculations add implementation complexity

**Validator Incentive Implications**:
- Validators benefit from issuance floor plus fee upside
- Long-term economics improve as network grows

**Simplicity vs Flexibility**:
- ⚠️ Most complex: Requires offset calculations, fee tracking
- ✅ Most adaptive: Self-adjusts to network maturity

**PQC Relevance**:
- Can include PQC premium in target issuance calculations
- Fee offset reduces long-term inflation pressure

**Verdict**: Most adaptive long-term, but highest implementation complexity.

---

### 6.5 Preliminary Direction

Based on QBIND's design philosophy (security first, operational realism, PQC awareness), the following direction appears most compatible:

**Recommended Design Family**: Option C (bounded ongoing inflation) or Option D (hybrid with fee offset), with explicit security-budget reasoning.

**Rationale**:
1. QBIND cannot assume high fee revenue in early operation
2. PQC operational costs require explicit accounting
3. Security budget must be fundable independent of fee assumptions
4. Governance-adjustable parameters enable adaptation without hard forks

**However**: This direction is not finalized. TestNet Beta should validate whatever model is chosen with observable economics.

---

## 7. Fee Model Design Space

This section explores fee model design options for QBIND.

### 7.1 Current State

**What is implemented** (per M18):
- Gas metering with deterministic accounting
- Overflow-protected fee calculations
- Atomic fee deduction and application

**What is NOT decided**:
- Final fee pricing (gas cost per operation)
- Fee split between burn and proposer reward
- Fee prediction or estimation mechanisms

### 7.2 Fee Purpose

Fees serve multiple purposes:

1. **Anti-spam**: Fees impose a cost on transaction submission, deterring spam
2. **Resource pricing**: Fees reflect computational, bandwidth, and storage costs
3. **Validator compensation**: Fees (partially) compensate proposers for block production
4. **Supply management**: Fee burns reduce circulating supply

### 7.3 Burn vs Proposer vs Split Models

**Option: Burn-Only Fees**

All fees are burned (removed from circulation).

- ✅ Simple: No reward distribution logic
- ✅ Deflationary pressure: Reduces supply over time
- ⚠️ No proposer compensation: Validator income comes entirely from issuance

**Option: Proposer-Only Fees**

All fees go to the block proposer.

- ✅ Strong proposer incentive: Direct compensation for block production
- ⚠️ No deflationary mechanism
- ⚠️ MEV concerns: Proposer may optimize for fee extraction

**Option: Split Burn/Reward**

Fees split between burn and proposer (e.g., 50/50, 80/20).

- ✅ Balanced: Some deflationary pressure, some proposer compensation
- ⚠️ More complex: Requires split configuration and logic
- ✅ Tunable: Governance can adjust split over time

### 7.4 Predictability vs Simplicity

**Simple Priority Fee Model**:
- Users specify maximum fee they're willing to pay
- Proposer includes transactions based on fee level
- Simple to implement and reason about
- Less predictable for users

**Base Fee + Priority Fee (EIP-1559 Style)**:
- Algorithmic base fee that adjusts to block utilization
- Priority fee on top for proposer compensation
- More predictable for users
- More complex to implement

**Legacy Synthesis Note**: EIP-1559-style base fee was considered for v1+ (see `QBIND_LEGACY_SYNTHESIS.md` §6.1), but is deferred from v0 scope.

### 7.5 What Should Be Simulated in TestNet Beta

TestNet Beta should validate:

1. Fee collection works correctly under load
2. Burn/reward split distributes correctly
3. Fee levels are not prohibitive for basic operations
4. Fee levels provide meaningful anti-spam protection
5. Proposer reward incentives are observable

### 7.6 Functional Fee Plumbing vs Economically Final Fee Policy

**Important Distinction**:

The protocol has functional fee plumbing (M18), but fee *policy* is not decided. TestNet environments can test fee mechanics with placeholder parameters. Final fee pricing and split should be decided based on Beta observations.

---

## 8. Validator Economics Design Space

This section explores validator economics considerations.

### 8.1 Minimum Stake Philosophy

**Current State**: Minimum stake is enforced at registration and epoch boundary (M2.1–M2.4).

**Design Questions**:

1. **How high should minimum stake be?**
   - Too low: Sybil risk, low skin-in-the-game
   - Too high: Centralizes stake among wealthy operators

2. **What operational costs should minimum stake assume?**
   - PQC hardware requirements
   - Bandwidth for larger signatures/keys
   - Storage for larger state

3. **Should minimum stake adjust over time?**
   - Fixed: Simple but inflexible
   - Governance-adjustable: Flexible but requires governance maturity

**Centralization Risk**: Setting minimum stake too high may exclude smaller validators, leading to centralization. Economic parameters must be evaluated for this risk.

### 8.2 Staking Returns / Validator Incentives

**Key Question**: What annual return should validators expect on their staked capital?

**Factors to Consider**:

1. **Opportunity cost**: Validators forgo other investments
2. **Operational cost**: Hardware, bandwidth, power, expertise
3. **Risk premium**: Slashing risk, protocol risk
4. **PQC premium**: Higher costs than classical chains

**Legacy Synthesis Reference** (for background only):

The legacy planning documents modeled a security-budget-driven approach with a "PQC premium formula":

```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

Where:
- β_compute ≈ 0.20–0.35 (ML-DSA-44 verification CPU overhead)
- β_bandwidth ≈ 0.10–0.20 (larger signature sizes)
- β_storage ≈ 0.05–0.10 (larger public keys)

This formula is **not canonical** but illustrates the reasoning that validator economics must account for PQC overhead.

### 8.3 PQC Validator Cost Profile

QBIND validators face higher operational costs than classical L1 validators:

| Cost Factor | PQC Impact |
|-------------|------------|
| CPU | ML-DSA-44 verification ~5–10× classical ECDSA |
| Bandwidth | Signatures 2,420 bytes vs 64 bytes (38× larger) |
| Storage | Public keys 1,312 bytes vs 32 bytes (41× larger) |
| Memory | Larger verification state |

**Implication**: Economics cannot copy classical L1 parameters blindly. Validator compensation must reflect PQC operational costs.

### 8.4 Centralization Risks

Economic parameters may inadvertently centralize the validator set:

1. **High minimum stake**: Excludes smaller operators
2. **High hardware requirements**: Favors well-capitalized operators
3. **Low returns**: Makes validation unattractive for smaller stakes
4. **Aggressive slashing**: Punishes errors disproportionately for smaller stakes

**Mitigation**: Economics parameters should be evaluated for centralization pressure before finalization.

---

## 9. Slashing and Economic Deterrence

This section describes the current canonical slashing state and remaining economics questions.

### 9.1 Current Canonical State

**Slashing is implemented and enforced** per M9/M11/M14/M17:

| Offense | Slash (bps) | Jail (epochs) |
|---------|-------------|---------------|
| O1 (Double-signing) | 750 (7.5%) | 10 |
| O2 (Invalid proposer signature) | 500 (5%) | 5 |
| O3 (Invalid vote) | 300 (3%) | 3 |
| O4 (Censorship) | 200 (2%) | 2 |
| O5 (Availability) | 100 (1%) | 1 |

**Governance Wiring**: `SlashingPenaltySchedule` in `ParamRegistry` with epoch-boundary activation semantics.

**Evidence Hardening**: M15 provides 8-step DoS-resistant verification ordering:
1. Reporter validation
2. Size bounds
3. Per-block cap
4. Deduplication
5. Structure validation
6. Age bounds
7. Future height check
8. Cryptographic verification (expensive, last)

**Environment Behavior**:
- MainNet/TestNet: Fail-closed if penalty schedule is missing
- DevNet: May use fallback defaults

### 9.2 Slashing Economics Considerations

**Are current slash levels appropriate?**

Draft considerations (not final determinations):

- **O1 (Double-signing) at 7.5%**: Severe for the most serious offense. May be appropriate given consensus safety impact.
- **O2–O5 at 1–5%**: Graduated penalties. Lower offenses have lighter penalties.

**Potential concerns**:
- Very high slashing may discourage validator participation
- Very low slashing may provide insufficient deterrence
- These trade-offs should be observed in TestNet Beta

### 9.3 Beta Testing for Slashing Economics

TestNet Beta should validate:

1. Slashing fires correctly for each offense class
2. Penalty amounts are sufficient to deter misbehavior
3. Penalty amounts are not so severe as to cause excessive validator churn
4. Jailing durations provide meaningful operational deterrence
5. Validator behavior post-slashing is observable

### 9.4 Interaction with Minimum Stake and Validator Churn

**Question**: If slashing reduces stake below minimum, what happens?

**Current behavior**: Validators below minimum stake are excluded from active set at epoch boundary.

**Economics question**: Should slashed validators have a path to recovery (restaking), or is exclusion permanent until manual reinstatement?

This interaction should be observed in TestNet Beta.

---

## 10. Reporter Rewards (C3) and Evidence Incentives

This section addresses the intentionally open C3 (reporter rewards) issue.

### 10.1 Current State

Per the contradiction tracker (`docs/whitepaper/contradiction.md`):

- **C3 Status**: ⚠️ **OPEN (Intentional)**
- `reporter_reward_bps` parameter exists in `ParamRegistry` but no code distributes rewards
- Evidence reporting has no monetary incentive mechanism
- M15 provides hardened, abuse-resistant evidence ingestion

**The question is now economics/incentive design, not protocol safety.** The protocol can safely process evidence without rewards; the question is whether monetary incentives should exist and how they should be structured.

### 10.2 Design Options

#### Option A: No Reporter Rewards at All

**Description**: Evidence reporting remains purely altruistic. Validators report evidence out of stake in network health, not monetary reward.

**Characteristics**:
- No reward distribution logic needed
- No abuse vectors from reward-seeking behavior
- Relies on validator alignment with network health

**Incentive Quality**:
- ⚠️ May underincentivize evidence reporting
- ✅ No perverse incentives to manufacture evidence
- ⚠️ Reporters bear cost (gas, bandwidth) without compensation

**Abuse/Spam Risk**:
- ✅ Low: No reward means no spam incentive
- M15 hardening provides baseline abuse resistance regardless

**Accounting Complexity**:
- ✅ None: No reward tracking needed

**Compatibility with M15 Pipeline**:
- ✅ Fully compatible: No changes needed

**Recommendation**: Simplest option. Acceptable if evidence reporting remains healthy without rewards.

---

#### Option B: Small Bounded Reward from Slashed Amount

**Description**: Reporter receives a small percentage of the slashed stake as reward.

**Characteristics**:
- Reward tied to slash amount (e.g., 5–10% of slash goes to reporter)
- Bounded: Reward cannot exceed the slash
- Creates direct incentive for reporting

**Incentive Quality**:
- ✅ Direct incentive tied to offense severity
- ✅ Self-funding: Does not require separate funding source
- ⚠️ May incentivize waiting for larger offenses

**Abuse/Spam Risk**:
- ⚠️ May incentivize collusion (validator commits offense, reporter splits reward)
- ⚠️ May incentivize evidence fabrication attempts
- M15 hardening mitigates fabrication attacks

**Accounting Complexity**:
- ⚠️ Moderate: Must track reporter identity, distribute portion of slash

**Compatibility with M15 Pipeline**:
- ✅ Compatible: Reporter identity already validated in M15 step 1

**Recommendation**: Classic bounty model. Requires careful analysis of collusion incentives.

---

#### Option C: Reward Funded Separately from Treasury/Community Pool

**Description**: Reporter rewards come from a separate pool (treasury, community fund) rather than the slashed amount.

**Characteristics**:
- Fixed or bounded reward per valid evidence submission
- Does not depend on slash amount
- Requires pool funding and management

**Incentive Quality**:
- ✅ Predictable reward for reporters
- ⚠️ May incentivize reporting regardless of offense severity
- ⚠️ Pool exhaustion risk

**Abuse/Spam Risk**:
- ⚠️ Fixed reward may incentivize spam attempts
- M15 per-block caps and validation mitigate spam
- ⚠️ Treasury drain risk under sustained spam

**Accounting Complexity**:
- ⚠️ Higher: Requires pool management, refill governance

**Compatibility with M15 Pipeline**:
- ✅ Compatible: Reward distribution separate from evidence validation

**Recommendation**: More complex. Appropriate if slash-based reward is deemed inappropriate.

---

#### Option D: Deferred Rewards Only After Formal Evidence Confirmation Windows

**Description**: Rewards are not immediate. Evidence enters a confirmation window during which challenges can be submitted. Reward distributes only after unchallenged confirmation.

**Characteristics**:
- Evidence submission does not immediately trigger reward
- Confirmation window (e.g., N blocks) allows challenge
- Reward distributes after window closes without successful challenge

**Incentive Quality**:
- ✅ Reduces false positive risk
- ⚠️ Delayed reward may discourage reporting
- ✅ Allows challenge/appeal process

**Abuse/Spam Risk**:
- ✅ Low: Confirmation window filters low-quality evidence
- ⚠️ Challenge mechanism may introduce new abuse vectors

**Accounting Complexity**:
- ⚠️ High: Requires evidence state tracking, challenge processing, delayed distribution

**Compatibility with M15 Pipeline**:
- ⚠️ Requires extension: M15 validates evidence immediately; deferred rewards require additional state

**Recommendation**: Most robust against false positives, but highest complexity.

---

### 10.3 What Should Be Decided Before MainNet

1. **Whether reporter rewards will exist at all** (Option A vs B/C/D)
2. If rewards exist:
   - Funding source (slashed stake vs separate pool)
   - Reward amount or percentage
   - Distribution timing (immediate vs deferred)
   - Collusion mitigation measures
3. **Whether Beta should simulate reporter rewards** or defer to post-Beta

### 10.4 Recommendation

Given QBIND's principle of simplicity before complexity:

1. **Option A (No Rewards)** is the simplest starting point
2. If evidence reporting proves insufficient, **Option B (Bounded Reward from Slash)** is the next simplest
3. Options C and D should be deferred unless simpler options prove inadequate

**TestNet Beta**: Consider whether Beta should simulate reporter rewards to validate incentive effects, or defer to post-MainNet governance.

---

## 11. Supply and Allocation Questions Still Open

This section explicitly lists major unresolved tokenomics questions. **These are design decisions, not specifications.**

### 11.1 Total Genesis Supply

**Not Decided**: What is the total supply at genesis?

Common ranges in other protocols: 100 million to 10 billion tokens.

This must be decided before MainNet.

### 11.2 Issuance Schedule

**Not Decided**: What is the ongoing token issuance schedule?

Options:
- No ongoing issuance (fixed supply)
- Fixed annual issuance
- Decreasing annual issuance (halving)
- Security-budget-driven issuance
- Fee-offset hybrid

Must be decided before MainNet.

### 11.3 Validator Rewards Source

**Not Decided**: Where do validator rewards come from?

Options:
- Fees only
- Issuance only
- Fees + issuance
- Pre-allocated pool drawdown

Must be decided before MainNet.

### 11.4 Treasury/Community Allocation

**Not Decided**: Is there a treasury or community allocation at genesis?

Questions:
- What percentage of genesis supply goes to treasury?
- Who controls treasury disbursement?
- What governance controls treasury spending?

Must be decided before MainNet.

### 11.5 Reporter Reward Funding Source

**Not Decided**: If reporter rewards are implemented, where does funding come from?

Options:
- Portion of slashed stake
- Separate treasury allocation
- Issuance allocation

Can be deferred to post-MainNet governance if rewards are not in v0 scope.

### 11.6 Test Token vs MainNet Token Branding

**Not Decided**: Should test environments use distinct token names/symbols?

Example:
- TestNet: tQBIND
- MainNet: QBIND

This is a naming convention decision with no protocol implications.

### 11.7 Premine / Reserve / Foundation Allocation

**Not Decided**: Is there any premine, reserve, or foundation allocation?

Questions:
- Is there a team allocation? What vesting schedule?
- Is there a foundation reserve? For what purpose?
- Is there an investor allocation? Under what terms?

These are sensitive questions with legal, financial, and community implications. They are explicitly out of scope for this technical draft.

---

## 12. What Must Be Validated in TestNet Beta

This section provides a concrete checklist for economics validation in TestNet Beta.

### 12.1 Fee Logic Validation

- [ ] Gas metering operates correctly under realistic transaction load
- [ ] Fee collection executes without errors or accounting discrepancies
- [ ] Burn/reward split (if configured) distributes correctly
- [ ] Fee levels are observable and can be reasoned about
- [ ] No transactions fail unexpectedly due to fee calculation errors

### 12.2 Validator Participation Health

- [ ] Validator set remains stable under draft economics
- [ ] No unexpected validator churn due to economic parameters
- [ ] Validator rewards (if issuance active) distribute correctly
- [ ] Staking returns are measurable and observable
- [ ] Minimum stake threshold appears appropriate (not excluding reasonable validators)

### 12.3 Slashing Deterrence Behavior

- [ ] Slashing fires correctly for all offense classes (O1–O5)
- [ ] Penalty amounts create observable deterrent effect
- [ ] Jailing durations operate as expected
- [ ] Slashed validators behave predictably (exit or restake)
- [ ] No unexpected validator exodus due to slashing fear

### 12.4 Minimum Stake Appropriateness

- [ ] Minimum stake does not exclude reasonable validators
- [ ] Minimum stake provides meaningful Sybil resistance
- [ ] Epoch boundary filtering works correctly at threshold
- [ ] Validators can reason about stake requirements

### 12.5 Anti-Spam and Griefing Resistance

- [ ] Fee levels deter transaction spam
- [ ] Evidence submission caps (M15) prevent evidence spam
- [ ] No griefing attacks emerge that exploit economic parameters
- [ ] Mempool remains healthy under adversarial conditions

### 12.6 Observability and Reasoning

- [ ] Economic metrics are exposed and observable
- [ ] Issuance (if active) can be measured
- [ ] Fee revenue can be measured
- [ ] Validator returns can be calculated
- [ ] Economic health can be assessed by external observers

---

## 13. What Is Explicitly Out of Scope for This Draft

This draft does **NOT**:

### 13.1 Presale Mechanics

This document does not set, imply, or authorize:
- Token sale structure
- Pricing mechanisms
- Allocation percentages to sale participants
- Sale timing or sequencing
- Investor terms

### 13.2 Exchange/Listing Strategy

This document does not address:
- Exchange listings
- Market-making arrangements
- Liquidity provisions
- Trading pair decisions

### 13.3 Final Token Distribution

This document does not finalize:
- Team allocation
- Foundation allocation
- Community allocation
- Investor allocation
- Advisor allocation
- Any vesting schedules

### 13.4 Price or Valuation Promises

This document makes no statements about:
- Token price
- Token valuation
- Return expectations
- Market capitalization targets

### 13.5 Legal/Financial Commitments

This document does not create:
- Legal obligations
- Financial guarantees
- Investment representations
- Securities offerings

### 13.6 MainNet Tokenomics Finalization

This document is a **draft**. A separate MainNet tokenomics finalization document will be required before MainNet launch, incorporating TestNet Beta validation results.

---

## 14. Recommended Next Economics Decisions

The following decisions should be made after this draft exists and before or during TestNet Beta:

### 14.1 Choose Preferred Monetary Model Family

**Decision**: Select between:
- Fixed supply (Option A)
- Fixed supply + rewards pool (Option B)
- Bounded ongoing inflation (Option C)
- Hybrid with fee offset (Option D)

**Timeline**: Before TestNet Beta parameters are set

**Owner**: Development team with economics input

### 14.2 Decide Whether Beta Will Simulate Draft Issuance

**Decision**: Should TestNet Beta include active issuance to validate the monetary model?

**Options**:
- Yes: Beta tests draft issuance parameters
- No: Beta tests mechanisms only; issuance deferred to MainNet finalization

**Timeline**: Before TestNet Beta launch

**Owner**: Development team

### 14.3 Decide Whether Reporter Rewards Are In-Scope for Beta or Deferred

**Decision**: Should TestNet Beta include reporter rewards (C3)?

**Options**:
- Yes: Beta tests draft reporter reward mechanics
- No: Defer to post-Beta or post-MainNet governance

**Timeline**: Before TestNet Beta launch

**Owner**: Development team with economics input

### 14.4 Create Separate Final Tokenomics Document

**Decision**: When Beta concludes, create a final tokenomics document incorporating validation results.

**Contents**:
- Finalized genesis supply
- Finalized issuance schedule
- Finalized fee model parameters
- Finalized allocations (team, foundation, community, etc.)
- Finalized minimum stake

**Timeline**: After TestNet Beta, before MainNet launch

**Owner**: Development team, potentially with external economics review

### 14.5 Set Initial Minimum Stake Parameter

**Decision**: What draft minimum stake should TestNet Beta use?

**Criteria**:
- Sufficient for Sybil resistance
- Not so high as to exclude reasonable validators
- Accounts for PQC operational costs

**Timeline**: Before TestNet Beta launch

**Owner**: Development team

---

## 15. Draft Conclusion

This document establishes the economics design framework for QBIND's progression from DevNet through MainNet.

### 15.1 Key Takeaways

1. **Economics are not finalized** — This is a design draft, not a specification
2. **TestNet Beta is the validation environment** — Economics must be tested before MainNet commitment
3. **Presale is NOT the next step** — Economics design proceeds independently of presale considerations
4. **Simplicity is preferred** — Complex token engineering should be avoided unless demonstrated necessary
5. **PQC costs must be accounted for** — Validator economics cannot copy classical L1 assumptions

### 15.2 Recommended Economic Direction

Based on the analysis in this document, the recommended direction is:

- **Monetary Model**: Bounded ongoing inflation (Option C) or hybrid with fee offset (Option D), with explicit security-budget reasoning
- **Fee Model**: Split burn/reward model with governance-adjustable parameters
- **Validator Economics**: PQC-aware cost modeling with moderate minimum stake
- **Reporter Rewards**: Start with no rewards (Option A); add if evidence reporting proves insufficient
- **Approach**: Test in Beta, finalize based on observations, avoid premature parameter lock-in

### 15.3 What Happens Next

1. Review and refine this draft with development team input
2. Decide on TestNet Beta economics scope (issuance, reporter rewards)
3. Set draft parameters for Beta dry-run
4. Execute TestNet Beta economics validation
5. Create final tokenomics document based on Beta results
6. Finalize economics before MainNet launch

---

**This document was created as part of the economics design phase and will be updated as TestNet Beta validation proceeds.**

---

*Canonical References:*
- `docs/whitepaper/QBIND_WHITEPAPER.md` — Authoritative protocol specification
- `docs/protocol/QBIND_PROTOCOL_REPORT.md` — Implementation status
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md` — Risk mitigation index
- `docs/whitepaper/contradiction.md` — C3 reporter rewards status
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md` — Release sequencing
- `docs/protocol/QBIND_LEGACY_SYNTHESIS.md` — Historical economics background (non-authoritative)