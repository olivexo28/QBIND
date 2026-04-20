# QBIND Next Step Decision Memo

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Decision Document  
**Author**: Strategic Planning Review

---

## 1. Executive Recommendation

**RECOMMENDED NEXT STEP: Release-Track Planning Documentation (Option A)**

The safest and highest-value next action for QBIND is to author **canonical release-track documentation** that defines:

1. DevNet operational scope and success criteria
2. TestNet Alpha/Beta gating requirements
3. MainNet launch readiness criteria
4. Explicit release sequencing dependencies

This recommendation is based on the following key observations:

- **Protocol maturity is high**: The M-series mitigation track (M0–M20) has addressed all pre-testnet critical protocol gaps. The security risk register shows all risks at "Low" residual risk level.
- **No public network exists yet**: DevNet, TestNet, and MainNet have not been publicly released, meaning release sequencing definitions are prerequisites for safe progression.
- **Tokenomics/economics depend on release context**: Economic parameters (inflation rates, staking yields, fee structures) are environment-dependent (DevNet vs TestNet vs MainNet) and cannot be safely finalized without first defining what each environment requires.
- **Presale planning is premature**: Without defined economics and release gates, presale discussions create unnecessary risk exposure and commitment without foundation.

---

## 2. Current Readiness Snapshot

### Protocol Implementation Status

| Component | Status | Evidence |
|-----------|--------|----------|
| Consensus (HotStuff BFT) | ✅ Complete | M5 timeout/view-change, 28 tests |
| Slashing (O1–O5) | ✅ Complete | M9/M11, all offense classes enforced |
| Minimum Stake Enforcement | ✅ Complete | M2.1–M2.4, epoch boundary filtering |
| DoS Protection | ✅ Complete | M6 cookie protection, M15 evidence hardening |
| NodeId/Authentication | ✅ Complete | M7/M8 KEMTLS mutual auth |
| Epoch Transition Safety | ✅ Complete | M16 atomic transitions |
| Gas Accounting | ✅ Complete | M18 formal specification |
| Slashing Persistence | ✅ Complete | M1/M19 canonicalization |

### Documentation Status

| Document | Status | Notes |
|----------|--------|-------|
| Whitepaper (Draft v3) | ✅ Stable | Technical specification complete, no tokenomics |
| Protocol Report | ✅ Stable | All spec gaps mitigated |
| M-Series Coverage | ✅ Stable | Audit-ready index |
| Contradiction Tracker | ✅ Stable | 1 intentionally open item (C3 reporter rewards) |
| Legacy Synthesis | ✅ Stable | Historical context preserved |

### Open Items (Intentional)

| Item | Status | Rationale |
|------|--------|-----------|
| C3: Reporter Rewards | ⚠️ Open (Intentional) | Future tokenomics work; not a safety gap; M15 provides abuse-resistant baseline |
| Validator vs Non-Validator Config | Pre-MainNet | Low priority, not critical |
| Monetary State Error Handling | Pre-MainNet | Production hardening, not blocking |

### Release Environment Status

| Environment | Public Status | Documentation Status |
|-------------|---------------|---------------------|
| DevNet | ❌ Not Released | ❌ No formal spec |
| TestNet Alpha | ❌ Not Released | ❌ No formal spec |
| TestNet Beta | ❌ Not Released | ❌ No formal spec |
| MainNet | ❌ Not Released | ❌ No formal spec |

**Critical Finding**: No canonical release-track documentation exists that defines the progression, gating criteria, or operational boundaries for each environment.

---

## 3. Option Comparison

### Option A: Release-Track Planning Documentation First ✅ RECOMMENDED

**Description**: Author canonical documents defining DevNet, TestNet (Alpha/Beta), and MainNet release stages, gates, success criteria, and operational constraints.

**Pros**:
- Establishes foundation for all downstream decisions (economics, presale, community engagement)
- Low risk—documentation commits no economic parameters or external promises
- Enables parallel work streams (economics team can draft against known release targets)
- Required for any credible external audit or investor discussion
- Consistent with legacy planning (QBIND_LEGACY_SYNTHESIS.md §3.1 defines this progression)

**Cons**:
- Does not immediately advance economics/tokenomics
- May reveal gaps that require protocol changes (feature, not a bug)

**Risk Level**: 🟢 **LOW**

---

### Option B: Economics/Tokenomics Specification First

**Description**: Define inflation model, staking yields, fee structures, reporter incentives, and supply parameters.

**Pros**:
- Addresses the only open item (C3 reporter rewards)
- Enables economic modeling and projections
- Required eventually for MainNet

**Cons**:
- **Without release gates, economic parameters lack context**—inflation targets for DevNet vs MainNet differ significantly
- Legacy planning (QBIND_LEGACY_SYNTHESIS.md §2.2) shows three-phase monetary model tied to network maturity stages
- Risk of designing economics in a vacuum, requiring later revision
- Cannot be finalized without knowing which features are active at each release stage

**Risk Level**: 🟡 **MEDIUM**

**Timing Recommendation**: After Option A; before TestNet Beta

---

### Option C: Presale / Launch Planning First

**Description**: Define token distribution, presale mechanics, vesting schedules, and community launch strategy.

**Pros**:
- Could accelerate funding/community building

**Cons**:
- **Extremely high risk without economics or release sequencing defined**
- Presale commitments create binding obligations without foundation
- No way to price tokens without inflation/yield model
- No way to set expectations without release timeline
- Creates regulatory and reputational risk if release timeline slips
- Premature external promises undermine project credibility

**Risk Level**: 🔴 **HIGH**

**Timing Recommendation**: After Option B (economics) is stable; likely after TestNet Beta demonstrates live economics

---

### Option D: Developer Tooling / Public Onboarding Documentation First

**Description**: Author SDK documentation, API references, smart contract guides, and developer tutorials.

**Pros**:
- Enables external developer engagement
- Builds ecosystem ahead of MainNet

**Cons**:
- **No public DevNet/TestNet exists for developers to target**
- Tooling docs without a live network is hollow—developers cannot actually build
- VM/execution semantics may still evolve (whitepaper marks EVM integration as "VM v0")
- Gas model changes could invalidate developer assumptions
- Risk of creating outdated documentation before network stabilizes

**Risk Level**: 🟡 **MEDIUM**

**Timing Recommendation**: After DevNet public release; accelerate during TestNet Alpha/Beta

---

### Option Ranking (Safest to Riskiest)

| Rank | Option | Risk Level | Timing |
|------|--------|------------|--------|
| 1 | **A: Release-Track Planning** | 🟢 Low | **NOW** |
| 2 | B: Economics/Tokenomics | 🟡 Medium | After A, before TestNet Beta |
| 3 | D: Developer Tooling | 🟡 Medium | After DevNet public, during TestNet |
| 4 | C: Presale/Launch Planning | 🔴 High | After B is stable, after TestNet Beta |

---

## 4. Recommended Release Sequence (DevNet / TestNet Alpha / TestNet Beta / MainNet)

Based on the legacy planning synthesis (QBIND_LEGACY_SYNTHESIS.md §3.1) and current implementation status:

### 4.1 DevNet (Internal/Controlled)

**Purpose**: Internal validation, integration testing, CI/CD pipeline verification

**Characteristics**:
- Controlled validator set (project team only)
- No external tokens or economic value
- LocalMesh or limited P2P networking
- Slashing: `RecordOnly` or `EnforceCritical` (configurable)
- Gas: Disabled or free-tier for testing
- Execution: Nonce-only engine initially, VM v0 integration testing

**Exit Criteria**:
- [ ] All M-series tests pass in DevNet configuration
- [ ] Multi-node consensus demonstrated (≥4 nodes)
- [ ] Epoch transitions verified across restart
- [ ] Basic transaction flow (nonce-only) functional
- [ ] Metrics and observability operational

**Duration**: 2–4 weeks internal testing

---

### 4.2 TestNet Alpha (Controlled Public)

**Purpose**: Limited external validator onboarding, stress testing, adversarial testing

**Characteristics**:
- Expanded validator set (invited partners, auditors)
- Test tokens with no economic value
- Full P2P networking
- Slashing: `EnforceCritical` (O1/O2 enforced, O3–O5 recorded)
- Gas: Enabled but low-stakes (test tokens)
- Execution: VM v0 with gas metering

**Exit Criteria**:
- [ ] External validators successfully onboard
- [ ] Slashing penalties fire correctly under adversarial conditions
- [ ] Performance benchmarks achieved (TPS, finality latency)
- [ ] No critical bugs from external testing
- [ ] Security audit initiated

**Duration**: 4–8 weeks

**RECOMMENDATION**: The first real-world public network should be **TestNet Alpha**, not TestNet Beta. Alpha allows controlled exposure with explicit "expect breakage" expectations, reducing reputational risk if issues emerge.

---

### 4.3 TestNet Beta (Open Public)

**Purpose**: Open public participation, economics dry-run, mainnet rehearsal

**Characteristics**:
- Open validator set (public permissionless or with minimum stake)
- Test tokens (may model real economic parameters for testing)
- Full P2P networking required
- Slashing: `EnforceAll` (all O1–O5 enforced)
- Gas: Enabled with hybrid model (burn + proposer reward)
- Execution: VM v0 with Stage A parallelism

**Exit Criteria**:
- [ ] Open participation successful (permissionless onboarding)
- [ ] Economics dry-run completed (test inflation, staking, fees)
- [ ] Security audit complete with no critical findings
- [ ] At least 2 weeks of stable operation under load
- [ ] Genesis ceremony process validated

**Duration**: 4–12 weeks (depending on economics validation needs)

---

### 4.4 MainNet v0 (Production)

**Purpose**: Live production network with real economic value

**Characteristics**:
- Permissionless validator set with minimum stake
- Real tokens with economic value
- P2P networking required
- Slashing: `EnforceAll` (mandatory, no override)
- Gas: Enforced hybrid model
- Execution: VM v0 + Stage B parallelism
- Keys: HSM-ready (remote signer required for validators)

**Entry Criteria (all must be met)**:
- [ ] TestNet Beta exit criteria satisfied
- [ ] Security audit signed off (no critical/high findings open)
- [ ] Economics finalized and documented
- [ ] Genesis file hash distributed and verified
- [ ] Upgrade governance process documented and tested
- [ ] Council multi-sig operational
- [ ] Bug bounty program active
- [ ] Legal/regulatory review complete (if applicable)

**IMPORTANT**: MainNet should only launch after:
1. Release-track documentation is complete
2. Economics/tokenomics are finalized
3. TestNet Beta has demonstrated economic mechanics work
4. Security audit is complete

---

## 5. Tokenomics / Presale Timing Recommendation

### 5.1 When to Finalize Tokenomics

| Milestone | Tokenomics Status | Rationale |
|-----------|-------------------|-----------|
| Before DevNet | ❌ Not Required | DevNet uses test tokens with no economics |
| Before TestNet Alpha | ❌ Not Required | Alpha tests protocol mechanics, not economics |
| Before TestNet Beta | ⚠️ Draft Required | Beta should dry-run economic parameters |
| Before MainNet | ✅ **Finalized Required** | MainNet commits to real economic value |

**RECOMMENDATION**: Tokenomics should be **drafted** before TestNet Beta and **finalized** before MainNet. It should NOT be finalized before TestNet because:

1. Economics parameters need live testing (inflation, staking yields, fee burns)
2. Legacy planning shows three-phase model with different parameters per phase
3. Premature finalization creates unnecessary commitment before validation

### 5.2 When to Begin Presale Planning

| Milestone | Presale Planning Status | Rationale |
|-----------|------------------------|-----------|
| Before Release-Track Docs | ❌ **Too Early** | No foundation for timeline or pricing |
| Before Economics Draft | ❌ **Too Early** | Cannot price without supply/inflation model |
| After Economics Draft | ⚠️ Can Begin Planning | Draft economics enables preliminary modeling |
| After TestNet Beta | ✅ **Safe to Finalize** | Validated economics, demonstrated network |

**RECOMMENDATION**: Presale planning should **NOT begin now**. Minimum prerequisites:

1. Release-track documentation complete (Option A)
2. Economics/tokenomics at least drafted (Option B)
3. TestNet Alpha demonstrating stable operation

**Safe Presale Timing**: After TestNet Beta demonstrates economic mechanics work correctly with draft tokenomics.

---

## 6. Proposed Next 3 Canonical Documents to Author

In priority order:

### 6.1 QBIND_RELEASE_TRACK_SPEC.md (Immediate)

**Location**: `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Contents**:
- DevNet scope, constraints, and exit criteria
- TestNet Alpha scope, constraints, and exit criteria
- TestNet Beta scope, constraints, and exit criteria
- MainNet v0 entry requirements
- Release gating decision authority
- Rollback/deprecation procedures

**Dependencies**: None (can start immediately)

---

### 6.2 QBIND_DEVNET_OPERATIONAL_GUIDE.md (Second Priority)

**Location**: `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`

**Contents**:
- DevNet genesis configuration
- Validator onboarding process (internal)
- Node configuration for DevNet
- Monitoring and observability setup
- Common issues and troubleshooting
- Upgrade procedures for DevNet

**Dependencies**: QBIND_RELEASE_TRACK_SPEC.md (for scope definition)

---

### 6.3 QBIND_ECONOMICS_DESIGN_DRAFT.md (Third Priority)

**Location**: `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md`

**Contents**:
- Security-budget-driven inflation philosophy (from legacy synthesis)
- Three-phase monetary model (bootstrap, transition, mature)
- Staking yield calculations
- Fee market structure (burn + proposer split)
- Reporter reward design (completes C3)
- Supply parameters and allocation framework

**Status**: Draft for TestNet Beta validation; finalize before MainNet

**Dependencies**: QBIND_RELEASE_TRACK_SPEC.md (for environment context)

---

## 7. What Not To Do Yet

### 7.1 DO NOT: Finalize Tokenomics Before TestNet Beta

**Reason**: Economic parameters need live testing. Premature commitment creates inflexibility if parameters prove suboptimal.

**Exception**: Draft economics for modeling is acceptable and recommended.

---

### 7.2 DO NOT: Begin Presale Planning Before Economics Draft

**Reason**: Cannot price tokens or set expectations without supply/inflation model. Presale commitments without foundation create binding obligations that may be impossible to fulfill.

---

### 7.3 DO NOT: Publish Public Developer Documentation Before DevNet

**Reason**: No network exists for developers to build against. Documentation without a target network is hollow and will become outdated as the protocol evolves.

**Exception**: Internal developer setup guides for team use are acceptable.

---

### 7.4 DO NOT: Announce MainNet Timeline Before TestNet Beta Exits Successfully

**Reason**: MainNet timing depends on TestNet Beta performance. Premature announcements create pressure to launch before ready, which is the single highest-risk outcome.

---

### 7.5 DO NOT: Skip TestNet Alpha and Go Directly to TestNet Beta

**Reason**: Alpha provides controlled exposure with explicit "expect breakage" expectations. Skipping to Beta increases reputational risk if issues emerge, because Beta implies production-readiness.

---

## 8. Final Decision

### Decision

**Proceed with Option A: Release-Track Planning Documentation**

Author `QBIND_RELEASE_TRACK_SPEC.md` as the immediate next step.

### Sequencing

```
NOW:         Option A (Release-Track Planning)
             ↓
             DevNet Internal Testing
             ↓
NEXT:        Option D (Developer Tooling - Internal Guides)
             ↓
             DevNet Stabilization
             ↓
PARALLEL:    Option B (Economics Draft)
             ↓
             TestNet Alpha (Controlled Public)
             ↓
             Option D (Public Developer Docs)
             ↓
             TestNet Beta (Economics Dry-Run)
             ↓
LATER:       Option C (Presale Planning)
             ↓
             Option B (Economics Finalization)
             ↓
             MainNet Launch
```

### Validation of User Hypothesis

The user's hypothesis was:

> "The safest next step is probably to create canonical release-track documents first"

**Verdict: CONFIRMED ✅**

This analysis validates the hypothesis. Release-track documentation is indeed the safest and most strategically correct next step because:

1. It establishes the foundation for all downstream work
2. It creates no premature external commitments
3. It enables parallel economics drafting with clear context
4. It aligns with the project's documented network evolution planning

---

## Appendix A: Contradictions Discovered During Analysis

No new contradictions were discovered between canonical documents during this analysis. The existing contradiction tracker (`contradiction.md`) accurately reflects the current state:

- **C3 (Reporter Rewards)** remains the only open item, and it is intentionally deferred to tokenomics work, consistent with this memo's sequencing recommendation.

The legacy synthesis document (`QBIND_LEGACY_SYNTHESIS.md`) is correctly marked as supplementary material that does not contradict canonical documentation.

---

## Appendix B: References

- `docs/whitepaper/QBIND_WHITEPAPER.md` — Protocol specification (Draft v3)
- `docs/protocol/QBIND_PROTOCOL_REPORT.md` — Implementation status and gaps
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md` — Risk mitigation index
- `docs/whitepaper/contradiction.md` — Implementation discrepancies
- `docs/protocol/QBIND_LEGACY_SYNTHESIS.md` — Legacy planning context
- `scripts/build-mainnet-release.sh` — Existing MainNet build tooling

---

*This document establishes the strategic direction for QBIND's next phase. All subsequent planning should reference this memo for sequencing and timing decisions.*