# QBIND Release Track Specification

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Canonical Release Planning Document

---

## 1. Purpose and Scope

This document is the **canonical release-track planning specification** for QBIND.

**What this document defines:**
- Environment scope for DevNet, TestNet Alpha, TestNet Beta, and MainNet v0
- Release gates and exit criteria for each stage transition
- Operational, security, and governance requirements
- Economics and presale timing constraints

**What this document does NOT finalize:**
- Tokenomics or inflation model parameters (deferred to separate economics documentation)
- Presale mechanics or token distribution
- Marketing timelines or public announcements

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md` — Authoritative technical specification
- `docs/protocol/QBIND_PROTOCOL_REPORT.md` — Protocol gaps and implementation status
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md` — Risk mitigation audit index

This document establishes the internal reference for release sequencing:

```
DevNet → TestNet Alpha → TestNet Beta → MainNet v0
```

---

## 2. Release Philosophy

QBIND's release strategy is built on the following principles:

### 2.1 Security and Correctness Over Speed

- Security invariants must never be bypassed to accelerate release timelines
- Protocol correctness takes precedence over feature completeness
- Unresolved critical issues block stage transitions regardless of schedule pressure

### 2.2 Progressive Exposure

- Public release stages may only widen after the prior stage demonstrates stability
- Each stage serves as a prerequisite validation for the next
- Regression in stability metrics at any stage may block or reverse progression

### 2.3 Environment Purpose Boundaries

| Environment | Purpose | Exposure |
|-------------|---------|----------|
| DevNet | Controlled internal integration and CI-like validation | Internal only |
| TestNet Alpha | First real-world public network with controlled exposure | Controlled public |
| TestNet Beta | Broader public exposure with economics dry-run | Open public |
| MainNet v0 | Production network with real economic value | Production |

### 2.4 Alpha Before Beta

- **TestNet Alpha is the first public-facing network**, not TestNet Beta
- Alpha explicitly communicates "expect breakage" expectations
- Beta implies higher stability and is a mainnet rehearsal environment
- Skipping Alpha to reach Beta faster is not permitted

### 2.5 Demonstrated Success Required

- MainNet launch depends on demonstrated TestNet Beta success
- Success is measured by defined exit criteria, not elapsed time
- No automatic progression based solely on calendar dates

### 2.6 No Premature Commitments

- No presale or binding public launch promises before economics and release gates are mature
- This release-track specification is not a launch announcement
- External communications must not imply dates or timelines until all prerequisites are satisfied

---

## 3. Current Baseline

This section summarizes the current project readiness based on canonical documentation.

### 3.1 Protocol Implementation Status

| Component | Status | Reference |
|-----------|--------|-----------|
| Consensus (HotStuff BFT) | ✅ Complete | M5 timeout/view-change |
| Slashing (O1–O5) | ✅ Complete | M9/M11 penalty enforcement |
| Minimum Stake Enforcement | ✅ Complete | M2.1–M2.4 epoch filtering |
| DoS Protection | ✅ Complete | M6 cookie protection, M15 evidence hardening |
| NodeId/Authentication | ✅ Complete | M7/M8 KEMTLS mutual auth |
| Epoch Transition Safety | ✅ Complete | M16 atomic transitions |
| Gas Accounting | ✅ Complete | M18 formal specification |
| Slashing Persistence | ✅ Complete | M1/M19 canonicalization |

### 3.2 Documentation Status

| Document | Status | Notes |
|----------|--------|-------|
| Whitepaper (Draft v3) | ✅ Stable | Technical specification complete, no tokenomics |
| Protocol Report | ✅ Stable | All spec gaps mitigated |
| M-Series Coverage | ✅ Stable | Audit-ready index (M0–M20 complete) |
| Contradiction Tracker | ✅ Stable | 1 intentionally open item (C3 reporter rewards) |
| Legacy Synthesis | ✅ Stable | Historical context preserved |

### 3.3 Pre-TestNet Critical Issues

- **All pre-testnet critical issues have been mitigated** per M-series coverage
- M0–M20 mitigation track addresses all identified security risks
- Residual risk levels are all at "Low" in the security risk register

### 3.4 Intentionally Open Items

| Item | Status | Rationale |
|------|--------|-----------|
| C3: Reporter Rewards | ⚠️ Open (Intentional) | Future tokenomics work; not a safety gap; M15 provides abuse-resistant baseline |

### 3.5 Release Environment Status

| Environment | Public Status | Notes |
|-------------|---------------|-------|
| DevNet | ❌ Not Released | No public DevNet exists |
| TestNet Alpha | ❌ Not Released | No public TestNet exists |
| TestNet Beta | ❌ Not Released | No public TestNet exists |
| MainNet | ❌ Not Released | Production network not launched |

### 3.6 Economics Status

- Tokenomics: **Not finalized** (intentionally deferred)
- Reporter rewards: **Not implemented** (deferred to tokenomics work)
- Inflation model: **Not finalized** (requires release context)
- Fee structures: **Functional for testing** but not economically final

---

## 4. Environment Definitions

### 4.1 DevNet

**A) Purpose**
- Internal controlled integration testing
- Operator onboarding practice and runbook validation
- CI-like validation for protocol changes
- Integration testing for new features before public exposure

**B) Intended Participants**
- Core development team only
- Invited technical partners for specific testing (under NDA)
- No external or public participants

**C) Network Characteristics**
- LocalMesh or limited P2P networking
- May use in-memory persistence for rapid iteration
- Network may be reset at any time without notice
- Genesis configuration controlled by development team

**D) Required Features On/Off**

| Feature | Status |
|---------|--------|
| Slashing | `RecordOnly` or `EnforceCritical` (configurable) |
| Gas/Fees | Disabled or free-tier for testing |
| Execution | Nonce-only engine or VM v0 integration testing |
| Persistence | In-memory acceptable; RocksDB for restart testing |
| Keys | EncryptedFs (HSM not required) |

**E) Stability Expectations**
- Instability is acceptable and expected
- Network resets are normal operations
- Breaking changes may be deployed without advance notice
- No uptime guarantees

**F) What Success Looks Like**
- [ ] Multi-node consensus operates stably (≥4 nodes)
- [ ] Restart safety demonstrated (nodes rejoin after crash/restart)
- [ ] Core observability operational (metrics, logs, basic alerting)
- [ ] Operator runbook draft validated through practice
- [ ] No unresolved critical protocol issues

---

### 4.2 TestNet Alpha

**A) Purpose**
- First public-facing network
- Controlled external validator onboarding
- Adversarial testing and bug discovery
- External security review and audit support

**B) Intended Participants**
- Core development team
- Invited external validators (partners, auditors)
- Security researchers (invited or through bug bounty)
- Limited external developers for feedback

**C) Network Characteristics**
- Full P2P networking
- RocksDB persistence required
- Network may be reset with advance notice
- Genesis configuration published but may be updated for Alpha resets

**D) Required Features On/Off**

| Feature | Status |
|---------|--------|
| Slashing | `EnforceCritical` (O1/O2 enforced, O3–O5 may be recorded only) |
| Gas/Fees | Enabled with test tokens (no economic value) |
| Execution | VM v0 with gas metering |
| Persistence | RocksDB (mandatory) |
| Keys | EncryptedFs (HSM optional) |

**E) Stability Expectations**
- Instability is acceptable but should improve over time
- Network resets possible with 48-hour notice (except emergency)
- Expected uptime target: 80%+ during active testing periods
- Breaking changes require advance communication

**F) What Success Looks Like**
- [ ] External validators successfully onboard and operate
- [ ] Slashing penalties fire correctly under adversarial conditions
- [ ] Performance benchmarks achieved (baseline TPS, finality latency)
- [ ] No critical security issues discovered (or all discovered issues resolved)
- [ ] Security audit initiated and providing feedback

---

### 4.3 TestNet Beta

**A) Purpose**
- Broader public exposure
- Economics dry-run environment
- MainNet rehearsal
- Validator operational readiness validation

**B) Intended Participants**
- Open public participation (permissionless or with stated minimum stake)
- Validator candidates preparing for MainNet
- External developers building applications
- Community testing

**C) Network Characteristics**
- Full P2P networking required
- RocksDB persistence required
- Network resets only in exceptional circumstances (7-day notice minimum)
- Genesis configuration frozen except for critical fixes

**D) Required Features On/Off**

| Feature | Status |
|---------|--------|
| Slashing | `EnforceAll` (all O1–O5 enforced) |
| Gas/Fees | Enabled with hybrid model (burn + proposer reward) using test tokens |
| Execution | VM v0 with Stage A parallelism |
| Persistence | RocksDB (mandatory) |
| Keys | EncryptedFs (HSM strongly recommended for serious validators) |

**E) Stability Expectations**
- High stability expected (MainNet rehearsal)
- Expected uptime target: 95%+
- Network resets strongly discouraged
- Breaking changes require formal upgrade governance process

**F) What Success Looks Like**
- [ ] Open participation successful (permissionless onboarding works)
- [ ] Economics dry-run completed (test inflation, staking, fees validated)
- [ ] Security audit complete with no critical/high findings open
- [ ] At least 2 weeks of sustained stable operation under realistic load
- [ ] Genesis ceremony process validated
- [ ] Upgrade governance process tested and documented

---

### 4.4 MainNet v0

**A) Purpose**
- Production network with real economic value
- Live protocol operation
- Long-term state persistence

**B) Intended Participants**
- Permissionless validator set (with minimum stake requirement)
- All users and applications
- Full public operation

**C) Network Characteristics**
- Full P2P networking required
- RocksDB persistence mandatory
- No network resets (state must be preserved indefinitely)
- Genesis configuration immutable after launch

**D) Required Features On/Off**

| Feature | Status |
|---------|--------|
| Slashing | `EnforceAll` (mandatory, no override) |
| Gas/Fees | Enforced hybrid model with finalized economic parameters |
| Execution | VM v0 + Stage B parallelism |
| Persistence | RocksDB (mandatory) |
| Keys | HSM-ready (remote signer required for validators) |

**E) Stability Expectations**
- Production-grade stability required
- Expected uptime target: 99%+ (excluding planned maintenance)
- No experimental shortcuts permitted
- All changes follow formal governance and upgrade procedures

**F) What Success Looks Like**
- [ ] All prior stage exit criteria satisfied
- [ ] Security audit signed off (no critical/high findings open)
- [ ] Economics finalized and documented
- [ ] Genesis file hash distributed and independently verified
- [ ] Upgrade governance process documented and operational
- [ ] Council multi-sig operational
- [ ] Bug bounty program active
- [ ] Incident response procedures documented and tested

---

## 5. Environment Matrix

| Attribute | DevNet | TestNet Alpha | TestNet Beta | MainNet v0 |
|-----------|--------|---------------|--------------|------------|
| **Participants** | Internal team only | Invited validators, auditors | Open public | Permissionless |
| **Networking Mode** | LocalMesh / limited P2P | Full P2P | Full P2P (required) | Full P2P (required) |
| **Persistence** | In-memory acceptable | RocksDB (required) | RocksDB (required) | RocksDB (required) |
| **Slashing Mode** | RecordOnly / EnforceCritical | EnforceCritical | EnforceAll | EnforceAll (mandatory) |
| **Gas/Fee Mode** | Disabled / free-tier | Enabled (test tokens) | Enabled (test economics) | Enforced (final economics) |
| **Validator Onboarding** | Manual / internal | Invited / controlled | Open / permissionless | Permissionless + min stake |
| **Observability** | Basic (metrics, logs) | Full (metrics, logs, alerts) | Full + public dashboards | Full + public + SLA |
| **Restart Tolerance** | Full reset permitted | Reset with 48h notice | Reset with 7d notice (exceptional) | No resets permitted |
| **Release Messaging** | Internal only | "Expect breakage" | "Rehearsal for MainNet" | "Production network" |
| **Key Management** | EncryptedFs | EncryptedFs (HSM optional) | EncryptedFs (HSM recommended) | HSM-ready (required) |
| **Economic Value** | None | None (test tokens) | None (test tokens) | Real value |
| **Uptime Target** | None | 80%+ | 95%+ | 99%+ |

**Notes:**
- Values marked "must be stricter than previous stage" indicate progression requirements without specifying exact parameters
- Exact configuration values should be documented in environment-specific operational guides
- Matrix values may be refined as operational experience is gained, but may not regress

---

## 6. Release Gates and Exit Criteria

### 6.1 DevNet → TestNet Alpha

**Required Exit Criteria (all must be satisfied):**

- [ ] **Consensus Stability**: Multi-node consensus demonstrated stable operation for ≥72 hours continuous
- [ ] **Restart Safety**: Nodes successfully rejoin network after crash/restart without state corruption
- [ ] **Node Count**: Minimum 4 nodes operating stably in DevNet configuration
- [ ] **Observability**: Core metrics and logging operational and validated
- [ ] **Runbook Draft**: Operator runbook draft exists and has been validated through practice
- [ ] **Critical Issues**: No unresolved critical protocol issues in the protocol report
- [ ] **M-Series Complete**: All relevant M-series mitigations verified in DevNet environment
- [ ] **Basic Transactions**: Transaction submission and execution functional (nonce-only at minimum)
- [ ] **Epoch Transitions**: Epoch transitions verified across restart cycles

**Documentation Requirements:**
- [ ] DevNet operational guide available for Alpha validators
- [ ] Known issues document maintained and current
- [ ] Validator onboarding instructions drafted

---

### 6.2 TestNet Alpha → TestNet Beta

**Required Exit Criteria (all must be satisfied):**

- [ ] **External Validators**: ≥3 external validators successfully onboarded and operating
- [ ] **Adversarial Testing**: Dedicated adversarial testing period completed (≥2 weeks)
- [ ] **Security Issues**: No critical security issues from Alpha remain unresolved
- [ ] **Performance Baseline**: TPS and finality latency benchmarks achieved and documented
- [ ] **Slashing Validation**: Slashing penalties verified to fire correctly under adversarial conditions
- [ ] **Security Audit**: Security audit initiated with initial feedback incorporated
- [ ] **Operational Stability**: 80%+ uptime achieved over final 2 weeks of Alpha
- [ ] **Economics Draft**: Draft economics document ready for Beta dry-run

**Documentation Requirements:**
- [ ] Alpha post-mortem with lessons learned documented
- [ ] Beta operational guide available
- [ ] Economics design draft complete for Beta testing
- [ ] Bug tracking and triage process operational

---

### 6.3 TestNet Beta → MainNet

**Required Exit Criteria (all must be satisfied):**

**Security:**
- [ ] **Security Audit Complete**: Independent security audit completed with no critical/high findings open
- [ ] **Contradiction Tracker Clear**: All critical items in contradiction tracker resolved or explicitly accepted
- [ ] **Bug Bounty**: Bug bounty program active for ≥4 weeks with no critical findings open

**Stability:**
- [ ] **Sustained Stability**: ≥2 weeks of sustained stable operation under realistic load
- [ ] **Uptime**: 95%+ uptime achieved during Beta stability period
- [ ] **No Network Resets**: Beta network has not required reset for ≥4 weeks

**Governance:**
- [ ] **Upgrade Process**: Governance upgrade process documented and tested in Beta
- [ ] **Council Operational**: Protocol Council multi-sig operational and tested
- [ ] **Release Ceremony**: Genesis/release ceremony process validated and documented

**Economics:**
- [ ] **Economics Finalized**: Tokenomics and economic parameters finalized and documented
- [ ] **Economics Dry-Run**: Economic model validated through Beta dry-run
- [ ] **Fee Model**: Fee model operational and economically sustainable

**Operations:**
- [ ] **Genesis Verified**: MainNet genesis file hash distributed and independently verified
- [ ] **Incident Response**: Incident response procedures documented and tested
- [ ] **Monitoring**: Full production monitoring and alerting operational

**Note:** Presale is NOT implied or required by MainNet launch. Presale is a separate decision with separate prerequisites.

---

## 7. What Is Explicitly Out of Scope at Each Stage

### 7.1 DevNet

The following are **NOT promised or implied** during DevNet:

- [ ] Public permanence (network may reset at any time)
- [ ] External developer access (internal only)
- [ ] Economic value of any kind
- [ ] Uptime guarantees
- [ ] Backward compatibility between resets
- [ ] Production-grade security posture

### 7.2 TestNet Alpha

The following are **NOT promised or implied** during TestNet Alpha:

- [ ] Economic finality (test tokens only, no value)
- [ ] Long-term state preservation (resets possible with notice)
- [ ] Final economic parameters
- [ ] MainNet timeline or date
- [ ] Presale timing or token pricing
- [ ] Production-grade uptime

### 7.3 TestNet Beta

The following are **NOT promised or implied** during TestNet Beta:

- [ ] Automatic MainNet date (depends on exit criteria)
- [ ] Final tokenomics (draft only, subject to validation)
- [ ] Presale launch
- [ ] Binding economic commitments
- [ ] Guaranteed state migration to MainNet

### 7.4 MainNet v0

The following are **NOT implied** by MainNet launch:

- [ ] Future tokenomics changes are locked forever (governance can evolve parameters)
- [ ] Presale has occurred (separate decision)
- [ ] All future features are finalized
- [ ] Protocol is immutable (governance-driven upgrades are expected)

---

## 8. Operational Readiness Requirements

Before widening release scope, the following operational artifacts must exist:

### 8.1 Documentation Requirements

| Artifact | DevNet | Alpha | Beta | MainNet |
|----------|--------|-------|------|---------|
| Operator runbook (draft) | ✅ Required | ✅ Required | ✅ Required | ✅ Required (final) |
| Validator bring-up guide | ⚠️ Optional | ✅ Required | ✅ Required | ✅ Required |
| Incident handling procedures | ⚠️ Optional | ✅ Required (draft) | ✅ Required | ✅ Required (tested) |
| Release verification steps | ⚠️ Optional | ✅ Required | ✅ Required | ✅ Required |
| Network recovery procedures | ⚠️ Optional | ⚠️ Optional | ✅ Required | ✅ Required |

### 8.2 Monitoring and Observability

| Artifact | DevNet | Alpha | Beta | MainNet |
|----------|--------|-------|------|---------|
| Metrics collection | ✅ Required | ✅ Required | ✅ Required | ✅ Required |
| Log aggregation | ⚠️ Optional | ✅ Required | ✅ Required | ✅ Required |
| Basic alerting | ⚠️ Optional | ✅ Required | ✅ Required | ✅ Required |
| SLA monitoring | ❌ Not required | ⚠️ Optional | ✅ Required | ✅ Required |
| Public status page | ❌ Not required | ⚠️ Optional | ✅ Required | ✅ Required |

### 8.3 Operational Processes

| Process | DevNet | Alpha | Beta | MainNet |
|---------|--------|-------|------|---------|
| Incident triage | Informal | Defined | Documented | Tested |
| On-call rotation | Not required | Optional | Recommended | Required |
| Change management | Informal | Basic | Formal | Strict |
| Communication protocols | Internal | Defined | Public channels | 24/7 coverage |

**Note:** This section defines requirements; specific operational guides are separate documents.

---

## 9. Security and Governance Gates

Release progression requires explicit security and governance checkpoints:

### 9.1 Security Review Requirements

| Checkpoint | Alpha Entry | Beta Entry | MainNet Entry |
|------------|-------------|------------|---------------|
| Internal security review | ✅ Complete | ✅ Complete | ✅ Complete |
| External audit initiated | ❌ Not required | ✅ Required | ✅ Complete |
| External audit complete | ❌ Not required | ❌ Not required | ✅ Required |
| Critical findings resolved | N/A | ✅ Required | ✅ Required |
| Bug bounty active | ❌ Not required | ⚠️ Recommended | ✅ Required (≥4 weeks) |

### 9.2 Contradiction Tracker Status

- Contradiction tracker (`docs/whitepaper/contradiction.md`) must be reviewed before each stage transition
- Critical contradictions must be resolved or explicitly documented as accepted risks
- Open items must not represent consensus-critical safety issues

### 9.3 Governance Readiness

| Checkpoint | Alpha Entry | Beta Entry | MainNet Entry |
|------------|-------------|------------|---------------|
| Upgrade path documented | ⚠️ Draft | ✅ Required | ✅ Tested |
| Council multi-sig | ❌ Not required | ⚠️ Recommended | ✅ Operational |
| Governance parameters defined | ❌ Not required | ✅ Draft | ✅ Finalized |

### 9.4 Gate Integrity

- **No silent waiving of critical gates** — All gate decisions must be documented
- Gate exceptions require explicit written approval with documented rationale
- Exceptions must be time-bounded and tracked to resolution

---

## 10. Economics / Tokenomics Timing

This section clarifies the relationship between release stages and economic finalization.

### 10.1 Tokenomics Timeline

| Milestone | Tokenomics Status | Rationale |
|-----------|-------------------|-----------|
| DevNet | ❌ Not Required | DevNet uses test tokens with no economics |
| TestNet Alpha | ❌ Not Required | Alpha tests protocol mechanics, not economics |
| TestNet Beta | ⚠️ **Draft Required** | Beta should dry-run economic parameters |
| MainNet | ✅ **Finalized Required** | MainNet commits to real economic value |

### 10.2 Separation of Concerns

**Functional gas/fees for testing** are distinct from **economically final tokenomics**:

| Aspect | Test Environments | MainNet |
|--------|-------------------|---------|
| Gas metering | Functional for correctness testing | Economically calibrated |
| Fee burn | Functional for mechanism testing | Final burn rate |
| Staking yields | Test parameters | Final inflation model |
| Token supply | Test allocation | Final supply and distribution |

### 10.3 Economics Document Sequencing

1. **Before TestNet Beta**: Draft economics design document (`QBIND_ECONOMICS_DESIGN_DRAFT.md`)
2. **During TestNet Beta**: Validate economic parameters through dry-run
3. **Before MainNet**: Finalize economics based on Beta validation

### 10.4 Reporter Rewards (C3)

- Reporter reward mechanism (C3 in contradiction tracker) is intentionally deferred to tokenomics work
- Evidence reporting is already hardened (M15) and abuse-resistant
- Monetary incentives will be designed as part of economics finalization
- This is not a protocol safety gap; it is a planned economics feature

---

## 11. Presale Timing and Non-Goals

### 11.1 Clear Statement

**Presale planning is NOT the next step.**

This release-track specification:
- Does NOT authorize presale planning
- Does NOT imply presale will occur at any specific time
- Does NOT create binding commitments for token distribution
- Is NOT a launch announcement

### 11.2 Presale Prerequisites

Presale should **NOT begin** until:

1. ✅ Release-track documentation is complete (this document)
2. ⏳ Economics/tokenomics are at least drafted
3. ⏳ TestNet Alpha demonstrates stable operation
4. ⏳ Economics are validated through TestNet Beta dry-run

**Safe presale timing:** After TestNet Beta demonstrates economic mechanics work correctly.

### 11.3 Presale Non-Goals

The following are explicitly **NOT goals** of this release-track specification:

- Token pricing or valuation
- Presale mechanics or structure
- Vesting schedules
- Community allocation percentages
- Marketing or promotional timelines
- Exchange listings

### 11.4 External Communication

- No binding public promises should be made based on this document
- External communications must clearly state that timelines depend on exit criteria
- Marketing materials must not imply dates that are not committed

---

## 12. Rollback / Pause / Abort Rules

Release progression is not guaranteed. The following rules govern handling of issues discovered during release stages.

### 12.1 Pause Conditions

Release progression **may be paused** if:

- Critical security issue discovered
- Consensus safety issue identified
- Stability metrics regress significantly
- External audit reveals blocking issues
- Operational readiness requirements not met

### 12.2 Stage Repetition

A stage **may be repeated** if:

- Exit criteria were prematurely marked as satisfied
- New requirements emerge that should have been validated at current stage
- Stability has regressed after initial exit

### 12.3 Network Reset Policy

| Environment | Reset Policy |
|-------------|--------------|
| DevNet | May reset at any time without notice |
| TestNet Alpha | May reset with 48-hour notice (24-hour for emergencies) |
| TestNet Beta | Reset only in exceptional circumstances with 7-day notice |
| MainNet | No resets permitted (state must be preserved) |

### 12.4 Economics Deferral

Economics finalization **may be deferred** if:

- TestNet Beta economics dry-run reveals fundamental issues
- External factors require parameter recalibration
- Community feedback indicates significant concerns

Deferring economics does NOT block DevNet or TestNet Alpha progression.

### 12.5 MainNet Delay

MainNet launch **may be delayed** if:

- Any MainNet entry criteria are not satisfied
- Security audit reveals issues requiring remediation
- Operational readiness is not demonstrated
- Governance structures are not operational

**Delay is not failure.** A delayed launch that meets all criteria is preferable to a premature launch that does not.

### 12.6 Decision Authority

| Decision | Authority |
|----------|-----------|
| DevNet → Alpha | Development team consensus |
| Alpha → Beta | Development team + external auditor input |
| Beta → MainNet | Protocol Council approval required |
| Pause/Rollback | Development team (DevNet/Alpha), Council (Beta/MainNet) |

---

## 13. Required Follow-Up Documents

This release-track specification implies the following canonical documents should be created:

### 13.1 Required (High Priority)

| Document | Location | Purpose |
|----------|----------|---------|
| DevNet Operational Guide | `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` | DevNet genesis, validator onboarding, configuration, monitoring |
| Economics Design Draft | `docs/economics/QBIND_ECONOMICS_DESIGN_DRAFT.md` | Security-budget-driven inflation, staking yields, fee structures, reporter rewards |

### 13.2 Recommended (Medium Priority)

| Document | Location | Purpose |
|----------|----------|---------|
| TestNet Alpha Plan | `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md` | Alpha-specific configuration, onboarding process, testing schedule |
| MainNet Readiness Checklist | `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` | Detailed checklist for MainNet entry validation |

### 13.3 Future Documents (As Needed)

| Document | Location | Purpose |
|----------|----------|---------|
| TestNet Beta Plan | `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` | Beta-specific configuration, economics dry-run plan |
| Incident Response Playbook | `docs/ops/QBIND_INCIDENT_RESPONSE.md` | Production incident handling procedures |
| Upgrade Governance Process | `docs/gov/QBIND_UPGRADE_GOVERNANCE.md` | Formal upgrade proposal and approval process |

**Note:** This section lists documents that should be created; they are not created by this specification.

---

## 14. Final Decision Summary

### 14.1 Release Sequence

```
                                NOW
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DevNet (Internal)                                                  │
│  - Controlled integration testing                                   │
│  - Operator practice and runbook validation                         │
│  - CI-like validation                                               │
│  Duration: 2–4 weeks internal testing                               │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                      Exit criteria satisfied
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TestNet Alpha (Controlled Public)                                  │
│  - First public-facing network                                      │
│  - Invited validator onboarding                                     │
│  - Adversarial testing and bug discovery                            │
│  Duration: 4–8 weeks                                                │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                      Exit criteria satisfied
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TestNet Beta (Open Public)                                         │
│  - Broader public exposure                                          │
│  - Economics dry-run                                                │
│  - MainNet rehearsal                                                │
│  Duration: 4–12 weeks                                               │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                      Exit criteria satisfied
                      Security audit complete
                      Economics finalized
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MainNet v0 (Production)                                            │
│  - Live production network                                          │
│  - Real economic value                                              │
│  - Long-term state persistence                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 14.2 Key Principles

1. **Security over speed** — No shortcuts on security gates
2. **Progressive exposure** — Each stage validates the next
3. **Alpha before Beta** — TestNet Alpha is the first public network
4. **Demonstrated success** — Exit criteria, not calendar dates, drive progression
5. **No premature commitments** — Economics and presale follow, not precede, release track

### 14.3 Immediate Next Steps

1. Create `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`
2. Begin DevNet internal testing
3. Draft economics design document for Beta preparation

### 14.4 What This Document Establishes

- ✅ Canonical release sequence: DevNet → TestNet Alpha → TestNet Beta → MainNet
- ✅ Clear environment definitions and scope
- ✅ Explicit exit criteria for each stage transition
- ✅ Economics and presale timing constraints
- ✅ Rollback and pause rules for safety

### 14.5 What This Document Does NOT Establish

- ❌ Calendar dates for any release
- ❌ Tokenomics or economic parameters
- ❌ Presale mechanics or timing
- ❌ Marketing or announcement schedule
- ❌ Binding external commitments

---

## Appendix A: Document References

| Document | Location | Relationship |
|----------|----------|--------------|
| Whitepaper | `docs/whitepaper/QBIND_WHITEPAPER.md` | Authoritative protocol specification |
| Protocol Report | `docs/protocol/QBIND_PROTOCOL_REPORT.md` | Implementation status and gaps |
| M-Series Coverage | `docs/protocol/QBIND_M_SERIES_COVERAGE.md` | Risk mitigation audit index |
| Contradiction Tracker | `docs/whitepaper/contradiction.md` | Implementation discrepancies |
| Legacy Synthesis | `docs/protocol/QBIND_LEGACY_SYNTHESIS.md` | Historical context |
| Decision Memo | `docs/protocol/QBIND_NEXT_STEP_DECISION_MEMO.md` | Strategic direction |

---

## Appendix B: Revision History

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-04-20 | 1.0 | Initial release-track specification | Strategic Planning |

---

*This document is the canonical internal reference for QBIND release sequencing. All release decisions should reference this specification for gate definitions and exit criteria.*