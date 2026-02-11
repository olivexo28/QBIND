# QBIND Validator Economics and Slashing Audit

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Code-Grounded Security Economics Audit

This document provides a comprehensive, code-grounded audit of the validator economics and slashing model implemented in the QBIND repository. All findings are strictly based on actual code implementation, not whitepaper assumptions.

---

# 1. Current Slashing Model (Code-Grounded)

## 1.1 Slashing Infrastructure Overview

The QBIND slashing system is implemented across three primary modules with a clear separation of concerns:

| Layer | Module | Responsibility | Implementation Status |
|-------|--------|----------------|----------------------|
| **Evidence Pipeline** | `qbind-consensus/src/slashing/mod.rs` | Evidence types, validation, deduplication | ✅ T228 Complete |
| **Penalty Application** | `qbind-consensus/src/slashing/mod.rs` | `PenaltySlashingEngine`, burn + jail logic | ✅ T229 Complete |
| **State Management** | `qbind-ledger/src/slashing_ledger.rs` | `SlashingLedger` trait, validator state tracking | ✅ T230 Complete (In-Memory Only) |
| **Node Integration** | `qbind-node/src/ledger_slashing_backend.rs` | `LedgerSlashingBackend` bridge between consensus and ledger | ✅ T230 Complete |

## 1.2 Offense Classes (T227 Taxonomy)

The following offense classes are defined in code (`qbind-consensus/src/slashing/mod.rs:42-72`):

| ID | Offense | Severity | Slash Range (bps) | Implementation Status |
|:---|:--------|:---------|:------------------|:---------------------|
| **O1** | Classical Double-Signing | Critical | 500–1000 (5–10%) | ✅ Penalty enforcement available |
| **O2** | Invalid Consensus Signature (Proposer) | High | 500 (5%) | ✅ Penalty enforcement available |
| **O3a** | Single Lazy Vote | Medium | 0–50 (0–0.5%) | ⚠️ Evidence-only (no penalty) |
| **O3b** | Repeated Lazy Votes | Medium-High | 100–300 (1–3%) | ⚠️ Evidence-only (no penalty) |
| **O4** | Invalid DAG Certificate Propagation | High | 500–1000 (5–10%) | ⚠️ Evidence-only (no penalty) |
| **O5** | DAG/Consensus Coupling Violations | Medium-High | 100–500 (1–5%) | ⚠️ Evidence-only (no penalty) |

**Code Reference**: `qbind-consensus/src/slashing/mod.rs:42-72` (`OffenseKind` enum)

## 1.3 Slashing Modes

The slashing system operates in one of four modes (`qbind-node/src/node_config.rs:1827-1852`):

| Mode | Evidence Processing | Penalty Application | Default For |
|------|---------------------|---------------------|-------------|
| **Off** | ❌ None | ❌ None | Dev tools only |
| **RecordOnly** | ✅ Record + metrics | ❌ None | MainNet v0, TestNet |
| **EnforceCritical** | ✅ Record + metrics | ✅ O1/O2 only | DevNet |
| **EnforceAll** | ✅ Record + metrics | ✅ O1–O5 | Reserved (not enabled) |

**Important**: MainNet v0 defaults to `RecordOnly` mode. Penalty enforcement requires governance to flip to `EnforceCritical`.

## 1.4 Slashing State Structures

### ValidatorSlashingState (qbind-ledger/src/slashing_ledger.rs:35-45)

```rust
pub struct ValidatorSlashingState {
    pub stake: StakeAmount,                       // Current stake amount
    pub jailed_until_epoch: Option<EpochNumber>,  // Jail expiration (None = not jailed)
    pub total_slashed: StakeAmount,               // Cumulative slashed amount
    pub jail_count: u32,                          // Number of times jailed
}
```

### SlashingRecord (qbind-ledger/src/slashing_ledger.rs:48-66)

```rust
pub struct SlashingRecord {
    pub validator_id: ValidatorLedgerId,
    pub offense_kind: String,
    pub slashed_amount: StakeAmount,
    pub jailed: bool,
    pub jailed_until_epoch: Option<EpochNumber>,
    pub height: u64,
    pub view: u64,
    pub epoch: u64,
}
```

### ValidatorRecord (qbind-types/src/state_validator.rs:13-28)

```rust
pub struct ValidatorRecord {
    pub version: u8,
    pub status: ValidatorStatus,  // Inactive, Active, Jailed, Exiting
    pub owner_keyset_id: AccountId,
    pub consensus_suite_id: u8,
    pub consensus_pk: Vec<u8>,
    pub network_suite_id: u8,
    pub network_pk: Vec<u8>,
    pub stake: u64,
    pub last_slash_height: u64,
    pub ext_bytes: Vec<u8>,
}
```

---

# 2. Slashing Pathways Analysis

## 2.1 O1: Double-Signing (Classical Equivocation)

| Field | Value |
|-------|-------|
| **File Path** | `qbind-consensus/src/slashing/mod.rs:1331-1355` |
| **Function** | `PenaltySlashingEngine::apply_penalty_if_needed()` |
| **Trigger Conditions** | Two conflicting `SignedBlockHeader` at same (height, view) with different block IDs |
| **Evidence Type** | `EvidencePayloadV1::O1DoubleSign { block_a, block_b }` |
| **State Mutation** | 1. Burn stake (configurable bps, default 750 = 7.5%)<br>2. Jail validator (configurable epochs, default 10) |
| **Stake Effect** | **BURNED** (reduced from validator's stake, cumulative) |
| **Jail Effect** | **JAILED** until epoch = current_epoch + jail_epochs |
| **Persistence** | ⚠️ **IN-MEMORY ONLY** - Lost on restart |
| **ValidatorSet Impact** | Jailed validators should be excluded from validator set |

**Penalty Calculation** (`qbind-ledger/src/slashing_ledger.rs:279-302`):
```rust
// Calculate slash amount: stake * slash_bps / 10000
let slash_amount = (state.stake as u128 * u128::from(slash_bps) / 10000) as u64;
state.stake = state.stake.saturating_sub(slash_amount);
state.total_slashed += slash_amount;
```

## 2.2 O2: Invalid Proposer Signature

| Field | Value |
|-------|-------|
| **File Path** | `qbind-consensus/src/slashing/mod.rs:1331-1355` |
| **Function** | `PenaltySlashingEngine::apply_penalty_if_needed()` |
| **Trigger Conditions** | Block header with signature that fails verification |
| **Evidence Type** | `EvidencePayloadV1::O2InvalidProposerSig { header, bad_signature }` |
| **State Mutation** | 1. Burn stake (configurable bps, default 500 = 5%)<br>2. Jail validator (configurable epochs, default 5) |
| **Stake Effect** | **BURNED** |
| **Jail Effect** | **JAILED** |
| **Persistence** | ⚠️ **IN-MEMORY ONLY** |
| **ValidatorSet Impact** | Jailed validators should be excluded |

## 2.3 O3a/O3b: Lazy Voting

| Field | Value |
|-------|-------|
| **File Path** | `qbind-consensus/src/slashing/mod.rs:198-202` |
| **Function** | Evidence processed but penalty NOT applied |
| **Trigger Conditions** | Voting for block with invalid QC or proposer signature |
| **Evidence Type** | `EvidencePayloadV1::O3LazyVote { vote, invalid_reason }` |
| **State Mutation** | ❌ **NONE** - Evidence-only in all current modes |
| **Stake Effect** | **NOT BURNED** (O3 enforcement reserved for EnforceAll mode) |
| **Jail Effect** | **NOT JAILED** |
| **Persistence** | Evidence stored in-memory only |
| **ValidatorSet Impact** | None currently |

## 2.4 O4: Invalid DAG Certificate

| Field | Value |
|-------|-------|
| **File Path** | `qbind-consensus/src/slashing/mod.rs:204-209` |
| **Function** | Evidence processed but penalty NOT applied |
| **Trigger Conditions** | Certificate with invalid signatures, quorum not met, or commitment mismatch |
| **Evidence Type** | `EvidencePayloadV1::O4InvalidDagCert { cert, failure_reason }` |
| **State Mutation** | ❌ **NONE** - Evidence-only |
| **Stake Effect** | **NOT BURNED** |
| **Jail Effect** | **NOT JAILED** |
| **ValidatorSet Impact** | None currently |

## 2.5 O5: DAG/Consensus Coupling Violation

| Field | Value |
|-------|-------|
| **File Path** | `qbind-consensus/src/slashing/mod.rs:211-216` |
| **Function** | Evidence processed but penalty NOT applied |
| **Trigger Conditions** | Block references batch_commitment with no valid certificate |
| **Evidence Type** | `EvidencePayloadV1::O5DagCouplingViolation { block, dag_state_proof }` |
| **State Mutation** | ❌ **NONE** - Evidence-only |
| **Stake Effect** | **NOT BURNED** |
| **Jail Effect** | **NOT JAILED** |
| **ValidatorSet Impact** | None currently |

---

# 3. Validator Incentive Model

## 3.1 Stake Mechanics

### Stake Source

| Parameter | Implementation | File Reference |
|-----------|---------------|----------------|
| **Stake Registration** | `RegisterValidatorCall.stake` field | `qbind-wire/src/validator.rs:57` |
| **Minimum Stake** | ❌ **NOT IMPLEMENTED** - No minimum stake validation | `qbind-system/src/validator_program.rs:83-97` |
| **Maximum Stake** | ❌ **NOT IMPLEMENTED** - No maximum stake cap | N/A |
| **Stake Lock Period** | ❌ **NOT IMPLEMENTED** - No unbonding period | N/A |

**Critical Finding**: Validators can register with any stake amount, including 0. No minimum stake requirement is enforced in `ValidatorProgram::handle_register()`.

### Stake State Tracking

Stake is tracked in two parallel structures:

1. **ValidatorRecord.stake** (`qbind-types/src/state_validator.rs:25`) - The canonical on-chain stake stored in account data
2. **ValidatorSlashingState.stake** (`qbind-ledger/src/slashing_ledger.rs:38`) - In-memory copy used by slashing ledger

**Warning**: These two stake values can diverge if slashing occurs while ValidatorRecord is not updated. No synchronization mechanism exists.

## 3.2 Reward Distribution Logic

### Seigniorage Distribution (T200)

The monetary engine (`qbind-ledger/src/monetary_engine.rs`) computes inflation rates but actual validator reward distribution is **NOT FULLY IMPLEMENTED**.

| Component | Status | File Reference |
|-----------|--------|----------------|
| **Inflation Rate Calculation** | ✅ Implemented | `qbind-ledger/src/monetary_engine.rs:265-293` |
| **Security Budget Computation** | ✅ Implemented | `qbind-ledger/src/monetary_engine.rs:272-281` |
| **Validator Reward Minting** | ⚠️ **CALCULATION ONLY** | `qbind-ledger/src/monetary_state.rs` (T199/T200) |
| **Actual Balance Credit** | ❌ **NOT IMPLEMENTED** | Deferred to T200+ |
| **Commission Structure** | ❌ **NOT IMPLEMENTED** | No validator commission |

**Code Comment** (`qbind-ledger/src/monetary_state.rs:13-20`):
> "T199 is calculation + state only: No actual minting / account balance changes. No reward distribution adjusted yet."

### Phase-Based Inflation Targets

| Phase | Years | Target Inflation | Implementation |
|-------|-------|------------------|----------------|
| **Bootstrap** | 0–3 | Higher (configurable) | ✅ Calculated |
| **Transition** | 3–7 | Moderate | ✅ Calculated |
| **Mature** | 7+ | Lower with floor | ✅ Calculated |

Default parameters (`qbind-ledger/src/monetary_engine.rs`):
- Bootstrap: No inflation floor, faster EMA lambda (700 bps)
- Transition: No inflation floor, balanced EMA lambda (300 bps)
- Mature: Active inflation floor, maximum EMA smoothing (150 bps)

## 3.3 Eligibility Rules

### Validator Set Eligibility

| Criterion | Implemented | Enforcement |
|-----------|-------------|-------------|
| **Stake Minimum** | ❌ No | N/A |
| **Key Validity** | ✅ Yes | Genesis/registration |
| **Jail Status** | ✅ Yes (in-memory) | `is_jailed()` check |
| **Suite Compatibility** | ✅ Yes | Suite registry check |

**Jail Impact on Eligibility** (`qbind-ledger/src/slashing_ledger.rs:328-334`):
```rust
fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool {
    self.validator_states
        .get(&validator_id)
        .and_then(|s| s.jailed_until_epoch)
        .map(|until| current_epoch < until)
        .unwrap_or(false)
}
```

**Warning**: Jail status is checked via `is_jailed()` but the caller must integrate this with validator set construction. No automatic exclusion mechanism exists.

---

# 4. Enforcement Completeness Assessment

## 4.1 Implementation Matrix

| Component | Status | Notes |
|-----------|--------|-------|
| **Evidence Types (O1–O5)** | ✅ Fully Defined | All wire formats and payloads exist |
| **Evidence Validation** | ✅ Structural Only | Signature verification NOT performed |
| **Evidence Deduplication** | ✅ Implemented | By (validator, offense, height, view) |
| **Stake Burning (O1/O2)** | ✅ Implemented | When mode = EnforceCritical/EnforceAll |
| **Stake Burning (O3–O5)** | ❌ Stubbed | Always returns EvidenceOnly |
| **Jailing (O1/O2)** | ✅ Implemented | Configurable epochs |
| **Jailing (O3–O5)** | ❌ Not Implemented | No jail logic for O3–O5 |
| **Unjailing** | ✅ Implemented | `unjail_validator()` available |
| **Auto-Unjail at Epoch** | ❌ Not Wired | No epoch boundary hook |
| **Persistent Storage** | ❌ Not Implemented | T230 is in-memory only |
| **Governance Override** | ⚠️ Partial | Mode can be changed via config |

## 4.2 Stubbed/Placeholder Code

### 1. Cryptographic Evidence Verification

**Location**: `qbind-consensus/src/slashing/mod.rs:491-497` (`is_known_validator`)

The slashing engine only verifies that the accused validator exists in the validator set. It does **NOT** verify:
- Signature authenticity on evidence blocks
- QC validity in lazy vote evidence
- DAG certificate signature verification

**Comment in code** (`qbind-consensus/src/slashing/mod.rs:13-16`):
> "This task implements the slashing infrastructure skeleton **without** penalty application. The `NoopSlashingEngine` only records evidence and emits metrics."

### 2. O3/O4/O5 Penalty Application

**Location**: `qbind-consensus/src/slashing/mod.rs:1361-1366`

```rust
// O3/O4/O5 parameters would go here when implemented
_ => {
    eprintln!(
        "[SLASHING] No penalty parameters for offense {}, treating as evidence-only",
        offense.as_str()
    );
    return PenaltyDecision::EvidenceOnly;
}
```

### 3. Persistent Slashing Storage

**Location**: `qbind-ledger/src/slashing_ledger.rs:14-19`

```rust
//! # Future Work
//!
//! T23x will add:
//! - Persistent RocksDB-backed implementation
//! - On-chain slashing evidence transactions
//! - Governance transactions for parameter adjustments
```

### 4. Reporter Reward Distribution

**Location**: `qbind-types/src/state_governance.rs:53`

```rust
pub struct ParamRegistry {
    // ...
    pub reporter_reward_bps: u16,  // Defined but NOT used anywhere
}
```

The `reporter_reward_bps` parameter exists in governance state but no code distributes rewards to evidence reporters.

---

# 5. Economic Security Classification

Based strictly on code analysis, the QBIND slashing model is classified as:

## **Classification: Hybrid (Burn + Jail), Partially Implemented**

### Justification:

| Criterion | Assessment |
|-----------|------------|
| **Stake Burning** | ✅ Implemented for O1/O2 offenses |
| **Validator Jailing** | ✅ Implemented for O1/O2 offenses |
| **Burn Permanence** | ✅ Permanent (stake reduced, total_slashed accumulated) |
| **Jail Expiration** | ✅ Time-limited (epoch-based) |
| **Governance Configurability** | ⚠️ Partial (mode and params via config, not on-chain governance TX) |
| **Evidence Persistence** | ❌ In-memory only |
| **Full Offense Coverage** | ❌ O3–O5 are evidence-only |

### Current Effective Classification by Mode:

| Mode | Effective Classification |
|------|-------------------------|
| **Off** | None |
| **RecordOnly** | Audit/Observation-only (no economic security) |
| **EnforceCritical** | Burn-based + Jail for critical offenses only |
| **EnforceAll** | Reserved - Not yet functional |

---

# 6. Gaps and Risks

## 6.1 Critical Economic Security Risks

### Risk 1: In-Memory Slashing State (HIGH)

**Impact**: All slashing evidence and penalties are lost on node restart.

**Location**: `qbind-ledger/src/slashing_ledger.rs:197-207` (`InMemorySlashingLedger`)

**Consequence**: 
- A Byzantine validator could trigger detection, restart their node, and continue participating without penalty.
- No historical audit trail of slashing events survives restarts.

**Mitigation**: Implement persistent `SlashingLedger` backed by RocksDB (planned for T23x).

### Risk 2: No Minimum Stake Requirement (HIGH)

**Impact**: Validators can register with zero stake.

**Location**: `qbind-system/src/validator_program.rs:83-97`

**Consequence**: 
- Zero-stake validators cannot be economically penalized (nothing to slash).
- Attackers can cheaply create validator identities for Sybil attacks.

**Mitigation**: Add minimum stake validation in `handle_register()`.

### Risk 3: Evidence Signature Verification Not Performed (HIGH)

**Impact**: Slashing evidence is accepted based on structural validity only.

**Location**: `qbind-consensus/src/slashing/mod.rs:459-465`

**Consequence**:
- Attackers could forge slashing evidence against honest validators.
- No cryptographic proof is verified before penalty application.

**Mitigation**: Implement signature verification for all evidence payloads.

### Risk 4: O3–O5 Offenses Unpenalized (MEDIUM)

**Impact**: Lazy voting, invalid DAG certificates, and coupling violations have no economic consequences.

**Location**: `qbind-consensus/src/slashing/mod.rs:1361-1366`

**Consequence**:
- Validators can engage in unsafe lazy voting without penalty.
- DAG integrity violations have no deterrent.

**Mitigation**: Implement penalty parameters for O3–O5 in `PenaltyEngineConfig`.

### Risk 5: MainNet Default is RecordOnly (MEDIUM)

**Impact**: MainNet v0 has no active slashing penalties.

**Location**: `qbind-node/src/node_config.rs:2020-2035` (`mainnet_default()`)

**Consequence**:
- Byzantine validators face no economic penalty during initial MainNet operation.
- Security relies entirely on social/governance response.

**Mitigation**: Plan governance activation of `EnforceCritical` mode post-launch.

## 6.2 Implementation Gaps

| Gap | Severity | Planned Task |
|-----|----------|--------------|
| Persistent slashing ledger | High | T23x |
| Evidence signature verification | High | Not scheduled |
| Minimum stake enforcement | High | Not scheduled |
| Reporter reward distribution | Medium | Not scheduled |
| O3–O5 penalty parameters | Medium | Future |
| Auto-unjail at epoch boundary | Low | Not scheduled |
| Stake synchronization (ValidatorRecord ↔ SlashingState) | Medium | Not scheduled |
| Unbonding period | Medium | Not scheduled |
| Commission structure | Low | Not scheduled |

## 6.3 Whitepaper Inconsistencies

The following inconsistencies with the whitepaper have been identified and should be appended to `docs/whitepaper/contradiction.md`:

1. **Slashing "Partially Implemented"**: Whitepaper acknowledges partial implementation but does not specify that O3–O5 penalties are completely stubbed.

2. **No Minimum Stake**: Whitepaper implies economic security through stake but code allows zero-stake validators.

3. **In-Memory Only**: Whitepaper does not clearly state that slashing evidence and state are lost on restart.

---

# 7. Configuration Reference

## 7.1 Default Slashing Parameters

**Location**: `qbind-node/src/node_config.rs:1984-2035`

| Parameter | DevNet | TestNet | MainNet | Range |
|-----------|--------|---------|---------|-------|
| `mode` | EnforceCritical | RecordOnly | RecordOnly | Off/RecordOnly/EnforceCritical/EnforceAll |
| `slash_bps_o1_double_sign` | 750 (7.5%) | 750 | 750 | 500–1000 |
| `slash_bps_o2_invalid_proposer_sig` | 500 (5%) | 500 | 500 | 450–550 |
| `jail_on_o1` | true | true | true | true/false |
| `jail_epochs_o1` | 10 | 10 | 10 | 1–1,000,000 |
| `jail_on_o2` | true | true | true | true/false |
| `jail_epochs_o2` | 5 | 5 | 5 | 1–1,000,000 |

## 7.2 Governance Parameters

**Location**: `qbind-types/src/state_governance.rs:44-55`

```rust
pub struct ParamRegistry {
    pub slash_bps_prevote: u16,      // Slashing for prevote equivocation (basis points)
    pub slash_bps_precommit: u16,    // Slashing for precommit equivocation (basis points)
    pub reporter_reward_bps: u16,    // Reporter reward (NOT IMPLEMENTED)
}
```

**Note**: These governance parameters exist but are NOT connected to the slashing engine. The engine uses `SlashingConfig` from node configuration instead.

---

# 8. File Reference Index

| Component | Primary File(s) | Key Functions/Structs |
|-----------|-----------------|----------------------|
| Offense Types | `qbind-consensus/src/slashing/mod.rs` | `OffenseKind`, `EvidencePayloadV1` |
| Evidence Handling | `qbind-consensus/src/slashing/mod.rs` | `SlashingEvidence`, `NoopSlashingEngine`, `PenaltySlashingEngine` |
| Penalty Application | `qbind-consensus/src/slashing/mod.rs` | `apply_penalty_if_needed()`, `SlashingBackend` |
| Slashing Ledger | `qbind-ledger/src/slashing_ledger.rs` | `SlashingLedger`, `ValidatorSlashingState`, `InMemorySlashingLedger` |
| Node Integration | `qbind-node/src/ledger_slashing_backend.rs` | `LedgerSlashingBackend` |
| Configuration | `qbind-node/src/node_config.rs` | `SlashingConfig`, `SlashingMode` |
| Validator Types | `qbind-types/src/state_validator.rs` | `ValidatorRecord`, `ValidatorStatus`, `SlashingEvent` |
| Wire Formats | `qbind-wire/src/validator.rs` | `SlashingProofCall`, `ProofKind` |
| Governance | `qbind-types/src/state_governance.rs` | `ParamRegistry` |
| Monetary Engine | `qbind-ledger/src/monetary_engine.rs` | `compute_monetary_decision()` |
| Monetary State | `qbind-ledger/src/monetary_state.rs` | `MonetaryEpochState` |

---

# Appendix A: Slashing Flow Diagram

```
                    ┌─────────────────────────┐
                    │   Evidence Submitted    │
                    │   (O1/O2/O3/O4/O5)      │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   Structural Validation │
                    │   (version, height, etc)│
                    └───────────┬─────────────┘
                                │
                        ┌───────┴───────┐
                        │               │
                    Invalid         Valid
                        │               │
                        ▼               ▼
                    ┌───────┐   ┌─────────────────────────┐
                    │Reject │   │   Deduplication Check   │
                    └───────┘   └───────────┬─────────────┘
                                            │
                                    ┌───────┴───────┐
                                    │               │
                                Duplicate        New
                                    │               │
                                    ▼               ▼
                                ┌───────┐   ┌─────────────────────────┐
                                │Reject │   │   Mode Check            │
                                └───────┘   └───────────┬─────────────┘
                                                        │
                        ┌───────────────────┬───────────┼───────────┐
                        │                   │           │           │
                      Off            RecordOnly   EnforceCritical  EnforceAll
                        │                   │           │           │
                        ▼                   ▼           ▼           ▼
                    ┌───────┐       ┌─────────┐   ┌───────────┐  ┌───────────┐
                    │Reject │       │Evidence │   │O1/O2 Only │  │All O1–O5  │
                    └───────┘       │  Only   │   │  Penalty  │  │  Penalty  │
                                    └─────────┘   └─────┬─────┘  └─────┬─────┘
                                                        │              │
                                                        ▼              ▼
                                                ┌─────────────────────────┐
                                                │   Apply Penalty         │
                                                │   1. burn_stake_bps()   │
                                                │   2. jail_validator()   │
                                                └───────────┬─────────────┘
                                                            │
                                                            ▼
                                                ┌─────────────────────────┐
                                                │   Store Record          │
                                                │   (IN-MEMORY ONLY)      │
                                                └─────────────────────────┘
```

---

# Appendix B: Update Rules

This document MUST be updated when:

1. Persistent slashing storage is implemented (T23x)
2. O3–O5 penalty parameters are added
3. Evidence signature verification is implemented
4. Reporter rewards are implemented
5. Minimum stake requirements are added
6. Governance slashing parameter integration is completed
7. Auto-unjail at epoch boundary is wired

---

*Document generated from exhaustive code inspection of QBIND repository (2026-02-11). All findings are strictly code-grounded. No features have been assumed beyond what exists in implementation.*
