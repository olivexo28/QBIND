# QBIND Economic Hardening Plan

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Pre-TestNet Engineering Plan

This document defines a step-by-step engineering plan to harden economic security before TestNet launch. All items are strictly hardening existing functionality—no feature expansion, no L2, conservative and security-first.

---

## Scope Constraints

- **Strictly hardening existing functionality** — No new features
- **No L2 integration** — Layer 1 only
- **Conservative and security-first** — Fail-safe over fail-fast where appropriate
- **Cross-reference file paths** — All changes are code-grounded

---

# 1. Persistent Slashing Ledger

## 1.1 Current Implementation Analysis

The slashing ledger is currently **in-memory only**, as documented in the T230 implementation.

| Component | File Path | Status |
|-----------|-----------|--------|
| Trait Definition | `crates/qbind-ledger/src/slashing_ledger.rs:115-191` | ✅ Complete |
| In-Memory Implementation | `crates/qbind-ledger/src/slashing_ledger.rs:197-367` | ✅ Complete |
| Persistent Implementation | N/A | ❌ Not Implemented |
| Node Backend Integration | `crates/qbind-node/src/ledger_slashing_backend.rs` | ✅ Complete (uses in-memory) |

**Current State Structures** (`crates/qbind-ledger/src/slashing_ledger.rs:34-66`):

```rust
// ValidatorSlashingState - Per-validator slashing state
pub struct ValidatorSlashingState {
    pub stake: StakeAmount,
    pub jailed_until_epoch: Option<EpochNumber>,
    pub total_slashed: StakeAmount,
    pub jail_count: u32,
}

// SlashingRecord - Audit trail entry
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

**Risk**: All slashing evidence and penalties are lost on node restart. A Byzantine validator could restart their node to evade penalties.

## 1.2 Required Changes

### 1.2.1 New Implementation: `RocksDbSlashingLedger`

Create a persistent implementation of the `SlashingLedger` trait backed by RocksDB.

**Target File**: `crates/qbind-ledger/src/slashing_ledger_rocks.rs` (new file)

**Implementation Requirements**:

1. Implement `SlashingLedger` trait for `RocksDbSlashingLedger`
2. Use atomic write batches for state transitions
3. Maintain backward compatibility with existing `InMemorySlashingLedger` API
4. Add schema versioning for future migrations

### 1.2.2 Schema Design

| Column Family | Key | Value | Purpose |
|---------------|-----|-------|---------|
| `slashing_state` | `validator_id: u64` | `ValidatorSlashingState` (CBOR) | Per-validator slashing state |
| `slashing_records` | `(validator_id, height, view): (u64, u64, u64)` | `SlashingRecord` (CBOR) | Immutable audit trail |
| `slashing_meta` | `"schema_version"` | `u32` | Schema version for migrations |
| `slashing_meta` | `"last_epoch"` | `u64` | Last processed epoch |

### 1.2.3 Serialization

- Use `qbind-serde` for state encoding (consistent with existing patterns)
- Add CBOR serialization for `ValidatorSlashingState` and `SlashingRecord`
- **File Reference**: Follow patterns in `crates/qbind-serde/src/lib.rs`

## 1.3 RocksDB Schema Updates

### 1.3.1 Column Family Registration

**Target File**: `crates/qbind-node/src/storage.rs` (or equivalent storage initialization)

Add column families during RocksDB initialization:

```rust
const CF_SLASHING_STATE: &str = "slashing_state";
const CF_SLASHING_RECORDS: &str = "slashing_records";
const CF_SLASHING_META: &str = "slashing_meta";
```

### 1.3.2 Schema Version

- Initial schema version: `1`
- Version check on startup; reject incompatible schemas
- Follow existing schema versioning patterns in codebase

## 1.4 State Transition Integration Points

### 1.4.1 Penalty Application Hook

**Target File**: `crates/qbind-consensus/src/slashing/mod.rs`

**Function**: `PenaltySlashingEngine::apply_penalty_if_needed()` (lines 1331-1355)

**Integration**:
1. After `slash_stake()` and `jail_validator()` calls, persist state atomically
2. Use RocksDB write batch to ensure atomicity
3. Only commit to persistent storage after consensus confirmation

### 1.4.2 Epoch Boundary Hook

**Target File**: `crates/qbind-ledger/src/slashing_ledger.rs`

**New Method**: `process_epoch_boundary(epoch: EpochNumber)`

**Behavior**:
1. Auto-unjail validators where `current_epoch >= jailed_until_epoch`
2. Update `slashing_meta.last_epoch`
3. Persist state atomically

### 1.4.3 Node Startup Integration

**Target File**: `crates/qbind-node/src/ledger_slashing_backend.rs`

**Changes**:
1. Load persistent slashing state on startup
2. Recover validator slashing states from RocksDB
3. Validate schema version; fail startup on incompatibility

## 1.5 Migration Considerations

### 1.5.1 Upgrade Path

| Scenario | Behavior |
|----------|----------|
| Fresh node (no prior data) | Initialize empty persistent ledger |
| Existing node (in-memory only) | Start with empty persistent ledger (no retroactive recovery) |
| Schema version mismatch | Fail startup with clear error message |

### 1.5.2 Rollback Safety

- Persistent slashing ledger is **append-only** for records
- State changes are idempotent (re-applying same evidence yields same result)
- No automatic rollback mechanism (governance intervention required)

### 1.5.3 Testing Migration

- Unit test: Empty → v1 initialization
- Unit test: Schema version rejection
- Integration test: Node restart with populated ledger

---

# 2. Evidence Signature Verification

## 2.1 Evidence Message Structure

Evidence payloads are defined in `crates/qbind-consensus/src/slashing/mod.rs`:

| Evidence Type | Payload Struct | Required Signatures | File Reference |
|---------------|----------------|---------------------|----------------|
| O1 Double-Sign | `EvidencePayloadV1::O1DoubleSign { block_a, block_b }` | Both block signatures | Lines 130-140 |
| O2 Invalid Proposer Sig | `EvidencePayloadV1::O2InvalidProposerSig { header, bad_signature }` | Header signature | Lines 142-148 |
| O3 Lazy Vote | `EvidencePayloadV1::O3LazyVote { vote, invalid_reason }` | Vote signature | Lines 150-156 |
| O4 Invalid DAG Cert | `EvidencePayloadV1::O4InvalidDagCert { cert, failure_reason }` | Certificate signatures | Lines 158-164 |
| O5 DAG Coupling | `EvidencePayloadV1::O5DagCouplingViolation { block, dag_state_proof }` | Block + proof signatures | Lines 166-172 |

**Current Status**: Evidence is accepted based on structural validity only. **No cryptographic verification is performed.**

**File Reference**: `crates/qbind-consensus/src/slashing/mod.rs:459-465` (TODO comment)

## 2.2 Required Verification Checks

### 2.2.1 O1 Double-Sign Verification

**Verification Steps**:
1. ✅ Both blocks reference same (height, view)
2. ✅ Block IDs differ (conflicting content)
3. ⚠️ **NEW**: Verify `block_a.signature` against accused validator's consensus key
4. ⚠️ **NEW**: Verify `block_b.signature` against accused validator's consensus key
5. ⚠️ **NEW**: Confirm accused validator was authorized proposer for that slot

**Target Function**: `validate_o1_evidence()` in `crates/qbind-consensus/src/slashing/mod.rs`

### 2.2.2 O2 Invalid Proposer Signature Verification

**Verification Steps**:
1. ✅ Header structure is valid
2. ⚠️ **NEW**: Verify `bad_signature` matches the signature in `header`
3. ⚠️ **NEW**: Confirm `bad_signature` fails verification against proposer's consensus key
4. ⚠️ **NEW**: Confirm proposer was scheduled for that slot

**Target Function**: `validate_o2_evidence()` in `crates/qbind-consensus/src/slashing/mod.rs`

### 2.2.3 O3 Lazy Vote Verification

**Verification Steps**:
1. ✅ Vote structure is valid
2. ⚠️ **NEW**: Verify vote signature against voter's consensus key
3. ⚠️ **NEW**: Confirm voter was in validator set at that height
4. ⚠️ **NEW**: Verify the `invalid_reason` claim (e.g., QC was actually invalid)

**Target Function**: `validate_o3_evidence()` in `crates/qbind-consensus/src/slashing/mod.rs`

### 2.2.4 O4 Invalid DAG Certificate Verification

**Verification Steps**:
1. ✅ Certificate structure is valid
2. ⚠️ **NEW**: Verify certificate signer list against validator set
3. ⚠️ **NEW**: Verify each signature in certificate
4. ⚠️ **NEW**: Confirm `failure_reason` claim is accurate

**Target Function**: `validate_o4_evidence()` in `crates/qbind-consensus/src/slashing/mod.rs`

### 2.2.5 O5 DAG/Consensus Coupling Verification

**Verification Steps**:
1. ✅ Block and proof structure are valid
2. ⚠️ **NEW**: Verify block proposer signature
3. ⚠️ **NEW**: Verify DAG state proof is authentic
4. ⚠️ **NEW**: Confirm coupling violation claim is accurate

**Target Function**: `validate_o5_evidence()` in `crates/qbind-consensus/src/slashing/mod.rs`

## 2.3 Signature Scheme Alignment with Validator Keys

### 2.3.1 Key Lookup Interface

**Current**: `is_known_validator()` checks validator existence only (`crates/qbind-consensus/src/slashing/mod.rs:491-497`)

**Required**: Add key retrieval for signature verification

```rust
/// Get validator's consensus public key for signature verification.
fn get_validator_consensus_key(&self, validator_id: ValidatorId) -> Option<Vec<u8>>;
```

**Target Trait**: `SlashingContext` in `crates/qbind-consensus/src/slashing/mod.rs`

### 2.3.2 Signature Verification Call

**Crypto Module**: `crates/qbind-crypto/src/ml_dsa.rs`

**Function**: Use `ml_dsa_44_verify(public_key, message, signature)` for ML-DSA-44 verification

**Domain Separation**: Follow existing domain-separated signing patterns in `crates/qbind-hash/src/lib.rs`

### 2.3.3 Suite Compatibility

- Evidence signatures MUST use the same suite as the validator's registered `consensus_suite_id`
- Reject evidence if suite mismatch detected
- **File Reference**: `crates/qbind-types/src/state_validator.rs:19` (`consensus_suite_id`)

## 2.4 Failure Handling

### 2.4.1 Verification Failure Responses

| Failure Type | Response | Log Level |
|--------------|----------|-----------|
| Signature verification fails | Reject evidence, emit metric | WARN |
| Validator key not found | Reject evidence, emit metric | WARN |
| Suite mismatch | Reject evidence, emit metric | WARN |
| Malformed evidence | Reject evidence, emit metric | ERROR |
| Duplicate evidence | Ignore (existing deduplication) | DEBUG |

### 2.4.2 Metrics

**Target File**: `crates/qbind-node/src/metrics.rs`

Add counters:
- `qbind_slashing_evidence_signature_failed_total{offense_kind="..."}`
- `qbind_slashing_evidence_key_not_found_total{offense_kind="..."}`
- `qbind_slashing_evidence_suite_mismatch_total{offense_kind="..."}`

### 2.4.3 Security Considerations

- **No automatic penalty on verification failure** — Evidence is simply rejected
- **Rate limiting**: Consider rate-limiting evidence submissions per peer to prevent DoS
- **Audit logging**: Log all rejected evidence for forensic analysis

---

# 3. Minimum Stake Enforcement

## 3.1 Define Stake Threshold Parameter

### 3.1.1 Parameter Location

**Target File**: `crates/qbind-types/src/state_governance.rs`

**Add to `ParamRegistry`** (lines 44-55):

```rust
pub struct ParamRegistry {
    // ... existing fields ...
    pub min_validator_stake: u64,  // Minimum stake required to register as validator
}
```

### 3.1.2 Default Values

| Network | Minimum Stake (microQBIND) | Equivalent (QBIND) | Rationale |
|---------|----------------------------|--------------------| ----------|
| DevNet | 1_000_000 | 1 QBIND | Low barrier for testing |
| TestNet | 10_000_000 | 10 QBIND | Moderate barrier for realistic testing |
| MainNet | 100_000_000_000 | 100,000 QBIND | Economic security threshold |

**Note**: All internal stake values are stored in microQBIND (1 QBIND = 1_000_000 microQBIND). The `min_validator_stake` parameter uses microQBIND units.

### 3.1.3 Configuration Integration

**Target File**: `crates/qbind-node/src/node_config.rs`

Add `min_validator_stake` to network presets:

```rust
impl NodeConfig {
    pub fn devnet_v0_preset() -> Self {
        // ... existing code ...
        // Add: min_validator_stake: 1_000_000
    }
    
    pub fn testnet_alpha_preset() -> Self {
        // ... existing code ...
        // Add: min_validator_stake: 10_000_000
    }
    
    pub fn mainnet_preset() -> Self {
        // ... existing code ...
        // Add: min_validator_stake: 100_000_000_000
    }
}
```

## 3.2 Enforcement Points

### 3.2.1 Validator Registration

**Target File**: `crates/qbind-system/src/validator_program.rs`

**Function**: `handle_register()` (lines 60-97)

**Current Code** (lines 82-97):
```rust
// Build initial ValidatorRecord.
let record = ValidatorRecord {
    version: 1,
    status: ValidatorStatus::Active,
    // ... no stake validation ...
    stake: call.stake,
    // ...
};
```

**Required Change**:

```rust
fn handle_register<S: AccountStore>(
    &self,
    ctx: &mut ExecutionContext<S>,
    tx: &Transaction,
) -> Result<(), ExecutionError> {
    // ... existing decode logic ...
    
    // NEW: Minimum stake enforcement
    let min_stake = ctx.get_param_registry()?.min_validator_stake;
    if call.stake < min_stake {
        return Err(ExecutionError::ProgramError(
            "stake below minimum required for validator registration"
        ));
    }
    
    // ... existing registration logic ...
}
```

### 3.2.2 Epoch Transition Eligibility

**Target File**: `crates/qbind-ledger/src/slashing_ledger.rs` (or epoch transition handler)

**Enforcement**: At epoch boundary, exclude validators whose stake has fallen below minimum (due to slashing).

**Logic**:
```rust
fn is_eligible_for_next_epoch(
    &self,
    validator_id: ValidatorLedgerId,
    current_epoch: EpochNumber,
    min_stake: StakeAmount,
) -> bool {
    if let Some(state) = self.get_validator_state(validator_id) {
        // Not jailed AND stake >= minimum
        !self.is_jailed(validator_id, current_epoch) && state.stake >= min_stake
    } else {
        false
    }
}
```

### 3.2.3 Validator Set Construction

**Target Integration Point**: Where validator set is constructed for each epoch

**Behavior**:
1. Filter out jailed validators (existing)
2. **NEW**: Filter out validators with stake < `min_validator_stake`
3. Sort by stake (if stake-weighted selection)
4. Emit metric for excluded validators

## 3.3 Governance Override Rules

### 3.3.1 Parameter Modification

- `min_validator_stake` can ONLY be changed via governance transaction
- Changes take effect at next epoch boundary (not mid-epoch)
- **File Reference**: `crates/qbind-system/src/governance_program.rs`

### 3.3.2 Emergency Override

- Safety Council can temporarily lower minimum stake via emergency governance
- Emergency changes require multi-sig (existing pattern in `crates/qbind-genesis/src/lib.rs`)
- Emergency override expires after fixed epoch count (configurable)

### 3.3.3 Constraints

| Constraint | Value | Rationale |
|------------|-------|-----------|
| Minimum allowed `min_validator_stake` | 1_000 microQBIND | Prevent zero-stake validators |
| Maximum allowed `min_validator_stake` | No hard cap | Governance discretion |
| Change rate limit | 1 change per 100 epochs | Prevent oscillation attacks |

---

# 4. Slashing Mode Enforcement

## 4.1 Remove RecordOnly for MainNet

### 4.1.1 Current Mode Definitions

**File**: `crates/qbind-node/src/node_config.rs:1827-1852`

```rust
pub enum SlashingMode {
    Off,             // Dev tools only
    RecordOnly,      // TestNet default
    EnforceCritical, // DevNet default (O1/O2 only)
    EnforceAll,      // Reserved (all offenses)
}
```

### 4.1.2 MainNet Mode Restriction

**Current Default** (`crates/qbind-node/src/node_config.rs:2027`):
```rust
// MainNet v0: RecordOnly by default
mode: SlashingMode::RecordOnly,
```

**Required Change for MainNet Launch**:

```rust
impl SlashingConfig {
    pub fn mainnet_default() -> Self {
        Self {
            mode: SlashingMode::EnforceCritical,  // Changed from RecordOnly
            // ... rest unchanged ...
        }
    }
}
```

### 4.1.3 Deprecation Timeline

| Phase | Allowed Modes | Network |
|-------|---------------|---------|
| TestNet Alpha | Off, RecordOnly, EnforceCritical, EnforceAll | TestNet |
| TestNet Beta | RecordOnly, EnforceCritical, EnforceAll | TestNet |
| MainNet v0 | EnforceCritical, EnforceAll | MainNet |
| MainNet v1+ | EnforceCritical, EnforceAll | MainNet |

## 4.2 Config Validation Rules

### 4.2.1 MainNet Validation

**Target File**: `crates/qbind-node/src/node_config.rs`

**Function**: `validate_mainnet_config()` (approximately lines 5100-5130)

**Add Validation**:

```rust
fn validate_mainnet_config(&self) -> Result<(), MainnetConfigError> {
    // ... existing validations ...
    
    // NEW: Slashing mode enforcement
    match self.slashing.mode {
        SlashingMode::Off => {
            return Err(MainnetConfigError::SlashingMisconfigured(
                "SlashingMode::Off is not allowed on MainNet".into()
            ));
        }
        SlashingMode::RecordOnly => {
            return Err(MainnetConfigError::SlashingMisconfigured(
                "SlashingMode::RecordOnly is not allowed on MainNet".into()
            ));
        }
        SlashingMode::EnforceCritical | SlashingMode::EnforceAll => {
            // Valid for MainNet
        }
    }
    
    Ok(())
}
```

### 4.2.2 Error Types

**Target File**: `crates/qbind-node/src/node_config.rs`

**Add to `MainnetConfigError`**:

```rust
pub enum MainnetConfigError {
    // ... existing variants ...
    SlashingMisconfigured(String),
}
```

## 4.3 Node Startup Checks

### 4.3.1 Startup Validation Sequence

**Target File**: `crates/qbind-node/src/main.rs` (or startup handler)

**Validation Order**:
1. Load configuration
2. Detect network type (DevNet/TestNet/MainNet)
3. **NEW**: Validate slashing mode against network type
4. Initialize slashing backend
5. Continue startup

### 4.3.2 Failure Behavior

| Scenario | Behavior |
|----------|----------|
| MainNet + Off | Fatal error, exit with code 1 |
| MainNet + RecordOnly | Fatal error, exit with code 1 |
| TestNet + Off | Warning log, allow startup |
| DevNet + Off | Debug log, allow startup |

### 4.3.3 CLI Override Prevention

- **No CLI flag** to override slashing mode on MainNet
- Environment variable override **disabled** for MainNet
- Only configuration file changes (requiring restart) are allowed

### 4.3.4 Logging

**On Startup**:
```
[INFO] Slashing mode: EnforceCritical (O1/O2 penalties enforced)
```

**On Invalid Mode**:
```
[FATAL] MainNet requires slashing mode EnforceCritical or EnforceAll. Current: RecordOnly
[FATAL] Node cannot start. Please update configuration.
```

---

# 5. Testing Strategy

## 5.1 Unit Tests

### 5.1.1 Persistent Slashing Ledger Tests

**Target File**: `crates/qbind-ledger/src/slashing_ledger_rocks.rs` (new, with `#[cfg(test)]` module)

| Test Name | Description |
|-----------|-------------|
| `test_rocks_slashing_ledger_empty_init` | Initialize empty ledger, verify schema version |
| `test_rocks_slashing_ledger_stake_persistence` | Set stake, restart, verify stake persisted |
| `test_rocks_slashing_ledger_jail_persistence` | Jail validator, restart, verify jail status |
| `test_rocks_slashing_ledger_record_persistence` | Store record, restart, verify record retrievable |
| `test_rocks_slashing_ledger_atomic_write` | Verify slash + jail applied atomically |
| `test_rocks_slashing_ledger_schema_version_check` | Verify startup fails on version mismatch |

### 5.1.2 Evidence Signature Verification Tests

**Target File**: `crates/qbind-consensus/src/slashing/mod.rs` (extend existing `#[cfg(test)]` module)

| Test Name | Description |
|-----------|-------------|
| `test_o1_evidence_valid_signatures` | Valid double-sign evidence accepted |
| `test_o1_evidence_invalid_signature` | Reject evidence with bad signature |
| `test_o1_evidence_wrong_validator_key` | Reject evidence signed by wrong key |
| `test_o2_evidence_signature_verification` | Verify O2 evidence signature checks |
| `test_o3_evidence_signature_verification` | Verify O3 evidence signature checks |
| `test_evidence_suite_mismatch_rejected` | Reject evidence with wrong suite |
| `test_evidence_unknown_validator_rejected` | Reject evidence for unknown validator |

### 5.1.3 Minimum Stake Enforcement Tests

**Target File**: `crates/qbind-system/tests/validator_program_tests.rs` (or new file)

| Test Name | Description |
|-----------|-------------|
| `test_registration_below_min_stake_rejected` | Reject registration below minimum |
| `test_registration_at_min_stake_accepted` | Accept registration at exactly minimum |
| `test_registration_above_min_stake_accepted` | Accept registration above minimum |
| `test_slashed_below_min_excluded_next_epoch` | Validator slashed below minimum excluded |
| `test_min_stake_parameter_governance_update` | Governance can update minimum |

### 5.1.4 Slashing Mode Enforcement Tests

**Target File**: `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs` (extend existing)

| Test Name | Description |
|-----------|-------------|
| `test_mainnet_rejects_slashing_mode_off` | ✅ Already exists |
| `test_mainnet_rejects_slashing_mode_recordonly` | **NEW**: Reject RecordOnly on MainNet |
| `test_mainnet_accepts_enforce_critical` | **NEW**: Accept EnforceCritical on MainNet |
| `test_mainnet_accepts_enforce_all` | **NEW**: Accept EnforceAll on MainNet |
| `test_testnet_allows_recordonly` | **NEW**: TestNet allows RecordOnly |

## 5.2 Adversarial Tests

### 5.2.1 Forged Evidence Attacks

**Target File**: `crates/qbind-consensus/tests/slashing_adversarial_tests.rs` (new file)

| Test Name | Description |
|-----------|-------------|
| `test_forged_double_sign_evidence_rejected` | Attacker forges evidence against honest validator |
| `test_replayed_evidence_rejected` | Same evidence submitted twice |
| `test_stale_evidence_handling` | Evidence from old epoch handling |
| `test_evidence_flood_rate_limiting` | Many evidence submissions from one peer |

### 5.2.2 Stake Manipulation Attacks

| Test Name | Description |
|-----------|-------------|
| `test_zero_stake_validator_cannot_register` | Zero-stake registration rejected |
| `test_slashed_validator_cannot_evade_by_restart` | Restart doesn't clear slashing |
| `test_rapid_stake_withdraw_before_slash` | Race condition: withdraw vs slash |

### 5.2.3 Mode Bypass Attacks

| Test Name | Description |
|-----------|-------------|
| `test_config_hot_reload_mode_change_rejected` | Runtime mode downgrade rejected |
| `test_env_var_override_mode_rejected_mainnet` | Env var cannot override on MainNet |

## 5.3 Restart Tests

### 5.3.1 State Recovery Tests

**Target File**: `crates/qbind-node/tests/slashing_restart_tests.rs` (new file)

| Test Name | Description |
|-----------|-------------|
| `test_node_restart_preserves_validator_jail_status` | Jailed validator still jailed after restart |
| `test_node_restart_preserves_slashed_stake` | Slashed amount persisted |
| `test_node_restart_preserves_slashing_records` | Audit trail intact |
| `test_crash_during_slash_atomic_recovery` | Incomplete slash rolled back or completed |
| `test_epoch_boundary_crossed_during_restart` | Auto-unjail applied after restart |

### 5.3.2 Crash Window Tests

| Test Name | Description |
|-----------|-------------|
| `test_crash_before_commit_no_partial_state` | Crash before RocksDB commit leaves clean state |
| `test_crash_after_commit_state_preserved` | Crash after commit preserves state |
| `test_wal_recovery_slashing_state` | RocksDB WAL recovery works for slashing |

## 5.4 Byzantine Simulation

### 5.4.1 Byzantine Validator Scenarios

**Target File**: `crates/qbind-node/tests/byzantine_simulation_tests.rs` (new file)

| Test Name | Description |
|-----------|-------------|
| `test_single_byzantine_double_sign_detected` | One Byzantine validator double-signs, detected |
| `test_single_byzantine_slashed_and_jailed` | Byzantine validator penalized |
| `test_byzantine_excluded_from_next_epoch` | Jailed validator excluded |
| `test_byzantine_unjail_after_epoch_expiry` | Validator unjailed at correct epoch |

### 5.4.2 Multi-Byzantine Scenarios

| Test Name | Description |
|-----------|-------------|
| `test_multiple_byzantine_threshold_safety` | Up to f Byzantine validators handled |
| `test_coordinated_attack_detection` | Multiple validators attack same target |
| `test_cascade_slashing_limits` | Slashing doesn't cascade beyond guilty |

### 5.4.3 Integration with Consensus

| Test Name | Description |
|-----------|-------------|
| `test_consensus_continues_after_slash` | Consensus makes progress after slashing |
| `test_quorum_maintained_after_jail` | Quorum requirements met after jailing |
| `test_validator_rotation_with_jailed` | Epoch transition with jailed validators |

---

# Appendix A: Implementation Priority

| Component | Priority | Estimated Effort | Dependencies |
|-----------|----------|------------------|--------------|
| Persistent Slashing Ledger | **P0** | 2 weeks | RocksDB setup |
| Evidence Signature Verification | **P0** | 1 week | Crypto module |
| Minimum Stake Enforcement | **P1** | 3 days | Governance types |
| Slashing Mode Enforcement | **P1** | 2 days | Config validation |
| Unit Tests | **P0** | 1 week | Above components |
| Adversarial Tests | **P1** | 1 week | Unit tests |
| Restart Tests | **P0** | 3 days | Persistent ledger |
| Byzantine Simulation | **P2** | 2 weeks | All above |

---

# Appendix B: File Reference Index

| Component | Primary File(s) |
|-----------|-----------------|
| Slashing Ledger Trait | `crates/qbind-ledger/src/slashing_ledger.rs` |
| In-Memory Slashing Ledger | `crates/qbind-ledger/src/slashing_ledger.rs:197-367` |
| Slashing Engine | `crates/qbind-consensus/src/slashing/mod.rs` |
| Penalty Application | `crates/qbind-consensus/src/slashing/mod.rs:1331-1355` |
| Node Slashing Backend | `crates/qbind-node/src/ledger_slashing_backend.rs` |
| Slashing Configuration | `crates/qbind-node/src/node_config.rs:1816-2100` |
| Validator Program | `crates/qbind-system/src/validator_program.rs` |
| Validator Registration | `crates/qbind-system/src/validator_program.rs:60-97` |
| Validator Types | `crates/qbind-types/src/state_validator.rs` |
| Governance Parameters | `crates/qbind-types/src/state_governance.rs:44-55` |
| MainNet Validation | `crates/qbind-node/src/node_config.rs:5100-5130` |
| Crypto (ML-DSA-44) | `crates/qbind-crypto/src/ml_dsa.rs` |
| Domain-Separated Hashing | `crates/qbind-hash/src/lib.rs` |
| Existing Slashing Tests | `crates/qbind-node/tests/t229_slashing_penalty_engine_tests.rs` |
| Existing Slashing Tests | `crates/qbind-node/tests/t230_slashing_ledger_backend_tests.rs` |
| MainNet Profile Tests | `crates/qbind-node/tests/t237_mainnet_launch_profile_tests.rs` |

---

# Appendix C: Update Rules

This document MUST be updated when:

1. Any component listed above is implemented
2. A security issue is discovered in slashing infrastructure
3. TestNet reveals gaps in this plan
4. Governance decides to change minimum stake parameters
5. Slashing mode requirements change

**Update procedure:**

1. Mark completed items with ✅
2. Document any deviations from plan
3. Add new tests discovered during implementation
4. Update priority if dependencies change

---

*Document created for Pre-TestNet economic hardening. All items are strictly hardening existing functionality—no feature expansion. Cross-references verified against QBIND repository (2026-02-11).*
