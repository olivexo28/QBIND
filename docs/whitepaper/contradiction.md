# QBIND Whitepaper Contradictions and Undocumented Behaviors

**Version**: 1.1  
**Date**: 2026-02-15  
**Status**: Active Tracking Document

This document tracks contradictions between the whitepaper (`docs/whitepaper/QBIND_WHITEPAPER.md`) and the actual implementation, as well as behaviors that are implemented but not documented.

---

## Contradictions

### C1. O3–O5 Offense Penalties Not Implemented

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M9/M11)** |
| **Whitepaper Reference** | Section 8.10, Section 12.2 |
| **Code Location** | `crates/qbind-consensus/src/slashing/mod.rs:2218-2240` (PenaltyEngineConfig defaults), `crates/qbind-consensus/src/slashing/mod.rs:2523-2540` (apply_penalty_if_needed O3-O5 handling) |
| **Evidence** | O3-O5 penalties are now fully implemented and enforced: O3 (Invalid Vote): 300 bps (3%) slash + 3 epoch jail; O4 (Censorship): 200 bps (2%) slash + 2 epoch jail; O5 (Availability): 100 bps (1%) slash + 1 epoch jail. Mode matrix: `EnforceCritical`/`EnforceAll` applies penalties for all O1-O5 offenses. |
| **Tests** | `crates/qbind-node/tests/m11_slashing_penalty_o3_o5_tests.rs` (21 tests) |

### C2. No Minimum Stake Requirement

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M2.1-M2.4)** |
| **Whitepaper Reference** | Section 8.1, Section 12.2, Section 18 |
| **Code Location** | `crates/qbind-system/src/validator_program.rs:130-132` (registration-time enforcement), `crates/qbind-consensus/src/validator_set.rs:116-178` (epoch-boundary filtering via `build_validator_set_with_stake_filter()`), `crates/qbind-node/src/hotstuff_node_sim.rs:936-987` (`with_stake_filtering_epoch_state_provider()`) |
| **Evidence** | Minimum stake is now enforced at both registration and epoch boundary. `min_validator_stake` enforced via `ExecutionContext.min_validator_stake` at registration. `StakeFilteringEpochStateProvider` excludes validators with `stake < min_validator_stake` at epoch transitions. Fail-closed: if all validators excluded, epoch transition fails. |
| **Tests** | `crates/qbind-consensus/tests/validator_set_tests.rs`, `crates/qbind-consensus/tests/m2_2_stake_filter_epoch_transition_tests.rs`, `crates/qbind-node/tests/m2_3_stake_filtering_node_integration_tests.rs`, `crates/qbind-node/tests/m2_4_production_stake_filtering_tests.rs` |

### C3. Reporter Rewards Not Implemented

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** |
| **Whitepaper Reference** | Section 12.2 (Slashing Model) |
| **Code Location** | `crates/qbind-types/src/state_governance.rs:52` (`reporter_reward_bps` field) |
| **Description** | `reporter_reward_bps` parameter exists in `ParamRegistry` but no code distributes rewards. Evidence reporting has no incentive mechanism. |
| **Impact** | Medium - Reduces incentive to report Byzantine behavior |
| **Remaining** | • Wire `reporter_reward_bps` to slashing engine reward distribution • Add reward transfer in penalty application path |

---

## Undocumented Implementation Details

### 1. In-Memory Slashing Ledger (T230)

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M1)** |
| **Implementation** | `crates/qbind-ledger/src/slashing_ledger.rs:572-628` (`RocksDbSlashingLedger`) |
| **Evidence** | Persistent slashing ledger implemented via `RocksDbSlashingLedger`. Provides restart-safe persistence for validator slashing state, evidence records, and penalty history. Atomic updates via `apply_slashing_update_atomic()` using RocksDB `WriteBatch` (M1.2). Failure injection tests verify atomicity (M1.3). |
| **Tests** | `crates/qbind-node/tests/m1_slashing_persistence_tests.rs`, `crates/qbind-ledger/tests/slashing_ledger_tests.rs` |

### 2. Vote History Memory Limits

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** (Documentation gap) |
| **Implementation** | `crates/qbind-consensus/src/hotstuff_state_engine.rs:107-122` (`votes_by_view`, eviction tracking) |
| **Whitepaper Reference** | Section 8.4 (Voting Rule) |
| **Description** | The vote history (`votes_by_view` HashMap) is subject to memory limits and eviction (`evict_votes_by_view_if_needed()`). Old views can be evicted, potentially missing equivocations in those views. |
| **Impact** | Medium - Equivocation detection may miss old misbehavior |
| **Remaining** | • Document memory management policy in whitepaper or operator guide |

### 3. CRC-32 Checksum for Storage Integrity

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** (Documentation gap - Low priority) |
| **Implementation** | `crates/qbind-node/src/storage.rs:256-336` (`compute_crc32()`, `wrap_checksummed()`, `unwrap_checksummed()`) |
| **Whitepaper Reference** | Section 10.5 (Persistence Guarantees) |
| **Description** | Storage uses CRC-32 checksums (IEEE 802.3 polynomial) for integrity detection. Sufficient for bit-rot but not for malicious tampering. |
| **Impact** | Low - Adequate for intended use case |
| **Remaining** | • Mention checksum mechanism in Section 10.5 (optional) |

### 4. Epoch Transition Write Ordering

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M12)** |
| **Implementation** | `crates/qbind-node/src/storage.rs`, Whitepaper Section 18.4.3 |
| **Evidence** | Epoch transition write ordering and persistence semantics formally specified in Whitepaper Section 18 "Validator Set Transition and Epoch Boundary Semantics" (M12). Section 18.4.3 defines persistence ordering: storage commits before in-memory state update. |

### 5. Key Rotation Grace Period Semantics

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** (Documentation gap - Low priority) |
| **Implementation** | `crates/qbind-consensus/src/key_rotation.rs:238-298` |
| **Whitepaper Reference** | Not mentioned |
| **Description** | Key rotation uses a grace period mechanism where both old and new keys are valid during transition. The grace period spans full epochs; partial-epoch rotations are not supported. |
| **Impact** | Low - Implementation constraint |
| **Remaining** | • Document key rotation mechanics in whitepaper Section 9 |

### 6. DAG Mempool Batch Priority

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** (Documentation gap - Low priority) |
| **Implementation** | `crates/qbind-node/src/dag_mempool.rs`, `crates/qbind-node/src/mempool.rs` |
| **Whitepaper Reference** | Section 7.1 (Async Runtime Model) |
| **Description** | Mempool priority scoring uses `arrival_id` which differs per node, meaning transaction ordering in blocks may vary between proposers. Deterministic per-node but not globally deterministic. |
| **Impact** | Low - Expected behavior for mempool |
| **Remaining** | • Clarify in whitepaper that transaction ordering within blocks is proposer-determined |

### 7. Timeout Exponential Backoff Parameters

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** (Documentation gap - Low priority) |
| **Implementation** | `crates/qbind-consensus/src/pacemaker.rs:74-109` (`TimeoutPacemakerConfig` with `timeout_multiplier: 2.0`, `max_timeout: 30s`) |
| **Whitepaper Reference** | Section 8.9 (Liveness Assumptions), Section 17 (Timeout/View-Change) |
| **Description** | The timeout pacemaker uses configurable exponential backoff (default multiplier 2.0, max 30s). Implementation complete via M5 but parameter documentation not in whitepaper. |
| **Impact** | Low - Configuration choice |
| **Remaining** | • Document timeout parameters in whitepaper or operator guide |

### 8. Evidence Signature Verification Not Performed

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M9/M11)** |
| **Implementation** | `crates/qbind-consensus/src/slashing/mod.rs:579-594` (`verify_ml_dsa_44_signature()`), lines 664-682 (O1 verification), 762-769 (O2 verification), 860-865 (O3 verification), 945-951 (O4 verification) |
| **Evidence** | Cryptographic signature verification IS implemented for all offense types. `verify_ml_dsa_44_signature()` performs ML-DSA-44 signature verification on evidence payloads. O1 verifies both block signatures; O2 verifies header signature invalidity; O3 verifies vote signature; O4 verifies certificate signatures. Deterministic verification with fail-closed behavior on non-verifiable evidence. |

### 9. Governance Slashing Parameters Not Connected

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M14)** |
| **Implementation** | `crates/qbind-types/src/state_governance.rs:44-117` (`SlashingPenaltySchedule` struct with O1-O5 parameters), `crates/qbind-consensus/src/slashing/mod.rs:2260-2370` (`PenaltyEngineConfig::from_governance_schedule()`, `GovernanceSlashingSchedule` type) |
| **Whitepaper Reference** | Section 11 (Governance) |
| **Description** | `ParamRegistry` now contains a canonical `SlashingPenaltySchedule` with all O1-O5 penalty parameters. `PenaltyEngineConfig::from_governance_schedule()` creates engine configurations directly from governance state. Slashing parameters are governed and upgradeable with epoch-boundary activation semantics. |
| **Evidence** | M14 implementation: (1) `SlashingPenaltySchedule` stores slash_bps and jail_epochs for O1-O5 plus activation_epoch, (2) `GovernanceSlashingSchedule` provides interface between types crate and consensus crate, (3) `PenaltyEngineConfig::from_governance_schedule()` constructs configs deterministically, (4) DevNet allows fallback defaults; TestNet/MainNet require schedule presence (fail-closed). |
| **Tests** | `crates/qbind-node/tests/m14_governance_slashing_params_tests.rs` (15 tests): deterministic schedule load (A1-A3), epoch-boundary activation (B1-B3), fail-closed behavior (C1-C5), O1-O5 regression (D1-D4). |

### 10. Stake Synchronization Gap

| Field | Value |
|-------|-------|
| **Status** | ✅ **PARTIAL (M13)** |
| **Implementation** | `crates/qbind-types/src/state_validator.rs:31-102` (`ValidatorRecord` with canonical fields), `crates/qbind-ledger/src/slashing_ledger.rs:1-50` (M13 documentation) |
| **Evidence** | Canonical economic state unified (M13). `ValidatorRecord.stake` and `ValidatorRecord.jailed_until_epoch` are the single source of truth. `ValidatorSlashingState` mirrors but is documented as non-authoritative. Eligibility predicates (`ValidatorRecord::is_eligible_at_epoch()`) read from canonical fields. |
| **Tests** | `crates/qbind-node/tests/m13_economic_state_unification_tests.rs` (12 tests) |
| **Remaining** | • Full architectural unification (single-write path for slashing penalties to both `ValidatorRecord` and `ValidatorSlashingState`) |

---

## Summary

| Category | Count | Items |
|----------|-------|-------|
| **RESOLVED** | 7 | C1, C2, Item 1, Item 4, Item 8, Item 9 (M14), Item 10 (partial) |
| **OPEN** | 6 | C3, Item 2, Item 3, Item 5, Item 6, Item 7 |

**High-Risk Open Items**: None. All formerly high-risk items (C1: O3-O5 penalties, C2: minimum stake, Item 1: in-memory slashing, Item 8: evidence signature verification) are now resolved.

**Medium-Risk Open Items**:
- C3 (Reporter Rewards): No economic incentive for evidence reporting

---

## Update History

| Date | Change | Author |
|------|--------|--------|
| 2026-02-11 | Initial document created during state audit | Audit |
| 2026-02-11 | Added C1-C3 contradictions, items 8-10 undocumented details from validator economics audit | Audit |
| 2026-02-15 | M12: Added formal validator set transition spec (Section 18). Items 4 (Epoch Transition Write Ordering) now documented in Section 18.4.3. C2 (Minimum Stake) partially addressed by M2 epoch-boundary filtering; registration-time validation still pending. | M12 |
| 2026-02-15 | M13: Canonical economic state unified. Item 10 (Stake Synchronization Gap) partially mitigated - canonical source defined (`ValidatorRecord.stake`, `ValidatorRecord.jailed_until_epoch`). `ValidatorSlashingState` documented as mirror. 12 restart safety tests added. | M13 |
| 2026-02-15 | M13.1: Full reconciliation pass. Updated all entries with Status/Evidence fields. Verified: C1 RESOLVED (M9/M11 O3-O5 penalties implemented), C2 RESOLVED (M2 minimum stake enforced), Item 1 RESOLVED (M1 RocksDbSlashingLedger), Item 8 RESOLVED (signature verification implemented). Updated line references and test citations. | M13.1 |
| 2026-02-15 | M14: Governance slashing parameters wired into penalty engine. Item 9 RESOLVED. `SlashingPenaltySchedule` added to `ParamRegistry` with O1-O5 penalty parameters + activation_epoch. `PenaltyEngineConfig::from_governance_schedule()` provides deterministic config from governance state. DevNet allows fallback; TestNet/MainNet fail-closed on missing schedule. 15 M14 tests added. | M14 |

---

*This document should be updated whenever a contradiction is discovered between the whitepaper and implementation, or when significant undocumented behaviors are identified.*