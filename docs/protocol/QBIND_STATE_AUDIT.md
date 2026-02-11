# QBIND 360-Degree Protocol State Audit

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Exhaustive State Audit Document

This document provides a complete, code-grounded audit of all global protocol state components and state mutation paths in the QBIND repository. It is intended to serve as the authoritative reference for consensus-critical state tracking.

---

# 1. Global State Components

## 1.1 State Component Classification Table

| Component | File Path(s) | Struct/Type | Persistence Location | Consensus-Critical | Commit Timing |
|-----------|--------------|-------------|---------------------|-------------------|---------------|
| **Account State** | `qbind-ledger/src/account.rs` | `Account`, `AccountHeader` | RocksDB `acct:<account_id>` | ✅ Yes | After commit |
| **Account Nonces** | `qbind-ledger/src/execution.rs` | In-memory HashMap or RocksDB | `nonce:<account_id>` | ✅ Yes | After commit |
| **Validator Set** | `qbind-consensus/src/validator_set.rs` | `ConsensusValidatorSet`, `ValidatorSetEntry` | In-memory (loaded from genesis/config) | ✅ Yes | Epoch boundary |
| **Epoch State** | `qbind-consensus/src/validator_set.rs` | `EpochState`, `EpochId` | RocksDB `meta:current_epoch` | ✅ Yes | Epoch boundary |
| **Validator Record** | `qbind-types/src/state_validator.rs` | `ValidatorRecord`, `ValidatorStatus` | Account data serialized | ✅ Yes | After commit |
| **Suite Registry** | `qbind-types/src/state_suite.rs` | `SuiteRegistry`, `SuiteEntry` | Account data (genesis) | ✅ Yes | Epoch boundary |
| **Governance Parameters** | `qbind-types/src/state_governance.rs` | `ParamRegistry`, `LaunchChecklist` | Account data | ✅ Yes | Governance TX |
| **Safety Council Keyset** | `qbind-types/src/state_governance.rs` | `SafetyCouncilKeyset`, `SafetyCouncilKeyAccount` | Account data | ✅ Yes | Governance TX |
| **Monetary Epoch State** | `qbind-ledger/src/monetary_state.rs` | `MonetaryEpochState`, `MonetaryEpochInputs` | Account data / in-memory | ✅ Yes | Epoch boundary |
| **Slashing State** | `qbind-ledger/src/slashing_ledger.rs` | `ValidatorSlashingState`, `SlashingRecord` | In-memory (T230), future persistent | ✅ Yes | After evidence |
| **Consensus Lock State** | `qbind-consensus/src/lib.rs`, `hotstuff_state_engine.rs` | `HotStuffState`, `HotStuffStateEngine` | In-memory | ✅ Yes | During consensus |
| **Committed Blocks** | `qbind-node/src/storage.rs` | `BlockProposal` | RocksDB `b:<block_id>` | ✅ Yes | After commit |
| **Quorum Certificates** | `qbind-node/src/storage.rs` | `QuorumCertificate` | RocksDB `q:<block_id>` | ✅ Yes | After commit |
| **Last Committed Marker** | `qbind-node/src/storage.rs` | `[u8; 32]` (block_id) | RocksDB `meta:last_committed` | ✅ Yes | After commit |
| **Schema Version** | `qbind-node/src/storage.rs` | `u32` | RocksDB `meta:schema_version` | ⚠️ Startup only | Initialization |
| **Key Rotation Registry** | `qbind-consensus/src/key_rotation.rs` | `KeyRotationRegistry`, `ValidatorKeyState` | In-memory | ✅ Yes | Epoch boundary |
| **Pacemaker State** | `qbind-consensus/src/pacemaker.rs` | `TimeoutPacemaker`, `BasicTickPacemaker` | In-memory | ⚠️ Liveness only | Runtime |
| **Vote Accumulator** | `qbind-consensus/src/vote_accumulator.rs` | `VoteAccumulator` | In-memory | ⚠️ During QC formation | Runtime |
| **Mempool State** | `qbind-node/src/mempool.rs` | `InMemoryMempool`, `TxPriorityScore` | In-memory | ❌ No | N/A |
| **DAG Mempool State** | `qbind-node/src/dag_mempool.rs` | `InMemoryDagMempool`, `QbindBatch` | In-memory | ⚠️ Proposer only | Runtime |
| **EVM State** (optional) | `qbind-runtime/src/evm_types.rs` | `EvmAccountState` | RocksDB (feature-gated) | ✅ Yes (if enabled) | After commit |
| **Peer Table** | `qbind-node/src/p2p_discovery.rs`, `async_peer_manager.rs` | `PeerTable`, `PeerState` | In-memory | ❌ No | Runtime |

---

# 2. Persistent State Layout

## 2.1 RocksDB Key Prefixes

All persistence uses RocksDB with a single column family. Keys follow this pattern:

| Key Pattern | Value Type | Description | Module |
|-------------|------------|-------------|--------|
| `b:<block_id_bytes>` | Serialized `BlockProposal` | Committed blocks | `qbind-node/src/storage.rs:230` |
| `q:<block_id_bytes>` | Serialized `QuorumCertificate` | QCs attesting to blocks | `qbind-node/src/storage.rs:233` |
| `meta:last_committed` | `[u8; 32]` (block_id) | Last committed block ID | `qbind-node/src/storage.rs:236` |
| `meta:current_epoch` | `u64` (big-endian, 8 bytes) | Current epoch number | `qbind-node/src/storage.rs:243` |
| `meta:schema_version` | `u32` (big-endian, 4 bytes) | Storage schema version | `qbind-node/src/storage.rs:250` |
| `acct:<account_id_bytes>` | Serialized `Account` | Account state | `qbind-ledger/src/execution.rs:1336` |
| `nonce:<account_id_bytes>` | `u64` (encoded) | Account nonces | `qbind-ledger/src/execution.rs:568` |

## 2.2 Checksum Envelope Format (T119)

All stored values are wrapped in a checksummed envelope:

```
[CRC32 (4 bytes, big-endian)] || [Payload (N bytes)]
```

- Checksum: CRC-32 (IEEE 802.3 polynomial 0xEDB88320)
- Legacy databases without checksums are handled via fallback logic

## 2.3 Schema Version Compatibility

| Version | Description | Compatibility |
|---------|-------------|---------------|
| 0 (implicit) | Legacy databases without schema version key | Compatible with v1 |
| 1 (current) | Current layout with blocks, QCs, meta keys | Current version |

Forward-incompatible schema versions cause startup failure with `StorageError::IncompatibleSchema`.

---

# 3. State Mutation Matrix

## 3.1 State × Mutation Trigger Matrix

| State Component | TX Execution | Block Commit | Epoch Transition | Upgrade Activation | Slashing Event |
|-----------------|-------------|--------------|------------------|-------------------|----------------|
| Account Balances | ✅ | ✅ (finalize) | ❌ | ❌ | ⚠️ (T229+) |
| Account Nonces | ✅ | ✅ (finalize) | ❌ | ❌ | ❌ |
| Validator Set | ❌ | ❌ | ✅ | ⚠️ | ⚠️ (jail) |
| Epoch ID | ❌ | ❌ | ✅ | ❌ | ❌ |
| Suite Registry | ❌ | ❌ | ✅ | ✅ | ❌ |
| Governance Parameters | ✅ (gov TX) | ✅ (finalize) | ❌ | ✅ | ❌ |
| Monetary State | ❌ | ❌ | ✅ | ❌ | ❌ |
| Slashing State | ❌ | ❌ | ⚠️ (unjail) | ❌ | ✅ |
| Locked QC | ❌ | ✅ | ❌ | ❌ | ❌ |
| Committed Block | ❌ | ✅ | ❌ | ❌ | ❌ |
| Last Committed Marker | ❌ | ✅ | ❌ | ❌ | ❌ |
| Current Epoch Key | ❌ | ❌ | ✅ | ❌ | ❌ |
| Key Rotation State | ❌ | ❌ | ✅ (commit rotation) | ❌ | ❌ |
| EVM State (if enabled) | ✅ | ✅ (finalize) | ❌ | ❌ | ❌ |

Legend:
- ✅ = Mutated during this trigger
- ❌ = Not mutated
- ⚠️ = Conditionally mutated / future implementation

## 3.2 State Mutation Functions

### Account Balance Mutations

| Function | Module | Trigger |
|----------|--------|---------|
| `Account::new()` | `qbind-ledger/src/account.rs` | Genesis, account creation |
| `AccountStore::put()` | `qbind-ledger/src/store.rs` | TX execution |
| `slash_stake()` | `qbind-ledger/src/slashing_ledger.rs` | Slashing (T230) |

### Validator Set Updates

| Function | Module | Trigger |
|----------|--------|---------|
| `ConsensusValidatorSet::new()` | `qbind-consensus/src/validator_set.rs` | Genesis, epoch transition |
| `EpochState::new()` | `qbind-consensus/src/validator_set.rs` | Epoch transition |
| `StaticEpochStateProvider::with_epoch()` | `qbind-consensus/src/validator_set.rs` | Configuration |

### Governance Parameter Updates

| Function | Module | Trigger |
|----------|--------|---------|
| `GovUpdateParamRegistryCall` (wire) | `qbind-wire/src/gov.rs` | Governance TX |
| Account data write | `qbind-ledger/src/store.rs` | TX execution |

### Suite Registry Transitions

| Function | Module | Trigger |
|----------|--------|---------|
| `genesis_suite_registry()` | `qbind-types/src/state_suite.rs` | Genesis |
| Governance TX (planned) | - | Epoch boundary |

### Slashing Application

| Function | Module | Trigger |
|----------|--------|---------|
| `SlashingLedger::slash_stake()` | `qbind-ledger/src/slashing_ledger.rs` | Evidence processed |
| `SlashingLedger::jail_validator()` | `qbind-ledger/src/slashing_ledger.rs` | Evidence processed |
| `SlashingLedger::unjail_validator()` | `qbind-ledger/src/slashing_ledger.rs` | Epoch boundary |

### Epoch Increments

| Function | Module | Trigger |
|----------|--------|---------|
| `ConsensusStorage::put_current_epoch()` | `qbind-node/src/storage.rs` | Epoch transition |
| `KeyRotationRegistry::advance_epoch()` | `qbind-consensus/src/key_rotation.rs` | Epoch transition |
| `compute_monetary_decision()` | `qbind-ledger/src/monetary_engine.rs` | Epoch transition |

### Gas Deduction

| Function | Module | Trigger |
|----------|--------|---------|
| `ExecutionEngine::execute()` | `qbind-ledger/src/execution.rs` | TX execution |
| `compute_tx_mempool_cost()` | `qbind-node/src/mempool.rs` | Mempool admission |

### Nonce Increment

| Function | Module | Trigger |
|----------|--------|---------|
| `NonceExecutionEngine::execute()` | `qbind-ledger/src/execution.rs` | TX execution |
| `StateUpdater::update()` | `qbind-ledger/src/execution.rs` | TX execution |

### Consensus Lock Updates

| Function | Module | Trigger |
|----------|--------|---------|
| `HotStuffState::update_lock()` | `qbind-consensus/src/lib.rs` | QC observed |
| `HotStuffStateEngine::update_lock_and_commit()` | `qbind-consensus/src/hotstuff_state_engine.rs` | 3-chain rule |

---

# 4. Implicit Consensus State

## 4.1 In-Memory-Only State

| State | Module | Impact on Safety | Impact on Liveness |
|-------|--------|-----------------|-------------------|
| **Locked QC** | `qbind-consensus/src/hotstuff_state_engine.rs:88` | ✅ Critical - prevents conflicting commits | ⚠️ Medium - affects voting eligibility |
| **Locked Height** | `qbind-consensus/src/lib.rs:468` | ✅ Critical - HotStuff safety rule | ⚠️ Medium - voting constraint |
| **View Number** | `qbind-consensus/src/lib.rs:461`, `pacemaker.rs:249` | ⚠️ Medium - leader election | ✅ Critical - progress tracking |
| **Last Voted** | `qbind-consensus/src/lib.rs:464` | ✅ Critical - double-vote prevention | ❌ None |
| **Commit Log** | `qbind-consensus/src/hotstuff_state_engine.rs:97` | ⚠️ Medium - audit trail | ❌ None |
| **Pending New View** | `qbind-consensus/src/pacemaker.rs:257` | ❌ None | ✅ Critical - view change |
| **Consecutive Timeouts** | `qbind-consensus/src/pacemaker.rs:255` | ❌ None | ⚠️ Medium - backoff calculation |
| **Vote Accumulator State** | `qbind-consensus/src/vote_accumulator.rs` | ⚠️ Medium - QC formation | ✅ Critical - quorum tracking |
| **Votes by View** | `qbind-consensus/src/hotstuff_state_engine.rs:107` | ✅ Critical - equivocation detection | ❌ None |
| **Equivocating Validators Set** | `qbind-consensus/src/hotstuff_state_engine.rs:117` | ⚠️ Medium - slashing evidence | ❌ None |
| **Mempool Transaction Queue** | `qbind-node/src/mempool.rs` | ❌ None | ⚠️ Medium - block content |
| **DAG Batch Frontier** | `qbind-node/src/dag_mempool.rs` | ❌ None | ⚠️ Medium - proposer selection |
| **Peer Connection State** | `qbind-node/src/async_peer_manager.rs:905` | ❌ None | ✅ Critical - network connectivity |

## 4.2 State Recovery After Restart

| State | Recovery Method | Gap Risk |
|-------|-----------------|----------|
| Last Committed Block | `meta:last_committed` key | ❌ None - persisted |
| Current Epoch | `meta:current_epoch` key | ❌ None - persisted |
| Locked QC | Reconstruct from last committed | ⚠️ May need to re-lock |
| View Number | Start from last committed view + 1 | ⚠️ May lag behind network |
| Vote History | Lost - rebuilt from network | ⚠️ May accept stale votes briefly |
| Mempool | Lost - clients must resubmit | ✅ Expected behavior |
| Peer Connections | Rediscovery via P2P | ⚠️ Temporary isolation |

---

# 5. Undocumented or Implicit Assumptions

## 5.1 Assumptions Not in Whitepaper

| Assumption | Location | Risk Level | Notes |
|------------|----------|------------|-------|
| Write-before-update for epoch transitions | `qbind-node/src/storage.rs` (implied) | Medium | Ensures crash consistency but not explicitly documented |
| Single column family for all data | `qbind-node/src/storage.rs` | Low | Simplifies implementation but limits future flexibility |
| CRC-32 sufficient for corruption detection | `qbind-node/src/storage.rs:257-292` | Low | Not cryptographic but adequate for bit-rot |
| In-memory slashing ledger (T230) | `qbind-ledger/src/slashing_ledger.rs` | High | Penalties not persisted; evidence may be lost on restart |
| Vote history eviction by memory limits | `qbind-consensus/src/hotstuff_state_engine.rs:118-119` | Medium | Could miss equivocations for old views |
| Mempool priority score determinism | `qbind-node/src/mempool.rs:143-150` | Medium | Ordering depends on arrival_id which differs per node |
| Timeout multiplier backoff ceiling | `qbind-consensus/src/pacemaker.rs:101` | Low | max_timeout caps exponential growth |
| Key rotation grace period spans full epochs | `qbind-consensus/src/key_rotation.rs` | Medium | Partial epoch rotations not supported |

## 5.2 Potentially Consensus-Critical State Not Explicitly Modeled

| State | Location | Risk | Recommendation |
|-------|----------|------|----------------|
| `votes_by_view` HashMap | `qbind-consensus/src/hotstuff_state_engine.rs:107` | Medium | Document eviction policy in spec |
| `pending_block_order` VecDeque | `qbind-consensus/src/hotstuff_state_engine.rs:85` | Low | Document memory management |
| `consecutive_timeouts` counter | `qbind-consensus/src/pacemaker.rs:255` | Low | Document backoff behavior |
| `timeout_emitted` flag | `qbind-consensus/src/pacemaker.rs:253` | Low | Document idempotency guarantee |
| DAG `frontier_commitments` | `qbind-consensus/src/slashing/mod.rs:160` | Medium | Document frontier selection algorithm |

## 5.3 State Persistence Timing Risks

| Risk | Current State | Impact |
|------|---------------|--------|
| Block persisted before QC | Write order in `storage.rs` | Low - both written atomically in practice |
| Epoch update race with commit | Write order in epoch transition | Medium - crash between writes could cause inconsistency |
| Slashing evidence not persisted | T230 in-memory only | High - evidence lost on restart |
| Key rotation commit at epoch boundary | In-memory until advance_epoch() | Medium - rotation may not apply if node restarts |

---

# 6. Recommendations for Formal State Tuple Definition

## 6.1 Proposed Global State Tuple

Define the global protocol state **S** as a tuple:

```
S = (
    Accounts,           // Map<AccountId, Account>
    Nonces,             // Map<AccountId, u64>
    ValidatorSet,       // Set<ValidatorSetEntry>
    Epoch,              // EpochId (u64)
    SuiteRegistry,      // SuiteRegistry
    ParamRegistry,      // ParamRegistry
    MonetaryState,      // MonetaryEpochState
    SlashingState,      // Map<ValidatorId, ValidatorSlashingState>
    KeyRotationState,   // KeyRotationRegistry
    
    // Consensus-specific
    LockedQC,           // Option<QuorumCertificate>
    LockedHeight,       // u64
    LastCommittedBlock, // Option<BlockId>
    CommittedHeight,    // u64
    
    // View state
    CurrentView,        // u64
    LastVoted,          // Option<(Height, Round, BlockId)>
    
    // Persistence markers
    SchemaVersion       // u32
)
```

## 6.2 State Transition Function

Formalize the state transition function:

```
δ: S × Input → S' × Output

Where Input is one of:
- Transaction(tx)
- BlockCommit(block, qc)
- EpochBoundary(new_epoch)
- UpgradeActivation(upgrade)
- SlashingEvidence(evidence)
- ViewChange(new_view)
```

## 6.3 Persistence Invariants to Document

1. **Atomicity**: Block and QC writes should be atomic (single batch)
2. **Ordering**: `last_committed` updated only after block + QC persisted
3. **Epoch Boundary**: Epoch key updated before in-memory epoch state
4. **Crash Recovery**: Define recovery procedure from `last_committed` + `current_epoch`
5. **Checksum Verification**: All reads verify CRC-32 checksum

## 6.4 Missing Formal Specifications

| Gap | Current State | Recommendation |
|-----|---------------|----------------|
| State transition function δ | Implicit in code | Formalize in whitepaper §10 |
| Validator set transition rules | Not specified | Add to whitepaper §8 |
| Slashing state model | T227 design doc only | Integrate into whitepaper |
| Key rotation state machine | Code comments only | Formalize in whitepaper |
| Epoch boundary atomicity | Implied | Document explicitly |
| View recovery after crash | Not documented | Add recovery specification |

---

# Appendix A: File Reference Index

| Module | Primary Files | Key Structs |
|--------|--------------|-------------|
| Types | `qbind-types/src/primitives.rs` | `AccountId`, `ChainId`, `NetworkEnvironment` |
| Types | `qbind-types/src/state_validator.rs` | `ValidatorRecord`, `ValidatorStatus`, `SlashingEvent` |
| Types | `qbind-types/src/state_governance.rs` | `ParamRegistry`, `SafetyCouncilKeyset`, `LaunchChecklist` |
| Types | `qbind-types/src/state_suite.rs` | `SuiteRegistry`, `SuiteEntry` |
| Ledger | `qbind-ledger/src/account.rs` | `Account`, `AccountHeader` |
| Ledger | `qbind-ledger/src/store.rs` | `AccountStore`, `InMemoryAccountStore` |
| Ledger | `qbind-ledger/src/execution.rs` | `QbindTransaction`, `StateView`, `StateUpdater` |
| Ledger | `qbind-ledger/src/monetary_state.rs` | `MonetaryEpochState`, `MonetaryEpochInputs` |
| Ledger | `qbind-ledger/src/slashing_ledger.rs` | `ValidatorSlashingState`, `SlashingLedger` |
| Consensus | `qbind-consensus/src/lib.rs` | `ConsensusState`, `HotStuffState` |
| Consensus | `qbind-consensus/src/validator_set.rs` | `ConsensusValidatorSet`, `EpochState`, `EpochId` |
| Consensus | `qbind-consensus/src/hotstuff_state_engine.rs` | `HotStuffStateEngine`, `CommittedEntry` |
| Consensus | `qbind-consensus/src/vote_accumulator.rs` | `VoteAccumulator`, `ConsensusLimitsConfig` |
| Consensus | `qbind-consensus/src/pacemaker.rs` | `TimeoutPacemaker`, `PacemakerEvent` |
| Consensus | `qbind-consensus/src/key_rotation.rs` | `KeyRotationRegistry`, `ValidatorKeyState` |
| Consensus | `qbind-consensus/src/slashing/mod.rs` | `OffenseKind`, `SlashingEvidence`, `EvidencePayloadV1` |
| Node | `qbind-node/src/storage.rs` | `ConsensusStorage`, `RocksDbStorage` |
| Node | `qbind-node/src/mempool.rs` | `Mempool`, `InMemoryMempool`, `TxPriorityScore` |
| Node | `qbind-node/src/dag_mempool.rs` | `DagMempool`, `QbindBatch`, `BatchRef` |

---

# Appendix B: Update Rules

**This document MUST be updated when:**

1. New state types are added to `qbind-types`
2. Storage key layout changes in `qbind-node/src/storage.rs`
3. Consensus state structures change
4. New mutation paths are introduced
5. Persistence timing or ordering changes
6. Slashing system (T229+) is implemented
7. Key rotation enters production use

**Update procedure:**

1. Identify affected section(s)
2. Update tables and matrices
3. Verify file path references are current
4. If contradictions with whitepaper found, append to `docs/whitepaper/contradiction.md`
5. Update version and date at document top

---

*Document generated from exhaustive code inspection of QBIND repository. All file paths and struct names are verified against codebase. No features invented beyond what exists in code.*