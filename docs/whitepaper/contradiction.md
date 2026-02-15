# QBIND Whitepaper Contradictions and Undocumented Behaviors

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Active Tracking Document

This document tracks contradictions between the whitepaper (`docs/whitepaper/QBIND_WHITEPAPER.md`) and the actual implementation, as well as behaviors that are implemented but not documented.

---

## Contradictions

### C1. O3–O5 Offense Penalties Not Implemented

| Field | Value |
|-------|-------|
| **Whitepaper Reference** | Section 8.10, Section 12.2 |
| **Code Location** | `qbind-consensus/src/slashing/mod.rs:1361-1366` |
| **Whitepaper Claim** | "Slashing penalties are partially implemented; enforcement expansion is planned" |
| **Actual Implementation** | O3 (Lazy Vote), O4 (Invalid DAG Cert), and O5 (Coupling Violation) penalties are completely stubbed. Code explicitly returns `EvidenceOnly` for these offenses with no penalty parameters defined. |
| **Impact** | High - 4 of 6 offense classes have no economic deterrent |
| **Recommendation** | Whitepaper should explicitly state O3–O5 are evidence-recording only, with no penalty application |

### C2. No Minimum Stake Requirement

| Field | Value |
|-------|-------|
| **Whitepaper Reference** | Section 8.1, Section 12.2 |
| **Code Location** | `qbind-system/src/validator_program.rs:83-97` |
| **Whitepaper Implication** | Economic security through stake-based slashing |
| **Actual Implementation** | Validators can register with zero stake (`call.stake` accepted without validation). Zero-stake validators cannot be meaningfully slashed. |
| **Impact** | High - Undermines economic security model |
| **Recommendation** | Add minimum stake validation or document this as a known limitation |

### C3. Reporter Rewards Not Implemented

| Field | Value |
|-------|-------|
| **Whitepaper Reference** | Section 12.2 (Slashing Model) |
| **Code Location** | `qbind-types/src/state_governance.rs:53` |
| **Whitepaper Implication** | `reporter_reward_bps` parameter suggests reward distribution to evidence reporters |
| **Actual Implementation** | Parameter exists in `ParamRegistry` but no code distributes rewards. Evidence reporting has no incentive mechanism. |
| **Impact** | Medium - Reduces incentive to report Byzantine behavior |
| **Recommendation** | Document that reporter rewards are not implemented |

---

## Undocumented Implementation Details

### 1. In-Memory Slashing Ledger (T230)

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-ledger/src/slashing_ledger.rs` |
| **Whitepaper Reference** | Section 8.10, Section 12.2 |
| **Description** | The slashing ledger is currently in-memory only (`InMemorySlashingLedger`). This means slashing evidence and penalty records are NOT persisted to disk and will be lost on node restart. |
| **Impact** | High - Byzantine behavior detected before restart may not be penalized |
| **Recommendation** | Document that persistent slashing is a T229+ feature; update whitepaper Section 8.10 |

### 2. Vote History Memory Limits

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-consensus/src/hotstuff_state_engine.rs:107-119` |
| **Whitepaper Reference** | Section 8.4 (Voting Rule) |
| **Description** | The vote history (`votes_by_view` HashMap) is subject to memory limits and eviction. Old views can be evicted, potentially missing equivocations in those views. |
| **Impact** | Medium - Equivocation detection may miss old misbehavior |
| **Recommendation** | Document memory management policy in whitepaper or design doc |

### 3. CRC-32 Checksum for Storage Integrity

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-node/src/storage.rs:257-336` |
| **Whitepaper Reference** | Section 10.5 (Persistence Guarantees) |
| **Description** | Storage uses CRC-32 checksums (non-cryptographic) for integrity detection. This is sufficient for bit-rot but not for malicious tampering. |
| **Impact** | Low - Adequate for intended use case |
| **Recommendation** | Mention checksum mechanism in Section 10.5 |

### 4. Epoch Transition Write Ordering

| Field | Value |
|-------|-------|
| **Implementation** | Implied in `qbind-node/src/storage.rs` |
| **Whitepaper Reference** | Section 10.5 (Persistence Guarantees) |
| **Description** | The whitepaper mentions "epoch transition writes storage before in-memory update to preserve atomicity" but the exact write ordering and crash recovery procedure are not formally specified. |
| **Impact** | Medium - Crash during epoch transition could cause inconsistent state |
| **Recommendation** | Add explicit atomicity guarantees and recovery procedure to whitepaper |

### 5. Key Rotation Grace Period Semantics

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-consensus/src/key_rotation.rs:238-298` |
| **Whitepaper Reference** | Not mentioned |
| **Description** | Key rotation uses a grace period mechanism where both old and new keys are valid during transition. The grace period spans full epochs; partial-epoch rotations are not supported. |
| **Impact** | Low - Implementation constraint |
| **Recommendation** | Document key rotation mechanics in whitepaper Section 9 |

### 6. DAG Mempool Batch Priority

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-node/src/dag_mempool.rs`, `mempool.rs:143-150` |
| **Whitepaper Reference** | Section 7.1 (Async Runtime Model) briefly mentions DAG mempool |
| **Description** | Mempool priority scoring uses `arrival_id` which differs per node, meaning transaction ordering in blocks may vary between proposers. This is deterministic per-node but not globally deterministic. |
| **Impact** | Low - Expected behavior for mempool |
| **Recommendation** | Clarify in whitepaper that transaction ordering within blocks is proposer-determined |

### 7. Timeout Exponential Backoff Parameters

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-consensus/src/pacemaker.rs:93-111` |
| **Whitepaper Reference** | Section 8.9 (Liveness Assumptions) |
| **Description** | The timeout pacemaker uses configurable exponential backoff (default multiplier 2.0, max 30s) but these parameters and their security implications are not documented. |
| **Impact** | Low - Configuration choice |
| **Recommendation** | Document timeout parameters in whitepaper or operator guide |

### 8. Evidence Signature Verification Not Performed

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-consensus/src/slashing/mod.rs:459-519` |
| **Whitepaper Reference** | Section 12.2 (Byzantine Detection) |
| **Description** | Slashing evidence is validated for structural correctness only. Cryptographic signatures in evidence payloads (block signatures, vote signatures, DAG certificates) are NOT verified before penalty application. |
| **Impact** | High - Forged evidence could penalize honest validators |
| **Recommendation** | Document that signature verification is planned but not implemented; add security warning |

### 9. Governance Slashing Parameters Not Connected

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-types/src/state_governance.rs:49-53`, `qbind-node/src/node_config.rs:1914-1953` |
| **Whitepaper Reference** | Section 11 (Governance) |
| **Description** | `ParamRegistry` contains `slash_bps_prevote`, `slash_bps_precommit`, and `reporter_reward_bps` but these are NOT connected to the slashing engine. The engine uses `SlashingConfig` from node configuration instead. Governance cannot dynamically adjust slashing parameters. |
| **Impact** | Medium - Governance control of slashing is ineffective |
| **Recommendation** | Document that governance-controlled slashing parameters are not yet wired |

### 10. Stake Synchronization Gap

| Field | Value |
|-------|-------|
| **Implementation** | `qbind-types/src/state_validator.rs:25`, `qbind-ledger/src/slashing_ledger.rs:38` |
| **Whitepaper Reference** | Not documented |
| **Description** | Validator stake is tracked in two parallel structures: `ValidatorRecord.stake` (on-chain account data) and `ValidatorSlashingState.stake` (slashing ledger). |
| **Impact** | ~~Medium - Stake inconsistency between ledger views~~ **Low (M13)** |
| **Status** | ✅ Partially Mitigated (M13) |
| **Recommendation** | ~~Document stake tracking architecture and synchronization requirements~~ |
| **M13 Note** | **M13**: Canonical economic state unified. `ValidatorRecord.stake` and `ValidatorRecord.jailed_until_epoch` are now the single source of truth. `ValidatorSlashingState` mirrors these values for operational tracking but is documented as non-authoritative. Eligibility predicates (`ValidatorRecord::is_eligible_at_epoch()`) read from canonical fields. Validator set builders (`build_validator_set_with_stake_and_jail_filter()`) construct candidates from canonical `ValidatorRecord` fields. Restart safety tested via 12 tests in `m13_economic_state_unification_tests.rs`. Full architectural unification (single-write path for slashing penalties to both `ValidatorRecord` and `ValidatorSlashingState`) is pending but the canonical source is now clearly defined. |

---

## Update History

| Date | Change | Author |
|------|--------|--------|
| 2026-02-11 | Initial document created during state audit | Audit |
| 2026-02-11 | Added C1-C3 contradictions, items 8-10 undocumented details from validator economics audit | Audit |
| 2026-02-15 | M12: Added formal validator set transition spec (Section 18). Items 4 (Epoch Transition Write Ordering) now documented in Section 18.4.3. C2 (Minimum Stake) partially addressed by M2 epoch-boundary filtering; registration-time validation still pending. | M12 |
| 2026-02-15 | M13: Canonical economic state unified. Item 10 (Stake Synchronization Gap) partially mitigated - canonical source defined (`ValidatorRecord.stake`, `ValidatorRecord.jailed_until_epoch`). `ValidatorSlashingState` documented as mirror. 12 restart safety tests added. | M13 |

---

*This document should be updated whenever a contradiction is discovered between the whitepaper and implementation, or when significant undocumented behaviors are identified.*