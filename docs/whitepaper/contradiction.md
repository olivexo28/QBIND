# QBIND Whitepaper Contradictions and Undocumented Behaviors

**Version**: 1.0  
**Date**: 2026-02-11  
**Status**: Active Tracking Document

This document tracks contradictions between the whitepaper (`docs/whitepaper/QBIND_WHITEPAPER.md`) and the actual implementation, as well as behaviors that are implemented but not documented.

---

## Contradictions

*None identified at this time.*

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

---

## Update History

| Date | Change | Author |
|------|--------|--------|
| 2026-02-11 | Initial document created during state audit | Audit |

---

*This document should be updated whenever a contradiction is discovered between the whitepaper and implementation, or when significant undocumented behaviors are identified.*