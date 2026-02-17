# QBIND DAG Mempool & Dissemination Design Specification

**Task**: T156  
**Status**: Design Document (DevNet-ready)  
**Author**: QBIND Engineering  
**Date**: 2026-01-27

---

## Table of Contents
1. [Motivation & Goals](#1-motivation--goals)
2. [Current Mempool Model Recap](#2-current-mempool-model-recap)
3. [DAG-Based Architecture Sketch](#3-dag-based-architecture-sketch)
4. [PQ Considerations](#4-pq-considerations)
5. [Integration with Execution & Parallelism](#5-integration-with-execution--parallelism)
6. [Rollout Plan](#6-rollout-plan-devnet--testnet--mainnet)

---

## 1. Motivation & Goals

### 1.1 Motivation

The current QBIND architecture uses a **FIFO mempool** with a **single-leader proposal** model:

| Current Design | Limitation |
| :--- | :--- |
| Single leader per view proposes transactions | Leader becomes a bottleneck for throughput and a single point of failure for liveness. |
| Transactions bundled directly in proposals | Large proposals consume network bandwidth; no separation between data availability and ordering. |
| FIFO ordering | No fairness guarantees; early submitters have advantage; susceptible to front-running. |
| Mempool is local to each node | Redundant signature verification across validators; no data availability guarantee before proposal. |

**Problem Statement**: As QBIND scales, the single-leader model limits TPS, increases latency, and creates fairness concerns. A DAG-based mempool architecture can address these limitations.

### 1.2 Goals

The DAG mempool design aims to achieve:

| Goal | Description |
| :--- | :--- |
| **Decouple Data Availability from Ordering** | Separate the dissemination of transaction data from the consensus ordering decision. This allows parallel data propagation while consensus focuses on total ordering. |
| **Reduce Leader Bottleneck** | All validators contribute batches to the DAG; the leader's role is to commit a frontier, not to be the sole data source. |
| **Improve Throughput** | Parallel batch creation and dissemination can increase effective TPS. |
| **Improve Fairness** | DAG structure can provide more equitable transaction inclusion (causal ordering, batch rotation). |
| **Maintain HotStuff Safety** | The 3-chain commit rule and PQ-safe signatures remain unchanged. DAG is an optimization layer beneath consensus. |
| **PQ-Only Cryptography** | All batch signatures, availability certificates, and network transport remain post-quantum secure (ML-DSA-44, ML-KEM-768). |

### 1.3 Non-Goals (T156 Scope)

- Implementing the DAG mempool in code (future task).
- Changing consensus protocol semantics.
- Introducing classical cryptographic assumptions.

---

## 2. Current Mempool Model Recap

### 2.1 InMemoryMempool (T151)

The current mempool implementation provides:

| Feature | Description |
| :--- | :--- |
| **Admission** | Transactions are verified upon receipt: ML-DSA-44 signature check, per-sender nonce validation, capacity check. |
| **Ordering** | Strict FIFO based on insertion order. No priority or fee-based ordering. |
| **Nonce Tracking** | Enforces per-sender nonce monotonicity; limits "nonce gaps" to prevent spam/replay. |
| **Capacity** | Bounded in-memory storage (default: 10,000 transactions). Rejects new transactions when full. |

### 2.2 Proposal Construction

1. **Leader Selection**: HotStuff pacemaker determines the current leader for each view.
2. **Transaction Selection**: Leader pulls top `max_txs_per_block` transactions from its local mempool.
3. **Block Creation**: Leader constructs a `BlockProposal` containing the transaction list.
4. **Dissemination**: Proposal is broadcast to all validators via KEMTLS channels.
5. **Voting**: Validators verify and vote on the proposal.

### 2.3 Limitations Analysis

| Limitation | Impact |
| :--- | :--- |
| **Leader as Single Data Source** | If the leader is slow or malicious, throughput drops. |
| **No Pre-Dissemination** | Transactions are only disseminated when included in a proposal; validators may not have them cached. |
| **Redundant Verification** | Each validator independently verifies all transaction signatures in the proposal. |
| **No Availability Guarantee** | A transaction in the mempool has no protocol-level availability guarantee until committed. |
| **Fairness** | FIFO favors nodes with faster network connections to the mempool entry point. |

---

## 3. DAG-Based Architecture Sketch

### 3.1 Overview

The DAG mempool architecture introduces a **data availability layer** that operates in parallel with consensus:

```
┌─────────────────────────────────────────────────────────────────┐
│                     QBIND DAG Mempool Architecture              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  Validator  │    │  Validator  │    │  Validator  │         │
│  │     A       │    │     B       │    │     C       │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  Batch A1   │    │  Batch B1   │    │  Batch C1   │         │
│  │  (signed)   │    │  (signed)   │    │  (signed)   │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                 │
│         └────────┬─────────┴─────────┬────────┘                │
│                  ▼                   ▼                          │
│           ┌─────────────┐     ┌─────────────┐                  │
│           │  Batch A2   │     │  Batch B2   │   (references    │
│           │  refs: B1   │     │  refs: A1,  │    parent        │
│           └──────┬──────┘     │       C1    │    batches)      │
│                  │            └──────┬──────┘                  │
│                  └─────────┬─────────┘                          │
│                            ▼                                    │
│                    ┌──────────────┐                             │
│                    │ DAG Frontier │ ◄── HotStuff Leader        │
│                    │ (certified)  │     proposes frontier      │
│                    └──────────────┘                             │
│                            │                                    │
│                            ▼                                    │
│                    ┌──────────────┐                             │
│                    │   HotStuff   │                             │
│                    │   Consensus  │                             │
│                    │  (3-chain)   │                             │
│                    └──────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Core Concepts

#### 3.2.1 Batches (QbindBatch)

A **batch** is a collection of transactions created by a single validator:

```
QbindBatch {
    author: ValidatorId,          // Creator of this batch
    round: u64,                   // DAG round number
    transactions: Vec<QbindTransaction>,
    parent_refs: Vec<BatchDigest>, // References to parent batches
    timestamp: u64,
    signature: ValidatorSignature, // ML-DSA-44 signature
}
```

**Properties**:
- Each validator creates at most one batch per round.
- Batches reference parent batches from the previous round (forming a DAG).
- Batches are signed by their author (PQ-safe ML-DSA-44).

#### 3.2.2 Availability Certificates

Before a batch is considered "available," it must be acknowledged by a quorum:

**T165 Implementation (v1)**:

```rust
/// A batch acknowledgment from a validator.
pub struct BatchAck {
    pub batch_ref: BatchRef,      // (creator, batch_id)
    pub validator_id: ValidatorId,
    pub view_hint: u64,
    pub suite_id: u16,            // 100 for ML-DSA-44
    pub signature: Vec<u8>,       // ML-DSA-44 signature
}

/// A batch availability certificate.
pub struct BatchCertificate {
    pub batch_ref: BatchRef,      // Reference to the certified batch
    pub view: u64,                // View at which cert was formed
    pub signers: Vec<ValidatorId>,// 2f+1 or more validators
    pub aggregated: Option<Vec<u8>>, // Placeholder for future aggregation (None in v1)
}
```

**BatchAck Signing Preimage** (T165 v1):
```
QBIND:<SCOPE>:BATCH_ACK:v1  (domain tag with chain scope)
batch_ref.creator            (8 bytes, little-endian)
batch_ref.batch_id           (32 bytes)
validator_id                 (8 bytes, little-endian)
view_hint                    (8 bytes, little-endian)
```

**Properties**:
- A certificate proves that ≥2f+1 validators have received and stored the batch.
- Certificates ensure data availability: even if the author crashes, the batch can be reconstructed.
- Domain separation prevents cross-chain ack replay (e.g., DevNet acks invalid on TestNet).

**V1 Limitations**:
- No batch fetch-on-miss: if a batch is unknown, the ack is ignored (with metrics).
- No signature aggregation: certificates store list of signers, not aggregated signature.
- Certificates are data-plane artifacts; consensus rules unchanged.

**Future v2 Enhancements** (planned):
- PQ-safe aggregate signatures (when standards mature)
- Batch fetch protocol for missing batches
- Consensus integration (require certs before commit)

#### 3.2.3 DAG Structure

The DAG is formed by batches referencing certified batches from previous rounds:

```
Round 0:   [Batch_A0]  [Batch_B0]  [Batch_C0]  [Batch_D0]
                 ↘         ↓         ↓         ↙
Round 1:   [Batch_A1]  [Batch_B1]  [Batch_C1]  [Batch_D1]
           (refs: B0,   (refs: A0,  (refs: A0,  (refs: B0,
            C0, D0)      C0, D0)     B0, D0)     C0, A0)
```

**Causal Ordering**: A batch at round R can only reference certified batches from round R-1. This creates a partial order (causality) within the DAG.

### 3.3 Roles and Responsibilities

| Component | Responsibility |
| :--- | :--- |
| **Mempool / DAG Layer** | Collect transactions, create batches, disseminate batches, issue availability certificates, maintain the DAG. |
| **HotStuff Consensus** | Total ordering of DAG frontiers; finality via 3-chain rule; leader proposes which certified batches to include. |
| **Execution Layer** | Execute transactions from finalized batches in the total order determined by consensus. |

### 3.4 Protocol Flow

1. **Batch Creation** (continuous):
   - Each validator collects transactions from clients.
   - Periodically (or when batch is full), validator creates a `QbindBatch`:
     - Includes pending transactions.
     - References certified batches from the previous round.
     - Signs the batch.
   - Broadcasts batch to all validators.

2. **Batch Certification** (per batch):
   - Validators receive batches and verify:
     - Signature validity (ML-DSA-44).
     - Referenced parents are certified and available.
     - Transaction validity (optional: defer to execution).
   - If valid, validator signs an acknowledgment.
   - Author collects 2f+1 acknowledgments → `BatchCertificate`.
   - Author broadcasts certificate.

3. **DAG Advancement** (per round):
   - When a validator has certificates for batches from 2f+1 validators in round R, it can start round R+1.
   - New batches reference the certified batches from round R.

4. **Consensus Proposal** (HotStuff view):
   - HotStuff leader selects a "frontier" of the DAG (set of certified batches not yet finalized).
   - Leader proposes: "Commit all transactions in batches reachable from this frontier."
   - Proposal is small: just batch digests, not full transaction data.

5. **Consensus Voting & Commit**:
   - Validators verify:
     - All referenced batches are certified and available.
     - No double-inclusion of batches.
   - Vote on proposal.
   - After 3-chain commit, extract transactions and execute.

### 3.5 Comparison: FIFO vs. DAG

| Aspect | FIFO Mempool | DAG Mempool |
| :--- | :--- | :--- |
| **Data Source** | Single leader | All validators contribute batches |
| **Availability** | No guarantee until commit | Guaranteed by certificates before commit |
| **Proposal Size** | Full transaction list | Batch digests only |
| **Bandwidth** | Leader-centric | Distributed across validators |
| **Fairness** | Insertion-order bias | Causal ordering; round-robin contribution |
| **Complexity** | Simple | Higher (DAG management, certificates) |

---

## 4. PQ Considerations

All cryptographic operations in the DAG mempool must use post-quantum secure primitives.

### 4.1 Batch Signatures

| Field | Primitive | Notes |
| :--- | :--- | :--- |
| Batch Author Signature | ML-DSA-44 | Signs batch metadata + transaction Merkle root. |
| Domain Separation | `QBIND:BATCH:v1` | Prevents cross-protocol signature reuse. |

**Signing Preimage**:
```
QBIND:BATCH:v1 || author || round || tx_root || parent_refs_root || timestamp
```

### 4.2 Availability Certificates

| Field | Primitive | Notes |
| :--- | :--- | :--- |
| Acknowledgment Signature | ML-DSA-44 | Each validator signs batch digest. |
| Certificate | Collection of 2f+1 signatures | Aggregation is simple concatenation (no BLS). |
| Domain Separation | `QBIND:BATCH_ACK:v1` | Distinct from batch signature domain. |

**Note**: ML-DSA-44 does not support efficient signature aggregation like BLS. Certificates will contain individual signatures. This increases certificate size but maintains PQ security.

**Future Optimization**: Investigate PQ-safe aggregate signatures (e.g., lattice-based) when standards mature.

### 4.3 Network Transport

| Channel | Primitive | Notes |
| :--- | :--- | :--- |
| Validator-to-Validator | KEMTLS (ML-KEM-768 + AEAD) | Reuse existing secure channels. |
| Batch Dissemination | Over KEMTLS | No new transport layer needed. |

### 4.4 Hashing

| Purpose | Primitive | Notes |
| :--- | :--- | :--- |
| Batch Digest | SHA3-256 (or QBIND standard) | Used for referencing batches. |
| Transaction Root | Merkle tree with SHA3-256 | Compact commitment to transaction list. |

### 4.5 Summary: No Classical Crypto

| Component | Classical? | PQ Primitive |
| :--- | :--- | :--- |
| Batch Signatures | ❌ | ML-DSA-44 |
| Ack Signatures | ❌ | ML-DSA-44 |
| Transport | ❌ | KEMTLS (ML-KEM-768) |
| Hashing | ✅ (SHA3 is PQ-safe) | SHA3-256 |

---

## 5. Integration with Execution & Parallelism

The DAG mempool design should complement the parallel execution model described in [QBIND_PARALLEL_EXECUTION_DESIGN.md](./QBIND_PARALLEL_EXECUTION_DESIGN.md).

### 5.1 Batch Organization for Parallelism

**Opportunity**: Batches can be organized to maximize parallel execution:

| Strategy | Description | Benefit |
| :--- | :--- | :--- |
| **Sender-Partitioned Batches** | Each batch contains transactions from a subset of senders. | Aligns with Stage A parallel execution (sender partitioning). |
| **Contract-Sharded Batches** | Batches target specific contracts or state shards. | Reduces conflicts in Stage B (VM parallelism). |
| **Random Batching** | No special organization; transactions batched as received. | Simplest; relies on execution-time parallelism. |

**Recommendation for DevNet/TestNet**: Start with random batching (simplest). Sender-partitioned batches can be explored later.

### 5.2 Execution Scheduler Integration

The execution scheduler can leverage DAG structure:

1. **Batch Independence**: Batches from the same DAG round (no causal relationship) are independent by construction.
2. **Pre-Execution Analysis**: While a batch is being certified, the execution layer can pre-analyze transactions to build conflict graphs.
3. **Pipelining**: Execution can begin on certified batches before full consensus finality (speculative execution with rollback on fork).

### 5.3 Metrics Integration

New metrics for DAG mempool:

| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_dag_batches_created_total` | Counter | Batches created by this validator. |
| `qbind_dag_batches_certified_total` | Counter | Batches certified (received 2f+1 acks). |
| `qbind_dag_round` | Gauge | Current DAG round. |
| `qbind_dag_batch_size_txs` | Histogram | Transactions per batch. |
| `qbind_dag_cert_latency_seconds` | Histogram | Time from batch creation to certification. |
| `qbind_dag_batches_pending` | Gauge | Batches awaiting certification. |
| `qbind_dag_bandwidth_bytes` | Counter | Network bytes for DAG dissemination. |

**T165 Availability Metrics** (new):

| Metric | Type | Description |
| :--- | :--- | :--- |
| `qbind_dag_batch_acks_total{result}` | Counter | Batch acks processed (accepted/rejected). |
| `qbind_dag_batch_certs_total` | Counter | Batch certificates formed. |
| `qbind_dag_batch_certs_pending` | Gauge | Batches with some acks but no cert yet. |
| `qbind_dag_batch_acks_invalid_total{reason}` | Counter | Invalid acks (bad_sig/duplicate/unknown_batch). |

### 5.4 Coexistence with FIFO Mempool

During the transition period:

1. **Feature Flag**: DAG mempool enabled via configuration.
2. **Fallback**: If DAG mode fails, fall back to FIFO mode.
3. **Interop**: DAG nodes must be able to participate in a mixed network (graceful degradation).

### 5.5 Gas Model Integration (T167)

The T167 gas and fee model will affect DAG mempool behavior in future phases:

| Component | Gas Integration Impact |
| :--- | :--- |
| **Batch Construction** | Batch creators may preferentially include higher-fee transactions for economic incentive. |
| **Block Construction** | When building blocks from DAG frontier, gas-invalid transactions are skipped and per-block gas limit is enforced. |
| **Admission Policy** | Transactions must satisfy gas legality (`gas(tx) <= gas_limit`) and balance requirements before entering any mempool. |
| **Eviction Policy** | Low-fee transactions may be evicted when mempool is full; fee priority determines eviction order. |

**Note**: Gas enforcement is not implemented in TestNet Alpha. See [QBIND Gas and Fee Model Design](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) for the complete specification and migration timeline.

> **T168 Implementation Note**: Task T168 implements initial VM v0 gas enforcement (config-gated) and mempool admission checks. Gas limits, fee deduction, and balance verification are available in both FIFO and DAG mempools when `ExecutionGasConfig.enabled = true`. However, DAG-specific fee prioritization and eviction remain future work.
>
> **T169 Implementation Note**: Task T169 implements optional fee-based priority and eviction for both FIFO and DAG mempools. When `enable_fee_priority = true` and gas enforcement is enabled, batch construction and frontier selection prioritize transactions with higher `fee_per_gas` and `effective_fee`. Consensus rules remain unchanged; fee priority only affects which transactions are proposed in blocks.

---

## 6. Rollout Plan (DevNet → TestNet → MainNet)

### 6.1 Phase Overview

| Phase | Network | Mempool | Execution | Status |
| :--- | :--- | :--- | :--- | :--- |
| **0** | DevNet v0 | FIFO | Sequential (T150) | ✅ Complete |
| **0.5** | DevNet v0 | FIFO | Async Sequential (T155) | ✅ Complete |
| **1** | DevNet v1 | FIFO | **Parallel Stage A** | Planned (T157+) |
| **2** | TestNet Alpha | **DAG Prototype** (feature flag) | Parallel Stage A | Planned |
| **3** | TestNet Beta | **DAG Default** | Parallel Stage A | Planned |
| **4** | MainNet | DAG + DoS Protection | **Parallel Stage B** | Planned |

### 6.2 Phase 1: DevNet v1 – Parallel Execution (Stage A)

**Focus**: Implement sender-partitioned parallel execution.

**Mempool**: FIFO (unchanged).  
**Execution**: `ParallelExecutionEngine` with sender partitioning.  

**Deliverables**:
- Parallel execution engine implementation.
- Determinism tests (parallel vs. sequential comparison).
- Updated TPS benchmark showing multi-core speedup.
- Metrics for parallelism factor.

**Success Criteria**:
- 2x+ speedup on blocks with many distinct senders.
- No determinism failures in 10M+ transaction tests.

### 6.3 Phase 2: TestNet Alpha – DAG Prototype

**Focus**: Implement DAG mempool as a prototype behind a feature flag.

**Mempool**: DAG (opt-in via `--dag-mempool` flag).  
**Execution**: Parallel Stage A.

**Deliverables**:
- `QbindBatch` and `BatchCertificate` data structures.
- Batch creation and dissemination logic.
- Availability certificate protocol.
- HotStuff integration: proposals reference batch digests.
- Feature flag for enabling/disabling DAG mode.

**Implementation Status**:
- **T165** implements availability certificates v1 (BatchAck, BatchCertificate, quorum accumulation).
- **T166** provides the first multi-node TestNet Alpha harness that exercises DAG availability in practice.

**Success Criteria**:
- 4-validator TestNet runs with DAG mempool.
- TPS comparable to or better than FIFO baseline.
- No safety violations.

### 6.4 Phase 3: TestNet Beta – DAG Default

**Focus**: Make DAG mempool the default for TestNet.

**Mempool**: DAG (default).  
**Execution**: Parallel Stage A.

**Deliverables**:
- Performance tuning (batch sizes, round timing).
- Improved certificate aggregation efficiency.
- Fairness analysis and metrics.
- Integration with TPS harness.
- Documentation for operators.

**P2P Integration**:

In TestNet Beta and MainNet, DAG batch dissemination will run atop the P2P overlay defined in [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) (T170). Key integration points:

| Component | P2P Overlay Usage |
| :--- | :--- |
| **Batch Dissemination** | Gossip protocol on DAG/mempool overlay (stream `0x0002`) |
| **Availability Acks** | Direct send to batch author on DAG availability overlay (stream `0x0003`) |
| **Certificate Broadcast** | Gossip on DAG/mempool overlay |

This replaces the current static mesh broadcast with efficient gossip-based propagation.

**T182-T183: DAG Batch Fetch-on-Miss v0**:

T182 and T183 implement a basic fetch-on-miss protocol for DAG batch availability:

| Component | Description |
| :--- | :--- |
| **Missing Batch Tracking** | `MissingBatchInfo` tracks batches we've seen acks for but don't have locally |
| **BatchRequest/BatchResponse** | New `DagNetMsg` variants for requesting and receiving missing batches |
| **DagP2pClient** | Helper for broadcasting batch requests and sending responses |
| **DagFetchHandler** | Inbound handler that processes fetch requests/responses |
| **Cooldown Logic** | `drain_missing_batches_for_fetch()` respects cooldown to avoid aggressive retries |

**Protocol Flow**:

```text
1. Node A receives BatchAck for batch B from validator V
2. Node A checks: do we have batch B? No.
3. Node A calls record_missing_batch(batch_ref, V, timestamp)
4. On tick: Node A calls drain_missing_batches_for_fetch(max, now, cooldown)
5. For each returned BatchRef: Node A broadcasts BatchRequest via DagP2pClient
6. Node B receives BatchRequest, looks up batch, sends BatchResponse if found
7. Node A receives BatchResponse, calls handle_batch_response() to insert
```

**Current Limitations (v0)**:

- Simple broadcast to all peers (no intelligent peer selection)
- Basic cooldown-based retry (no exponential backoff)
- No consensus-level coupling (certificates not required for commit)
- Limited metrics (requests/responses/failures counted)

**Future Enhancements (TestNet Beta / MainNet)**:

- Targeted peer selection based on who sent acks
- Exponential backoff with jitter
- Consensus coupling: require certificates before commit
- Certificate aggregation for efficiency

**Success Criteria**:
- Stable operation over weeks of TestNet.
- Clear TPS improvement over FIFO.
- Fairness metrics within acceptable bounds.

### 6.5 Phase 4: MainNet – Full Production

**Focus**: Production-ready DAG mempool with full parallel execution.

**Mempool**: DAG with DoS protections.  
**Execution**: Parallel Stage A + Stage B (VM parallelism).

**Deliverables**:
- DoS protection: rate limiting, stake-weighted batch quotas.
- Stage B parallel execution (conflict graph scheduling).
- Extensive security audit.
- Monitoring and alerting dashboards.
- Incident response procedures.

**Success Criteria**:
- Successful security audit.
- Stable operation under adversarial conditions.
- TPS targets met (specific targets TBD based on TestNet data).

### 6.6 Rollback Strategy

Each phase includes a rollback plan:

| Phase | Rollback Mechanism |
| :--- | :--- |
| Phase 1 | Disable parallel execution; fall back to sequential. |
| Phase 2 | Disable DAG flag; use FIFO mempool. |
| Phase 3 | Re-enable FIFO as default if DAG issues emerge. |
| Phase 4 | Staged rollout with canary validators; halt if anomalies detected. |

---

## Appendix A: References

- [QBIND DevNet v0 Spec](./QBIND_DEVNET_V0_SPEC.md) — Current architecture.
- [QBIND Parallel Execution Design](./QBIND_PARALLEL_EXECUTION_DESIGN.md) — Companion parallel execution spec.
- [QBIND DevNet Audit Log](./QBIND_DEVNET_AUDIT.md) — Risk tracking (R2, R5, R6).
- [QBIND Gas and Fee Model Design](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) — Gas and fee specification (T167).
- [QBIND P2P Network Design](../network/QBIND_P2P_NETWORK_DESIGN.md) — P2P networking architecture (T170).
- **Narwhal and Tusk** (Danezis et al., 2022) — DAG-based mempool and consensus.
- **Bullshark** (Spiegelman et al., 2022) — DAG-based BFT with improved latency.
- **PBFT** (Castro & Liskov, 1999) — Classical BFT consensus.
- **HotStuff** (Yin et al., 2019) — Linear-communication BFT.

---

## Appendix B: Glossary

| Term | Definition |
| :--- | :--- |
| **Batch** | A collection of transactions created and signed by a single validator. |
| **Availability Certificate** | Proof that 2f+1 validators have received and stored a batch. |
| **DAG** | Directed Acyclic Graph; batches form a DAG via parent references. |
| **Frontier** | The set of certified batches at the head of the DAG (not yet finalized). |
| **Round** | A logical time unit in the DAG; each validator produces one batch per round. |
| **Causal Ordering** | A partial order where batch B causally follows batch A if B references A (directly or transitively). |
| **2f+1** | Quorum size for n=3f+1 validators (tolerates f Byzantine faults). |

---

## Appendix C: Open Questions (Future Tasks)

| Question | Notes |
| :--- | :--- |
| **Garbage Collection** | How to prune old DAG rounds after finality? |
| **Validator Churn** | How does the DAG handle validators joining/leaving? |
| **Batch Size Tuning** | Optimal batch size for throughput vs. latency trade-off? |
| **PQ Aggregate Signatures** | Can future PQ schemes reduce certificate size? |
| **Speculative Execution** | Execute batches before consensus finality (with rollback)? |

These questions will be addressed in future design tasks (T157+).

---

## Appendix D: DoS Protections (T218)

**Added**: 2026-02-08

The DAG mempool includes DoS protections to prevent malicious senders from overwhelming the mempool. These are implemented in T218 and documented in [QBIND_MAINNET_V0_SPEC.md §4.4](../mainnet/QBIND_MAINNET_V0_SPEC.md#44-dos-protections-and-fee-aware-eviction).

### Per-Sender Quotas

| Parameter | Description | MainNet Default |
| :--- | :--- | :--- |
| `max_pending_per_sender` | Maximum pending txs per sender | 1,000 |
| `max_pending_bytes_per_sender` | Maximum pending bytes per sender | 8 MiB |

**Enforcement**: At admission time, if a sender already has `max_pending_per_sender` pending transactions or `max_pending_bytes_per_sender` bytes, new transactions from that sender are rejected.

### Batch Size Limits

| Parameter | Description | MainNet Default |
| :--- | :--- | :--- |
| `max_txs_per_batch` | Maximum transactions per batch | 4,000 |
| `max_batch_bytes` | Maximum bytes per batch | 2 MiB |

**Enforcement**: At batch creation time, transactions are included up to these limits. Excess transactions remain pending for future batches.

### Metrics

- `qbind_dag_sender_rate_limited_total`: Count of txs rejected due to sender limits
- `qbind_dag_batch_size_limited_total`: Count of batches affected by size limits

### Future Work

- **Stake-weighted quotas** (MainNet v0.x): Allow higher limits for staked validators
- **Dynamic tuning**: Adjust limits based on network conditions

---

## Appendix E: Eviction Rate Limiting (T219/T220)

**Added**: 2026-02-08

The DAG mempool includes eviction rate limiting to prevent excessive mempool churn under adversarial conditions. This complements the DoS protections from T218 by limiting the rate at which transactions can be evicted (replaced) from the mempool.

### Configuration

| Parameter | Description | MainNet Default |
| :--- | :--- | :--- |
| `eviction_mode` | Rate limiting mode (Off/Warn/Enforce) | Enforce |
| `max_evictions_per_interval` | Max evictions allowed per window | 1,000 |
| `eviction_interval_secs` | Window length in seconds | 10 |

### Mode Semantics

| Mode | Behavior |
| :--- | :--- |
| **Off** | No rate limiting. Eviction proceeds as normal. Metrics still recorded. |
| **Warn** | Log warnings when limit exceeded. Still allow eviction. Track via `mode="warn"` metric. |
| **Enforce** | Block evictions when limit reached. Reject incoming tx instead. Track via `mode="enforce"` metric. |

### Interaction with Fee-Priority Eviction (T169)

When `enable_fee_priority` is true and the mempool is at capacity:

1. **Fee-priority check**: Incoming tx must have higher priority than the lowest-priority tx in mempool
2. **Eviction rate check** (T220): Before evicting, consult the `EvictionWindow`:
   - If within limit: Allow eviction, increment window counter
   - If at limit + Warn mode: Allow eviction, log warning, increment warn metric
   - If at limit + Enforce mode: Block eviction, reject incoming tx with `EvictionRateLimited` error

### Interaction with Per-Sender Quotas (T218)

These protections work in parallel:

- **T218 quotas**: Prevent a single sender from filling 100% of mempool capacity
- **T219/T220 rate limiting**: Limit the total eviction rate regardless of sender

When all protections are enabled (MainNet default):
1. A single abusive sender cannot fill the mempool (T218)
2. Even under churn, total eviction rate is bounded (T219/T220)
3. When eviction limit is reached, the node degrades gracefully by rejecting further incoming txs

### Metrics

- `qbind_mempool_eviction_mode`: Config gauge (0=off, 1=warn, 2=enforce)
- `qbind_mempool_max_evictions_per_interval`: Config gauge
- `qbind_mempool_eviction_interval_secs`: Config gauge
- `qbind_mempool_evictions_total{reason="capacity"}`: Evictions due to mempool full
- `qbind_mempool_evictions_total{reason="lifetime"}`: Evictions due to TTL
- `qbind_mempool_eviction_rate_limit_total{mode="warn"}`: Warn mode limit hits
- `qbind_mempool_eviction_rate_limit_total{mode="enforce"}`: Enforce mode rejections
- `qbind_mempool_evictions_window_reset_total`: Window reset count

### Implementation

- **Config**: `MempoolEvictionConfig` in `node_config.rs` (T219)
- **Tracking**: `EvictionWindow` struct in `dag_mempool.rs` (T219)
- **Enforcement**: `InMemoryDagMempool::insert_local_txs()` (T220)

---

*End of Document*