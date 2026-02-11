# QBIND Codebase Architecture Overview

**Version**: 1.0  
**Date**: February 2026

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Crate-by-Crate Overview](#2-crate-by-crate-overview)
3. [Critical Paths](#3-critical-paths)
4. [Testing and Harnesses](#4-testing-and-harnesses)

---

## 1. High-Level Architecture

### 1.1 End-to-End Transaction Flow

QBIND is a post-quantum secure Layer-1 blockchain using **ML-DSA-44** (FIPS 204) for signatures and **ML-KEM-768** (FIPS 203) for KEMTLS-based validator transport. The architecture separates data availability (DAG mempool) from consensus ordering (HotStuff BFT).

```
Transaction Submission → DAG Mempool → BFT Consensus → Execution → State Update → Storage

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           QBIND Transaction Flow                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  1. SUBMISSION           2. DAG MEMPOOL          3. BFT CONSENSUS               │
│  ┌──────────────┐       ┌───────────────┐       ┌─────────────────┐             │
│  │ Transaction  │──────►│ Batch + Sign  │──────►│ Leader Proposes │             │
│  │ (ML-DSA-44)  │       │ (ML-DSA-44)   │       │ DAG Frontier    │             │
│  └──────────────┘       │               │       │                 │             │
│                         │ ┌───────────┐ │       │ ┌─────────────┐ │             │
│                         │ │ BatchAcks │ │       │ │   Votes     │ │             │
│                         │ │  (2f+1)   │ │       │ │  (3-chain)  │ │             │
│                         │ └───────────┘ │       │ └─────────────┘ │             │
│                         │       ↓       │       │       ↓         │             │
│                         │ Certificate   │       │      QC         │             │
│                         └───────────────┘       └─────────────────┘             │
│                                                          │                       │
│  4. EXECUTION                5. STATE UPDATE            6. STORAGE              │
│  ┌──────────────────┐       ┌───────────────┐       ┌──────────────┐            │
│  │ VM v0 (Transfer) │──────►│ Account State │──────►│   RocksDB    │            │
│  │ Stage A/B Exec   │       │ + Nonces      │       │   + WAL      │            │
│  └──────────────────┘       └───────────────┘       └──────────────┘            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Flow Details**:

1. **Transaction Submission**: Clients submit ML-DSA-44-signed transactions to any validator. The signature is verified, and the transaction enters the local mempool.

2. **DAG Mempool (Data Availability)**: Validators batch transactions into `QbindBatch` structures, sign them, and disseminate to peers. Receiving validators send `BatchAck` acknowledgments. Once 2f+1 acks are collected, a `BatchCertificate` is formed, proving data availability.

3. **BFT Consensus (HotStuff)**: The designated leader proposes a block referencing certified DAG batches (the "frontier"). Validators verify the proposal (including certificate validity for MainNet) and send votes. A 3-chain commit rule finalizes blocks: a block is committed when it has a QC-bearing child and grandchild.

4. **Execution**: The `VmV0ExecutionEngine` processes committed transactions. Stage B parallel execution (conflict-graph-based) is available for MainNet, with determinism verified by soak testing.

5. **State Update**: Account balances and nonces are updated. Fee distribution follows a hybrid model (burn + proposer reward) for MainNet.

6. **Storage**: State is persisted to RocksDB with write-ahead logging. Periodic snapshots enable fast node synchronization.

### 1.2 Main Binaries and Crates

| Binary/Crate | Purpose |
|--------------|---------|
| **qbind-node** | Validator node binary; integrates all subsystems |
| **qbind-consensus** | HotStuff BFT logic, pacemaker, vote accumulation, slashing |
| **qbind-ledger** | Account state, execution engines, genesis, monetary engine |
| **qbind-crypto** | ML-DSA-44, ML-KEM-768, AEAD, KDF primitives |
| **qbind-net** | KEMTLS transport, session management, handshake |
| **qbind-remote-signer** | Remote signing service for HSM/isolated key management |
| **qbind-gov** | Upgrade envelopes, council signatures, governance CLI |
| **qbind-types** | Shared primitives, domain separation, account types |
| **qbind-wire** | Wire protocols, consensus messages, transaction encoding |
| **qbind-runtime** | Block execution, EVM state (future), gas model |
| **qbind-hash** | Hashing utilities (SHA3-256) |
| **qbind-serde** | Serialization helpers |

---

## 2. Crate-by-Crate Overview

### 2.1 qbind-node

**Purpose**: The main validator binary that orchestrates all subsystems. It wires together consensus, networking, mempool, execution, and storage into a cohesive node runtime.

**Key Responsibilities**:
- Async runtime driving the consensus loop (`AsyncNodeRunner`)
- P2P networking with KEMTLS channels, peer discovery, and anti-eclipse protections
- DAG mempool management (`InMemoryDagMempool`) with batch/certificate lifecycle
- Block store and commit index for chain state
- Metrics exposure (Prometheus format) and HTTP endpoints
- CLI handling for node configuration, key management, and genesis validation

**Key Types**:
- `NodeHotstuffHarness`: Full node harness integrating consensus + execution
- `InMemoryDagMempool`, `DagMempoolConfig`: DAG-based transaction batching
- `AsyncPeerManager`, `P2pDiscoveryConfig`: Peer connectivity management
- `NodeMetrics`, `ExecutionMetrics`: Observability structures
- `NodeValidatorConfig`: Per-validator runtime configuration

**Key Interactions**:
- Uses `qbind-consensus` for BFT logic
- Uses `qbind-ledger` for state and execution
- Uses `qbind-crypto` via `CryptoProvider` for signing/verification
- Uses `qbind-net` for KEMTLS transport
- Uses `qbind-wire` for message encoding

### 2.2 qbind-consensus

**Purpose**: Pure consensus verification and state management. Implements HotStuff-style BFT with 3-chain commit, quorum certificate aggregation, and pacemaker-driven view changes.

**Key Responsibilities**:
- Proposal and vote verification (structural + safety)
- QC (Quorum Certificate) aggregation and validation
- HotStuff locking rules and commit tracking
- Timeout messages and view-change coordination
- Slashing infrastructure (offense detection, evidence model)
- Key rotation and governed key registry

**Key Types**:
- `HotStuffStateEngine`: State machine with QC-based locking
- `BasicHotStuffEngine`: Core engine with vote accumulation
- `QuorumCertificate`, `VoteAccumulator`: QC formation
- `TimeoutPacemaker`, `PacemakerConfig`: View transition control
- `PenaltySlashingEngine`, `SlashingEvidence`: Slashing enforcement
- `ValidatorSet`, `EpochState`: Validator registry and epochs

**Key Interactions**:
- Receives proposals/votes from `qbind-node` via network abstraction
- Uses `qbind-crypto` for signature verification via `CryptoConsensusVerifier`
- Slashing backend integrates with `qbind-ledger` for penalty application

### 2.3 qbind-ledger

**Purpose**: Account state management, transaction execution, genesis configuration, and monetary policy engine.

**Key Responsibilities**:
- Account storage (nonces, balances) with RocksDB backend
- Transaction execution engines (NonceOnly, VmV0)
- Stage A/B parallel execution with conflict graph analysis
- Genesis state parsing and validation
- Monetary engine (inflation, fee distribution, phase transitions)
- State pruning and snapshot management
- Slashing ledger integration

**Key Types**:
- `AccountState`, `CachedPersistentAccountState`, `RocksDbAccountState`
- `VmV0ExecutionEngine`, `NonceExecutionEngine`: Execution modes
- `GenesisConfig`, `GenesisAllocation`, `GenesisHash`: Genesis handling
- `MonetaryEngine`, `MonetaryState`, `MonetaryPhase`: Economic subsystem
- `ParallelSchedule`, `ConflictGraph`: Stage B execution
- `SlashingLedger`, `InMemorySlashingLedger`: Penalty tracking

**Key Interactions**:
- Called by `qbind-node` for block execution
- Uses `qbind-crypto` for transaction signature verification
- Provides state roots to consensus for block headers

### 2.4 qbind-crypto

**Purpose**: Post-quantum cryptographic primitives. All consensus-critical operations use PQC-only algorithms.

**Key Responsibilities**:
- ML-DSA-44 signing and verification (FIPS 204)
- ML-KEM-768 key encapsulation (FIPS 203)
- ChaCha20-Poly1305 AEAD for encrypted channels
- HKDF for session key derivation
- PBKDF2 for keystore encryption
- Suite catalog and crypto-agility support

**Key Types**:
- `MlDsa44Backend`, `ValidatorSigningKey`: Signature operations
- `MlKem768Backend`: Key encapsulation
- `CryptoProvider`, `StaticCryptoProvider`: Abstraction over crypto backends
- `ConsensusSigSuiteId`, `SUITE_PQ_RESERVED_1`: Suite identifiers
- `SignatureSuite`, `KemSuite`, `AeadSuite`: Trait abstractions

**Key Interactions**:
- Used by all crates requiring cryptographic operations
- `qbind-consensus` uses it for vote/QC verification
- `qbind-net` uses it for KEMTLS handshakes
- `qbind-ledger` uses it for transaction signature checks

### 2.5 qbind-net

**Purpose**: KEMTLS-based secure transport between validators. Provides post-quantum authenticated and encrypted channels.

**Key Responsibilities**:
- KEMTLS handshake using ML-KEM-768
- Session key derivation via HKDF
- Framed I/O with length-prefixed messages
- Connection lifecycle management
- KEM metrics for observability

**Key Types**:
- `ServerHandshakeConfig`, `ClientHandshakeConfig`: Handshake parameters
- `KemPrivateKey`, `KemPublicKey`: Key material
- `SecureSession`: Encrypted channel abstraction
- `FramedIo`: Length-delimited message framing
- `KemMetrics`: Handshake performance counters

**Key Interactions**:
- Used by `qbind-node` for P2P connections
- Depends on `qbind-crypto` for KEM and AEAD primitives

### 2.6 qbind-remote-signer

**Purpose**: Isolated signing service for production validators. Keeps consensus keys on a separate hardened host or HSM.

**Key Responsibilities**:
- Accept signing requests over KEMTLS channel
- Sign consensus messages (proposals, votes, timeouts)
- Reject unauthorized signing requests
- Support HSM/PKCS#11 backends

**Key Types**:
- Remote signer protocol messages
- Signing request/response structures

**Key Interactions**:
- Receives requests from `qbind-node` validator
- Uses `qbind-crypto` for actual signing operations
- Uses `qbind-net` for secure transport

### 2.7 qbind-gov

**Purpose**: Governance tooling for protocol upgrades. Provides upgrade envelope creation, verification, and council signature coordination.

**Key Responsibilities**:
- Upgrade envelope format definition
- Multi-signature collection (M-of-N council)
- Envelope verification and hash computation
- CLI tools for governance operations (`qbind-envelope`)

**Key Types**:
- `UpgradeEnvelope`: Signed upgrade payload
- `CouncilSignature`, `CouncilConfig`: Multi-sig structures
- `EnvelopeHash`, `EnvelopeDigest`: Content hashing

**Key Interactions**:
- Uses `qbind-crypto` for ML-DSA-44 signatures
- Standalone tooling; envelope verification can be done by any node

### 2.8 qbind-types

**Purpose**: Shared primitive types and domain separation constants. Ensures consistent type definitions across all crates.

**Key Responsibilities**:
- `AccountId` and address types
- Domain separation tags for signature contexts
- Chain scope identifiers
- Validator state types

**Key Types**:
- `AccountId`, `ValidatorId`
- `DomainKind`, `domain_prefix()`, `chain_scope()`
- State governance and keyset types

### 2.9 qbind-wire

**Purpose**: Wire protocol definitions for consensus messages, transactions, and network packets.

**Key Responsibilities**:
- `BlockProposal`, `BlockHeader` encoding
- `QbindTransaction`, `TransferPayload` serialization
- Vote and timeout message formats
- Governance message types
- `WireEncode`/`WireDecode` traits

**Key Types**:
- `BlockProposal`, `BlockHeader`, `CertifiedBatchRef`
- `QbindTransaction`, `TransferPayloadV1`
- `VoteMessage`, `TimeoutMessage`
- `BatchCommitment`, `NULL_BATCH_COMMITMENT`

### 2.10 qbind-runtime

**Purpose**: Block-level execution logic and EVM integration (future).

**Key Responsibilities**:
- Block application orchestration
- Gas model implementation
- EVM state management (future expansion)

**Key Types**:
- `BlockExecutor`, `BlockExecutionResult`
- `GasModel`, `GasConfig`
- EVM types (for future smart contracts)

---

## 3. Critical Paths

### 3.1 Transaction Validation / Precheck Path

```
Transaction Received
        │
        ▼
┌───────────────────────────────────────┐
│ 1. Decode TransferPayloadV1           │
│    - Verify payload format (72 bytes) │
│    - Extract recipient, amount, gas   │
└───────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────┐
│ 2. ML-DSA-44 Signature Verify         │
│    - Domain tag: QBIND:<chain>:TX:v1  │
│    - Suite ID: 100 (SUITE_PQ_RESERVED_1)
└───────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────┐
│ 3. Nonce Check (per-sender ordering)  │
│    - Must be next expected nonce      │
│    - Limited nonce gap tolerance      │
└───────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────┐
│ 4. Gas/Fee Precheck                   │
│    - gas_limit > 0                    │
│    - max_fee_per_gas ≥ base_fee       │
│    - Balance covers max possible fee  │
└───────────────────────────────────────┘
        │
        ▼
    Admitted to Mempool
```

**Key Functions**:
- `InMemoryDagMempool::insert_local_txs()` — admission with DoS checks
- `qbind_ledger::auth::verify_transaction()` — signature verification
- `check_eviction_rate_limit()` — spam protection

### 3.2 Consensus Hot Path (Proposal → Vote → QC → Commit)

```
Leader: create_proposal()
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. PROPOSAL CONSTRUCTION                                         │
│    - Select certified DAG frontier (MainNet: coupling enforced)  │
│    - Compute batch_commitment (Merkle root of CertifiedBatchRef) │
│    - Attach parent QC, state_root, tx_root                       │
│    - Sign proposal with ML-DSA-44 consensus key                  │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼ (broadcast to validators)
        
Validator: on_proposal()
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. PROPOSAL VERIFICATION                                         │
│    - Verify proposer ML-DSA-44 signature                         │
│    - Check parent QC validity (2f+1 votes, view consistency)     │
│    - Verify batch_commitment matches certified batches (Enforce) │
│    - Check HotStuff safety: locked_qc rule                       │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. VOTE CASTING                                                  │
│    - Sign vote with ML-DSA-44 consensus key                      │
│    - Vote contains: block_hash, view, validator_id               │
│    - Send to leader (or all validators)                          │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼ (votes collected by leader/validators)

┌─────────────────────────────────────────────────────────────────┐
│ 4. QC AGGREGATION                                                │
│    - VoteAccumulator collects 2f+1 valid votes                   │
│    - Form QuorumCertificate with bitmap + signatures             │
│    - QC proves block is "certified" at this view                 │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. 3-CHAIN COMMIT                                                │
│    - Block B commits when:                                       │
│      • B has QC (child C exists with QC pointing to B)           │
│      • C has QC (grandchild D exists with QC pointing to C)      │
│    - Committed blocks are finalized and executed                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key Types**:
- `BlockProposal`, `VoteMessage`, `QuorumCertificate`
- `HotStuffStateEngine::on_proposal()`, `on_vote()`
- `VoteAccumulator::try_form_qc()`

### 3.3 DAG Batch/Certificate Path

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. BATCH FORMATION                                               │
│    - Validator V collects pending transactions                   │
│    - Forms QbindBatch: (author, round, txs, parent_refs)         │
│    - Signs batch with ML-DSA-44                                  │
│    - Assigns batch_id = SHA3-256(batch_content)                  │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼ (gossip to all validators)

┌─────────────────────────────────────────────────────────────────┐
│ 2. BATCH ACKNOWLEDGMENT                                          │
│    - Receiving validator verifies batch signature                │
│    - Stores batch locally                                        │
│    - Sends BatchAck: (batch_ref, validator_id, signature)        │
│    - Signing preimage: domain_tag || batch_ref || view_hint      │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼ (acks collected by batch creator)

┌─────────────────────────────────────────────────────────────────┐
│ 3. CERTIFICATE FORMATION                                         │
│    - Once 2f+1 BatchAcks received, form BatchCertificate         │
│    - Certificate proves data availability across quorum          │
│    - Batch is now "certified" and can be included in proposals   │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼

┌─────────────────────────────────────────────────────────────────┐
│ 4. DAG–CONSENSUS COUPLING (MainNet Enforce Mode)                 │
│    - Leader references only certified batches in proposal        │
│    - batch_commitment = Merkle root of CertifiedBatchRef list    │
│    - Validators verify certificates before voting                │
│    - Invariant I1: All committed txs belong to certified batches │
└─────────────────────────────────────────────────────────────────┘
```

**Key Types**:
- `QbindBatch`, `BatchRef`, `BatchId`
- `BatchAck`, `BatchCertificate`
- `DagCouplingMode::{Off, Warn, Enforce}`
- `CertifiedBatchRef`, `BatchCommitment`

### 3.4 Signer Path (ML-DSA-44 Keys and KEMTLS)

**Key Types and Roles**:

| Key Role | Algorithm | Purpose | MainNet Requirement |
|----------|-----------|---------|---------------------|
| Consensus Key | ML-DSA-44 | Sign proposals, votes, timeouts | HSM strongly recommended |
| P2P Identity Key | ML-KEM-768 | KEMTLS handshake | HSM recommended |
| Batch Signing Key | ML-DSA-44 | Sign DAG batches/acks | HSM strongly recommended |

**Signer Modes**:

```
┌─────────────────────────────────────────────────────────────────┐
│ SignerMode::EncryptedFs (Development/TestNet)                    │
│    - Keys stored in PBKDF2-encrypted local keystore              │
│    - Passphrase-protected; loaded at startup                     │
│    - Acceptable for TestNet with hardened host                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ SignerMode::RemoteSigner (Production Recommended)                │
│    - Node connects to separate signer host via KEMTLS            │
│    - Signing requests sent over secure channel                   │
│    - Key material never on consensus node                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ SignerMode::Hsm (Production - PKCS#11)                           │
│    - Keys held in Hardware Security Module                       │
│    - Signing via PKCS#11 API                                     │
│    - Private key never exported                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ SignerMode::Loopback (Testing Only)                              │
│    - In-memory keys, no persistence                              │
│    - FORBIDDEN on MainNet (startup validation rejects)           │
└─────────────────────────────────────────────────────────────────┘
```

**KEMTLS Flow**:
1. Initiator sends ML-KEM-768 public key
2. Responder encapsulates shared secret, returns ciphertext
3. Both derive session keys via HKDF
4. Channel encrypted with ChaCha20-Poly1305

### 3.5 Monetary Engine Integration Points

The `MonetaryEngine` in `qbind-ledger` integrates with execution at these points:

```
Block Commit
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. FEE COLLECTION                                                │
│    - Sum gas_used * effective_fee_per_gas for all txs            │
│    - Hybrid distribution: burn_ratio + proposer_ratio            │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. INFLATION CALCULATION (per-epoch)                             │
│    - R_target based on phase (Bootstrap/Transition/Mature)       │
│    - Fee offset: actual_inflation = R_target - α × fee_revenue   │
│    - EMA smoothing prevents abrupt changes                       │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. SEIGNIORAGE DISTRIBUTION                                      │
│    - Newly minted tokens distributed to validators               │
│    - Proportional to stake weight                                │
│    - Recorded in MonetaryState                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Key Types**:
- `MonetaryEngine`, `MonetaryState`, `MonetaryPhase`
- `FeeDistributionResult`, `HybridFeeConfig`

---

## 4. Testing and Harnesses

### 4.1 Key Test Harnesses

The codebase includes comprehensive test harnesses prefixed with `Txxx_*` that validate protocol behavior:

| Harness | Location | Purpose |
|---------|----------|---------|
| **T132** | `t132_three_node_mldsa44_consensus_tests.rs` | Three-node consensus with real ML-DSA-44 |
| **T138** | `t138_three_node_pqc_full_stack_tests.rs` | Full-stack PQC integration |
| **T146** | `t146_timeout_view_change_tests.rs` | Timeout handling and view changes |
| **T154** | `t154_devnet_tps_harness.rs` | DevNet TPS measurement |
| **T160** | `t160_devnet_cluster_harness.rs` | Multi-node DevNet cluster |
| **T166** | `t166_testnet_alpha_cluster_harness.rs` | TestNet Alpha cluster validation |
| **T192** | `t192_dag_coupling_invariant_tests.rs` | DAG–consensus coupling invariants |
| **T221** | `t221_dag_coupling_cluster_tests.rs` | Multi-node DAG coupling scenarios |
| **T222** | `t222_consensus_chaos_harness.rs` | Adversarial chaos testing |
| **T223** | `t223_stage_b_soak_harness.rs` | Stage B determinism soak |
| **T228** | `t228_slashing_infra_tests.rs` | Slashing infrastructure |
| **T234** | `t234_pqc_end_to_end_perf_tests.rs` | E2E PQC performance |
| **T236** | `t236_fee_market_adversarial_tests.rs` | Fee market adversarial testing |
| **T237** | `t237_mainnet_launch_profile_tests.rs` | MainNet launch gates |
| **T238** | `t238_multi_region_latency_harness.rs` | Multi-region latency simulation |

### 4.2 Harness Details

#### T222 — Consensus Chaos Harness

**What it validates**: Safety and liveness under adversarial network conditions.

**Scenarios**:
- `LeaderCrashAndRecover`: Verifies view-change recovery after leader failure
- `RepeatedViewChangesUnderMessageLoss`: Tests timeout behavior with message drops
- `ShortPartitionThenHeal`: Network partition recovery without chain divergence
- `MixedFaultsBurst`: Combined stress testing

**Run**: `cargo test -p qbind-node --test t222_consensus_chaos_harness`

---

#### T223 — Stage B Soak & Determinism Harness

**What it validates**: Stage B parallel execution produces identical results to sequential execution.

**Method**:
- Executes 100+ blocks with randomized transaction mixes
- Compares state roots, receipts, and gas between Stage B and sequential
- Verifies `stage_b_mismatch_total` metric remains zero

**Run**: `cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1`

---

#### T234 — PQC End-to-End Performance Harness

**What it validates**: Effective TPS and latency with real ML-DSA-44 signatures.

**Measurements**:
- Committed transactions per second
- End-to-end latency distribution (p50/p90/p99)
- Stage B vs sequential performance delta
- PQC signature throughput impact

**Profiles**: DevNet (Stage B off), Beta (Stage B on), MainNet (full coupling)

**Run**: `cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests`

---

#### T236 — Fee Market Adversarial Harness

**What it validates**: Fee market resilience against economic attacks.

**Scenarios**:
- Spam attacks with low-fee transactions
- Front-running attack patterns
- Priority churn attacks
- Balance manipulation attempts

**Invariants**: No negative balances, no double-spend, fee ordering respected.

**Run**: `cargo test -p qbind-node --test t236_fee_market_adversarial_tests -- --test-threads=1`

---

#### T237 — MainNet Launch Profile Tests

**What it validates**: All MainNet launch gates and invariants.

**Coverage**:
- `validate_mainnet_invariants()` subsystem coverage
- Genesis hash verification requirements
- Signer mode restrictions (loopback forbidden)
- P2P anti-eclipse enforcement
- DAG coupling mode enforcement

**Run**: `cargo test -p qbind-node --test t237_mainnet_launch_profile_tests`

---

#### T238 — Multi-Region Latency Harness

**What it validates**: Consensus behavior under realistic cross-region network conditions.

**Scenarios**:
- Uniform latency baseline
- Asymmetric latency (one slow region)
- High jitter variance
- Lossy network (packet drops)
- Mixed adversarial conditions

**Measurements**: Height divergence, commit latency, view-change counts, safety flags.

**Run**: `cargo test -p qbind-node --test t238_multi_region_latency_harness`

---

#### T192/T221 — DAG Coupling Tests

**What they validate**: DAG–consensus coupling invariants (I1–I5 from spec).

**T192** (Unit):
- `DagCouplingBlockCheckResult` behavior
- Mode transitions (Off/Warn/Enforce)
- Batch commitment verification

**T221** (Cluster):
- Multi-node DAG certificate formation
- Coupling enforcement across validators
- Metrics recording

**Run**: `cargo test -p qbind-node --test t192_dag_coupling_invariant_tests`

---

### 4.3 Running Tests

```bash
# Run all tests for a crate
cargo test -p qbind-node

# Run specific harness
cargo test -p qbind-node --test t223_stage_b_soak_harness

# Run with single thread (for determinism-sensitive tests)
cargo test -p qbind-node --test t236_fee_market_adversarial_tests -- --test-threads=1

# Run consensus tests
cargo test -p qbind-consensus

# Run crypto tests
cargo test -p qbind-crypto
```

---

## References

- [QBIND_WHITEPAPER.md](../whitepaper/QBIND_WHITEPAPER.md) — Protocol overview
- [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) — MainNet specification
- [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) — DAG architecture
- [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](../mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) — Coupling semantics
- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) — Signer architecture
- [QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md](../consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md) — Slashing model
- [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) — Economic model
- [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) — Upgrade process