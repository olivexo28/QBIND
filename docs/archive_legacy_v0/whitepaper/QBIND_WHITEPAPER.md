# QBIND Protocol Whitepaper

**Post-Quantum Secure Layer-1 Blockchain**

Version 1.0 — February 2026

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction & Background](#2-introduction--background)
3. [Design Goals](#3-design-goals)
4. [System Architecture](#4-system-architecture)
5. [Cryptography & Key Management](#5-cryptography--key-management)
6. [Monetary Policy & Fee Model](#6-monetary-policy--fee-model)
7. [Security Model](#7-security-model)
8. [Performance & Benchmarking](#8-performance--benchmarking)
9. [Governance & Upgrades](#9-governance--upgrades)
10. [Roadmap](#10-roadmap)
11. [Wallet & SDK Roadmap](#11-wallet--sdk-roadmap)
12. [Layer-2 and Zero-Knowledge Vision](#12-layer-2-and-zero-knowledge-vision)
13. [Launch Plan & External Audit](#13-launch-plan--external-audit)
14. [Conclusion](#14-conclusion)
15. [References](#15-references)

---

## 1. Abstract

Current blockchain systems rely overwhelmingly on classical cryptographic primitives—ECDSA, Ed25519, and related elliptic curve constructions—that are known to be vulnerable to cryptanalytic attacks by sufficiently powerful quantum computers. While large-scale, fault-tolerant quantum computers remain a future prospect, the "harvest now, decrypt later" threat model means that long-lived blockchain data and key material may be at risk today if adversaries are archiving encrypted traffic and signed transactions for future decryption.

QBIND addresses this threat by constructing a **post-quantum cryptography (PQC)-only Layer-1 blockchain** from the ground up. The protocol uses:

- **ML-DSA-44** (FIPS 204) for all digital signatures, including consensus votes, block proposals, transaction authorization, and governance approvals.
- **ML-KEM-768** (FIPS 203) for key encapsulation, enabling KEMTLS-style authenticated transport between validators.
- **No classical cryptographic primitives** in the consensus-critical path.

The architecture combines a **DAG-based mempool** for parallel data dissemination with a **HotStuff-style BFT consensus** protocol for total ordering and finality. This separation of data availability from ordering enables throughput scaling while maintaining strong safety guarantees.

QBIND MainNet v0 targets **≈300–500 sustained transactions per second** on commodity validator hardware, with sub-2-second median finality in a small validator set. The monetary policy is designed around a **security-budget-driven inflation model** that accounts for the higher computational costs of post-quantum cryptography, with fee-based funding progressively reducing reliance on inflation as network adoption grows.

The system is engineered for **institutional-grade operations**: HSM integration for validator key protection, comprehensive operational runbooks, Prometheus/Grafana observability, and a documented external security audit process prior to MainNet launch.

---

## 2. Introduction & Background

### 2.1 The Quantum Threat to Blockchain Security

Blockchain systems derive their security from cryptographic primitives. Consensus protocols assume that signatures cannot be forged; transaction authorization assumes that private keys cannot be derived from public keys; secure channels assume that key exchanges cannot be broken by eavesdroppers.

Classical cryptography meets these requirements under the assumption that certain mathematical problems—discrete logarithms on elliptic curves, integer factorization—are computationally intractable. However, Shor's algorithm demonstrates that a sufficiently powerful quantum computer can solve these problems in polynomial time, rendering ECDSA, Ed25519, RSA, and Diffie-Hellman key exchange fundamentally insecure against quantum adversaries.

The timeline for fault-tolerant quantum computers capable of breaking 256-bit elliptic curve cryptography is uncertain, but estimates range from 10 to 30 years. Critically, adversaries operating under a **harvest-now-decrypt-later** model can archive signed blockchain transactions and encrypted network traffic today, then decrypt or forge signatures once quantum capability is achieved. This makes migration urgent for systems designed to operate for decades.

### 2.2 Threat Model

QBIND's security model considers three adversary classes:

**Quantum Adversary**: An adversary with access to a large-scale quantum computer capable of running Shor's algorithm. This adversary can:
- Forge ECDSA and Ed25519 signatures
- Break Diffie-Hellman and ECDH key exchanges
- Derive private keys from public keys for classical schemes

**Network Adversary**: An adversary who can observe, delay, reorder, or selectively drop network messages between validators. This adversary cannot:
- Break cryptographic primitives
- Control more than f validators in a 3f+1 Byzantine fault tolerant system

**Misbehaving Validators**: Up to f out of 3f+1 validators may be Byzantine—they may deviate arbitrarily from the protocol, including sending conflicting messages, refusing to participate, or colluding with other Byzantine validators.

### 2.3 Design Philosophy

QBIND takes a **security-first** approach to post-quantum blockchain design:

1. **No hybrid schemes**: Rather than layering PQC on top of classical cryptography, QBIND uses PQC exclusively in the consensus-critical path. This eliminates the risk of classical cryptography becoming a single point of failure.

2. **Conservative algorithm selection**: QBIND uses NIST-standardized algorithms (ML-DSA-44, ML-KEM-768) rather than newer, less-analyzed constructions. While these algorithms have larger signatures and higher computational costs than classical alternatives, they have undergone extensive cryptanalytic review.

3. **Operational realism**: Post-quantum security is meaningless if validators cannot securely manage their keys. QBIND provides HSM integration, remote signer protocols, key rotation mechanisms, and comprehensive operational guidance.

4. **Crypto agility**: While the initial deployment uses ML-DSA-44 and ML-KEM-768, the architecture supports future migration to alternative PQC schemes if cryptanalytic advances weaken the current selections.

---

## 3. Design Goals

### 3.1 Pure Post-Quantum Security at Layer 1

All cryptographic operations in the QBIND consensus and validation path use post-quantum secure primitives:

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Transaction signatures | ML-DSA-44 | FIPS 204 |
| Consensus votes and proposals | ML-DSA-44 | FIPS 204 |
| DAG batch signing | ML-DSA-44 | FIPS 204 |
| Availability certificates | ML-DSA-44 | FIPS 204 |
| Validator-to-validator transport | KEMTLS (ML-KEM-768) | FIPS 203 |
| Governance approvals | ML-DSA-44 | FIPS 204 |

No classical signature schemes or key exchange mechanisms are used in the L1 protocol.

### 3.2 Strong Security, Correctness, and Auditability

QBIND prioritizes security and correctness over raw performance:

- **Safety over liveness**: The consensus protocol is designed to halt rather than produce conflicting blocks under adversarial conditions.
- **Deterministic execution**: All validators produce identical state given identical inputs, verified through extensive soak testing.
- **Formal specification**: Protocol rules are documented in sufficient detail for independent implementation and verification.
- **External audit**: MainNet launch is gated on completion of an external security audit by qualified third parties.

### 3.3 Operational Realism

QBIND is designed for institutional-grade operation:

- **HSM integration**: Production validators can use Hardware Security Modules via PKCS#11 for key protection.
- **Remote signer protocol**: Key material can be isolated on dedicated signing hosts, reducing the attack surface of consensus nodes.
- **Key rotation**: Validators can rotate keys with documented grace periods and state machine semantics.
- **Operational runbooks**: Detailed procedures for node bootstrapping, incident response, and upgrade coordination.
- **Observability**: Prometheus metrics and Grafana dashboards for all critical subsystems.

### 3.4 Crypto Agility and Suite Governance

The cryptographic suite is versioned and governed:

- **Suite ID**: All signatures include a suite identifier (currently `SUITE_PQ_RESERVED_1 = 100` for ML-DSA-44).
- **Domain separation**: Signing preimages include chain ID and message type tags to prevent cross-chain and cross-context replay.
- **Governance hooks**: Future protocol upgrades can introduce new cryptographic suites via the upgrade envelope mechanism.

### 3.5 Long-Term Scalability

While MainNet v0 prioritizes security and correctness, the architecture is designed for future throughput scaling:

- **DAG mempool**: Separates data dissemination from ordering, enabling parallel batch creation.
- **Stage B parallel execution**: Conflict-graph-based parallel transaction execution is implemented and available.
- **Availability certificates**: Ensure data availability before consensus ordering, enabling efficient reconstruction.

---

## 4. System Architecture

### 4.1 High-Level Node Architecture

A QBIND validator node consists of several major components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         QBIND Validator Node                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                        P2P Network Layer                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │   KEMTLS    │  │  Discovery  │  │  Anti-Eclipse       │   │   │
│  │  │  Transport  │  │   (T205-7)  │  │  Protections (T231) │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     DAG Mempool Layer                         │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │   Batches   │  │ Certificates│  │   DoS Protections   │   │   │
│  │  │  & Acks     │  │   (2f+1)    │  │   (T218-220)        │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Consensus Layer (HotStuff BFT)              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │  Proposals  │  │    Votes    │  │  Quorum Certificates│   │   │
│  │  │  (Leader)   │  │  (3-chain)  │  │       (QC)          │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                      Execution Layer                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │  VM v0      │  │  Stage A/B  │  │   State (RocksDB)   │   │   │
│  │  │  (Transfer) │  │  Parallel   │  │    + Snapshots      │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     Signer Subsystem                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │EncryptedFs  │  │   Remote    │  │   HSM/PKCS#11       │   │   │
│  │  │  Keystore   │  │   Signer    │  │    (T211)           │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Execution & VM

QBIND MainNet v0 implements a **transfer-only VM (VM v0)**:

- **Transaction type**: Transfer of value between accounts
- **Account state**: Nonce and balance per account
- **Payload format**: `TransferPayloadV1` (72 bytes)
- **Gas enforcement**: Mandatory for MainNet

#### 4.2.1 Stage A/B Parallel Execution

Execution supports two parallelism modes:

**Stage A (Sender-Partitioned)**: Transactions from different senders can execute in parallel, as they access disjoint account state.

**Stage B (Conflict-Graph)**: A finer-grained approach that analyzes read/write sets and builds a conflict graph to identify maximal parallelism:

1. Extract read/write sets for each transaction
2. Build conflict graph based on account overlap
3. Generate parallel schedule via topological layering
4. Execute layers in parallel using work-stealing
5. Merge results deterministically

Stage B is implemented and enabled by default for MainNet v0. Determinism is verified via the T223 soak harness, which confirms that Stage B execution produces identical state to sequential execution over 100+ block randomized workloads.

### 4.3 DAG Mempool & Data Availability

The DAG mempool architecture separates data dissemination from consensus ordering:

#### 4.3.1 Transaction Flow

1. **Submission**: Transactions are submitted to any validator and added to the local mempool after signature verification.

2. **Batch Formation**: Each validator periodically forms batches of pending transactions. Batches are signed by the creating validator using ML-DSA-44.

3. **Dissemination**: Batches are propagated to all validators via the P2P network.

4. **Acknowledgment**: Validators receiving a batch verify its contents and send a signed `BatchAck` to the creator.

5. **Certificate Formation**: Once 2f+1 acknowledgments are collected, a `BatchCertificate` is formed, proving data availability.

6. **Consensus**: The HotStuff leader includes certified batch references (the "DAG frontier") in its block proposal.

#### 4.3.2 DAG–Consensus Coupling

The DAG and consensus layers are coupled via the `batch_commitment` field in block headers:

- **Proposer obligation**: Leaders must reference only certified DAG batches in proposals.
- **Validator enforcement**: Before voting, validators verify that the `batch_commitment` corresponds to valid certificates.
- **Coupling mode**: `DagCouplingMode::Enforce` is required for MainNet operation.

This coupling ensures that committed blocks only reference data that is provably available, preventing data withholding attacks.

### 4.4 Consensus (HotStuff BFT)

QBIND uses a HotStuff-style BFT consensus protocol with the following characteristics:

- **Safety**: No two honest validators commit different blocks at the same height.
- **Liveness**: Given eventual network synchrony and at least 2f+1 honest validators, the chain progresses.
- **Commit rule**: 3-chain commit—a block is finalized when it has a direct child and grandchild, each with quorum certificates.

#### 4.4.1 Consensus Roles

| Role | Responsibility |
|------|----------------|
| **Leader** | Proposes blocks containing certified DAG batches |
| **Voter** | Verifies proposals and sends signed votes |
| **Pacemaker** | Manages view transitions and timeout handling |

#### 4.4.2 View Change

When the current leader fails to produce a valid proposal within the timeout window:

1. Validators broadcast timeout messages for the current view
2. Once 2f+1 timeouts are collected, validators advance to the next view
3. The next leader is determined by a deterministic rotation schedule

### 4.5 Networking & P2P

#### 4.5.1 KEMTLS Transport

All validator-to-validator communication uses KEMTLS, a post-quantum authenticated key exchange:

- **Key encapsulation**: ML-KEM-768 provides quantum-resistant key exchange
- **Session keys**: Derived via HKDF from the encapsulated shared secret
- **Authentication**: Validators are authenticated by their registered P2P identity keys

#### 4.5.2 Dynamic Discovery

Validators discover peers through:

- **Bootstrap peers**: Statically configured initial peer list
- **Peer exchange**: Active validators share their known peer lists
- **Outbound targeting**: Validators maintain a target number of outbound connections (default: 4+)

#### 4.5.3 Anti-Eclipse Protections

Eclipse attacks attempt to isolate a validator by surrounding it with adversary-controlled peers. QBIND implements countermeasures:

| Protection | Mechanism |
|------------|-----------|
| **IP prefix limits** | Maximum peers per /24 IPv4 prefix |
| **ASN diversity** | Minimum distinct autonomous systems |
| **Outbound minimums** | Validators must maintain minimum outbound connections |
| **Diversity enforcement** | `P2pAntiEclipseConfig` with `enforce = true` for MainNet |

#### 4.5.4 Liveness Detection

The P2P layer includes heartbeat-based liveness detection:

- Periodic heartbeat messages between connected peers
- Liveness scoring based on heartbeat response times
- Automatic disconnection and replacement of unresponsive peers

---

## 5. Cryptography & Key Management

### 5.1 PQC Primitives

#### 5.1.1 ML-DSA-44 (Signatures)

QBIND uses **ML-DSA-44** (FIPS 204), a lattice-based digital signature algorithm from the NIST Post-Quantum Cryptography standardization process:

| Property | Value |
|----------|-------|
| Security level | NIST Level 2 (equivalent to AES-128) |
| Public key size | 1,312 bytes |
| Signature size | 2,420 bytes |
| Sign time | ~10 μs (reference, varies by implementation) |
| Verify time | ~5 μs (reference, varies by implementation) |

The larger signature sizes and higher verification costs compared to classical schemes (Ed25519: 64-byte signatures, ~1 μs verify) are a key design consideration. The monetary policy and slashing model account for this overhead.

#### 5.1.2 ML-KEM-768 (Key Encapsulation)

For key exchange in the KEMTLS transport, QBIND uses **ML-KEM-768** (FIPS 203):

| Property | Value |
|----------|-------|
| Security level | NIST Level 3 (equivalent to AES-192) |
| Public key size | 1,184 bytes |
| Ciphertext size | 1,088 bytes |
| Shared secret | 32 bytes |

### 5.2 Key Roles

Validators manage multiple key types:

| Key Role | Purpose | Algorithm | HSM Recommended |
|----------|---------|-----------|-----------------|
| **Consensus Key** | Sign proposals, votes, timeouts | ML-DSA-44 | Strongly |
| **P2P Identity Key** | KEMTLS handshake authentication | ML-KEM-768 | Yes |
| **Batch Signing Key** | Sign DAG batches and acks | ML-DSA-44 | Strongly |

Domain separation ensures signatures cannot be replayed across contexts:

```
Proposals: QBIND:<SCOPE>:PROPOSAL:v1 || chain_id || view || ...
Votes:     QBIND:<SCOPE>:VOTE:v1 || chain_id || view || ...
Timeouts:  QBIND:<SCOPE>:TIMEOUT:v1 || chain_id || view || ...
BatchAcks: QBIND:<SCOPE>:BATCH_ACK:v1 || batch_ref || ...
```

### 5.3 Signer Modes & Backends

QBIND supports multiple signer configurations:

| Mode | Key Location | MainNet Allowed | Security Level |
|------|--------------|-----------------|----------------|
| **LoopbackTesting** | In-memory | **No** | Low (testing only) |
| **EncryptedFsV1** | Encrypted file | Yes (with conditions) | Medium-High |
| **RemoteSigner** | Separate process/host | Yes | High |
| **HsmPkcs11** | HSM device | Yes (recommended) | Very High |

MainNet invariant validation rejects `LoopbackTesting` mode at startup.

### 5.4 HSM Integration

For production validators, QBIND provides HSM integration via PKCS#11:

- **Key generation**: Keys can be generated and stored in the HSM
- **Signing**: Private keys never leave the HSM; signing requests are sent via PKCS#11
- **KEMTLS integration**: Session key derivation can utilize HSM capabilities
- **Failure handling**: `SignerFailureMode::ExitOnFailure` ensures the node halts rather than proceeding without proper signing capability

Redundancy is achieved through infrastructure-level patterns:
- **Active/Passive Signer Hosts**: One consensus node with two signer boxes
- **HSM Clustering**: Vendor-provided HA configurations (e.g., AWS CloudHSM clusters)

### 5.5 Key Rotation

Validators can rotate keys through a documented process:

1. **Generate new key pair** in keystore/HSM
2. **Register new public key** via governance transaction
3. **Grace period**: Both old and new keys are valid during the transition window
4. **Transition complete**: Old key is deregistered and can be destroyed

Key rotation is critical for responding to potential key compromise without losing validator status.

---

## 6. Monetary Policy & Fee Model

### 6.1 Design Principles

The QBIND monetary policy is designed around these core principles:

1. **Security-budget-driven inflation**: Inflation exists to fund network security. The target inflation rate is computed to ensure validators receive adequate compensation to cover operational costs and provide economic return on staked capital.

2. **PQC cost acknowledgment**: ML-DSA-44 verification costs approximately 5× more CPU than classical EdDSA. The monetary model accounts for this through explicit PQC premium factors.

3. **Progressive fee-funding**: As network adoption grows, transaction fees should increasingly cover the security budget, reducing reliance on inflation.

4. **Smooth transitions**: No abrupt changes to monetary parameters. Phase transitions and parameter adjustments use time-based gates and EMA smoothing.

### 6.2 Three-Phase Model

The monetary policy operates across three phases:

#### Phase 1: Bootstrap (Years 0–3)

- **Purpose**: Establish network security during initial low-usage period
- **Inflation target**: Higher (~8–9% annual, PQC-adjusted)
- **Fee offset**: Limited (to prevent instability from volatile early fees)
- **Rationale**: Early network has uncertain fee revenue; higher inflation ensures adequate security budget regardless of adoption

#### Phase 2: Transition (Years 3–7)

- **Purpose**: Gradually shift from inflation-funded to fee-funded security
- **Inflation target**: Moderate (~6–7% annual, PQC-adjusted)
- **Fee offset**: Full sensitivity
- **Rationale**: Established usage patterns allow inflation reduction as fees grow

#### Phase 3: Mature (Year 7+)

- **Purpose**: Long-term sustainable operation
- **Inflation target**: Lower (~4–5% annual, PQC-adjusted)
- **Inflation floor**: Active (1–2% annual minimum)
- **Rationale**: Mature network is primarily fee-funded; small floor ensures ongoing staking incentives

### 6.3 PQC-Adjusted Inflation Target

The inflation target accounts for PQC computational overhead:

```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

Where:
- `β_compute ≈ 0.20–0.35` (ML-DSA-44 is ~5–10× classical verification cost)
- `β_bandwidth ≈ 0.10–0.20` (larger signatures: 2,420 bytes vs 64 bytes)
- `β_storage ≈ 0.05–0.10` (larger public keys: 1,312 bytes vs 32 bytes)

Example: A classical 5% target becomes 7.75% PQC-adjusted.

### 6.4 Fee Model

QBIND MainNet v0 implements a **priority-fee model** with hybrid distribution:

| Component | Mechanism |
|-----------|-----------|
| **Priority ordering** | Higher `max_fee_per_gas` transactions are prioritized |
| **Fee split** | 50% burned, 50% to block proposer |
| **Gas enforcement** | Mandatory for MainNet |

#### 6.4.1 EMA-Based Fee Smoothing

To prevent inflation volatility from short-term fee fluctuations, fee input to the inflation formula is smoothed using an exponential moving average:

```
EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}
```

Phase-specific smoothing factors:
- Bootstrap: λ ≈ 0.05–0.10 (faster response)
- Transition: λ ≈ 0.02–0.05 (balanced)
- Mature: λ ≈ 0.01–0.02 (maximum stability)

#### 6.4.2 Rate-of-Change Limiters

Per-epoch rate limiters prevent sudden inflation changes:

- Maximum inflation increase: Capped per epoch
- Maximum inflation decrease: Capped per epoch
- Prevents manipulation via short-term fee manipulation

### 6.5 Seigniorage Distribution

New token issuance is distributed according to network needs:

| Recipient | Allocation | Purpose |
|-----------|------------|---------|
| **Validators** | Primary | Reward for consensus participation |
| **Treasury** | Secondary | Protocol development and ecosystem |
| **Insurance** | Reserve | Slashing victim compensation |

---

## 7. Security Model

### 7.1 Consensus Safety and Liveness

The HotStuff BFT consensus provides:

**Safety** (assuming ≤f Byzantine validators in 3f+1 system):
- No two honest validators commit different blocks at the same height
- Verified via the 3-chain commit rule with quorum certificates

**Liveness** (assuming eventual synchrony and >2f honest validators):
- The chain makes progress
- View-change mechanism handles leader failures

### 7.2 DAG Mempool DoS Protections

The DAG mempool implements multiple layers of denial-of-service protection:

| Protection | Mechanism | Reference |
|------------|-----------|-----------|
| **Per-sender quotas** | Maximum pending transactions per sender | T218 |
| **Per-sender byte limits** | Maximum pending bytes per sender | T218 |
| **Batch size limits** | Maximum transactions per DAG batch | T218 |
| **Eviction rate limiting** | Maximum evictions per time interval | T219/T220 |
| **Fee-priority eviction** | Low-fee transactions evicted first under pressure | T169 |

Adversarial testing (T236) verified these protections maintain honest sender inclusion rates above 30% even under aggressive spam attacks.

### 7.3 P2P Defenses

| Threat | Defense |
|--------|---------|
| **Eclipse attacks** | IP prefix limits, ASN diversity requirements, minimum outbound connections |
| **Sybil attacks** | Stake-weighted peer selection (future), bootstrap peer diversity |
| **Network partitions** | Multi-region awareness, heartbeat-based liveness detection |
| **Transport attacks** | KEMTLS encryption, authenticated channels |

### 7.4 PQC-Specific Slashing Offenses

QBIND defines a slashing model addressing PQC-specific misbehavior incentives:

| ID | Offense | Severity | Slash Range |
|----|---------|----------|-------------|
| **O1** | Classical double-signing | Critical | 5–10% |
| **O2** | Invalid proposal signature | High | 5% |
| **O3a** | Single lazy vote | Medium | 0–0.5% (warning) |
| **O3b** | Repeated lazy votes | High | 1–3% |
| **O4** | Invalid DAG certificate propagation | High | 5–10% |
| **O5** | DAG/consensus coupling violation | Medium-High | 1–5% |

**Economic rationale**: ML-DSA-44 verification costs create incentives for validators to skip verification ("lazy verification"). The slashing penalties are calibrated such that:

```
Expected slashing cost > Expected savings from lazy verification
```

For MainNet v0, slashing operates in `RecordOnly` mode, logging evidence without executing penalties. `EnforceCritical` mode (O1, O2, O4 enforcement) can be activated via governance.

### 7.5 External Security Audit

MainNet launch is gated on completion of an external security audit. The audit scope includes:

- Consensus safety and liveness under Byzantine faults
- PQC cryptographic implementation correctness
- P2P anti-eclipse and transport security
- DAG mempool DoS resistance
- Slashing evidence model and penalty engine
- Key management and HSM integration
- Genesis configuration and upgrade envelope verification

The audit RFP ([QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md)) provides detailed scope and deliverable requirements.

---

## 8. Performance & Benchmarking

### 8.1 TPS Claims and Methodology

**QBIND MainNet v0 targets ≈300–500 sustained transactions per second** on commodity validator hardware, with sub-2-second median finality in a small validator set.

This target is based on:

1. **PQC cost microbenchmarks (T198)**: Individual ML-DSA-44 sign (~10 μs) and verify (~5 μs) operations.

2. **Stage B soak harness (T223)**: Verified determinism of parallel execution over 100+ block randomized workloads.

3. **E2E performance harness (T234)**: End-to-end TPS and latency measurement with real ML-DSA-44 signatures in a 3–4 validator cluster.

4. **Multi-region latency harness (T238)**: Consensus behavior under simulated cross-region latency, jitter, and packet loss.

### 8.2 Reference Performance Characteristics

| Configuration | Expected TPS Range | Notes |
|---------------|-------------------|-------|
| 3 validators, local cluster, Stage B off | 100–300 TPS | DevNet reference |
| 4 validators, local cluster, Stage B on | 300–800 TPS | Beta reference |
| 7 validators, WAN-like latency, Stage B on | 100–400 TPS | Realistic MainNet estimate |

**These are reference ranges, not guarantees.** Actual throughput depends on:
- Validator count (more validators = more signature verification per block)
- Hardware specifications (CPU cores, NVMe storage, network bandwidth)
- Geographic distribution (cross-region latency)
- Transaction mix (computational intensity)

### 8.3 Latency Expectations

For typical configurations:

| Percentile | Expected Latency |
|------------|-----------------|
| p50 (median) | 100–500 ms |
| p90 | 200–1,000 ms |
| p99 | 500–5,000 ms |

Higher latencies may occur under heavy load, view changes, or network partitions.

### 8.4 Future Throughput Scaling

The architecture supports scaling into the **low-thousands TPS range** as a future optimization target. This requires:

- Additional benchmarking with larger validator sets
- Network optimization for cross-region deployments
- Potential DAG mempool enhancements
- Continued Stage B optimization

**Final public TPS numbers will be refined from Public TestNet Beta benchmarks** prior to MainNet launch.

### 8.5 Multi-Region Testing

The T238.5 multi-region dress rehearsal defines how to validate real-infrastructure performance against synthetic baselines:

1. Run T234 harness to establish baseline TPS and latency
2. Measure actual network characteristics between regions
3. Run tests on real cloud infrastructure
4. Compare results—TPS and latency should be within 0.5–2× of synthetic baseline

---

## 9. Governance & Upgrades

### 9.1 Council-Based Governance (MainNet v0)

MainNet v0 uses **off-chain governance with cryptographic accountability**:

| Aspect | Approach |
|--------|----------|
| **Decision making** | Off-chain deliberation via governance forum |
| **Approval mechanism** | M-of-N PQC multi-signature by Protocol Council |
| **Enforcement** | Social consensus + operator compliance |
| **Audit trail** | Signed documents published to governance repository |

This design provides strong accountability while allowing rapid iteration on governance processes before codifying them on-chain.

### 9.2 Protocol Council

The Protocol Council governs MainNet v0 upgrades:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Total members (N) | 7 | Odd number prevents ties |
| Approval threshold (M) | 5 | Supermajority (≥70%) required |
| Emergency threshold | 4 | Lower threshold for security patches |
| Diversity requirement | Min 3 organizations | No single entity controls majority |

Council members hold ML-DSA-44 signing keys and must be reachable with 48-hour response SLA for emergency votes.

### 9.3 Upgrade Classes

| Class | Description | Examples | Process |
|-------|-------------|----------|---------|
| **A** | Non-consensus changes | CLI improvements, documentation | Maintainer approval |
| **B** | Consensus-compatible | Performance optimizations | Council approval, rolling deployment |
| **C** | Hard fork / protocol changes | Consensus rules, monetary policy | Council approval, coordinated activation |

### 9.4 Upgrade Envelope Format

Council approvals are recorded in signed **Upgrade Envelopes**:

```json
{
  "envelope_version": "1.0",
  "envelope_id": "T225-2026-02-08-001",
  "protocol_version": "0.1.0",
  "network_environment": "mainnet",
  "class": "c_hard_fork",
  "activation_height": 1000000,
  "binary_hashes": {
    "linux-x86_64": "sha3-256:...",
    "linux-aarch64": "sha3-256:..."
  },
  "council_approvals": [
    {
      "member_id": "council-1",
      "public_key": "<ml-dsa-44-pubkey>",
      "signature": "<ml-dsa-44-signature>",
      "timestamp": "2026-02-08T10:00:00Z"
    }
  ]
}
```

Operators verify envelopes using the `qbind-envelope` CLI tool before applying upgrades.

### 9.5 Release Manifest and Reproducible Builds

Each release includes a **Release Manifest** pinning:

- Git commit and tag
- Genesis file hash
- Binary hashes (SHA3-256)
- Container image digests
- Build configuration (Rust version, Cargo profile)
- Software bill of materials (SBOM)

This enables operators to verify they are running authentic, unmodified release artifacts.

### 9.6 Future On-Chain Governance

The v0 off-chain model is designed for future migration to on-chain governance:

| Phase | Governance Scope | Timeline |
|-------|-----------------|----------|
| v0 | Off-chain council + multi-sig envelopes | Current |
| v0.x | On-chain upgrade signaling | 6–12 months |
| v1.0 | On-chain parameter governance | 12–18 months |
| v1.x | Full on-chain governance with voting | 18–24 months |

---

## 10. Roadmap

### Phase 0: Research & DevNet (Complete)

- Core PQC cryptographic primitives implemented (ML-DSA-44, ML-KEM-768)
- HotStuff BFT consensus with PQC signatures
- DAG mempool architecture and basic availability certificates
- Domain separation and chain-aware signing
- Local cluster testing harness

### Phase 1: Public TestNet Alpha (Correctness-First)

- Minimal VM (transfer-only) with gas enforcement
- State persistence (RocksDB)
- P2P transport with KEMTLS
- DAG–consensus coupling
- Initial security audit preparation

### Phase 2: Public TestNet Beta (Performance + Operations)

- Stage B parallel execution enabled
- HSM/PKCS#11 integration
- Remote signer protocol
- Dynamic peer discovery and anti-eclipse protections
- Multi-region testing infrastructure
- Operational runbooks and observability stack
- Fee market adversarial testing
- Monetary engine integration

### Phase 3: MainNet v0 (Security-First Launch)

- External security audit completed
- Genesis configuration finalized
- Release manifest and reproducible builds
- Council governance operational
- Launch gates verified:
  - All critical audit findings remediated
  - Multi-region dress rehearsal passed
  - Chaos harness tests passed
  - Documentation complete

**MainNet v0 Target**: ≈300–500 sustained TPS on commodity hardware, sub-2s median finality

### Phase 4: v0.x Hardening and Performance Tuning

- Slashing enforcement activation (graduated rollout)
- Performance optimization toward low-thousands TPS
- On-chain upgrade signaling
- Stake-weighted DAG quotas (enhanced DoS protection)
- State growth management refinements

### Phase 5: L2 and zk-Based Cross-Chain Hub + On-Chain Governance

- Layer-2 research and development
- zk-based validity proofs for L1 state verification
- Cross-chain bridge architecture
- Full on-chain governance module
- Smart contract support (VM v1)

---

## 11. Wallet & SDK Roadmap

### 11.1 Official QBIND Wallet

Before Layer-2 or cross-chain bridging, QBIND will release an **official wallet application** (reference client):

| Feature | Description |
|---------|-------------|
| **Account management** | ML-DSA-44 key generation and secure storage |
| **Transaction signing** | Native PQC transaction construction and signing |
| **Balance and history** | Query account state via RPC |
| **Staking interface** | Delegate to validators, view rewards |
| **Multi-platform** | Desktop (Linux, macOS, Windows) and mobile (iOS, Android) |

The wallet will be open-source to enable community audit and derivative implementations.

### 11.2 SDK Roadmap

SDKs enable developers to integrate QBIND into their applications:

#### 11.2.1 Rust SDK (Primary)

The Rust SDK provides native integration with the QBIND protocol:

- Transaction construction and signing
- ML-DSA-44 key generation and management
- RPC client for node communication
- Validator and delegator operations
- Full type safety and compile-time guarantees

#### 11.2.2 TypeScript/JavaScript SDK

For web and Node.js applications:

- Browser-compatible key management (WebCrypto fallback where available)
- Transaction construction and signing
- JSON-RPC client with TypeScript types
- Support for standard user flows

#### 11.2.3 Future SDKs

Additional language bindings are planned based on ecosystem demand:

- Python (for scripting and data analysis)
- Go (for infrastructure tooling)
- Mobile-native (Swift, Kotlin)

### 11.3 SDK Timeline

Wallet and SDK development is prioritized **before Layer-2**:

| Phase | Deliverable |
|-------|-------------|
| TestNet Beta | Rust SDK alpha, basic wallet prototype |
| MainNet v0 | Rust SDK stable, TypeScript SDK beta, wallet v1.0 |
| v0.x | TypeScript SDK stable, additional language SDKs |

---

## 12. Layer-2 and Zero-Knowledge Vision

### 12.1 Context and Timeline

Layer-2 and cross-chain bridging are **future roadmap items**, not part of MainNet v0. This section describes the long-term vision, not immediate deliverables.

### 12.2 zk-Based L2 Architecture

The QBIND Layer-2 vision centers on **zero-knowledge validity proofs**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         QBIND L2 Vision                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    External Chains                            │   │
│  │         (EVM, other ecosystems)                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                    Validity Proofs (zk)                             │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    QBIND L2 Hub                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │   │
│  │  │  Rollup     │  │   Bridge    │  │   Cross-Chain       │   │   │
│  │  │  Execution  │  │   Contracts │  │   State Proofs      │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                    Validity Proofs (zk)                             │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    QBIND L1 (PQC-Only)                        │   │
│  │                    ML-DSA-44 + ML-KEM-768                     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### 12.2.1 Rollup-Style Scalability

The L2 hub would operate as a validity rollup:

- Transactions execute on L2 with faster finality and lower costs
- State transitions are batched and proven via zk proofs
- Validity proofs are submitted to QBIND L1 for final settlement
- L1 verifies proofs without re-executing transactions

#### 12.2.2 Cross-Chain Bridging

zk proofs enable trust-minimized bridges:

- External chain state is proven via validity proofs
- QBIND L2 verifies proofs and updates bridged asset balances
- No trusted intermediaries or multi-sig committees
- Bridge security derives from cryptographic proofs, not economic incentives

### 12.3 Security Model Transparency

**Critical distinction**: QBIND L1 is PQC-only, but current practical zk systems rely on classical cryptographic assumptions.

| Component | Cryptographic Assumptions |
|-----------|--------------------------|
| **QBIND L1** | Post-quantum secure (ML-DSA-44, ML-KEM-768) |
| **L2/Bridge (initial)** | Classical (elliptic curve pairings, discrete log) |

**Implications**:

1. L2 and bridge security **does not inherit** the post-quantum guarantees of L1.
2. A quantum adversary could potentially compromise L2 zk proofs even while L1 remains secure.
3. Assets bridged to/from L2 are subject to the security of the weakest link.

This is an explicit security-honesty statement. We do not claim L2 is post-quantum secure.

### 12.4 Path to Post-Quantum zk

The long-term goal is PQC-compatible zero-knowledge proofs:

| Approach | Status | Notes |
|----------|--------|-------|
| **Hash-based SNARKs** | Research | Rely only on hash function security |
| **Lattice-based proofs** | Research | Aligned with QBIND PQC assumptions |
| **Symmetric-key MPC** | Research | Potentially quantum-resistant |

QBIND will monitor advances in PQC-compatible zk constructions and update the L2 architecture as practical systems become available. This is a **research direction**, not a near-term commitment.

### 12.5 L2/zk Roadmap Summary

| Phase | Milestone |
|-------|-----------|
| MainNet v0 | L1 only; no L2 or bridges |
| v0.x | L2 research; bridge architecture design |
| v1.x | L2 testnet with classical zk (security caveat applies) |
| v2+ | PQC-compatible zk if practical constructions are available |

---

## 13. Launch Plan & External Audit

### 13.1 MainNet Launch Gates

MainNet v0 launch requires satisfying multiple gates:

#### 13.1.1 Security Audit

- External security audit completed by qualified third party
- All **Critical** findings remediated
- All **High** findings remediated or explicitly accepted with documented rationale
- Final audit report published (redacted if necessary for security)

#### 13.1.2 Operational Readiness

- Multi-region dress rehearsal (T238.5) passed:
  - Consensus liveness under realistic latency
  - Performance within 0.5–2× of synthetic baseline
  - No consensus forks or safety violations
- Chaos harness (T222) tests passed
- Stage B soak harness (T223) tests passed
- Operational runbook and alerting verified

#### 13.1.3 Governance Readiness

- Protocol Council formed and keys registered
- Upgrade envelope mechanism tested
- Emergency response procedures documented

#### 13.1.4 Genesis and Release

- Genesis configuration finalized and hash published
- Release manifest with binary hashes published
- Reproducible build instructions verified

### 13.2 External Audit Scope

The external audit RFP ([QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md)) covers:

| Area | Focus |
|------|-------|
| **Consensus & DAG** | HotStuff safety, DAG–consensus coupling, view-change liveness |
| **Execution & VM** | Transfer semantics, Stage B determinism, state root computation |
| **PQC Cryptography** | ML-DSA-44/ML-KEM-768 usage, KEMTLS implementation |
| **Networking / P2P** | Anti-eclipse protections, transport security |
| **Mempool & DAG** | DoS resistance, eviction logic |
| **Slashing** | Evidence model, penalty engine |
| **Keys & HSM** | Signer modes, HSM integration, key rotation |
| **Monetary Engine** | Phase transitions, EMA smoothing, seigniorage |
| **Genesis & Governance** | Config validation, upgrade envelope verification |

### 13.3 Launch Timeline

The launch process follows a structured timeline:

1. **Feature freeze**: Code stabilization for audit
2. **Active audit**: 6–10 weeks of security review
3. **Remediation**: Address audit findings
4. **Retest**: Verify critical/high fixes
5. **Dress rehearsal**: Multi-region operational validation
6. **Genesis ceremony**: Finalize and publish genesis
7. **Launch announcement**: Public launch date
8. **MainNet activation**: Network goes live

---

## 14. Conclusion

QBIND addresses the existential threat that quantum computing poses to blockchain security by building a **post-quantum cryptography-only Layer-1** from the ground up.

### 14.1 Key Differentiators

**Pure PQC at L1**: Unlike hybrid approaches that layer PQC over classical cryptography, QBIND uses ML-DSA-44 and ML-KEM-768 exclusively in the consensus-critical path. There is no classical cryptographic single point of failure.

**Security-First Engineering**: The protocol prioritizes safety and correctness over raw performance. Determinism is verified through extensive soak testing. External audit is required before MainNet launch.

**Institutional-Grade Operations**: HSM integration, remote signer protocols, key rotation mechanisms, and comprehensive operational runbooks make QBIND suitable for institutional validators.

**Realistic Performance**: MainNet v0 targets **≈300–500 sustained TPS** with sub-2-second median finality—sufficient for meaningful economic activity while maintaining full post-quantum security.

**Transparent Roadmap**: Layer-2 and zk integration are clearly labeled as future work, with explicit acknowledgment that early zk systems will rely on classical assumptions.

### 14.2 Near-Term Path

1. **Public TestNet Beta**: Operational stress testing and community participation
2. **External Security Audit**: Third-party verification of protocol security
3. **MainNet v0 Launch**: Security-first production deployment

### 14.3 Long-Term Direction

1. **Performance scaling** toward low-thousands TPS
2. **On-chain governance** evolution
3. **Layer-2 hub** with zk-based validity proofs
4. **Cross-chain bridges** with trust-minimized verification
5. **Ecosystem growth** via wallet and SDK support

QBIND is not a theoretical exercise but a practical implementation backed by working code, documented designs, and rigorous testing. The post-quantum future of blockchain infrastructure starts with a secure foundation—and QBIND provides that foundation.

---

## 15. References

### 15.1 QBIND Documentation

| Document | Path |
|----------|------|
| MainNet v0 Specification | `docs/mainnet/QBIND_MAINNET_V0_SPEC.md` |
| MainNet Audit Skeleton | `docs/mainnet/QBIND_MAINNET_AUDIT_SKELETON.md` |
| DevNet v0 Freeze Capsule | `docs/devnet/QBIND_DEVNET_V0_FREEZE.md` |
| Monetary Policy Design | `docs/econ/QBIND_MONETARY_POLICY_DESIGN.md` |
| Fee Market Adversarial Analysis | `docs/econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md` |
| Slashing & PQC Offenses Design | `docs/consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md` |
| Key Management Design | `docs/keys/QBIND_KEY_MANAGEMENT_DESIGN.md` |
| Governance & Upgrades Design | `docs/gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md` |
| MainNet Runbook | `docs/ops/QBIND_MAINNET_RUNBOOK.md` |
| Multi-Region Dress Rehearsal | `docs/ops/QBIND_MULTI_REGION_DRESS_REHEARSAL.md` |
| Performance & TPS Design | `docs/devnet/QBIND_PERF_AND_TPS_DESIGN.md` |
| DAG Mempool Design | `docs/devnet/QBIND_DAG_MEMPOOL_DESIGN.md` |
| Genesis & Launch Design | `docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` |
| External Security Audit RFP | `docs/audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md` |
| Release Manifest | `docs/release/QBIND_MAINNET_V0_RELEASE_MANIFEST.md` |

### 15.2 Standards

| Standard | Description |
|----------|-------------|
| FIPS 204 | ML-DSA (Module-Lattice-Based Digital Signature Algorithm) |
| FIPS 203 | ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) |
| NIST PQC | Post-Quantum Cryptography Standardization |

### 15.3 Test Harnesses

| Harness | Reference | Purpose |
|---------|-----------|---------|
| T221 | `t221_dag_coupling_cluster_tests.rs` | DAG–consensus coupling |
| T222 | `t222_consensus_chaos_harness.rs` | Consensus fault injection |
| T223 | `t223_stage_b_soak_harness.rs` | Stage B determinism |
| T234 | `t234_pqc_end_to_end_perf_tests.rs` | PQC E2E performance |
| T236 | `t236_fee_market_adversarial_tests.rs` | Fee market adversarial |
| T238 | `t238_multi_region_latency_harness.rs` | Multi-region latency |

---

*End of Document*