# QBIND Future Technology Research Report

**5–10 Year Horizon Analysis**

**Internal Planning Document — February 2026**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Threat & Opportunity Map](#2-threat--opportunity-map)
   - [PQC Evolution](#21-pqc-evolution)
   - [Post-Quantum Friendly Zero-Knowledge](#22-post-quantum-friendly-zero-knowledge)
   - [Hardware and Acceleration](#23-hardware-and-acceleration)
   - [Networking and P2P](#24-networking-and-p2p)
3. [Implications for QBIND](#3-implications-for-qbind)
   - [PQC Implications](#31-pqc-implications)
   - [Zero-Knowledge Implications](#32-zero-knowledge-implications)
   - [Hardware Implications](#33-hardware-implications)
   - [Networking Implications](#34-networking-implications)
4. [Roadmap Hooks](#4-roadmap-hooks)
   - [0–2 Years (v0.x, v1.0)](#41-02-years-v0x-v10)
   - [2–5 Years (v1.x, v2.0)](#42-25-years-v1x-v20)
   - [5+ Years (Exploratory)](#43-5-years-exploratory)
5. [Open Problems and Uncertainties](#5-open-problems-and-uncertainties)
6. [Conclusion](#6-conclusion)

---

## 1. Introduction

This document provides a critical analysis of the technology landscape that QBIND will operate in over the next 5–10 years. The goal is to identify threats, opportunities, and research milestones that should inform long-term planning.

**Scope**: This report covers post-quantum cryptography evolution, zero-knowledge proof systems, hardware acceleration, and networking protocols—all areas that directly impact QBIND's core architecture and future roadmap.

**Caveat**: Technology forecasting is inherently uncertain. This document represents our best-effort analysis based on current research trends and standards activity. Specific timelines are estimates, not commitments.

---

## 2. Threat & Opportunity Map

### 2.1 PQC Evolution

#### 2.1.1 Lattice-Based Signatures (ML-DSA)

**Current State**: QBIND uses ML-DSA-44 (FIPS 204, formerly Dilithium-2) for all signatures. This is the smallest NIST-standardized lattice signature, selected for its balance of security and performance.

**Expected Developments (5–10 years)**:

| Timeline | Development | Confidence |
|----------|-------------|------------|
| 2026–2028 | Wider industry adoption of ML-DSA in TLS, code signing, PKI | High |
| 2027–2029 | Parameter refinement based on ongoing cryptanalysis | Medium |
| 2028–2030 | Potential smaller-signature lattice schemes (hybrid lattice-code constructions) | Low-Medium |
| 2030+ | Possible NIST parameter updates or new security levels | Medium |

**Risks**:

1. **Cryptanalytic advances against module lattices**: The Learning With Errors (LWE) and related problems underpin ML-DSA security. While current attacks are far from practical, sustained cryptanalytic effort could reduce security margins. NIST chose conservative parameters, but parameter tightening is possible.

2. **Implementation vulnerabilities**: Side-channel attacks (timing, power analysis) against lattice implementations are an active research area. Hardware and software implementations may require hardening over time.

3. **Signature size overhead**: ML-DSA-44 signatures are ~2420 bytes vs. ~64 bytes for Ed25519. If this remains a bottleneck for L2 or high-throughput applications, pressure for smaller signatures will increase. There is no clear path to dramatically smaller post-quantum signatures.

**Opportunities**:

- NIST standardization provides a stable foundation for the next decade
- Optimized implementations (AVX2/AVX-512, ARM NEON) will continue to improve performance
- Hardware acceleration support in future CPUs is likely given NIST adoption

#### 2.1.2 Lattice-Based Key Encapsulation (ML-KEM)

**Current State**: QBIND uses ML-KEM-768 (FIPS 203, formerly Kyber-768) for KEMTLS-style transport authentication.

**Expected Developments**:

| Timeline | Development | Confidence |
|----------|-------------|------------|
| 2026–2028 | KEMTLS adoption in browsers and web servers | Medium-High |
| 2027–2029 | ML-KEM integration into TLS 1.3 ecosystem widely deployed | Medium |
| 2028–2030 | Hardware KEM accelerators in HSMs and secure enclaves | Medium |

**Risks**:

1. **Decapsulation failures**: Unlike classical DH, KEMs can have decapsulation failures (extremely rare for ML-KEM, but non-zero). Protocol design must account for this.

2. **Key size**: ML-KEM-768 public keys are ~1184 bytes. For protocols with frequent key exchanges, this overhead matters.

3. **Side channels**: KEM decapsulation is a known side-channel target. Constant-time implementations are critical.

#### 2.1.3 Alternative PQC Directions

**Hash-based signatures (XMSS, LMS, SPHINCS+)**:

- Already NIST-standardized (FIPS 205 for SLH-DSA/SPHINCS+)
- Stateless variant (SLH-DSA) has very large signatures (~17KB–49KB)
- Stateful variants (XMSS, LMS) require careful state management
- Could serve as backup if lattice assumptions break

**Code-based (Classic McEliece)**:

- Very large public keys (~0.5–1MB), impractical for most blockchain use cases
- Strong security track record (decades of cryptanalysis)
- Primarily interesting for key encapsulation where keys can be cached

**Isogeny-based**:

- SIDH/SIKE was broken in 2022, demonstrating cryptanalytic risk in newer constructions
- Research continues but no near-term standardization expected
- Treat as high-risk, high-reward research direction

### 2.2 Post-Quantum Friendly Zero-Knowledge

#### 2.2.1 Current zk Landscape

The L2 roadmap depends heavily on zero-knowledge proof systems. Current practical systems (Groth16, PLONK, STARKs) have different trust and quantum-resistance properties:

| System | Assumptions | PQ-Secure? | Proof Size | Verification Cost |
|--------|-------------|------------|------------|-------------------|
| **Groth16** | Pairing-based (discrete log) | No | ~200 bytes | Very fast |
| **PLONK** | Pairing-based | No | ~500 bytes | Fast |
| **STARKs** | Hash functions only | Yes* | 50–200 KB | Moderate |
| **Bulletproofs** | Discrete log | No | ~700 bytes | Slow |

*STARKs are quantum-resistant if the underlying hash function is secure against quantum attacks (SHA-3/Keccak are believed to be).

#### 2.2.2 PQ-Friendly zk Directions

**Hash-based SNARKs (Aurora, Ligero, STARKs)**:

- Rely only on collision-resistant hash functions
- STARK proofs are already quantum-resistant (assuming hash security)
- **Tradeoff**: Proof sizes 100–1000x larger than pairing-based SNARKs
- **Opportunity**: Prover efficiency is improving; verification can be amortized via recursion

**Lattice-based proofs**:

- Active research area (Lattice-based zkSNARKs)
- Would align with QBIND's lattice-based signature assumptions
- **Status**: Not production-ready; theoretical constructions exist but practical systems are 5–10+ years away
- **Risk**: May inherit vulnerabilities if lattice assumptions are weakened

**Symmetric-key MPC (MPC-in-the-head)**:

- Based on symmetric primitives (AES, SHA-3)
- Quantum-resistant if symmetric primitives hold
- Generally slower provers than algebraic approaches
- Potentially relevant for specific applications (signature schemes, range proofs)

#### 2.2.3 Tradeoffs vs. Classical SNARKs

**The core tension**: Classical pairing-based SNARKs offer 10–100x smaller proofs and faster verification than PQ-friendly alternatives. This creates a dilemma for the L2 roadmap:

| Approach | Pros | Cons |
|----------|------|------|
| **Deploy classical zk now** | Mature tooling, small proofs, fast verification | Not PQ-secure; L2 becomes the weak link |
| **Wait for PQ zk** | Future-proof | May wait 5–10 years; opportunity cost |
| **Hybrid** | Get to market faster | Complex migration path; unclear security semantics |

**Recommendation**: Proceed with classical zk L2 (with clear security disclaimers) while actively tracking PQ zk research. Plan for proof system migration as a Class C (hard fork) upgrade path.

### 2.3 Hardware and Acceleration

#### 2.3.1 General-Purpose Acceleration (GPUs, SIMD)

**Current State**: ML-DSA benefits significantly from AVX2/AVX-512 vectorization. Current benchmarks show ~10μs sign, ~5μs verify on modern x86.

**Expected Developments**:

| Timeline | Development | Impact |
|----------|-------------|--------|
| 2026–2028 | ARM SVE/SVE2 optimized implementations | Broadens validator hardware options |
| 2027–2030 | GPU-accelerated batch verification | 10–100x throughput for verification-heavy workloads |
| 2028–2032 | CPU-native PQC instructions (speculative) | Potential 2–5x speedup |

**GPU Opportunities**:

- Batch ML-DSA verification is embarrassingly parallel
- NTT (Number Theoretic Transform) used in ML-DSA/ML-KEM maps well to GPU architectures
- Could enable significantly higher TPS for validators with GPU resources
- **Caution**: Creates validator hardware heterogeneity; may affect decentralization

#### 2.3.2 FPGAs and ASICs

**FPGA Acceleration**:

- Already demonstrated for lattice operations (AWS F1 instances have Xilinx FPGAs)
- 10–50x speedup over CPU for NTT-heavy operations is plausible
- Useful for HSM integration (custom FPGA in HSM for PQC acceleration)
- **Timeline**: Available now for those willing to invest in custom development

**ASICs**:

- No ASIC market for PQC signatures currently (too early)
- If QBIND (or PQC generally) gains significant adoption, ASICs could emerge
- **Risk**: ASIC availability could centralize validation toward well-funded operators

#### 2.3.3 HSM Evolution

**Current State**: QBIND supports PKCS#11 HSMs via T211 integration. Current HSMs (YubiHSM, Thales Luna, AWS CloudHSM) have limited or no native PQC support.

**Expected Developments**:

| Timeline | Development | Confidence |
|----------|-------------|------------|
| 2026–2027 | HSM vendors add ML-DSA software emulation | High |
| 2027–2029 | HSM hardware acceleration for ML-DSA/ML-KEM | Medium |
| 2028–2030 | FIPS 140-3 validated PQC HSM modules | Medium-High |

**Risks**:

- Software emulation in HSMs may be slower than native CPU implementation
- Transition period where QBIND validators may need to choose between HSM security and PQC

#### 2.3.4 PQC-Specific Accelerators

**Emerging hardware**:

- Academic projects demonstrating lattice accelerators
- Intel/AMD may add PQC instructions to future CPUs (no announcements as of 2026)
- Secure enclaves (SGX, ARM TrustZone) beginning to support PQC algorithms

**Uncertainty**: Hardware vendor roadmaps are opaque. Cannot plan around specific acceleration availability.

### 2.4 Networking and P2P

#### 2.4.1 KEMTLS Standardization

**Current State**: QBIND uses KEMTLS-style transport (ML-KEM-768 for key encapsulation, ML-DSA-44 for authentication). This predates widespread KEMTLS standardization.

**Expected Developments**:

| Timeline | Development | Confidence |
|----------|-------------|------------|
| 2026–2027 | IETF TLS-KEM draft reaches RFC status | Medium |
| 2027–2028 | Browser and server adoption begins | Medium |
| 2028–2030 | KEMTLS becomes mainstream for sensitive applications | Medium-High |

**Opportunities**:

- As KEMTLS matures, QBIND can adopt standardized protocol rather than custom implementation
- Interoperability with external systems becomes easier
- Library support (OpenSSL, BoringSSL) will reduce maintenance burden

**Risks**:

- IETF process may produce a protocol incompatible with QBIND's current approach
- Migration from custom KEMTLS to standardized KEMTLS may require protocol changes

#### 2.4.2 Anti-Eclipse Techniques

**Current State**: QBIND implements anti-eclipse protections (T231): /24 prefix limits, ASN diversity tracking, minimum outbound peers.

**Expected Developments**:

- Research on more sophisticated topology inference attacks
- Machine learning-based eclipse attacks (adversarial peer selection)
- Potential for verifiable network topology proofs (research-stage)

**Risks**:

1. **IPv4/IPv6 exhaustion and NAT**: As IPv4 becomes more scarce, more validators may be behind NAT or CGNAT, complicating peer diversity metrics.

2. **Cloud concentration**: If validators concentrate in a few cloud providers (AWS, GCP, Azure), ASN diversity provides limited protection.

3. **Sophisticated attackers**: State-level adversaries may control diverse ASNs; current protections assume economically-motivated attackers.

#### 2.4.3 QUIC and Next-Gen Transport

**Current State**: QBIND transport is custom over TCP/TLS-like semantics.

**QUIC Considerations**:

| Factor | Analysis |
|--------|----------|
| **Latency** | QUIC's 0-RTT connection establishment could reduce reconnection latency |
| **Multiplexing** | Stream multiplexing could simplify DAG and consensus message handling |
| **PQC Integration** | QUIC is designed for crypto agility; PQC integration is being explored |
| **Maturity** | QUIC is now mature (HTTP/3), but PQC-QUIC is nascent |

**Recommendation**: Monitor PQC-QUIC development. Consider migration in v2.0+ timeframe if benefits materialize and standardization settles.

#### 2.4.4 Validator Discovery and DHT Evolution

**Current State**: P2P discovery (T205-207) uses custom mechanisms.

**Future Considerations**:

- Decentralized discovery (DHT) could reduce reliance on bootstrap nodes
- DHTs have their own eclipse attack surface
- IPFS/libp2p provides battle-tested P2P primitives, but adds dependency complexity

---

## 3. Implications for QBIND

### 3.1 PQC Implications

#### What Could Break or Become Suboptimal

| Component | Risk | Likelihood | Impact |
|-----------|------|------------|--------|
| **ML-DSA-44 signatures** | Cryptanalytic break requiring parameter update | Low | High |
| **ML-DSA-44 performance** | Remains too slow for high-TPS L2 requirements | Medium | Medium |
| **ML-KEM-768 transport** | Security margin reduction requiring parameter increase | Low | Medium |
| **Signature size** | Remains prohibitive for certain applications (mobile, IoT) | High | Low-Medium |

#### Crypto Agility Readiness

**Already Prepared**:

- Suite ID mechanism (§3.4 of whitepaper): All signatures include `SUITE_PQ_RESERVED_1 = 100`
- Domain separation prevents cross-context signature reuse
- Governance hooks for cryptographic suite upgrades (Class C hard fork)
- Upgrade envelope mechanism supports coordinated migration

**Gaps**:

1. **No defined backup suite**: If ML-DSA is weakened, we have not pre-selected and tested an alternative (e.g., SLH-DSA/SPHINCS+).

2. **Signature verification caching**: Current design assumes ML-DSA; verification caching strategies may not transfer to backup schemes with different performance characteristics.

3. **HSM migration path**: If HSMs need to switch algorithms, the transition may be complex and require extended dual-support periods.

#### Recommended Actions

| Priority | Action | Timeline |
|----------|--------|----------|
| **High** | Define and test SLH-DSA (SPHINCS+) as backup suite | v0.x |
| **Medium** | Implement suite negotiation for future algorithm migration | v1.0 |
| **Low** | Research smaller PQ signature schemes (hybrid constructions) | Ongoing |

### 3.2 Zero-Knowledge Implications

#### What Could Break or Become Suboptimal

| Component | Risk | Likelihood | Impact |
|-----------|------|------------|--------|
| **L2 classical zk** | Quantum adversary breaks bridge security | Low (near-term), Medium (long-term) | Critical |
| **L2 proof verification** | Classical proofs become unacceptable to users | Medium | High |
| **Rollup economics** | Large PQ proofs increase L1 verification costs | High | Medium |

#### Crypto Agility Readiness

**Already Prepared**:

- L2 architecture explicitly designed as separate component (§12 of whitepaper)
- Security model transparency: L2 does not claim PQ security
- Proof verification is abstracted (can swap proof systems)

**Gaps**:

1. **No STARK verifier implementation**: While STARKs are identified as PQ-friendly, no L1 verifier is implemented.

2. **Proof size economics**: If PQ proofs are 100x larger, fee model may need adjustment for L2 settlement.

3. **Prover infrastructure**: PQ zk provers may require different hardware (more RAM, different compute profile).

#### Recommended Actions

| Priority | Action | Timeline |
|----------|--------|----------|
| **Medium** | Prototype STARK verifier on L1 testnet | v1.0 |
| **Medium** | Economic modeling for large-proof settlement | v1.x |
| **Low** | Track lattice-based zkSNARK research | Ongoing |

### 3.3 Hardware Implications

#### What Could Break or Become Suboptimal

| Component | Risk | Likelihood | Impact |
|-----------|------|------------|--------|
| **Validator economics** | GPU/FPGA validators outcompete CPU-only | Medium | Medium |
| **HSM integration** | Native PQC HSMs don't materialize; software HSM remains slower | Medium | Low |
| **Decentralization** | Hardware acceleration concentrates validation | Low-Medium | High |

#### Crypto Agility Readiness

**Already Prepared**:

- HSM abstraction layer (T211 PKCS#11 integration)
- Modular signer interface supports different backends
- Performance targets are conservative (300–500 TPS), not hardware-dependent

**Gaps**:

1. **No GPU acceleration path**: Current codebase has no GPU support; adding it later requires significant refactoring.

2. **Hardware diversity metrics**: No mechanism to measure or encourage validator hardware diversity.

3. **Minimum hardware requirements**: Unclear if consensus would need adjustment for hardware-divergent validation.

#### Recommended Actions

| Priority | Action | Timeline |
|----------|--------|----------|
| **Low** | Prototype GPU batch verification | v1.x |
| **Low** | Define minimum validator hardware requirements | v1.0 |
| **Medium** | Monitor HSM vendor PQC roadmaps | Ongoing |

### 3.4 Networking Implications

#### What Could Break or Become Suboptimal

| Component | Risk | Likelihood | Impact |
|-----------|------|------------|--------|
| **Custom KEMTLS** | Diverges from eventual standard; maintenance burden | Medium | Low |
| **Anti-eclipse /24 prefix** | IPv4 scarcity makes prefix diversity less meaningful | Medium | Low |
| **TCP-based transport** | Performance bottleneck vs. QUIC alternatives | Low | Low |

#### Crypto Agility Readiness

**Already Prepared**:

- P2P layer is modular (transport abstraction exists)
- Anti-eclipse configuration is parameterized (P2pAntiEclipseConfig)
- Discovery mechanism is pluggable

**Gaps**:

1. **No QUIC support**: Adding QUIC requires significant transport layer changes.

2. **IPv6 transition planning**: Anti-eclipse metrics may need revision for IPv6-dominant future.

3. **Standardized KEMTLS integration**: Current implementation may need refactoring when IETF KEMTLS finalizes.

#### Recommended Actions

| Priority | Action | Timeline |
|----------|--------|----------|
| **Medium** | Track IETF KEMTLS progress; plan migration | v1.x |
| **Low** | Evaluate QUIC adoption | v2.0+ |
| **Low** | Research IPv6-aware anti-eclipse metrics | v1.x |

---

## 4. Roadmap Hooks

### 4.1 0–2 Years (v0.x, v1.0)

#### Milestone: Backup Cryptographic Suite Definition (v0.x)

**Description**: Define and test SLH-DSA (SPHINCS+) as the official backup signature scheme if ML-DSA requires migration.

**Success Criteria**:
- Suite ID allocated and documented (e.g., `SUITE_PQ_RESERVED_2 = 101`)
- Reference implementation integrated (behind feature flag)
- Performance benchmarks documented
- Migration playbook written (not necessarily tested in production)

**Dependencies**:
- NIST FIPS 205 finalization (complete as of 2024)
- SLH-DSA library integration (e.g., `pqcrypto-sphincsplus` crate)

---

#### Milestone: On-Chain Upgrade Signaling (v0.x)

**Description**: Implement on-chain mechanism for validators to signal readiness for protocol upgrades.

**Success Criteria**:
- Validators can publish upgrade-readiness signals on-chain
- Governance can query aggregate readiness before activation
- Minimum threshold enforcement before Class C upgrades proceed

**Dependencies**:
- VM v0 capable of storing small metadata per validator
- Governance tooling to interpret signals

---

#### Milestone: STARK Verifier Prototype (v1.0)

**Description**: Implement a prototype STARK proof verifier on QBIND L1 testnet to validate PQ-friendly zk integration path.

**Success Criteria**:
- STARK verification succeeds for simple computation proofs
- Gas/fee cost model for STARK verification documented
- Performance baseline established (proofs per block, verification latency)

**Dependencies**:
- STARK library (e.g., `winterfell`, `stone-prover`) integration
- VM enhancements for verifier execution (may require VM v1)

---

#### Milestone: Multi-Suite Negotiation Protocol (v1.0)

**Description**: Extend P2P handshake to negotiate cryptographic suite, enabling graceful migration to new algorithms.

**Success Criteria**:
- Nodes can advertise supported suites during handshake
- Connection established using highest mutually-supported suite
- Backward compatibility: v1.0 nodes can peer with v0.x nodes

**Dependencies**:
- Suite versioning infrastructure
- Regression testing for mixed-version networks

---

### 4.2 2–5 Years (v1.x, v2.0)

#### Milestone: L2 Testnet with Classical zk (v1.x)

**Description**: Deploy L2 testnet using classical zk proofs (Groth16 or PLONK) with explicit security caveats.

**Success Criteria**:
- L2 execution environment operational on testnet
- Validity proofs verified on L1
- Documentation explicitly states L2 is not PQ-secure
- User-facing warnings for L2 transactions

**Dependencies**:
- VM v1 (smart contract support) on L1
- Bridge architecture design finalized
- Classical zk library integration

---

#### Milestone: HSM Native PQC Support Assessment (v1.x)

**Description**: Evaluate which HSM vendors provide native ML-DSA/ML-KEM support and update operational guidance.

**Success Criteria**:
- Survey of HSM vendor PQC capabilities published
- Updated HSM integration guide for native PQC HSMs
- Migration path from software-emulated to hardware-accelerated PQC

**Dependencies**:
- HSM vendor product releases (external)
- FIPS 140-3 validation of PQC modules (external)

---

#### Milestone: QUIC Transport Evaluation (v2.0)

**Description**: Prototype QUIC-based transport for validator P2P, comparing latency and throughput to TCP-based transport.

**Success Criteria**:
- QUIC transport implementation functional on testnet
- Benchmark comparison with current transport
- Analysis of PQC-QUIC integration (if IETF drafts mature)

**Dependencies**:
- PQC-QUIC IETF progress (external)
- QUIC library with PQC support (may require custom work)

---

#### Milestone: Standardized KEMTLS Migration (v2.0)

**Description**: Migrate from custom KEMTLS implementation to IETF-standardized KEMTLS when RFC is finalized.

**Success Criteria**:
- Protocol updated to match IETF KEMTLS specification
- Backward compatibility period defined for migration
- Security audit of new KEMTLS implementation

**Dependencies**:
- IETF TLS-KEM RFC finalization (external)
- Library support (OpenSSL, rustls) for standardized KEMTLS

---

#### Milestone: PQ zk Research Integration (v2.0)

**Description**: If practical PQ-friendly zk systems emerge, prototype integration on testnet.

**Success Criteria**:
- PQ zk proof verifier operational on L1 testnet
- Proof size and verification cost comparison with classical zk
- Assessment of prover hardware requirements

**Dependencies**:
- Academic/industry breakthroughs in PQ zk (highly uncertain)
- STARK ecosystem maturity or lattice-based zkSNARK emergence

---

### 4.3 5+ Years (Exploratory)

#### Milestone: Full PQ L2 Stack (v2.x+)

**Description**: Deploy L2 with end-to-end post-quantum security, using PQ-friendly zk proofs.

**Success Criteria**:
- L2 proofs use only PQ-secure assumptions
- Bridge security inherits L1 PQ guarantees
- No classical cryptographic dependencies in L2 security model

**Dependencies**:
- Practical PQ zk systems (research-stage as of 2026)
- Hardware capable of efficient PQ zk proving
- 5–10 year maturation of PQ zk ecosystem

**Uncertainty**: High. This milestone depends on research breakthroughs that may not occur on any specific timeline.

---

#### Milestone: Lattice Assumption Monitoring Program (Ongoing)

**Description**: Establish continuous monitoring of cryptanalytic advances against module lattice problems (LWE, MLWE, SIS).

**Success Criteria**:
- Annual review of IACR ePrint and major conference publications
- Relationship with academic cryptography community
- Rapid response plan if significant cryptanalytic advances published

**Dependencies**:
- Ongoing research community engagement
- Internal cryptographic expertise

---

#### Milestone: Next-Generation PQC Evaluation (v3.0+)

**Description**: Evaluate emerging PQC candidates (code-based, isogeny-based successors, etc.) for potential future migration.

**Success Criteria**:
- Candidates identified and security properties analyzed
- Prototype implementations tested
- Migration cost assessment completed

**Dependencies**:
- NIST PQC Round 5 or successor competition (speculative)
- Academic development of new PQC constructions

---

#### Milestone: Hardware-Accelerated Validation Tier (v3.0+)

**Description**: If GPU/FPGA acceleration becomes widespread and cost-effective, evaluate tiered validator model.

**Success Criteria**:
- Analysis of acceleration impact on decentralization
- Economic model for different validator tiers
- Governance framework for hardware requirements evolution

**Dependencies**:
- Hardware acceleration maturity (external)
- Community consensus on decentralization tradeoffs

---

## 5. Open Problems and Uncertainties

### 5.1 Cryptographic Uncertainties

1. **Lattice security margins**: Current NIST parameters are conservative, but how conservative? A major cryptanalytic advance could require parameter increases (larger signatures, slower verification) or algorithm replacement.

2. **PQ zk timeline**: When (if ever) will PQ-friendly zk proofs achieve performance parity with classical SNARKs? Current gap is 100–1000x for proof size.

3. **Quantum computer timeline**: The "Q-day" when quantum computers can break classical crypto is unpredictable. Current estimates range from 10–30+ years. Earlier arrival increases urgency; later arrival reduces pressure but doesn't eliminate need for PQC.

### 5.2 Ecosystem Uncertainties

1. **HSM vendor commitment**: Will HSM vendors prioritize PQC support? Blockchain is a niche market; enterprise demand from TLS/PKI may drive timelines.

2. **Developer tooling**: Will PQC development tooling (libraries, debuggers, formal verification tools) mature sufficiently?

3. **Regulatory requirements**: Will regulators mandate PQC for financial infrastructure? Timeline and scope are unclear.

### 5.3 Economic Uncertainties

1. **Validator economics**: How will hardware acceleration affect validator economics and decentralization?

2. **L2 fee model**: If PQ proofs are 100x larger, how does this affect L2 settlement economics?

3. **User willingness**: Will users accept tradeoffs (larger transactions, higher fees) for PQ security?

### 5.4 Unresolved Design Questions

1. **Hybrid vs. pure PQC**: Should L2 offer a hybrid mode (classical + PQ) for transition period? What are the security semantics?

2. **Emergency algorithm replacement**: What is the fastest we could replace ML-DSA if a critical vulnerability is discovered? Current governance may be too slow for emergency response.

3. **State migration**: If signature schemes change, how do we handle historical state (old signatures in archived blocks)?

---

## 6. Conclusion

QBIND's position as a PQC-first blockchain is strategically sound for the 5–10 year horizon. The selection of NIST-standardized algorithms (ML-DSA-44, ML-KEM-768) provides a stable foundation, and the existing crypto agility mechanisms (suite IDs, governance hooks) create pathways for future evolution.

**Key strengths**:
- Pure PQC L1 avoids classical crypto as a single point of failure
- Conservative algorithm selection aligns with NIST recommendations
- Modular architecture supports future migration

**Key risks**:
- L2/bridge security depends on classical zk until PQ alternatives mature
- Hardware evolution could affect validator economics
- Cryptanalytic advances are unpredictable

**Priority actions for near-term roadmap**:
1. Define backup cryptographic suite (SLH-DSA)
2. Prototype STARK verifier for PQ-friendly zk path
3. Implement multi-suite negotiation for graceful migration
4. Establish cryptanalytic monitoring program

This document should be reviewed and updated annually as the technology landscape evolves. Specific timelines and confidence levels will shift as research progresses and industry adoption patterns become clearer.

---

*Document prepared: February 2026*
*Classification: Internal Planning*
*Review cycle: Annual*