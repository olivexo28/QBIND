# QBIND Legacy Design Synthesis

**Version**: 1.0  
**Date**: 2026-04-20  
**Status**: Canonical Distilled Legacy Material

---

## 1. Purpose and Scope

This document consolidates useful design material from the legacy documentation archive (`docs/archive_legacy_v0/`) that remains relevant to understanding QBIND's design evolution. All content here is **compatible with current canonical documentation** and provides supplementary background for implementers and auditors.

**What this document is:**
- A distilled synthesis of legacy design thinking worth preserving
- Supplementary background material for the current protocol
- Source-traced content with clear provenance

**What this document is NOT:**
- A replacement for canonical docs (`docs/whitepaper/QBIND_WHITEPAPER.md`, `docs/protocol/QBIND_PROTOCOL_REPORT.md`)
- New protocol claims or specifications
- Material that contradicts current canonical documentation

**Canonical documentation always takes precedence over this synthesis.**

---

## 2. Legacy Monetary and Fee-Market Background

This section synthesizes the design thinking behind QBIND's economic model from legacy planning documents.

### 2.1 Security-Budget-Driven Inflation Philosophy

The core monetary design principle established early in QBIND's development was that **inflation exists to fund network security**, not as an arbitrary parameter. The security budget is computed to ensure validators receive adequate compensation for:

- Hardware and bandwidth operational costs
- Post-quantum cryptographic overhead (ML-DSA-44 ~5–10× classical signature verification cost)
- Staked capital return expectations

The PQC premium formula accounts for the higher costs of operating a post-quantum chain:

```
R_target_PQC = R_target_classical × (1 + β_compute + β_bandwidth + β_storage)
```

Where:
- `β_compute ≈ 0.20–0.35` — ML-DSA-44 verification CPU overhead
- `β_bandwidth ≈ 0.10–0.20` — Larger signature sizes (2,420 bytes vs 64 bytes for ECDSA)
- `β_storage ≈ 0.05–0.10` — Larger public keys (1,312 bytes vs 32 bytes)

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_MONETARY_POLICY_DESIGN.md`, `archive_legacy_v0/econ/T198_PQC_COST_BENCHMARKING.md`

### 2.2 Three-Phase Monetary Model

QBIND's monetary policy operates across three distinct phases, each with different inflation targets and governance flexibility:

| Phase | Time Window | Characteristics |
|-------|-------------|-----------------|
| **Bootstrap** | Years 0–3 | Higher inflation (~8–9% PQC-adjusted), limited fee offset, faster EMA response |
| **Transition** | Years 3–7 | Moderate inflation (~6–7% PQC-adjusted), full fee offset sensitivity |
| **Mature** | Year 7+ | Lower inflation (~4–5% PQC-adjusted) with floor, maximum stability |

Phase transitions require both time gates (epochs) and economic readiness gates (fee coverage ratio, staking participation, fee volatility thresholds).

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_MONETARY_POLICY_DESIGN.md`

### 2.3 Fee Market Adversarial Analysis Methodology

The T236 adversarial fee market harness established the testing methodology for validating fee market safety under attack conditions:

**Tested scenarios:**
1. **Single-sender spam attack** — Per-sender quotas (T218) prevent monopolization
2. **Front-running pattern attack** — Fee accounting remains correct (MEV mitigation deferred)
3. **Churn attack** — Eviction rate limiting (T219/T220) caps mempool churn

**Verified invariants:**
- No negative balances
- No double-spend or replay
- Total debits == burned + proposer rewards
- Honest senders not fully starved (>30% inclusion under attack)

This methodology established the repeatable stress harness approach used for production readiness validation.

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md`

### 2.4 PQC Cost Benchmarking Methodology

The T198 harness established the methodology for measuring post-quantum cryptographic costs:

**ML-DSA-44 reference sizes:**
- Public key: 1,312 bytes
- Secret key: 2,560 bytes  
- Signature: 2,420 bytes

**BatchCertificate overhead (2f+1 signatures):**
- 3 validators (n=4): ~7.3 KB
- 7 validators (n=10): ~17.0 KB
- 67 validators (n=100): ~162.3 KB

This benchmarking informed the PQC premium calibration in the monetary policy.

**Source legacy docs**: `archive_legacy_v0/econ/T198_PQC_COST_BENCHMARKING.md`

---

## 3. Legacy DevNet / TestNet / MainNet Planning Background

This section preserves the network evolution planning that shaped QBIND's staged rollout approach.

### 3.1 Network Environment Progression

The staged approach from DevNet → TestNet Alpha → TestNet Beta → MainNet was designed to progressively harden the protocol:

| Capability | DevNet v0 | TestNet Alpha | TestNet Beta | MainNet v0 |
|------------|-----------|---------------|--------------|------------|
| Execution | Nonce-only | VM v0 | VM v0 (gas-on) | VM v0 + Stage B |
| Gas/Fees | None | Design only | Enforced (burn) | Enforced (hybrid) |
| Mempool | FIFO | FIFO + DAG opt-in | DAG default | DAG only |
| Networking | LocalMesh | LocalMesh + P2P opt-in | P2P default | P2P required |
| Persistence | In-memory | RocksDB | RocksDB | RocksDB mandatory |
| Keys | EncryptedFs | EncryptedFs | EncryptedFs | HSM-ready |

This progression allowed each capability to be tested in isolation before integration.

**Source legacy docs**: `archive_legacy_v0/devnet/QBIND_DEVNET_V0_FREEZE.md`, `archive_legacy_v0/mainnet/QBIND_MAINNET_V0_SPEC.md`

### 3.2 Genesis and Launch Design Patterns

The genesis configuration design established key principles for network initialization:

**Required invariants:**
1. Non-empty chain_id
2. All allocation amounts > 0
3. No duplicate addresses in allocations
4. At least one validator with non-empty PQC key
5. Council threshold: 0 < threshold ≤ member count
6. Total supply > 0

**MainNet-specific requirements:**
- External genesis file required (`--genesis-path` CLI flag)
- Embedded genesis forbidden (unlike DevNet/TestNet)
- Hash verification mandatory before startup
- Canonical distribution across all validators

**Source legacy docs**: `archive_legacy_v0/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md`

---

## 4. Legacy DAG Mempool and Parallel Execution Ideas

This section preserves the design thinking behind QBIND's DAG mempool and parallel execution architecture.

### 4.1 DAG-Based Mempool Architecture

The DAG mempool design separated **data availability** from **consensus ordering**:

**Core concepts:**
- **Batches (QbindBatch)**: Collections of transactions created by a single validator, signed with ML-DSA-44
- **BatchCertificate**: Formed when 2f+1 validators acknowledge a batch, proving data availability
- **DAG Frontier**: The set of certified batches that the HotStuff leader proposes for ordering

**Benefits over FIFO mempool:**
- Reduces leader bottleneck (all validators contribute batches)
- Parallel data propagation while consensus focuses on total ordering
- Improved fairness through causal ordering and batch rotation
- Data availability guarantee before proposal

This architecture allows HotStuff consensus to operate on certified frontiers rather than raw transaction lists.

**Source legacy docs**: `archive_legacy_v0/devnet/QBIND_DAG_MEMPOOL_DESIGN.md`

### 4.2 DAG-Consensus Coupling Design

For MainNet, availability certificates became consensus-coupled rather than purely data-plane:

**Evolution:**
- TestNet Alpha/Beta: Certificates v1 (data-plane only)
- MainNet v0: Consensus-coupled certificates (validators verify cert validity in proposals)

This coupling ensures that blocks reference only properly certified data, providing stronger safety guarantees at the cost of tighter integration between DAG and consensus layers.

**Source legacy docs**: `archive_legacy_v0/mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md`

### 4.3 Stage A/B Parallel Execution Model

The parallel execution design introduced a two-stage model:

**Stage A (DevNet/TestNet):** Per-account independence for nonce-only engine
- Transactions from different senders commute (no shared state)
- Per-sender ordering preserved (nonce monotonicity)
- Sender-partitioned parallelism using rayon thread pool
- Determinism guaranteed by preserving per-sender order

**Stage B (MainNet):** Conflict-graph-based VM parallelism
- Static conflict analysis based on read/write sets
- Transactions touching different accounts/storage execute in parallel
- Conflicting transactions serialized via dependency graph
- Adversarial workloads degrade gracefully to sequential execution

The design anticipated that adversarial workloads (all transactions hitting same storage) would serialize, but per-sender quotas and fee mechanisms discourage such patterns.

**Source legacy docs**: `archive_legacy_v0/devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md`

---

## 5. Legacy Future-Tech Research Worth Preserving

This section preserves forward-looking research analysis from the legacy planning documents.

### 5.1 PQC Evolution Outlook (5–10 Year Horizon)

**ML-DSA-44 expected developments:**
- 2026–2028: Wider industry adoption in TLS, code signing, PKI
- 2027–2029: Parameter refinement based on ongoing cryptanalysis
- 2028–2030: Potential smaller-signature lattice schemes
- 2030+: Possible NIST parameter updates

**Key risks identified:**
- Cryptanalytic advances against module lattices (currently far from practical)
- Implementation vulnerabilities (side-channel attacks)
- Signature size overhead for high-throughput applications

**Alternative PQC directions tracked:**
- Hash-based signatures (SPHINCS+/SLH-DSA): Very large signatures but strong security track record
- Code-based (Classic McEliece): Impractical key sizes for blockchain use
- Isogeny-based: SIDH/SIKE broken in 2022; treat as high-risk research direction

**Source legacy docs**: `archive_legacy_v0/roadmap/QBIND_FUTURE_TECH_RESEARCH.md`

### 5.2 Post-Quantum Zero-Knowledge Considerations

**The core tension for L2 roadmap:**
- Classical pairing-based SNARKs (Groth16, PLONK): Small proofs, fast verification, but NOT PQ-secure
- STARKs: PQ-secure (hash-based), but 50–200 KB proofs
- Lattice-based zkSNARKs: Research stage, 5–10+ years from production

**Legacy recommendation (preserved):**
Proceed with classical zk L2 (with clear security disclaimers) while tracking PQ zk research. Plan for proof system migration as a Class C (hard fork) upgrade path.

**Source legacy docs**: `archive_legacy_v0/roadmap/QBIND_FUTURE_TECH_RESEARCH.md`

### 5.3 Hardware Acceleration Outlook

**Near-term (2026–2028):**
- ARM SVE/SVE2 optimized ML-DSA implementations
- GPU-accelerated batch verification (10–100× throughput)

**Medium-term (2028–2032):**
- CPU-native PQC instructions (speculative)
- FPGA acceleration for NTT operations (10–50× speedup)
- HSM integration with PQC acceleration

**Concern noted:** GPU/ASIC acceleration may create validator hardware heterogeneity affecting decentralization.

**Source legacy docs**: `archive_legacy_v0/roadmap/QBIND_FUTURE_TECH_RESEARCH.md`

---

## 6. Future Considerations (Non-Canonical)

This section contains legacy ideas that were identified as interesting but **not adopted** in the current protocol. These are preserved for future reference only and do not represent current protocol direction.

### 6.1 EIP-1559-Style Base Fee (Deferred)

The legacy fee market analysis noted that an EIP-1559-style base fee mechanism was considered for v1+ to improve fee predictability. The current protocol uses a simpler priority-fee model with 50% burn / 50% proposer split.

**Status**: Not adopted for v0. May be considered for future versions.

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md`

### 6.2 Oracle-Assisted Parameter Hints (Deferred)

The monetary policy design anticipated future phases where off-chain oracles could provide economic data hints for parameter adjustment. This was planned for Phase 2+ but is not part of the current protocol.

**Status**: Deferred to future governance evolution.

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_MONETARY_POLICY_DESIGN.md`

### 6.3 AI-Based Monitoring (Exploratory)

Long-term planning documents referenced AI-based monitoring for detecting anomalous network behavior. This remains an exploratory concept with no current implementation path.

**Status**: Exploratory research direction only.

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_MONETARY_POLICY_DESIGN.md`

### 6.4 MEV Mitigation (Deferred)

The fee market adversarial analysis explicitly noted that MEV mitigation (commit-reveal, proposer-builder separation) was deferred to v1+. Front-running remains economically possible in the current protocol, but fee accounting is correct.

**Status**: Deferred to future protocol versions.

**Source legacy docs**: `archive_legacy_v0/econ/QBIND_FEE_MARKET_ADVERSARIAL_ANALYSIS.md`

---

## 7. Governance Model Background

This section preserves the governance design thinking from legacy planning documents.

### 7.1 Off-Chain Council Model (v0)

The v0 governance model uses an off-chain Protocol Council with multi-signature approval:

**Design principles:**
- Multi-party approval (M-of-N threshold)
- No single key can unilaterally change the protocol
- Council signs specific binary hashes, not just version numbers
- Geographic and organizational distribution of council members

**Upgrade envelope structure:**
- PQC-signed upgrade envelopes with ML-DSA-44
- Version tracking and activation height encoding
- TestNet Beta soak period before MainNet deployment

### 7.2 Upgrade Classification System

Three classes of upgrades were defined:

| Class | Description | Process |
|-------|-------------|---------|
| **Class A** | Soft-fork compatible; old nodes can follow new chain | Standard council approval |
| **Class B** | Hard-fork requiring all validators to upgrade | Extended timeline + soak testing |
| **Class C** | Breaking changes (proof system migration, crypto suite changes) | Long activation window + governance vote |

**Source legacy docs**: `archive_legacy_v0/gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md`

---

## 8. PQC Background Context

This section preserves foundational PQC context from early project planning.

### 8.1 Threat Model Foundation

QBIND was designed around the "harvest now, decrypt later" threat model:

- Adversaries may store encrypted traffic today for future quantum decryption
- Long-lived blockchain data and key material at risk even before practical quantum computers exist
- NIST estimates large-scale quantum computers feasible by 2030–2040

This motivated the **no classical cryptography** requirement in the consensus-critical path.

### 8.2 Suite Catalog Design

The cryptographic agility design established a suite registry approach:

- Suite IDs map to specific algorithm implementations
- Backend registry dispatches verification by suite_id
- Governance-driven upgrades can activate new suites, deprecate old ones

**Registered suites:**
- ID 100: ML-DSA-44 (NIST Level 1, production)
- ID 101: ML-DSA-87 (NIST Level 3, reserved)
- ID 102: SPHINCS+-SHAKE-128s (stateless hash-based, reserved)

**Constraint:** All suites must provide ≥128-bit classical security.

**Source legacy docs**: `archive_legacy_v0/project_context_pqc.md`

---

*This document was synthesized from legacy documentation as part of the docs consolidation task. All content is compatible with current canonical documentation and provides supplementary background only.*