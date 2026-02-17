# QBIND External Security Audit RFP & Scope Document

**Task**: T235  
**Status**: Ready for Vendor Review  
**Date**: 2026-02-10

---

## 1. Overview & Objectives

### 1.1 Protocol Summary

QBIND is a **post-quantum cryptography (PQC)-only Layer 1 blockchain** designed for a quantum-resistant future. Key architectural characteristics include:

- **Consensus**: HotStuff-style BFT with DAG-based data availability layer
- **Cryptography**: ML-DSA-44 signatures (FIPS 204), ML-KEM-768 key encapsulation (FIPS 203), KEMTLS-based networking
- **Execution**: Transfer-only VM v0 with Stage B parallel execution capability
- **Networking**: P2P transport with KEMTLS encryption, dynamic discovery, anti-eclipse protections
- **Monetary Engine**: Three-phase model (Bootstrap/Transition/Mature) with EMA-based fee smoothing and seigniorage distribution
- **Key Management**: HSM/PKCS#11 support, remote signer protocol, key rotation hooks
- **Slashing**: PQC-specific offense taxonomy addressing lazy verification, invalid signatures, and DAG coupling violations

### 1.2 Audit Objectives

The primary goals of this external security audit are to:

| Objective | Description |
| :--- | :--- |
| **Consensus Safety & Liveness** | Verify HotStuff BFT safety under realistic faults; verify DAG–consensus coupling cannot lead to forks or stalls |
| **PQC Crypto Usage** | Verify correct use of ML-DSA-44 for signing, ML-KEM-768 for key exchange, KEMTLS for transport; verify HSM integration |
| **Networking / P2P** | Verify anti-eclipse protections, peer diversity enforcement, liveness detection, and discovery security |
| **Mempool & DAG** | Verify fee-priority DAG mempool DoS resistance, eviction rate limiting, and consensus coupling |
| **Slashing Pipeline** | Verify evidence model, penalty engine, and ledger backend for PQC-specific offenses |
| **Genesis & Governance** | Verify genesis config validation, hash commitment, and upgrade envelope verification |
| **Key Management** | Verify signer modes, HSM/PKCS#11 adapter, remote signer protocol, and key rotation hooks |
| **Monetary Engine** | Verify phase transitions, EMA smoothing, rate limiters, and seigniorage distribution |

---

## 2. In-Scope Components

### 2.1 Consensus & DAG

**Scope**: The HotStuff-style BFT consensus mechanism and its coupling with the DAG data availability layer.

The consensus layer implements a modified HotStuff protocol with 3-chain commit rule, view-change mechanisms, and timeout handling. The DAG layer provides batched data availability with availability certificates. T188–T192 implemented the coupling between DAG and consensus, ensuring that proposals only reference certified batches.

**Key audit areas**:
- HotStuff safety (no forks under Byzantine faults ≤f)
- View-change liveness (leader failure recovery)
- DAG certificate validity and consensus enforcement
- `DagCouplingMode` configuration (Off/Warn/Enforce)
- Proposer-side frontier selection (T190)
- Validator-side pre-vote validation (T191)
- Block-level invariant probes (T192)

**Design Documents**:
- [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](../mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) (T188)
- [QBIND_MAINNET_V0_SPEC.md §6](../mainnet/QBIND_MAINNET_V0_SPEC.md#6-consensus--dag)

### 2.2 Execution & VM / Stage B

**Scope**: The VM v0 execution engine and Stage B parallel execution.

VM v0 implements transfer-only execution with nonce tracking, balance accounting, and gas enforcement. Stage B provides conflict-graph-based parallel execution for throughput scaling while maintaining determinism.

**Key audit areas**:
- Transfer execution semantics (balance conservation)
- Gas enforcement and fee deduction
- Stage B parallel vs sequential determinism
- State root computation
- Payload format validation (v1 only for MainNet)

**Design Documents**:
- [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) (Stage A/B)
- [QBIND_MAINNET_V0_SPEC.md §2](../mainnet/QBIND_MAINNET_V0_SPEC.md#2-execution--state)

**Test Harnesses**:
- T223: Stage B soak harness (`t223_stage_b_soak_harness.rs`)

### 2.3 PQC Cryptography

**Scope**: Post-quantum cryptographic primitives and their usage throughout the protocol.

QBIND uses **FIPS 204 ML-DSA-44** for all digital signatures and **FIPS 203 ML-KEM-768** for key encapsulation (KEMTLS). The PQC cost model (T198) documents the computational overhead.

**Key audit areas**:
- ML-DSA-44 key generation, signing, and verification
- Domain separation tags (`QBIND:MAIN:*:v1` for MainNet)
- KEMTLS key schedule and nonce discipline
- HSM integration (PKCS#11 adapter) for ML-DSA-44
- Remote signer protocol security (T212)
- Key rotation hooks (T213)
- Signature serialization and parsing

**Design Documents**:
- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) (T209)
- [T198_PQC_COST_BENCHMARKING.md](../econ/T198_PQC_COST_BENCHMARKING.md)

**Specific Concerns**:
- ML-DSA-44 signature size (2,420 bytes) and bandwidth implications
- Verification cost (~5μs) and lazy verification incentives
- Any non-standard ML-DSA-44 usage patterns

### 2.4 Networking / P2P

**Scope**: P2P transport, peer discovery, liveness detection, and anti-eclipse protections.

The P2P layer uses KEMTLS (ML-KEM-768) for transport encryption. Dynamic discovery (T205, T206, T207) enables peer finding. Anti-eclipse protections (T226, T231) enforce diversity constraints.

**Key audit areas**:
- KEMTLS transport implementation
- Dynamic peer discovery protocol (T205–T207)
- Peer liveness detection and heartbeat protocol (T226)
- Anti-eclipse constraints: IP prefix limits, ASN diversity (T231)
- Sentry node topology and validator isolation
- Bootstrap peer fallback mechanisms

**Design Documents**:
- [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) (T170)
- [QBIND_MAINNET_V0_SPEC.md §5](../mainnet/QBIND_MAINNET_V0_SPEC.md#5-networking--p2p)

### 2.5 Mempool & DAG

**Scope**: Fee-priority DAG mempool, DoS protections, and eviction rate limiting.

The DAG mempool implements fee-priority ordering with per-sender quotas (T218), eviction rate limiting (T219, T220), and consensus coupling (T221, T222).

**Key audit areas**:
- Fee-priority eviction logic
- Per-sender load tracking (`SenderLoad` struct)
- Batch size limits and byte limits
- Eviction rate limiting (mode: Off/Warn/Enforce)
- DAG–consensus coupling harness tests (T221)
- Consensus chaos harness tests (T222)

**Design Documents**:
- [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) (T158)
- [QBIND_MAINNET_V0_SPEC.md §4](../mainnet/QBIND_MAINNET_V0_SPEC.md#4-mempool--dag)

**Test Harnesses**:
- T221: DAG–consensus coupling cluster harness (`t221_dag_coupling_cluster_tests.rs`)
- T222: Consensus chaos harness (`t222_consensus_chaos_harness.rs`)

### 2.6 State & Persistence

**Scope**: State retention, pruning, snapshots, and fast sync.

State persistence uses RocksDB with configurable retention (T208) and periodic snapshots (T215) for fast sync.

**Key audit areas**:
- State pruning correctness (no pruning of needed data)
- Snapshot creation via RocksDB checkpoint API
- Fast sync restore procedure
- State size metrics and growth monitoring
- MainNet validation: snapshots enabled, interval 10,000–500,000 blocks

**Design Documents**:
- [QBIND_MAINNET_V0_SPEC.md §2.4](../mainnet/QBIND_MAINNET_V0_SPEC.md#24-state-growth-management)

### 2.7 Monetary Policy & Seigniorage

**Scope**: Monetary engine, inflation model, fee smoothing, and seigniorage distribution.

The monetary engine (T194–T203) implements a three-phase model with EMA-based fee smoothing and rate-of-change limiters.

**Key audit areas**:
- Phase transitions (Bootstrap → Transition → Mature)
- EMA-based fee smoothing (T202)
- Per-epoch rate-of-change limiters (T203)
- Seigniorage distribution to validators (T200)
- Treasury/insurance/community routing (T201)
- Epoch monetary state tracking (T199)
- Hybrid fee distribution (50% burn, 50% proposer) (T193)

**Design Documents**:
- [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) (T194)

### 2.8 Keys, HSM & Remote Signing

**Scope**: Key management architecture, signer modes, HSM integration, and remote signer protocol.

The key management design (T209) defines signer modes and the implementation tasks T210–T214 provide HSM/PKCS#11 adapter, remote signer protocol, key rotation hooks, and failure mode handling.

**Key audit areas**:
- Signer mode enforcement (`LoopbackTesting` forbidden on MainNet)
- `SignerFailureMode::ExitOnFailure` (fail-closed) for MainNet
- HSM/PKCS#11 adapter implementation (T211)
- Remote signer daemon and KEMTLS transport (T212)
- Key rotation hooks and dual-key grace period (T213)
- HSM failure handling and redundancy patterns (T214)
- Startup reachability checks for signer
- `qbind_hsm_startup_ok` metric

**Design Documents**:
- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) (T209)
- [QBIND_MAINNET_RUNBOOK.md §6](../ops/QBIND_MAINNET_RUNBOOK.md#6-key-rotation--compromise-handling)

### 2.9 Slashing & PQC Offenses

**Scope**: Offense taxonomy, evidence model, penalty engine, and ledger backend.

The slashing model (T227–T230) addresses PQC-specific concerns around lazy verification, invalid signatures, and DAG coupling violations.

**Key audit areas**:
- Offense taxonomy (O1–O5): double-signing, invalid signatures, lazy voting, invalid DAG certificates, coupling violations
- Evidence model and proof format
- Penalty engine with modes (Off/RecordOnly/EnforceCritical/EnforceAll)
- Slash percentages and jail durations
- `SlashingLedger` trait and persistence
- Slashing metrics (`qbind_slashing_*` counters)
- Economic rationale for penalty magnitudes

**Design Documents**:
- [QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md](../consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md) (T227)

### 2.10 Genesis & Launch

**Scope**: Genesis configuration validation and genesis hash commitment.

Genesis config (T232) defines initial network state. Genesis hash commitment (T233) prevents accidental startup with wrong genesis.

**Key audit areas**:
- `GenesisConfig` invariants (non-zero amounts, unique addresses, valid council threshold)
- `--genesis-path` requirement for MainNet (no embedded genesis)
- `--expect-genesis-hash` requirement for MainNet
- SHA3-256 hash computation over exact genesis bytes
- `ChainMeta` and chain identity

**Design Documents**:
- [QBIND_GENESIS_AND_LAUNCH_DESIGN.md](../consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md) (T232, T233)
- [QBIND_MAINNET_V0_SPEC.md §1.5, §1.6](../mainnet/QBIND_MAINNET_V0_SPEC.md#15-genesis-state--chain-id-t232)

### 2.11 Performance & PQC Cost

**Scope**: PQC cost microbenchmarks and end-to-end TPS harness.

PQC cost benchmarking (T198) documents the computational overhead. The E2E TPS harness (T234) validates end-to-end performance.

**Key audit areas**:
- ML-DSA-44 signing/verification latency
- QC aggregation cost with multiple validators
- Block commit latency under load
- Stage B parallel execution throughput
- Bandwidth consumption from PQC signature sizes

**Design Documents**:
- [T198_PQC_COST_BENCHMARKING.md](../econ/T198_PQC_COST_BENCHMARKING.md)
- [QBIND_PERF_AND_TPS_DESIGN.md](../QBIND_PERF_AND_TPS_DESIGN.md) (if present)

**Test Harnesses**:
- T234: PQC E2E performance harness (`t234_pqc_end_to_end_perf_tests.rs`)

---

## 3. Out-of-Scope / Lower Priority

The following areas are **explicitly out of scope** for this first audit pass:

| Area | Reason | Future Timeline |
| :--- | :--- | :--- |
| **Full MEV / Auction Design** | Not implemented in v0; future T24x tasks | Post-MainNet v0 |
| **Oracle / L2-Bridge Economics** | Not implemented in v0 | Post-MainNet v0 |
| **On-Chain Governance / Parameter Voting** | v0 uses off-chain council model; on-chain planned for v0.x+ | 6–18 months |
| **Smart Contracts** | v0 is transfer-only; smart contracts planned for v1+ | 12+ months |
| **Light Client Support** | Full nodes only in v0 | v1+ |
| **Cross-Shard Transactions** | Single-shard in v0 | v2+ |
| **Stake-Weighted DAG Quotas** | Post-launch enhancement | v0.x |
| **ZK L2 Integration** | Future work | v2+ |

These areas may be included in future audit engagements as they are implemented.

---

## 4. Threat Model Summary

### 4.1 Existing Threat Models

The following threat models have been developed and documented:

| Risk ID | Category | Description | Reference |
| :--- | :--- | :--- | :--- |
| **MN-R1** | Consensus Safety | Double-signing, view-change chaos, DAG/HotStuff coupling | [Audit Skeleton §3.2](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#32-mn-r1-consensus-safety--fork-risk) |
| **MN-R2** | Economic Integrity | Fee market gaming, balance integrity, eviction attacks | [Audit Skeleton §3.3](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#33-mn-r2-economic-integrity-gasfees-fee-market) |
| **MN-R4** | P2P & Eclipse | Eclipse attacks, topology attacks, liveness detection | [Audit Skeleton §3.5](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#35-mn-r4-p2p--eclipse-resistance) |
| **MN-R5** | Keys & HSM | Host compromise, remote signer compromise, HSM misconfiguration | [Audit Skeleton §3.6](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#36-mn-r5-key-management--remote-signing) |
| **MN-R9** | Slashing & PQC | Lazy verification, invalid signatures, DAG coupling violations | [Audit Skeleton §3.9](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md#39-mn-r9-slashing--pqc-misbehavior) |

### 4.2 PQC-Specific Concerns

The following concerns are specific to QBIND's PQC-only design:

| Concern | Description | Impact |
| :--- | :--- | :--- |
| **ML-DSA-44 Size/Cost** | Large signatures (2,420 bytes) and 5× verification overhead create incentives for lazy verification | Safety violations if validators skip verification |
| **Non-Standard Usage** | Any deviation from FIPS 204/203 standards could introduce vulnerabilities | Cryptographic weaknesses |
| **KEMTLS Key Schedule** | Custom KEMTLS implementation must correctly derive session keys | Transport security compromise |
| **KEMTLS Nonce Discipline** | Nonce reuse or predictability could enable attacks | Session key compromise |
| **HSM Integration Errors** | Incorrect PKCS#11 usage could lead to key leakage or signing failures | Key compromise or DoS |
| **HSM Fail-Stop Behavior** | Incorrect failure handling could leave node in inconsistent state | Safety or liveness issues |
| **Remote Signer Protocol** | MITM or replay attacks on signer protocol | Key compromise |

---

## 5. Artifacts Provided to Auditor

### 5.1 Design & Specification Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Specification** | `docs/mainnet/QBIND_MAINNET_V0_SPEC.md` | Complete MainNet architecture specification |
| **MainNet Audit Skeleton** | `docs/mainnet/QBIND_MAINNET_AUDIT_SKELETON.md` | Risk tracking and readiness checklist |
| **DAG Consensus Coupling** | `docs/mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md` | DAG–HotStuff coupling design (T188) |
| **Monetary Policy Design** | `docs/econ/QBIND_MONETARY_POLICY_DESIGN.md` | Monetary engine specification (T194) |
| **Key Management Design** | `docs/keys/QBIND_KEY_MANAGEMENT_DESIGN.md` | Key management and HSM design (T209) |
| **Governance & Upgrades** | `docs/gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md` | Governance model (T224) |
| **Slashing & PQC Offenses** | `docs/consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md` | Slashing design (T227) |
| **Genesis & Launch** | `docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` | Genesis specification (T232, T233) |
| **MainNet Runbook** | `docs/ops/QBIND_MAINNET_RUNBOOK.md` | Operational procedures |
| **Prometheus Alerts** | `docs/ops/prometheus/qbind_mainnet_alerts.example.yaml` | Alert configuration |
| **Grafana Dashboard** | `docs/ops/grafana/qbind_mainnet_dashboard.example.json` | Dashboard configuration |

### 5.2 Primary Crates for Code Review

| Crate | Path | Description |
| :--- | :--- | :--- |
| **qbind-crypto** | `crates/qbind-crypto/` | PQC primitives (ML-DSA-44, ML-KEM-768) |
| **qbind-consensus** | `crates/qbind-consensus/` | HotStuff BFT, slashing engine, key rotation |
| **qbind-ledger** | `crates/qbind-ledger/` | State persistence, slashing ledger, genesis |
| **qbind-node** | `crates/qbind-node/` | Node binary, P2P, mempool, HSM/signer |
| **qbind-gov** | `crates/qbind-gov/` | Governance envelope library (T225) |

### 5.3 Test Harnesses

| Harness | Path | Description |
| :--- | :--- | :--- |
| **T221** | `crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs` | DAG–consensus coupling cluster tests |
| **T222** | `crates/qbind-node/tests/t222_consensus_chaos_harness.rs` | Consensus chaos harness (leader crashes, message loss, partitions) |
| **T223** | `crates/qbind-node/tests/t223_stage_b_soak_harness.rs` | Stage B soak/determinism tests (100+ blocks) |
| **T234** | `crates/qbind-node/tests/t234_pqc_end_to_end_perf_tests.rs` | PQC E2E performance harness |

**Running Harnesses**:
```bash
# DAG–consensus coupling
cargo test -p qbind-node --test t221_dag_coupling_cluster_tests -- --test-threads=1

# Consensus chaos
cargo test -p qbind-node --test t222_consensus_chaos_harness -- --test-threads=1

# Stage B soak
cargo test -p qbind-node --test t223_stage_b_soak_harness -- --test-threads=1

# PQC E2E performance
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests -- --test-threads=1
```

---

## 6. Audit Tasks & Deliverables

### 6.1 Audit Tasks

The audit vendor is expected to perform the following:

| Task | Description |
| :--- | :--- |
| **Code Review** | Manual review of crates listed in §5.2, focusing on security-critical paths |
| **Threat Modeling** | Workshop and written threat model covering consensus, P2P, keys, slashing |
| **Differential Fuzzing** | Property-based testing and fuzzing where appropriate (e.g., signature parsing, mempool eviction) |
| **Adversarial Scenarios** | Attempted attacks including: DAG/consensus mismatch, P2P eclipse, lazy verification cartel, HSM failure |
| **Configuration Review** | Review of MainNet profile and `validate_mainnet_invariants()` enforcement |
| **Cryptographic Review** | Review of ML-DSA-44/ML-KEM-768 usage, KEMTLS implementation, domain separation |

### 6.2 Adversarial Scenarios

The following adversarial scenarios should be specifically evaluated:

| Scenario | Description | Expected Outcome |
| :--- | :--- | :--- |
| **DAG/Consensus Mismatch** | Proposer includes uncertified batches in proposal | Validators reject proposal; no commit |
| **P2P Eclipse** | Attacker controls all peer slots for a validator | Anti-eclipse constraints prevent; diversity enforced |
| **Lazy Verification Cartel** | Validators skip ML-DSA-44 verification | Slashing penalties make laziness unprofitable |
| **HSM Failure During Signing** | HSM becomes unreachable mid-operation | Node exits cleanly (`ExitOnFailure`); no partial state |
| **Remote Signer MITM** | Attacker intercepts remote signer traffic | KEMTLS prevents MITM; requests require authentication |
| **Genesis Hash Mismatch** | Operator starts with wrong genesis file | Node refuses to start if `--expect-genesis-hash` mismatch |
| **Key Rotation Race** | Concurrent key rotations for same validator | Only one rotation active; overlapping rotations rejected |

### 6.3 Deliverables

The audit vendor is expected to deliver:

| Deliverable | Description |
| :--- | :--- |
| **Written Audit Report** | Detailed findings with severity classification, exploitability assessment, and fix recommendations |
| **Executive Summary** | High-level summary (2–3 pages) suitable for non-technical stakeholders |
| **Threat Model Document** | Written threat model based on workshop findings |
| **Finding Severity Classification** | Findings classified as Critical, High, Medium, Low, or Informational |
| **Fix Recommendations** | Specific remediation guidance for each finding |
| **Remediation Retest** | Optional: Verification that fixes address findings (within retest window) |

### 6.4 Severity Definitions

| Severity | Definition |
| :--- | :--- |
| **Critical** | Direct loss of funds, consensus failure, or complete compromise of cryptographic security |
| **High** | Significant economic impact, denial of service, or partial security compromise |
| **Medium** | Limited impact requiring specific conditions to exploit |
| **Low** | Minor issues with negligible security impact |
| **Informational** | Best practice recommendations or documentation improvements |

---

## 7. Timeline & Process

### 7.1 Expected Timeline

| Phase | Duration | Description |
| :--- | :--- | :--- |
| **Kickoff & Onboarding** | 1 week | Project setup, codebase orientation, access provisioning |
| **Active Audit** | 6–10 weeks | Code review, threat modeling, testing, finding documentation |
| **Draft Report** | 1 week | Initial findings report delivered for review |
| **Clarification Period** | 1 week | Address questions, provide additional context |
| **Final Report** | 1 week | Final report with all findings |
| **Remediation Window** | 2–4 weeks | Team addresses findings |
| **Retest (Optional)** | 1–2 weeks | Verification of critical/high fixes |

**Total Estimated Duration**: 12–20 weeks

### 7.2 Desired Start Window

- **Ideal Start**: Post-feature-freeze, pre-MainNet code freeze
- **Target Window**: Relative to MainNet launch timeline, approximately 4–6 months before planned launch

### 7.3 Interaction Model

| Channel | Purpose |
| :--- | :--- |
| **Slack/Matrix** | Daily async communication, quick questions |
| **Weekly Check-ins** | 30–60 minute video calls for status updates and blocking issues |
| **Shared Document Space** | Finding drafts, clarification documents, and evidence |
| **Private GitHub Access** | Repository access for code review (read-only or specific branch) |

### 7.4 MainNet Launch Gate

MainNet v0 launch requires:
1. All **Critical** findings remediated
2. All **High** findings remediated OR explicitly accepted by governance with documented rationale
3. Final audit report published (redacted if necessary for security)

---

## 8. Vendor Qualification

### 8.1 Required Experience

The audit vendor must demonstrate experience in:

| Area | Requirement |
| :--- | :--- |
| **BFT Consensus** | Prior audits of HotStuff, Tendermint, or similar BFT protocols |
| **L1/L2 Blockchain** | Experience auditing Layer 1 or Layer 2 blockchain implementations |
| **Post-Quantum Cryptography** | Familiarity with lattice-based cryptography (ML-DSA, ML-KEM) or NIST PQC standards |
| **Cryptographic Protocols** | Experience with TLS, key exchange protocols, or similar |
| **HSM / Key Management** | Understanding of PKCS#11, HSM integration, or enterprise key management |
| **Rust Ecosystem** | Proficiency in Rust code review and common security patterns |

### 8.2 Preferred Qualifications

Strongly preferred (not required):

- Prior audits of DAG-based consensus (Narwhal, Bullshark, etc.)
- Experience with KEMTLS or post-quantum TLS variants
- Published research in blockchain security or PQC
- Red team or offensive security experience

### 8.3 References

Please provide:

- **Sample Reports**: 2–3 redacted sample audit reports demonstrating quality and depth
- **Client References**: 2–3 references from prior blockchain/cryptography audit engagements
- **Team Composition**: CVs or backgrounds of proposed audit team members

---

## 9. Contact & Next Steps

### 9.1 Proposal Submission

Interested vendors should submit:

1. **Statement of Work**: Proposed scope, methodology, and timeline
2. **Team Composition**: Names and backgrounds of proposed auditors
3. **Pricing**: Fixed-price or time-and-materials estimate
4. **References**: As described in §8.3
5. **Questions**: Any clarifying questions about scope or requirements

### 9.2 Evaluation Criteria

Proposals will be evaluated on:

| Criterion | Weight |
| :--- | :--- |
| **Relevant Experience** | 35% |
| **Team Qualifications** | 25% |
| **Methodology & Approach** | 20% |
| **Pricing** | 15% |
| **Availability & Timeline** | 5% |

---

## 10. Related Documents

| Document | Path |
| :--- | :--- |
| **MainNet v0 Specification** | [docs/mainnet/QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) |
| **MainNet Audit Skeleton** | [docs/mainnet/QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) |
| **MainNet Runbook** | [docs/ops/QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) |
| **Governance Design** | [docs/gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) |
| **Monetary Policy** | [docs/econ/QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) |
| **Key Management** | [docs/keys/QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) |
| **Slashing Design** | [docs/consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md](../consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md) |
| **Genesis Design** | [docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md](../consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md) |

---

*End of Document*