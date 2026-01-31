# QBIND TestNet Alpha Audit & Readiness Capsule

**Task**: T176  
**Status**: Ready  
**Date**: 2026-01-31

---

## 1. Scope & Status

### 1.1 What "TestNet Alpha" Means

TestNet Alpha is the first public test network for QBIND, extending the DevNet v0 architecture with:

- **Network Environment**: `NetworkEnvironment::Testnet` (`QBIND_TESTNET_CHAIN_ID`)
- **Execution Profile**: `ExecutionProfile::VmV0` (sequential VM execution with account balances)
- **State Persistence**: RocksDB-backed persistent account state
- **DAG Availability**: Opt-in availability certificates v1
- **Gas & Fees**: Design complete; enforcement config-gated off by default
- **P2P Networking**: LocalMesh default; P2P v1 opt-in with multi-process runbook

### 1.2 Relationship to DevNet v0 and Future Phases

| Phase | Network | Status | Relationship |
| :--- | :--- | :--- | :--- |
| **DevNet v0** | DevNet | ✅ Frozen (T161) | Baseline for TestNet Alpha; nonce-only execution |
| **TestNet Alpha** | TestNet | ✅ Feature-bounded | Extends DevNet with VM v0, persistence, DAG certs, P2P opt-in |
| **TestNet Beta** | TestNet | ⏳ Planned | Full gas enforcement, DAG default, dynamic P2P |
| **MainNet** | MainNet | ⏳ Planned | Production-ready with HSM, full security audit |

### 1.3 Auditability Statement

> **TestNet Alpha is feature-bounded and auditable, but NOT frozen.**

Unlike DevNet v0 (which is explicitly frozen), TestNet Alpha represents a **moving target** that continues to evolve. However, as of this document, the core architecture is stable enough for:

- **Security review** of VM v0, DAG availability, and P2P transport
- **Integration testing** via cluster harness and multi-process runbook
- **Performance benchmarking** via TPS scenarios

New features should target TestNet Beta or later. TestNet Alpha changes should be limited to:

- Bug fixes and stability improvements
- Documentation and observability enhancements
- Minor configuration adjustments

---

## 2. Component Summary

The following table summarizes each major component of TestNet Alpha, linking to underlying tasks and risk status.

| Component | TestNet Alpha Implementation | Key Tasks | Risk Status | Delta vs DevNet v0 |
| :--- | :--- | :--- | :--- | :--- |
| **Keys / Keystore** | EncryptedFsV1 + ValidatorSigner + RemoteSigner loopback | T143, T144, T148, T149, T153 | Mitigated | No change |
| **Consensus** | HotStuff + timeouts + parallel verify pool | T146, T147, T160 | Mitigated | No change |
| **Execution** | VM v0 (account + balance) + sequential + profiles | T163 | TA-R1 open | Nonce-only → VM v0 |
| **State Persistence** | RocksDB-backed account state with caching | T164 | TA-R2 partial | In-memory → disk |
| **Mempool (FIFO)** | InMemoryMempool with gas admission (config-gated) | T151, T168, T169 | TA-R3 partial | Fee priority opt-in |
| **DAG Mempool** | InMemoryDagMempool + availability certs v1 (opt-in) | T158, T165 | TA-R4 partial | Certs added (no consensus coupling) |
| **Gas & Fees** | Design complete; enforcement off by default | T167, T168, T169 | TA-R3 open | Design → config-gated impl |
| **Networking (LocalMesh)** | Static KEMTLS mesh (default) | T160 | Mitigated | No change |
| **Networking (P2P v1)** | TcpKemTlsP2pService + multi-process runbook (opt-in) | T172, T173, T174, T175 | TA-R5 partial | P2P transport added |
| **Observability** | Metrics for consensus, mempool, execution, DAG, P2P | T154, T155, T157, T158, T165 | Ready | Enhanced metrics |
| **Cluster Harness** | TestnetAlphaClusterHandle with TPS scenarios | T166 | Ready | New capability |

### Reference Documents

- [QBIND TestNet Alpha Specification](./QBIND_TESTNET_ALPHA_SPEC.md) — Full TestNet Alpha spec (T163–T175)
- [QBIND DevNet v0 Freeze Capsule](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet v0 baseline
- [QBIND DevNet Audit Log](../devnet/QBIND_DEVNET_AUDIT.md) — DevNet task and risk tracking
- [QBIND P2P TestNet Alpha Guide](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md) — Multi-process runbook

---

## 3. Delta vs DevNet v0

This section explicitly lists what changed from DevNet v0 to TestNet Alpha.

### 3.1 Execution: Nonce-Only → VM v0

| Aspect | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Execution Profile** | `NonceOnly` | `VmV0` |
| **Account State** | Nonce only | Nonce + Balance |
| **Transaction Semantics** | Nonce validation only | Balance transfers |
| **Parallelism** | Stage A (sender-partitioned) | Sequential (for safety) |

**Reference**: [QBIND_TESTNET_ALPHA_SPEC.md §2](./QBIND_TESTNET_ALPHA_SPEC.md)

### 3.2 State: In-Memory → RocksDB Persistence

| Aspect | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Storage Backend** | In-memory HashMap | RocksDB |
| **Durability** | Lost on restart | Persisted to disk |
| **Caching** | N/A | Write-through cache |
| **Restart Recovery** | Not supported | State survives restart |

**Reference**: [QBIND_TESTNET_ALPHA_SPEC.md §4.4](./QBIND_TESTNET_ALPHA_SPEC.md)

### 3.3 DAG: Data Structures → Availability Certificates v1

| Aspect | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **DAG Batches** | QbindBatch only | QbindBatch + BatchAck |
| **Availability Proof** | None | BatchCertificate (2f+1 acks) |
| **Consensus Coupling** | None | None (data-plane only) |
| **Domain Separation** | N/A | `QBIND:TST:BATCH_ACK:v1` |

**Reference**: [QBIND_TESTNET_ALPHA_SPEC.md §5.6](./QBIND_TESTNET_ALPHA_SPEC.md)

### 3.4 Gas & Fees: None → Design + Config-Gated Implementation

| Aspect | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Gas Model** | None | Designed (T167) |
| **Gas Enforcement** | None | Config-gated (T168), default off |
| **Fee Priority** | FIFO only | Config-gated (T169), default off |
| **Public TestNet** | N/A | Gas/fees disabled |

**Reference**: [QBIND_GAS_AND_FEES_DESIGN.md](./QBIND_GAS_AND_FEES_DESIGN.md)

### 3.5 Networking: LocalMesh Only → P2P v1 Opt-In

| Aspect | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Default Mode** | LocalMesh | LocalMesh |
| **P2P Transport** | Not available | TcpKemTlsP2pService (opt-in) |
| **Multi-Process** | Not supported | Runbook available (T175) |
| **Discovery** | Static config | Static config (dynamic planned for Beta) |

**Reference**: [QBIND_P2P_TESTNET_ALPHA_GUIDE.md](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md)

---

## 4. Threat / Risk Model (TestNet Alpha)

This section updates the DevNet v0 risk categories for TestNet Alpha's expanded attack surface.

### 4.1 Risk Summary Table

| ID | Category | Severity | Status | Mitigation Target |
| :--- | :--- | :--- | :--- | :--- |
| TA-R1 | Execution / VM | Medium | Open | TestNet Beta |
| TA-R2 | State Persistence | Medium | Partially Mitigated | TestNet Beta |
| TA-R3 | Gas / Fees | High | Open | TestNet Beta |
| TA-R4 | DAG Availability | Medium | Partially Mitigated | TestNet Beta |
| TA-R5 | P2P Networking | Medium | Partially Mitigated | TestNet Beta |
| TA-R6 | Parallelism | Low | Open | MainNet |

### 4.2 Detailed Risk Analysis

#### TA-R1: Execution / VM Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Non-determinism** | VM v0 execution may have subtle non-determinism bugs | Medium | Open |
| **State corruption** | Bugs in balance arithmetic could corrupt account state | Medium | Open |
| **Parallelism staging** | Sequential execution limits throughput; Stage B deferred | Low | Open |

**Mitigation Status**:
- ✅ VM v0 execution is single-threaded (sequential) to avoid race conditions
- ✅ All balance arithmetic uses safe integer operations (checked/saturating)
- ✅ Extensive unit tests for edge cases (t163_vm_v0_tests.rs)
- ⏳ Fuzzing and property-based testing planned for TestNet Beta

**Target Phase**: TestNet Beta (additional testing), MainNet (Stage B parallelism)

#### TA-R2: State Persistence Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Crash consistency** | State may be corrupted if node crashes mid-write | Medium | Partially Mitigated |
| **No pruning** | State grows monotonically; no garbage collection | Low | Open |
| **No snapshots** | No checkpointing for fast sync | Low | Open |

**Mitigation Status**:
- ✅ RocksDB provides crash-safe writes (WAL)
- ✅ State flushed at block boundaries (atomic per-block updates)
- ✅ Persistence tests validate restart consistency (t164_vm_persistence_tests.rs)
- ⏳ State pruning and snapshotting planned for TestNet Beta

**Target Phase**: TestNet Beta (pruning, checkpointing)

#### TA-R3: Gas / Fees Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **DoS surface** | No gas enforcement allows resource exhaustion attacks | High | Open |
| **Fee market gaming** | No fee market allows transaction spam | Medium | Open |
| **Eviction attacks** | Without fees, attackers can flood mempool | Medium | Open |

**Mitigation Status**:
- ✅ Gas model fully designed (T167)
- ✅ Gas enforcement implemented but config-gated off (T168)
- ✅ Fee-priority mempool implemented but config-gated off (T169)
- ⏳ TestNet Alpha runs without gas/fees (acceptable for limited Alpha)
- ⏳ Gas enforcement enabled by default in TestNet Beta

**Target Phase**: TestNet Beta (gas enabled by default)

#### TA-R4: DAG Availability Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Partial deployment** | DAG availability is opt-in; not exercised in production | Medium | Partially Mitigated |
| **No consensus coupling** | Certs are data-plane only; consensus ignores them | Medium | Open |
| **No fetch-on-miss** | Missing batches are ignored (no recovery) | Low | Open |

**Mitigation Status**:
- ✅ BatchAck and BatchCertificate implemented (T165)
- ✅ Domain-separated signing preimages prevent cross-chain replay
- ✅ Cluster harness can test DAG availability (T166)
- ⏳ Consensus coupling (require certs before commit) planned for Beta
- ⏳ Batch fetch protocol planned for Beta

**Target Phase**: TestNet Beta (consensus coupling, fetch protocol)

#### TA-R5: P2P Networking Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Static peers** | No dynamic discovery; topology is fixed at startup | Medium | Partially Mitigated |
| **No liveness detection** | Peers that crash are not automatically removed | Low | Open |
| **Eclipse potential** | With static peers, attacker could control all peer slots | Medium | Open |
| **Local-only testing** | Multi-machine P2P not extensively tested | Medium | Partially Mitigated |

**Mitigation Status**:
- ✅ P2P v1 transport implemented (T172)
- ✅ Consensus and DAG messages wired through P2P (T173)
- ✅ Inbound demuxer and receive path complete (T174)
- ✅ Multi-process runbook available (T175)
- ⏳ Dynamic peer discovery planned for TestNet Beta
- ⏳ Peer liveness and scoring planned for TestNet Beta

**Target Phase**: TestNet Beta (discovery, liveness, anti-eclipse)

#### TA-R6: Parallelism Risks

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Throughput ceiling** | Sequential execution limits TPS | Low | Open |
| **Stage B complexity** | Conflict-graph scheduling adds implementation risk | Low | Open |

**Mitigation Status**:
- ✅ Stage A parallelism available for nonce-only (DevNet)
- ✅ Stage B design and skeleton implemented (T171)
- ⏳ Stage B production wiring deferred to MainNet

**Target Phase**: MainNet (Stage B parallelism)

---

## 5. TestNet Alpha Readiness Checklist

This checklist defines the must-have properties for TestNet Alpha and their current status.

### 5.1 Core Functionality

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 1 | Deterministic VM v0 execution with persisted state | ✅ Ready | t163_vm_v0_tests.rs, t164_vm_persistence_tests.rs |
| 2 | Clean network environments & chain-id separation | ✅ Ready | QBIND_CHAIN_ID_AND_DOMAINS.md, T159 |
| 3 | Domain-separated signing preimages for all message types | ✅ Ready | `QBIND:TST:*:v1` tags throughout |
| 4 | RocksDB state persistence with restart recovery | ✅ Ready | t164_vm_v0_persistence_integration_tests.rs |
| 5 | DAG availability certs v1 wired and tested | ✅ Ready | t165_dag_availability_tests.rs |

### 5.2 Testing & Validation

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 6 | Cluster harness for multi-node TestNet Alpha | ✅ Ready | t166_testnet_alpha_cluster_harness.rs |
| 7 | TPS measurement scenarios | ✅ Ready | test_testnet_alpha_tps_scenario_minimal |
| 8 | State consistency after restart | ✅ Ready | test_testnet_alpha_cluster_vm_v0_fifo_restart_consistency |
| 9 | P2P mode exercised in cluster harness | ✅ Ready | test_testnet_alpha_cluster_p2p_vm_v0_fifo_smoke |

### 5.3 Observability

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 10 | Metrics for consensus, mempool, execution | ✅ Ready | T154, T155, T157 metrics |
| 11 | DAG availability metrics (acks, certs) | ✅ Ready | T165 metrics |
| 12 | P2P transport metrics (connections, bytes) | ✅ Ready | T172 metrics |

### 5.4 Documentation

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 13 | TestNet Alpha specification complete | ✅ Ready | QBIND_TESTNET_ALPHA_SPEC.md |
| 14 | Gas & fees design documented | ✅ Ready | QBIND_GAS_AND_FEES_DESIGN.md |
| 15 | P2P multi-process runbook | ✅ Ready | QBIND_P2P_TESTNET_ALPHA_GUIDE.md |
| 16 | Audit & readiness capsule | ✅ Ready | This document |

### 5.5 Out-of-Scope for TestNet Alpha

The following items are explicitly **NOT** required for TestNet Alpha readiness:

| Item | Target Phase |
| :--- | :--- |
| Gas enforcement enabled by default | TestNet Beta |
| DAG as default mempool | TestNet Beta |
| Dynamic P2P discovery | TestNet Beta |
| Stage B parallel execution | MainNet |
| HSM / remote signer production mode | MainNet |
| Full security audit | MainNet |

---

## 6. Roadmap: TestNet Alpha → TestNet Beta → MainNet

This section summarizes what remains out-of-scope for Alpha and the explicit goals for future phases.

### 6.1 TestNet Beta Goals

| Work Item | Description | Reference |
| :--- | :--- | :--- |
| **Gas Enforcement Default** | Enable gas limits and fee deduction by default | [QBIND_GAS_AND_FEES_DESIGN.md §8](./QBIND_GAS_AND_FEES_DESIGN.md) |
| **Fee Market Enabled** | Enable fee-priority mempool ordering | [QBIND_GAS_AND_FEES_DESIGN.md §6](./QBIND_GAS_AND_FEES_DESIGN.md) |
| **DAG as Default** | Switch from FIFO to DAG mempool as default | [QBIND_DAG_MEMPOOL_DESIGN.md §6](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) |
| **DAG Consensus Coupling** | Require availability certs before commit | [QBIND_DAG_MEMPOOL_DESIGN.md §3](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) |
| **Dynamic P2P Discovery** | Basic peer exchange and discovery | [QBIND_P2P_NETWORK_DESIGN.md §4](../network/QBIND_P2P_NETWORK_DESIGN.md) |
| **Peer Liveness & Scoring** | Detect and remove unresponsive peers | [QBIND_P2P_NETWORK_DESIGN.md §6](../network/QBIND_P2P_NETWORK_DESIGN.md) |
| **State Pruning** | Garbage collection for old state | Future task |
| **Multi-Machine Staging** | Distributed test deployments | Future task |

### 6.2 MainNet Goals

| Work Item | Description | Reference |
| :--- | :--- | :--- |
| **Stage B Parallelism** | Conflict-graph-based VM parallelism | [QBIND_PARALLEL_EXECUTION_DESIGN.md §4.2](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) |
| **Full DoS Protection** | Rate limiting, stake-weighted quotas | [QBIND_P2P_NETWORK_DESIGN.md §6](../network/QBIND_P2P_NETWORK_DESIGN.md) |
| **Anti-Eclipse Measures** | Peer diversity requirements | [QBIND_P2P_NETWORK_DESIGN.md §6](../network/QBIND_P2P_NETWORK_DESIGN.md) |
| **HSM Production Mode** | Real HSM integration for signing | [QBIND_DEVNET_V0_FREEZE.md §4.4](../devnet/QBIND_DEVNET_V0_FREEZE.md) |
| **Key Rotation** | Validator key rotation mechanism | Future task |
| **Full Security Audit** | External security audit | Future task |
| **Smart Contracts** | Full EVM or custom VM support | Future task |

### 6.3 Evolution Path

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  DevNet v0      │     │  TestNet Alpha  │     │  TestNet Beta   │
│  (Frozen)       │────►│  (Current)      │────►│  (Planned)      │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ • Nonce-only    │     │ • VM v0         │     │ • Gas enforced  │
│ • In-memory     │     │ • RocksDB       │     │ • Fee market    │
│ • No DAG certs  │     │ • DAG certs v1  │     │ • DAG default   │
│ • Static mesh   │     │ • P2P opt-in    │     │ • Dynamic P2P   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │    MainNet      │
                                               │    (Planned)    │
                                               ├─────────────────┤
                                               │ • Stage B ‖exec │
                                               │ • Full DoS prot │
                                               │ • HSM prod      │
                                               │ • Audit complete│
                                               └─────────────────┘
```

---

## 7. Appendix: Task Index (T163–T175)

This table maps TestNet Alpha tasks to their areas and documentation coverage.

| Task | Area | Summary | Audit Section |
| :--- | :--- | :--- | :--- |
| **T163** | Execution | Minimal VM v0 (account + balance) | §2, §3.1 |
| **T164** | Execution | RocksDB state persistence | §2, §3.2 |
| **T165** | Mempool / DAG | DAG availability certificates v1 | §2, §3.3, §4.2 (TA-R4) |
| **T166** | Testing | TestNet Alpha cluster harness | §2, §5.2 |
| **T167** | Gas / Fees | Gas and fee model design | §2, §3.4, §4.2 (TA-R3) |
| **T168** | Gas / Fees | Config-gated gas enforcement | §2, §3.4, §4.2 (TA-R3) |
| **T169** | Gas / Fees | Fee-priority mempool (config-gated) | §2, §3.4, §4.2 (TA-R3) |
| **T170** | Networking | P2P network design specification | §4.2 (TA-R5), §6 |
| **T171** | Execution | Stage B parallel execution skeleton | §4.2 (TA-R6) |
| **T172** | Networking | P2P transport v1 (TcpKemTlsP2pService) | §2, §3.5, §4.2 (TA-R5) |
| **T173** | Networking | Consensus/DAG messages over P2P | §2, §3.5 |
| **T174** | Networking | P2P receive path + cluster harness P2P mode | §2, §3.5, §5.2 |
| **T175** | Networking | qbind-node P2P wiring + multi-process runbook | §2, §3.5, §5.4 |
| **T176** | Documentation | This audit & readiness capsule | This document |

---

## 8. Appendix: Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| TestNet Alpha Spec | [QBIND_TESTNET_ALPHA_SPEC.md](./QBIND_TESTNET_ALPHA_SPEC.md) | Full TestNet Alpha architecture |
| Gas and Fees Design | [QBIND_GAS_AND_FEES_DESIGN.md](./QBIND_GAS_AND_FEES_DESIGN.md) | Gas and fee model (T167) |
| DevNet v0 Freeze | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet v0 baseline |
| DevNet Audit Log | [QBIND_DEVNET_AUDIT.md](../devnet/QBIND_DEVNET_AUDIT.md) | DevNet task tracking |
| Parallel Execution Design | [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) | Stage A/B parallelism |
| DAG Mempool Design | [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) | DAG architecture |
| P2P Network Design | [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) | P2P networking (T170) |
| P2P TestNet Alpha Guide | [QBIND_P2P_TESTNET_ALPHA_GUIDE.md](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md) | Multi-process runbook (T175) |
| Chain ID and Domains | [QBIND_CHAIN_ID_AND_DOMAINS.md](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) | Domain separation |

---

*End of Document*