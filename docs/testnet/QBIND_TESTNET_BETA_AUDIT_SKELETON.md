# QBIND TestNet Beta Audit Skeleton

**Task**: T178  
**Status**: Working Skeleton (Not Ready)  
**Date**: 2026-01-31

---

## 1. Scope

This document tracks risks, mitigations, and readiness for **TestNet Beta** as defined in [QBIND_TESTNET_BETA_SPEC.md](./QBIND_TESTNET_BETA_SPEC.md).

> **⚠️ TestNet Beta is not ready yet. This document is a working skeleton that will be filled in as Beta features are implemented and validated.**

### 1.1 Purpose

This skeleton serves as:

1. **Risk Tracker**: Forward-looking identification of Beta-specific risks
2. **Readiness Checklist**: Tracking requirements for Beta launch
3. **Audit Framework**: Structure for the eventual full `QBIND_TESTNET_BETA_AUDIT.md`

### 1.2 Relationship to Alpha Audit

Many underlying mitigations from TestNet Alpha carry forward to Beta:

- VM property tests (T177)
- DevNet parallel verify pool
- RocksDB crash safety
- Domain-separated signing preimages

However, Beta introduces **new attack surfaces**:

- Gas enforcement enabled by default
- Fee market enabled by default
- DAG mempool as default data plane
- P2P networking as default transport

**Reference**: [QBIND_TESTNET_ALPHA_AUDIT.md](./QBIND_TESTNET_ALPHA_AUDIT.md) for Alpha risk analysis.

---

## 2. Component / Risk Table

### 2.1 Risk Summary

| ID | Category | Severity | Status | Spec Section |
| :--- | :--- | :--- | :--- | :--- |
| **TB-R1** | Execution & VM | Medium | Partially Mitigated (T179) | [§2](./QBIND_TESTNET_BETA_SPEC.md#2-execution--state) |
| **TB-R2** | State Persistence & Growth | Medium | Planned | [§2.2](./QBIND_TESTNET_BETA_SPEC.md#22-state-persistence) |
| **TB-R3** | Gas / Fees & Fee Market | High | Partially Mitigated (T179) | [§3](./QBIND_TESTNET_BETA_SPEC.md#3-gas--fees-beta-defaults) |
| **TB-R4** | DAG as Default | Medium | Planned | [§4](./QBIND_TESTNET_BETA_SPEC.md#4-mempool--dag) |
| **TB-R5** | P2P & Topology | Medium | Planned | [§5](./QBIND_TESTNET_BETA_SPEC.md#5-networking--p2p) |
| **TB-R6** | Ops & Observability | Low | Planned | [§7](./QBIND_TESTNET_BETA_SPEC.md#7-operational-profiles--cli-defaults) |

### 2.2 Detailed Risk Analysis

---

#### TB-R1: Execution & VM

**Category**: Execution layer behavior under Beta configuration (gas-on, higher load)

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Gas-on execution bugs** | New failure modes (out-of-gas, fee deduction) may introduce bugs not covered by existing tests | Medium | Partially Mitigated |
| **Non-determinism under load** | Higher transaction volume with gas enforcement may expose latent non-determinism | Medium | Partially Mitigated |
| **State corruption** | Fee deduction logic errors could corrupt account balances | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ T177 property-based tests validate core VM v0 invariants (Alpha)
- ✅ Sequential execution prevents race conditions
- ✅ **T179**: Gas-enabled property tests now cover gas/fee accounting:
  - `t179_vm_v0_gas_proptests.rs`: Ledger-level gas property tests verifying:
    - G1: No overflow/underflow under gas-on execution
    - G2: Balance + burned fees conservation
    - G3: Nonce monotonicity with gas-on
    - G4: Failed transactions don't consume fees
    - G5: Block gas limit is respected
  - `t179_gas_pipeline_proptests.rs`: Node-level gas pipeline tests
- ✅ **T180**: Beta configuration preset (`NodeConfig::testnet_beta_preset()`) ensures gas-on is explicitly set and tested in cluster scenarios

**Planned Mitigations**:
- [x] Extend T177 property tests to cover gas-enabled scenarios (T179)
- [x] Beta configuration profile with gas-on defaults (T180)
- [ ] Fuzzing with gas-limit edge cases
- [ ] Stress testing under high TPS with gas enforcement

**Target Phase**: TestNet Beta implementation

---

#### TB-R2: State Persistence & Growth

**Category**: RocksDB storage durability, growth, and operational concerns

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **State growth** | No pruning means state grows monotonically; disk exhaustion risk | Medium | Planned |
| **No snapshots** | No checkpointing for fast sync or state recovery | Low | Planned |
| **Crash consistency** | Edge cases in crash-during-write scenarios | Low | Partially Mitigated |

**Current Mitigations**:
- ✅ RocksDB provides crash-safe writes via WAL (Alpha)
- ✅ State flushed at block boundaries (Alpha)
- ✅ Persistence tests validate restart consistency (T164)

**Planned Mitigations**:
- [ ] State pruning implementation
- [ ] Snapshot/checkpoint mechanism
- [ ] State size monitoring and alerts

**Target Phase**: TestNet Beta (pruning), MainNet (snapshots)

---

#### TB-R3: Gas / Fees & Fee Market

**Category**: DoS resistance, fee market fairness, economic attack vectors

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Fee market gaming** | Simple priority ordering may be gameable; front-running possible | High | Open |
| **Gas limit manipulation** | Attackers may craft transactions to maximize gas usage | Medium | Partially Mitigated |
| **Eviction attacks** | Attackers may flood mempool to evict legitimate low-fee txs | Medium | Open |
| **Balance draining** | Bugs in fee deduction could drain accounts unexpectedly | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ Gas model fully designed (T167)
- ✅ Gas enforcement implemented and config-gated (T168)
- ✅ Fee-priority mempool implemented and config-gated (T169)
- ✅ Mempool admission checks balance sufficiency
- ✅ **T179**: Property tests for fee deduction correctness:
  - `t179_vm_v0_gas_proptests.rs`: Validates balance + fee conservation, no fee charge for failed txs
  - `t179_gas_pipeline_proptests.rs`: Validates mempool gas checks and block gas limit enforcement
- ✅ **T180**: Beta preset enables fee-priority by default, with cluster tests exercising gas+fee scenarios

**Planned Mitigations**:
- [x] Property tests for fee deduction correctness (T179)
- [x] Beta configuration profile with fee-priority enabled by default (T180)
- [ ] Mempool eviction rate limiting
- [ ] Fee market analysis and tuning
- [ ] EIP-1559-style base fee (MainNet consideration)

**Target Phase**: TestNet Beta

---

#### TB-R4: DAG as Default

**Category**: DAG availability enforcement, consensus coupling, data plane reliability

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Availability enforcement gaps** | Certs are data-plane only; consensus doesn't require them | Medium | Planned |
| **No fetch-on-miss** | Missing batches are ignored; data availability holes possible | Medium | Planned |
| **Certificate aggregation overhead** | No signature aggregation; large certificate sizes | Low | Planned |
| **Coupling complexity** | Consensus coupling adds implementation risk | Medium | Planned |

**Current Mitigations**:
- ✅ BatchAck and BatchCertificate implemented (T165)
- ✅ Domain-separated signing preimages prevent cross-chain replay
- ✅ Cluster harness exercises DAG availability (T166)
- ✅ **T180**: Beta preset sets DAG as default mempool mode (`mempool_mode = Dag`); cluster tests validate DAG-enabled scenarios

**Planned Mitigations**:
- [x] Beta configuration profile with DAG as default mempool (T180)
- [ ] Batch fetch protocol for missing batches
- [ ] Consensus rule: require certs before commit
- [ ] Certificate aggregation efficiency improvements
- [ ] DAG metrics and alerting

**Target Phase**: TestNet Beta (fetch, coupling)

---

#### TB-R5: P2P & Topology

**Category**: P2P network resilience, topology attacks, multi-region concerns

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Eclipse attacks** | Static peers allow attackers to control all peer slots | Medium | Planned |
| **No discovery** | Validators cannot find new peers if configured ones fail | Medium | Planned |
| **Liveness detection gaps** | Crashed peers not automatically removed | Low | Planned |
| **Multi-region latency** | P2P not optimized for cross-region deployments | Low | Planned |

**Current Mitigations**:
- ✅ P2P v1 transport implemented (T172)
- ✅ Consensus and DAG messages wired through P2P (T173, T174)
- ✅ Multi-process runbook available (T175)
- ✅ KEMTLS encryption on all connections
- ✅ **T180**: Beta preset sets P2P as default network mode (`network_mode = P2p`); ignored P2P smoke test available for manual validation

**Planned Mitigations**:
- [x] Beta configuration profile with P2P as default (T180)
- [ ] Basic peer discovery protocol
- [ ] Peer liveness scoring and eviction
- [ ] Minimum peer diversity requirements
- [ ] Connection retry with backoff

**Target Phase**: TestNet Beta (discovery, liveness)

---

#### TB-R6: Ops & Observability

**Category**: Operational tooling, monitoring, incident response

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Insufficient metrics** | Beta-specific metrics (gas, fees, DAG, P2P) may be incomplete | Low | Planned |
| **No alerting** | No automated alerting for Beta operational issues | Low | Planned |
| **Missing runbooks** | Operational procedures for Beta not documented | Low | Planned |

**Current Mitigations**:
- ✅ Metrics for consensus, mempool, execution, DAG, P2P (Alpha)
- ✅ P2P multi-process runbook (T175)
- ✅ Cluster harness for testing (T166)

**Planned Mitigations**:
- [ ] Gas/fee-specific metrics (gas used, fees burned)
- [ ] DAG health metrics (cert formation rate, pending batches)
- [ ] P2P topology metrics (peer diversity, connection health)
- [ ] Beta operational runbook

**Target Phase**: TestNet Beta

---

## 3. Readiness Checklist

### 3.1 Core Functionality

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 1 | Gas enforcement enabled by default | ✅ Ready | T180: `NodeConfig::testnet_beta_preset()` |
| 2 | Fee-priority mempool enabled by default | ✅ Ready | T180: `NodeConfig::testnet_beta_preset()` |
| 3 | DAG mempool as default | ✅ Ready | T180: `NodeConfig::testnet_beta_preset()` |
| 4 | P2P networking as default | ✅ Ready | T180: `NodeConfig::testnet_beta_preset()` |
| 5 | v0/v1 payload compatibility | ✅ Ready | T168 implementation |
| 6 | Configuration profile CLI flag | ✅ Ready | T180: `--profile testnet-beta` |

### 3.2 Testing & Validation

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 7 | Gas-enabled property tests | ✅ Ready | T179: `t179_vm_v0_gas_proptests.rs` |
| 8 | Fee market stress tests | ⏳ Planned | Future task |
| 9 | DAG-default cluster tests | ✅ Ready | T180: `test_testnet_beta_cluster_fifo_fallback_smoke` |
| 10 | P2P-default cluster tests | ✅ Ready | T174, T175 tests; T180 `#[ignore]` P2P test |
| 11 | Multi-machine deployment test | ⏳ Planned | Future task |
| 12 | Beta config spec compliance test | ✅ Ready | T180: `test_testnet_beta_cluster_config_matches_spec` |

### 3.3 Documentation

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 13 | Beta specification | ✅ Ready | `QBIND_TESTNET_BETA_SPEC.md` (updated T180) |
| 14 | Beta audit skeleton | ✅ Ready | This document (updated T180) |
| 15 | Beta operational runbook | ⏳ Planned | Future task |
| 16 | Migration guide (Alpha → Beta) | ⏳ Planned | Future task |

---

## 4. Linkage to Alpha Audit

### 4.1 Inherited Mitigations

The following mitigations from TestNet Alpha carry forward to Beta:

| Alpha Risk | Mitigation | Beta Status |
| :--- | :--- | :--- |
| TA-R1 (Execution/VM) | T177 property tests | Applies to non-gas scenarios |
| TA-R2 (State Persistence) | RocksDB + crash tests | Fully inherited |
| TA-R4 (DAG Availability) | T165 certs | Strengthened (certs default) |
| TA-R5 (P2P Networking) | T172-T175 implementation | Strengthened (P2P default) |

### 4.2 New Beta Surfaces

The following are **new** attack surfaces introduced in Beta:

| Beta Risk | New Surface | Alpha Equivalent |
| :--- | :--- | :--- |
| TB-R1 | Gas-on execution | TA-R1 (partial) |
| TB-R3 | Fee market enabled | TA-R3 (design only in Alpha) |
| TB-R4 | DAG default mode | TA-R4 (opt-in in Alpha) |
| TB-R5 | P2P default mode | TA-R5 (opt-in in Alpha) |

### 4.3 Reference

For Alpha-specific risks and their detailed analysis, see [QBIND_TESTNET_ALPHA_AUDIT.md](./QBIND_TESTNET_ALPHA_AUDIT.md).

---

## 5. Future Work

This skeleton will be converted into a full `QBIND_TESTNET_BETA_AUDIT.md` once Beta tasks start landing:

1. **TB-R* status updates**: Mark risks as mitigated when implementations land
2. **Readiness checklist updates**: Mark requirements as ready when validated
3. **Testing evidence**: Link to specific test files and results
4. **Operational procedures**: Add incident response and monitoring guidance

---

## 6. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| TestNet Beta Spec | [QBIND_TESTNET_BETA_SPEC.md](./QBIND_TESTNET_BETA_SPEC.md) | Beta architecture and requirements |
| TestNet Alpha Spec | [QBIND_TESTNET_ALPHA_SPEC.md](./QBIND_TESTNET_ALPHA_SPEC.md) | Alpha architecture baseline |
| TestNet Alpha Audit | [QBIND_TESTNET_ALPHA_AUDIT.md](./QBIND_TESTNET_ALPHA_AUDIT.md) | Alpha risk and readiness |
| Gas and Fees Design | [QBIND_GAS_AND_FEES_DESIGN.md](./QBIND_GAS_AND_FEES_DESIGN.md) | Gas and fee specification |
| DAG Mempool Design | [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) | DAG architecture |
| P2P Network Design | [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) | P2P networking architecture |
| DevNet v0 Freeze | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet v0 baseline |

---

*End of Document*