# QBIND MainNet v0 Audit & Readiness Capsule

**Task**: T184  
**Status**: Working Document (Not Ready)  
**Date**: 2026-02-02

---

## 1. Scope & Status

### 1.1 What This Document Tracks

This document is the **canonical place for MainNet v0 readiness tracking**. It covers:

- Risk categories specific to MainNet v0
- Readiness checklist with ~25 must-have items
- Task mapping from DevNet, TestNet Alpha, TestNet Beta to MainNet
- Mitigation status for each identified risk

> **⚠️ MainNet v0 is NOT ready yet.** This document tracks what must be completed before launch.

### 1.2 MainNet v0 Definition

MainNet v0 is the **first production, economic-value-carrying network** for QBIND:

- **Network Environment**: `NetworkEnvironment::Mainnet` (`QBIND_MAINNET_CHAIN_ID`)
- **Economic Value**: Real assets at stake
- **Security Bar**: External audit required before launch
- **Operational Bar**: HSM support, monitoring, incident response

### 1.3 Relationship to Prior Phases

| Phase | Status | Audit Document |
| :--- | :--- | :--- |
| **DevNet v0** | ✅ Frozen | [QBIND_DEVNET_AUDIT.md](../devnet/QBIND_DEVNET_AUDIT.md) |
| **TestNet Alpha** | ✅ Feature-bounded | [QBIND_TESTNET_ALPHA_AUDIT.md](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) |
| **TestNet Beta** | ✅ Profile Implemented | [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md) |
| **MainNet v0** | ⏳ Not Ready | **This document** |

### 1.4 Maintenance Instructions

- **Append new tasks** to the Task Index (§5)
- **Update risk status** when mitigations land
- **Update readiness checklist** as items are completed
- **Cross-reference** from spec and other audit docs

---

## 2. Component Summary Table

| Area | Related Tasks | Risk Status | Notes |
| :--- | :--- | :--- | :--- |
| **Execution & VM** | T163, T164, T171, T177, T179 | Partially Mitigated | Stage B needs production wiring |
| **State Persistence & Growth** | T164 | Partially Mitigated | Pruning & snapshots pending |
| **Gas/Fees & Fee Market** | T167, T168, T169, T179, T181 | Partially Mitigated | Hybrid fee distribution pending |
| **Mempool & DAG** | T158, T165, T182, T183 | Partially Mitigated | Consensus coupling pending |
| **Networking / P2P** | T170, T172, T173, T174, T175 | Partially Mitigated | Discovery, anti-eclipse pending |
| **Keys & Remote Signer / HSM** | T143, T144, T148, T149 | Open | HSM production integration pending |
| **Observability & Ops** | T154, T155, T157, T158 | Partially Mitigated | MainNet runbooks pending |
| **Governance / Upgrades** | — | Open | Not implemented |

---

## 3. Risk / Threat Categories

### 3.1 Risk Summary Table

| ID | Category | Severity | Status | Spec Section |
| :--- | :--- | :--- | :--- | :--- |
| **MN-R1** | Consensus Safety & Fork Risk | Critical | Open | [Spec §6.3](./QBIND_MAINNET_V0_SPEC.md#63-dag-availability-and-consensus-coupling) |
| **MN-R2** | Economic Integrity (gas/fees) | High | Partially Mitigated | [Spec §3](./QBIND_MAINNET_V0_SPEC.md#3-gas--fees) |
| **MN-R3** | State Growth & Data Availability | Medium | Open | [Spec §2.4](./QBIND_MAINNET_V0_SPEC.md#24-state-growth-management) |
| **MN-R4** | P2P & Eclipse Resistance | High | Partially Mitigated | [Spec §5](./QBIND_MAINNET_V0_SPEC.md#5-networking--p2p) |
| **MN-R5** | Key Management & Remote Signing | Critical | Open | [Spec §6.5](./QBIND_MAINNET_V0_SPEC.md#65-key-management-and-remote-signer--hsm) |
| **MN-R6** | Operational & Monitoring Gaps | Medium | Partially Mitigated | [Spec §7](./QBIND_MAINNET_V0_SPEC.md#7-operational-profiles--cli-defaults) |

---

### 3.2 MN-R1: Consensus Safety & Fork Risk

**Category**: Consensus-level safety and liveness in production environment

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Fork on consensus coupling** | DAG consensus coupling is new; may introduce consensus bugs | Critical | Open |
| **Availability certificate bugs** | Invalid/forged certs could cause consensus divergence | High | Partially Mitigated |
| **HotStuff safety violations** | Bugs in 3-chain commit rule could cause safety failures | Critical | Mitigated (DevNet) |
| **View-change liveness** | Leader failure could stall consensus | Medium | Mitigated (DevNet) |

**Current Mitigations**:
- ✅ HotStuff BFT with 3-chain commit rule (DevNet)
- ✅ Parallel verify pool for signature verification (DevNet)
- ✅ Domain-separated signing preimages (T159)
- ✅ DAG availability certificates v1 (T165)
- ⏳ Consensus coupling to DAG pending

**Additional MainNet Requirements**:
- [ ] Consensus coupling implementation and testing
- [ ] Formal verification of consensus rules (optional but recommended)
- [ ] Chaos testing for view-change scenarios
- [ ] External security audit of consensus path

**Target Phase**: MainNet v0 (blocking)

---

### 3.3 MN-R2: Economic Integrity (Gas/Fees, Fee Market)

**Category**: Economic attacks, fee market manipulation, balance integrity

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Fee market gaming** | Priority fee model may be gameable; front-running possible | High | Partially Mitigated |
| **Balance draining** | Bugs in fee deduction could drain accounts | High | Partially Mitigated |
| **Proposer reward manipulation** | Proposer could game fee distribution | Medium | Open |
| **Gas limit manipulation** | Attackers craft txs to maximize gas | Medium | Partially Mitigated |
| **Eviction attacks** | Flood mempool to evict legitimate txs | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ Gas model designed (T167)
- ✅ Gas enforcement implemented (T168)
- ✅ Fee-priority mempool implemented (T169)
- ✅ Gas property tests (T179)
- ✅ Fee-market cluster tests (T181)
- ⏳ Hybrid fee distribution pending

**Additional MainNet Requirements**:
- [ ] Hybrid fee distribution (burn + proposer) implementation
- [ ] Fee market analysis under adversarial conditions
- [ ] Mempool eviction rate limiting
- [ ] External audit of fee accounting code

**Target Phase**: MainNet v0 (blocking)

---

### 3.4 MN-R3: State Growth & Data Availability

**Category**: State size, pruning, snapshots, data availability

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **State bloat** | Unbounded state growth exhausts disk | Medium | Open |
| **No pruning** | Old state retained indefinitely | Medium | Open |
| **No snapshots** | No fast sync for new nodes | Medium | Open |
| **DAG availability holes** | Missing batches despite fetch-on-miss | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ RocksDB crash-safe persistence (T164)
- ✅ Fetch-on-miss v0 (T182, T183)
- ⏳ State pruning pending
- ⏳ State snapshots pending

**Additional MainNet Requirements**:
- [ ] State pruning implementation
- [ ] Snapshot/checkpoint mechanism
- [ ] State size monitoring and alerting
- [ ] Archival node support

**Target Phase**: MainNet v0 (blocking for pruning; snapshots can be v0.x)

---

### 3.5 MN-R4: P2P & Eclipse Resistance

**Category**: Network topology attacks, peer isolation, DoS

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Eclipse attacks** | Attacker controls all validator peer slots | High | Partially Mitigated |
| **No dynamic discovery** | Validators cannot find new peers if configured ones fail | High | Open |
| **Sybil attacks** | Attacker creates many fake nodes | High | Mitigated (permissioned) |
| **Liveness detection gaps** | Crashed peers not automatically removed | Medium | Open |
| **Multi-region latency** | P2P not optimized for cross-region | Low | Open |

**Current Mitigations**:
- ✅ P2P v1 transport (T172)
- ✅ KEMTLS encryption (ML-KEM-768)
- ✅ Permissioned validator set
- ✅ Per-peer rate limiting
- ⏳ Dynamic peer discovery pending
- ⏳ Peer liveness scoring pending
- ⏳ Anti-eclipse enforcement pending

**Additional MainNet Requirements**:
- [ ] Dynamic peer discovery protocol
- [ ] Peer liveness scoring and eviction
- [ ] Anti-eclipse constraints (ASN diversity, IP range limits)
- [ ] Multi-region validation testing

**Target Phase**: MainNet v0 (blocking)

---

### 3.6 MN-R5: Key Management & Remote Signing

**Category**: Validator key security, HSM integration, key rotation

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Key compromise** | Compromised signing key allows forgery | Critical | Open |
| **No HSM support** | Keys stored on disk vulnerable to theft | High | Open |
| **Loopback signer in prod** | Test signer used in production | High | Open |
| **Key rotation failures** | Unable to rotate compromised key | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ EncryptedFsV1 keystore (encrypted at rest)
- ✅ Key separation (consensus vs network keys)
- ✅ RemoteSigner interface (loopback for testing)
- ⏳ HSM production integration pending

**Additional MainNet Requirements**:
- [ ] HSM production integration (PKCS#11 or similar)
- [ ] Key rotation procedures documented
- [ ] Compromised key handling procedures
- [ ] External audit of key management code

**Target Phase**: MainNet v0 (blocking)

---

### 3.7 MN-R6: Operational & Monitoring Gaps

**Category**: Observability, incident response, operational tooling

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Insufficient metrics** | Missing metrics for MainNet operations | Medium | Partially Mitigated |
| **No alerting** | No automated alerting for issues | Medium | Open |
| **Missing runbooks** | No documented procedures for incidents | Medium | Open |
| **No dashboards** | No operational dashboards | Low | Open |

**Current Mitigations**:
- ✅ Metrics for consensus, mempool, execution, DAG, P2P
- ✅ P2P multi-process runbook (T175)
- ⏳ MainNet operational runbook pending
- ⏳ Alerting integration pending

**Additional MainNet Requirements**:
- [ ] MainNet operational runbook
- [ ] Prometheus/Grafana alerting integration
- [ ] Operational dashboards
- [ ] Incident response procedures

**Target Phase**: MainNet v0 (blocking for runbook; dashboards can be v0.x)

---

## 4. Readiness Checklist

This checklist defines the **MUST-HAVE items** for MainNet v0 launch. Each item must be testable/verifiable.

### 4.1 Execution & VM

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 1 | VM v0 execution produces deterministic state | ✅ Ready | T177 property tests |
| 2 | Gas-enabled property tests pass in CI (G1-G5) | ✅ Ready | `t179_vm_v0_gas_proptests.rs` |
| 3 | Balance + fee conservation verified | ✅ Ready | G2 property test |
| 4 | Stage B parallel execution skeleton tested | ✅ Ready | T171 tests |
| 5 | Stage B production wiring complete | ⏳ Pending | Future task |
| 6 | Stage B vs sequential determinism verified | ⏳ Pending | Future task |

### 4.2 State Persistence & Growth

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 7 | RocksDB persistence survives node restart | ✅ Ready | T164 tests |
| 8 | State pruning implemented and configurable | ⏳ Pending | Future task |
| 9 | State size monitoring metrics available | ⏳ Pending | Future task |

### 4.3 Gas/Fees & Fee Market

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 10 | Gas enforcement cannot be disabled on MainNet | ⏳ Pending | Future task |
| 11 | Fee-priority mempool is default and required | ✅ Ready | T169, T180 |
| 12 | Hybrid fee distribution (burn + proposer) implemented | ⏳ Pending | Future task |
| 13 | Fee-market cluster tests pass | ✅ Ready | `test_testnet_beta_fee_market_*` |

### 4.4 Mempool & DAG

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 14 | DAG mempool is only mode for MainNet validators | ⏳ Pending | Future task |
| 15 | DAG availability certificates enforced by consensus | ⏳ Pending | Future task |
| 16 | Proposals only commit certified batches | ⏳ Pending | Future task |
| 17 | Fetch-on-miss recovers missing batches | ✅ Ready | T182, T183 tests |
| 18 | Fee-aware eviction implemented | ✅ Ready | T169 |

### 4.5 Networking / P2P

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 19 | P2P transport is only mode for MainNet validators | ⏳ Pending | Future task |
| 20 | Dynamic peer discovery protocol implemented | ⏳ Pending | Future task |
| 21 | Peer liveness scoring removes unresponsive peers | ⏳ Pending | Future task |
| 22 | Anti-eclipse: no single peer can trivially eclipse 1/3+ validators | ⏳ Pending | Future task |
| 23 | P2P topology tests demonstrate peer diversity | ⏳ Pending | Future task |

### 4.6 Keys & HSM

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 24 | HSM production integration available | ⏳ Pending | Future task |
| 25 | Loopback signer rejected for MainNet profile | ⏳ Pending | Future task |
| 26 | Key rotation procedures documented | ⏳ Pending | Future task |

### 4.7 Operations & Security

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 27 | MainNet configuration profile implemented | ⏳ Pending | Future task |
| 28 | MainNet operational runbook complete | ⏳ Pending | Future task |
| 29 | External security audit completed | ⏳ Pending | External |
| 30 | All MainNet-blocking issues resolved | ⏳ Pending | This checklist |

### 4.8 Readiness Summary

| Category | Ready | Pending | Total |
| :--- | :--- | :--- | :--- |
| Execution & VM | 4 | 2 | 6 |
| State Persistence | 1 | 2 | 3 |
| Gas/Fees | 2 | 2 | 4 |
| Mempool & DAG | 2 | 3 | 5 |
| Networking / P2P | 0 | 5 | 5 |
| Keys & HSM | 0 | 3 | 3 |
| Operations | 0 | 4 | 4 |
| **Total** | **9** | **21** | **30** |

---

## 5. Roadmap and Task Mapping

### 5.1 DevNet Tasks (T143+)

| Task | Area | Summary | MainNet Relevance |
| :--- | :--- | :--- | :--- |
| T143 | Keys | ML-DSA-44 keystore | ✅ Foundation |
| T144 | Keys | EncryptedFsV1 keystore | ✅ Foundation |
| T146 | Consensus | HotStuff BFT core | ✅ Foundation |
| T147 | Consensus | Timeouts + parallel verify | ✅ Foundation |
| T148 | Keys | ValidatorSigner abstraction | ✅ Foundation |
| T149 | Keys | RemoteSigner interface | ✅ Foundation |
| T150 | Execution | Nonce execution engine | ✅ Foundation |
| T155 | Execution | Async execution pipeline | ✅ Foundation |
| T158 | Mempool | DAG mempool v0 | ✅ Foundation |
| T159 | Domain | Chain ID + domain separation | ✅ Foundation |
| T160 | Testing | DevNet cluster harness | ✅ Foundation |
| T161 | Freeze | DevNet v0 freeze | ✅ Milestone |

### 5.2 TestNet Alpha Tasks (T163–T177)

| Task | Area | Summary | MainNet Risk Category |
| :--- | :--- | :--- | :--- |
| T163 | Execution | VM v0 (accounts + balances) | MN-R2 |
| T164 | State | RocksDB persistence | MN-R3 |
| T165 | DAG | Availability certificates v1 | MN-R1, MN-R3 |
| T166 | Testing | TestNet Alpha cluster harness | — |
| T167 | Gas/Fees | Gas and fee model design | MN-R2 |
| T168 | Gas/Fees | Gas enforcement implementation | MN-R2 |
| T169 | Gas/Fees | Fee-priority mempool | MN-R2 |
| T170 | P2P | P2P network design | MN-R4 |
| T171 | Execution | Stage B parallel skeleton | MN-R1 |
| T172 | P2P | P2P transport v1 | MN-R4 |
| T173 | P2P | Consensus/DAG over P2P | MN-R1, MN-R4 |
| T174 | P2P | P2P receive path | MN-R4 |
| T175 | P2P | Node P2P wiring + runbook | MN-R4, MN-R6 |
| T176 | Audit | TestNet Alpha audit capsule | — |
| T177 | Testing | VM v0 property tests | MN-R1 |

### 5.3 TestNet Beta Tasks (T178+)

| Task | Area | Summary | MainNet Risk Category |
| :--- | :--- | :--- | :--- |
| T178 | Spec | TestNet Beta spec + audit skeleton | — |
| T179 | Testing | Gas-enabled property tests | MN-R2 |
| T180 | Config | Beta configuration profile | MN-R6 |
| T181 | Testing | Fee-market cluster tests | MN-R2 |
| T182 | DAG | Missing batch tracking | MN-R3 |
| T183 | DAG | Fetch-on-miss v0 | MN-R3 |
| T184 | Spec | **MainNet v0 spec + audit** | All |

### 5.4 Future MainNet Tasks (T18x+)

| Task (Planned) | Area | Summary | MainNet Risk Category |
| :--- | :--- | :--- | :--- |
| T18x | Consensus | Consensus coupling to DAG | MN-R1 |
| T18x | P2P | Dynamic peer discovery | MN-R4 |
| T18x | P2P | Peer liveness scoring | MN-R4 |
| T18x | P2P | Anti-eclipse enforcement | MN-R4 |
| T18x | State | State pruning | MN-R3 |
| T18x | State | State snapshots | MN-R3 |
| T18x | Keys | HSM production integration | MN-R5 |
| T18x | Gas/Fees | Hybrid fee distribution | MN-R2 |
| T18x | Execution | Stage B production wiring | MN-R1 |
| T18x | Config | MainNet configuration profile | MN-R6 |
| T18x | Ops | MainNet operational runbook | MN-R6 |
| External | Security | External security audit | All |

---

## 6. Cross-References

### 6.1 References From This Document

- [QBIND MainNet v0 Specification](./QBIND_MAINNET_V0_SPEC.md) — MainNet architecture
- [QBIND TestNet Beta Specification](../testnet/QBIND_TESTNET_BETA_SPEC.md) — Beta predecessor
- [QBIND TestNet Beta Audit Skeleton](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md) — Beta risks
- [QBIND TestNet Alpha Audit](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) — Alpha risks
- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet baseline
- [QBIND DevNet Audit](../devnet/QBIND_DEVNET_AUDIT.md) — DevNet risks

### 6.2 References To This Document

The following documents should reference this MainNet audit:

- [QBIND_MAINNET_V0_SPEC.md](./QBIND_MAINNET_V0_SPEC.md) — Links to this audit for risk tracking
- [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) — "Path to MainNet" section
- [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) — Roadmap summary
- [QBIND_TESTNET_ALPHA_AUDIT.md](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) — Roadmap section

---

## Appendix A: Risk Status Definitions

| Status | Definition |
| :--- | :--- |
| **Open** | Risk identified but no mitigation implemented |
| **Partially Mitigated** | Some mitigations in place but not complete |
| **Ready** | Risk adequately mitigated for MainNet v0 launch |
| **N/A** | Risk not applicable to MainNet v0 |

## Appendix B: Severity Definitions

| Severity | Definition |
| :--- | :--- |
| **Critical** | Could cause consensus failure, fund loss, or chain halt |
| **High** | Could cause significant degradation or economic loss |
| **Medium** | Could cause operational issues or minor economic impact |
| **Low** | Minor impact; acceptable for initial launch |

---

*End of Document*