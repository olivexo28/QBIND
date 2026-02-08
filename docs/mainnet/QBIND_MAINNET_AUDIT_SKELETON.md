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
| **Execution & VM** | T163, T164, T171, T177, T179, T186, T187 | Partially Mitigated | Stage B wired and tested (T186, T187) |
| **State Persistence & Growth** | T164, T208, T215 | ✅ Mitigated | Pruning (T208) & snapshots (T215) implemented |
| **Gas/Fees & Fee Market** | T167, T168, T169, T179, T181, T193 | Partially Mitigated | Hybrid fee distribution implemented (T193) |
| **Mempool & DAG** | T158, T165, T182, T183, T218 | ✅ Mitigated | DoS protections (T218), consensus coupling |
| **Networking / P2P** | T170, T172, T173, T174, T175 | Partially Mitigated | Discovery, anti-eclipse pending |
| **Keys & Remote Signer / HSM** | T143, T144, T148, T149 | Open | HSM production integration pending |
| **Observability & Ops** | T154, T155, T157, T158, T187, T215 | Partially Mitigated | Stage B metrics (T187), snapshot metrics (T215); MainNet runbooks pending |
| **Governance / Upgrades** | — | Open | Not implemented |

---

## 3. Risk / Threat Categories

### 3.1 Risk Summary Table

| ID | Category | Severity | Status | Spec Section |
| :--- | :--- | :--- | :--- | :--- |
| **MN-R1** | Consensus Safety & Fork Risk | Critical | Open | [Spec §6.3](./QBIND_MAINNET_V0_SPEC.md#63-dag-availability-and-consensus-coupling) |
| **MN-R2** | Economic Integrity (gas/fees) | High | Partially Mitigated | [Spec §3](./QBIND_MAINNET_V0_SPEC.md#3-gas--fees) |
| **MN-R3** | State Growth & Data Availability | Medium | ✅ Mitigated (T208, T215) | [Spec §2.4](./QBIND_MAINNET_V0_SPEC.md#24-state-growth-management) |
| **MN-R4** | P2P & Eclipse Resistance | High | Partially Mitigated | [Spec §5](./QBIND_MAINNET_V0_SPEC.md#5-networking--p2p) |
| **MN-R5** | Key Management & Remote Signing | Critical | Partially Mitigated (T211–T214) | [Spec §6.5](./QBIND_MAINNET_V0_SPEC.md#65-key-management-and-remote-signer--hsm) |
| **MN-R6** | Operational & Monitoring Gaps | Medium | ✅ Mitigated (T216) | [Spec §10](./QBIND_MAINNET_V0_SPEC.md#10-operational-runbook--observability) |
| **MN-R7** | Misconfiguration / Wrong Profile | High | ✅ Mitigated | [Spec §8.3](./QBIND_MAINNET_V0_SPEC.md#83-misconfiguration-handling), T185 |

---

### 3.2 MN-R1: Consensus Safety & Fork Risk

**Category**: Consensus-level safety and liveness in production environment

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Fork on consensus coupling** | DAG consensus coupling is new; may introduce consensus bugs | Critical | Partially Mitigated (T188-T192) |
| **Availability certificate bugs** | Invalid/forged certs could cause consensus divergence | High | Partially Mitigated |
| **HotStuff safety violations** | Bugs in 3-chain commit rule could cause safety failures | Critical | Mitigated (DevNet) |
| **View-change liveness** | Leader failure could stall consensus | Medium | Mitigated (DevNet) |

**Current Mitigations**:
- ✅ HotStuff BFT with 3-chain commit rule (DevNet)
- ✅ Parallel verify pool for signature verification (DevNet)
- ✅ Domain-separated signing preimages (T159)
- ✅ DAG availability certificates v1 (T165)
- ✅ **DAG–HotStuff coupling design complete (T188)** — see [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md)
- ✅ **Proposer-side DAG coupling (T190)** — certified frontier selection
- ✅ **Validator-side DAG coupling enforcement (T191)** — pre-vote validation
- ✅ **Block-level invariant probes (T192)** — post-commit observational checks

**Additional MainNet Requirements**:
- [x] **Consensus coupling design** — T188 complete
- [x] Consensus coupling implementation (T189: config + block format)
- [x] Proposer-side enforcement (T190)
- [x] Validator-side enforcement (T191)
- [x] Block-level invariant probes (T192) — metrics/logging for operator visibility
- [ ] Cluster harness tests for coupling (T192 — partial, more tests needed)
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
| **Proposer reward manipulation** | Proposer could game fee distribution | Medium | Partially Mitigated |
| **Gas limit manipulation** | Attackers craft txs to maximize gas | Medium | Partially Mitigated |
| **Eviction attacks** | Flood mempool to evict legitimate txs | Medium | ✅ Mitigated (T218) |

**Current Mitigations**:
- ✅ Gas model designed (T167)
- ✅ Gas enforcement implemented (T168)
- ✅ Fee-priority mempool implemented (T169)
- ✅ Gas property tests (T179)
- ✅ Fee-market cluster tests (T181)
- ✅ Hybrid fee distribution implemented (T193)
- ✅ **Monetary policy design complete (T194)** — see [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md)
- ✅ **EMA-based fee smoothing (T202)** — consensus-level EMA with phase-dependent λ
- ✅ **Rate-of-change limiters (T203)** — consensus-side per-epoch Δ-limit on annual inflation, per phase, applied after floor/cap with deterministic clamping
- ✅ **DAG mempool DoS protections (T218)** — per-sender quotas + batch size limits

**Additional MainNet Requirements**:
- [x] Hybrid fee distribution (burn + proposer) implementation (T193)
- [x] Monetary policy design specification (T194) — Design Ready
- [x] Monetary engine core implementation (T195) — Engine Core Ready
- [x] Monetary telemetry / shadow mode (T196) — Telemetry Ready (nodes compute recommended inflation but do not enact it)
- [x] Epoch monetary state (T199) — **Ready** (consensus-tracked per-epoch monetary state with phase, fee inputs, and inflation rate)
- [x] Seigniorage distribution to validators (T200) — **Ready** (stake-proportional reward distribution)
- [x] Treasury/insurance/community routing (T201) — **Ready** (seigniorage split and application logic)
- [x] EMA-based fee smoothing (T202) — **Ready** (per-epoch EMA with phase-dependent λ)
- [x] Rate-of-change limiters (T203) — **Ready** (per-epoch Δ-limit with phase-specific max_delta_r_inf_per_epoch_bps)
- [x] Phase transition logic (T204) — **Ready** (time + economic gates wired into consensus; automatic phase transitions)
- [ ] Fee market analysis under adversarial conditions
- [ ] Mempool eviction rate limiting
- [ ] External audit of fee accounting code

**Target Phase**: MainNet v0 (blocking)

---

### 3.4 MN-R3: State Growth & Data Availability

**Category**: State size, pruning, snapshots, data availability

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **State bloat** | Unbounded state growth exhausts disk | Medium | ✅ Mitigated (T208) |
| **No pruning** | Old state retained indefinitely | Medium | ✅ Mitigated (T208) |
| **No snapshots** | No fast sync for new nodes | Medium | ✅ Mitigated (T215) |
| **DAG availability holes** | Missing batches despite fetch-on-miss | Medium | Partially Mitigated |

**Current Mitigations**:
- ✅ RocksDB crash-safe persistence (T164)
- ✅ Fetch-on-miss v0 (T182, T183)
- ✅ State pruning implemented (T208) — configurable retention period
- ✅ State snapshots implemented (T215) — periodic RocksDB checkpoints
- ✅ Snapshot metrics: `qbind_snapshot_*` counters and gauges

**Additional MainNet Requirements**:
- [x] State pruning implementation (T208)
- [x] Snapshot/checkpoint mechanism (T215)
- [x] State size monitoring and alerting (T208, T215)
- [ ] Archival node support (uses pruning disabled mode)

**Target Phase**: ✅ MainNet v0 (pruning and snapshots implemented)

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
| **Key compromise** | Compromised signing key allows forgery | Critical | Partially Mitigated |
| **No HSM support** | Keys stored on disk vulnerable to theft | High | Mitigated (T211) |
| **Loopback signer in prod** | Test signer used in production | High | Mitigated (T210) |
| **Key rotation failures** | Unable to rotate compromised key | Medium | Mitigated (T213) |
| **HSM failures / signer unavailability** | Validator offline if signer down | High | Partially Mitigated (T214) |

**Current Mitigations**:
- ✅ EncryptedFsV1 keystore (encrypted at rest)
- ✅ Key separation (consensus vs network keys)
- ✅ RemoteSigner interface (loopback for testing)
- ✅ **Key management design complete (T209)** — see [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md)
- ✅ **HSM/PKCS#11 adapter implemented (T211)** — MainNet supports PKCS#11 HSM signer via HsmPkcs11 mode (SoftHSM + hardware HSMs)
- ✅ **Remote signer protocol implemented (T212)** — TcpKemTlsSignerTransport + qbind-remote-signer daemon
- ✅ **Key rotation hooks implemented (T213)** — KeyRotationEvent, dual-key grace period, CLI helper
- ✅ **HSM redundancy & failover v0 (T214)** — see mitigations below

**T214 Mitigations (HSM Failures / Signer Unavailability)**:
- ✅ `SignerFailureMode::ExitOnFailure` enforced on MainNet — node exits on signer error (fail-closed)
- ✅ Startup reachability checks for HSM/remote signer — `qbind_hsm_startup_ok` metric
- ✅ Health signaling via `SignerHealth` enum and metrics
- ✅ Operator runbook for HSM redundancy and signer failover — see [Key Management Design §3.7](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#37-signer-failure-modes--redundancy-patterns-t214)
- ✅ Documented redundancy patterns (active/passive, HSM cluster)

**Additional MainNet Requirements**:
- [x] **Key management design** — T209 complete
- [x] Signer mode config + `validate_mainnet_invariants()` enforcement (T210) — Complete
- [x] **HSM production integration (PKCS#11 adapter) (T211)** — Ready
- [x] **Remote signer protocol v0 (T212)** — Ready
- [x] **Key rotation hooks v0 (T213)** — Ready (KeyRotationRegistry with dual-key support, CLI helper)
- [x] Key rotation procedures documented — T213 implementation docs
- [x] **HSM redundancy v0 (T214)** — Fail-closed behavior, health signaling, redundancy patterns documented
- [x] **Compromised key handling procedures (T217)** — Ready; see [QBIND_KEY_MANAGEMENT_DESIGN.md §5.4](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md#54-compromised-key-handling-t217) and [QBIND_MAINNET_RUNBOOK.md §10.5](../ops/QBIND_MAINNET_RUNBOOK.md#105-compromised-key-incident-procedures-t217)
- [ ] External audit of key management code

**Status Summary**: Partially mitigated by T211–T214 and T217 (compromised key handling procedures); only remaining blocker is external audit of key management code.

**Target Phase**: MainNet v0 (blocking)

---

### 3.7 MN-R6: Operational & Monitoring Gaps

**Category**: Observability, incident response, operational tooling

| Risk | Description | Severity | Status |
| :--- | :--- | :--- | :--- |
| **Insufficient metrics** | Missing metrics for MainNet operations | Medium | ✅ Mitigated |
| **No alerting** | No automated alerting for issues | Medium | ✅ Mitigated (T216) |
| **Missing runbooks** | No documented procedures for incidents | Medium | ✅ Mitigated (T216) |
| **No dashboards** | No operational dashboards | Low | ✅ Mitigated (T216) |

**Current Mitigations**:
- ✅ Metrics for consensus, mempool, execution, DAG, P2P
- ✅ P2P multi-process runbook (T175)
- ✅ **MainNet operational runbook (T216)** — see [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md)
- ✅ **Prometheus alert rules skeleton (T216)** — see [prometheus/qbind_mainnet_alerts.example.yaml](../ops/prometheus/qbind_mainnet_alerts.example.yaml)
- ✅ **Grafana dashboard skeleton (T216)** — see [grafana/qbind_mainnet_dashboard.example.json](../ops/grafana/qbind_mainnet_dashboard.example.json)

**T216 Deliverables**:
- [x] MainNet operational runbook (node roles, topology, config, bootstrap, snapshots, key rotation, P2P, monetary telemetry)
- [x] Prometheus/Grafana alerting skeleton (consensus, P2P, signer, state, monetary alerts)
- [x] Operational dashboard (JSON template with panels for all major domains)
- [x] Incident response procedures (key compromise, signer failure, state issues)

**Target Phase**: ✅ MainNet v0 (runbook and skeletons complete)

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
| 5 | Stage B production wiring complete | ✅ Ready | T186, T187 - wired into VM v0 pipeline |
| 6 | Stage B vs sequential determinism verified | ✅ Ready | T187 `test_stage_b_pipeline_determinism_against_sequential` |

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
| 12 | Hybrid fee distribution (burn + proposer) implemented | ✅ Ready | T193 `FeeDistributionPolicy`, `execute_block_with_proposer()` |
| 13 | Fee-market cluster tests pass | ✅ Ready | `test_testnet_beta_fee_market_*` |

### 4.4 Mempool & DAG

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 14 | DAG mempool is only mode for MainNet validators | ⏳ Pending | Future task |
| 15 | DAG–HotStuff consensus coupling design complete | ✅ Ready | T188 [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) |
| 16 | DAG availability certificates enforced by consensus | ✅ Ready | T191 validator-side enforcement |
| 17 | Proposals only commit certified batches | ✅ Ready | T190 proposer-side enforcement |
| 18 | Fetch-on-miss recovers missing batches | ✅ Ready | T182, T183 tests |
| 19 | Fee-aware eviction implemented | ✅ Ready | T169 |
| 20 | Block-level coupling invariant probes | ✅ Ready | T192 `check_dag_coupling_invariant_for_committed_block()` |

### 4.5 Networking / P2P

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 21 | P2P transport is only mode for MainNet validators | ⏳ Pending | Future task |
| 22 | Dynamic peer discovery protocol implemented | ⏳ Pending | Future task |
| 23 | Peer liveness scoring removes unresponsive peers | ⏳ Pending | Future task |
| 24 | Anti-eclipse: no single peer can trivially eclipse 1/3+ validators | ⏳ Pending | Future task |
| 25 | P2P topology tests demonstrate peer diversity | ⏳ Pending | Future task |

### 4.6 Keys & HSM

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 26 | Key management design specification | ✅ Ready | T209 [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) |
| 27 | HSM production integration available | ✅ Ready | T211 – PKCS#11 adapter implemented, SoftHSM + hardware HSMs |
| 28 | Loopback signer rejected for MainNet profile | ⏳ Pending | T210 |
| 29 | Key rotation procedures documented | ✅ Ready | T213 – `KeyRotationRegistry`, dual-key grace period, CLI helper |
| 30 | Remote signer protocol implemented | ✅ Ready | T212 – TcpKemTlsSignerTransport + qbind-remote-signer daemon |

**T212 Audit Scope (Remote Signer Protocol)**:

- [ ] Verify KEMTLS implementation for remote signer transport
- [ ] Verify request validation (validator_id, suite_id, preimage bounds)
- [ ] Verify per-connection rate limiting implementation
- [ ] Verify that no private key material crosses the wire
- [ ] Verify error handling does not leak sensitive information
- [ ] Verify startup reachability check in `validate_mainnet_invariants()`
- [ ] Review protocol wire format for correctness and security

**T213 Audit Scope (Key Rotation Hooks)**:

- [ ] Verify dual-key validation accepts both keys during grace period
- [ ] Verify rotation commits correctly after grace period ends
- [ ] Verify overlapping rotations are rejected
- [ ] Verify saturating arithmetic for epoch overflow
- [ ] Verify CLI helper produces valid JSON event descriptors
- [ ] Review grace period boundary conditions (grace_epochs=0)

### 4.7 Operations & Security

| # | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| 31 | MainNet configuration profile implemented | ✅ Ready | T185 |
| 32 | MainNet invariant validation (`validate_mainnet_invariants()`) | ✅ Ready | T185 |
| 33 | MainNet operational runbook complete | ✅ Ready | T216 [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) |
| 34 | Prometheus alerting skeleton | ✅ Ready | T216 [qbind_mainnet_alerts.example.yaml](../ops/prometheus/qbind_mainnet_alerts.example.yaml) |
| 35 | Grafana dashboard skeleton | ✅ Ready | T216 [qbind_mainnet_dashboard.example.json](../ops/grafana/qbind_mainnet_dashboard.example.json) |
| 36 | External security audit completed | ⏳ Pending | External |
| 37 | All MainNet-blocking issues resolved | ⏳ Pending | This checklist |

### 4.8 Readiness Summary

| Category | Ready | Pending | Total |
| :--- | :--- | :--- | :--- |
| Execution & VM | 6 | 0 | 6 |
| State Persistence | 1 | 2 | 3 |
| Gas/Fees | 2 | 2 | 4 |
| Mempool & DAG | 6 | 1 | 7 |
| Networking / P2P | 0 | 5 | 5 |
| Keys & HSM | 4 | 1 | 5 |
| Operations | 5 | 2 | 7 |
| **Total** | **24** | **13** | **37** |

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
| T185 | Config | **MainNet configuration profile + safety rails** | MN-R6, MN-R7 |
| **T188** | **Design** | **DAG–HotStuff consensus coupling design** | **MN-R1** |
| **T189** | **Config** | **Wire `dag_coupling_mode` config + block format** | **MN-R1** |
| **T190** | **Consensus** | **Proposer-side enforcement (certified frontier)** | **MN-R1** |
| **T191** | **Consensus** | **Validator-side enforcement (verify certs before vote)** | **MN-R1** |
| **T192** | **Observability** | **Block-level invariant probes & metrics** | **MN-R1** |
| **T194** | **Design** | **Monetary policy & monetary engine design** | **MN-R2** |
| **T209** | **Design** | **Key management & signer architecture design** | **MN-R5** |
| **T217** | **Docs** | **Compromised key handling procedures** | **MN-R5** |
| **T218** | **Mempool** | **DAG mempool DoS protections v1** | **MN-R2** |

### 5.4 Future MainNet Tasks (T193+)

| Task (Planned) | Area | Summary | MainNet Risk Category |
| :--- | :--- | :--- | :--- |
| T19x | P2P | Dynamic peer discovery | MN-R4 |
| T19x | P2P | Peer liveness scoring | MN-R4 |
| T19x | P2P | Anti-eclipse enforcement | MN-R4 |
| ~~T208~~ | ~~State~~ | ~~State pruning~~ | ~~MN-R3~~ |
| ~~**T215**~~ | ~~**State**~~ | ~~**State snapshots**~~ | ~~**MN-R3**~~ |
| **T210** | **Keys** | **Signer mode config + `validate_mainnet_invariants()`** | **MN-R5** |
| ~~**T211**~~ | ~~**Keys**~~ | ~~**HSM/PKCS#11 adapter v0**~~ | ~~**MN-R5**~~ |
| ~~**T212**~~ | ~~**Keys**~~ | ~~**Remote signer protocol v0**~~ | ~~**MN-R5**~~ |
| ~~**T213**~~ | ~~**Keys**~~ | ~~**Key rotation hooks v0**~~ | ~~**MN-R5**~~ |
| ~~T193~~ | ~~Gas/Fees~~ | ~~Hybrid fee distribution~~ | ~~MN-R2~~ |
| ~~T18x~~ | ~~Execution~~ | ~~Stage B production wiring~~ | ~~MN-R1~~ |
| T19x | Ops | MainNet operational runbook | MN-R6 |
| External | Security | External security audit | All |

> **Note**: Stage B production wiring completed in T186 + T187 (strikethrough above).
>
> **Note**: Hybrid fee distribution completed in T193 (strikethrough above). Implements 50% burn / 50% proposer split per MainNet v0 spec.
>
> **Note**: State pruning completed in T208 (strikethrough above). Provides height-based pruning with configurable retention.
>
> **Note**: State snapshots completed in T215 (strikethrough above). Provides:
> - `StateSnapshotter` trait with RocksDB checkpoint implementation
> - `SnapshotConfig` for periodic snapshot creation
> - `FastSyncConfig` for local snapshot restore
> - MainNet validation: snapshots must be enabled with interval 10,000–500,000 blocks
> - Prometheus metrics: `qbind_snapshot_*`
>
> **Note**: DAG–HotStuff consensus coupling design completed in T188. Implementation tasks T189–T192 complete:
> - T189: `DagCouplingMode` enum, `batch_commitment` in `BlockHeader`
> - T190: Proposer builds proposals from certified frontier
> - T191: Validators validate DAG coupling before voting
> - T192: Block-level invariant probes, metrics, and unit tests
>
> See [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) for the design specification.
>
> **Note**: Monetary policy and monetary engine design completed in T194. This provides:
> - Three-phase model (Bootstrap / Transition / Mature) with time and economic readiness gates
> - PQC-adjusted inflation targets and EMA-based fee smoothing
> - Seigniorage allocation and integration with hybrid fee distribution (T193)
> - Parameter classification (hard-coded vs governance-tunable vs future/oracle-driven)
> - Implementation roadmap for T195+ tasks
>
> See [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) for the design specification.
>
> **Note**: Key management and signer architecture design completed in T209. This provides:
> - Key roles (consensus, P2P identity, batch signing) with PQC requirements
> - Signer modes (LoopbackTesting, EncryptedFsV1, RemoteSigner, HsmPkcs11)
> - HSM and remote signer architecture with PKCS#11 integration plan
> - Key rotation and compromise handling procedures
> - Network-specific requirements matrix (DevNet through MainNet)
> - Implementation roadmap for T210–T213 tasks
>
> See [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) for the design specification.
>
> **Note**: T211 (HSM/PKCS#11 adapter) completed. See `qbind-node/src/hsm_pkcs11.rs`.
>
> **Note**: T212 (Remote signer protocol) completed. See `qbind-node/src/remote_signer.rs` and `qbind-remote-signer` crate.
>
> **Note**: T213 (Key rotation hooks) completed. This provides:
> - `KeyRotationEvent` and `KeyRotationKind` types for representing rotations
> - `KeyRotationRegistry` with dual-key grace period support
> - `ValidatorKeyState` and `PendingKey` for tracking rotation state
> - `apply_key_rotation_event()` and `advance_epoch_for_rotation()` functions
> - CLI helper (`init_key_rotation()`) for generating rotation event descriptors
> - Logging helpers and `KeyRotationMetrics` for observability
>
> See `qbind-consensus/src/key_rotation.rs` and `qbind-node/src/key_rotation_cli.rs`.

---

## 6. Cross-References

### 6.1 References From This Document

- [QBIND MainNet v0 Specification](./QBIND_MAINNET_V0_SPEC.md) — MainNet architecture
- [QBIND MainNet Operational Runbook](../ops/QBIND_MAINNET_RUNBOOK.md) — MainNet operations (T216)
- [QBIND DAG Consensus Coupling Design](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) — DAG–HotStuff coupling (T188)
- [QBIND TestNet Beta Specification](../testnet/QBIND_TESTNET_BETA_SPEC.md) — Beta predecessor
- [QBIND TestNet Beta Audit Skeleton](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md) — Beta risks
- [QBIND TestNet Alpha Audit](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md) — Alpha risks
- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet baseline
- [QBIND DevNet Audit](../devnet/QBIND_DEVNET_AUDIT.md) — DevNet risks
- [QBIND Monetary Policy Design](../econ/QBIND_MONETARY_POLICY_DESIGN.md) — Monetary policy specification (T194)
- [QBIND Key Management Design](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) — Key management and signer architecture (T209)

### 6.2 References To This Document

The following documents should reference this MainNet audit:

- [QBIND_MAINNET_V0_SPEC.md](./QBIND_MAINNET_V0_SPEC.md) — Links to this audit for risk tracking
- [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) — References audit for operational context (T216)
- [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](./QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) — References audit for MN-R1
- [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) — References audit for MN-R2
- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) — References audit for MN-R5
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