# QBIND DevNet v0 Freeze Capsule

**Task**: T161  
**Status**: DevNet v0 Frozen  
**Date**: 2026-01-28

---

## 1. Scope & Status

### DevNet v0 is Now Frozen

DevNet v0 is a **closed, static PQC DevNet** that represents the first functional baseline for the QBIND protocol. As of T161, DevNet v0 is considered **feature-complete** and **frozen**. New architectural changes should target TestNet Alpha and beyond.

### What DevNet v0 Includes

| Capability | Implementation |
| :--- | :--- |
| **Consensus** | 4–7 validator HotStuff BFT (3-chain commit rule) |
| **Cryptography** | ML-DSA-44 (signatures), ML-KEM-768 (KEM), KEMTLS networking |
| **Mempool** | FIFO mempool (default) + DAG mempool v0 (opt-in, experimental) |
| **Execution** | Nonce-only engine + async pipeline + Stage A sender-partitioned parallelism |
| **Domain Separation** | DevNet chain-id + domain tags (`QBIND:DEV:*:v1`) |
| **Keys/Keystore** | EncryptedFsV1 (recommended) + PlainFs (testing) + loopback remote signer |
| **Testing Harness** | Local 4-node cluster harness + soak tests (T160) |

### What DevNet v0 Explicitly Does NOT Include

- **No VM / Smart Contracts**: Execution is nonce-only; payloads are opaque
- **No Full DAG with Availability Certificates**: DAG v0 provides data structures only; no cross-node certificate protocol
- **No Dynamic P2P**: Static mesh topology; no peer discovery or NAT traversal
- **No DoS Safeguards**: No rate limiting, stake-weighted quotas, or fee market
- **No HSM/Remote Signer in Production Mode**: Loopback transport for testing only
- **No Distributed Staging Environment**: Single-machine cluster harness only

---

## 2. DevNet v0 Component Summary

The following table summarizes each major axis of DevNet v0, linking to the underlying tasks and current risk status from the [DevNet Audit Log](./QBIND_DEVNET_AUDIT.md).

| Component | DevNet v0 Implementation | Key Tasks | Risk Status |
| :--- | :--- | :--- | :--- |
| **Keys/Keystore** | EncryptedFsV1 + ValidatorSigner + RemoteSigner loopback | T143, T144, T148, T149, T153 | R1 mitigated |
| **Consensus** | HotStuff + timeouts + parallel verify pool | T146, T147, T160 | No open safety risks |
| **Execution** | Nonce engine + async pipeline + Stage A parallel | T150, T155, T157 | R3 mitigated, R6 partially mitigated |
| **Mempool** | FIFO (default) + DAG v0 (opt-in, experimental) | T151, T158 | R5 partially mitigated, R6 partially mitigated |
| **Crypto Separation** | ChainId + domain-separated signing preimages | T159 | R7 mitigated |
| **Networking** | Static KEMTLS mesh + 4-node cluster harness | T160 | R4 partially mitigated |
| **Observability** | Metrics for consensus, mempool, execution, signer | T154, T155, T157, T158 | Ready |

### Reference Documents

- [QBIND DevNet v0 Architecture Spec](./QBIND_DEVNET_V0_SPEC.md) — Full DevNet v0 architecture
- [QBIND DevNet Audit Log](./QBIND_DEVNET_AUDIT.md) — Task and risk tracking
- [QBIND Parallel Execution Design](./QBIND_PARALLEL_EXECUTION_DESIGN.md) — Stage A/B parallel execution design
- [QBIND DAG Mempool Design](./QBIND_DAG_MEMPOOL_DESIGN.md) — DAG mempool architecture
- [QBIND Chain ID and Domains](./QBIND_CHAIN_ID_AND_DOMAINS.md) — Domain separation scheme
- [QBIND Gas and Fee Model Design](../testnet/QBIND_GAS_AND_FEES_DESIGN.md) — Gas and fee specification (T167)

---

## 3. Remaining DevNet v0 Limitations

The following limitations are **accepted** for DevNet v0 and will be addressed in TestNet Alpha and beyond:

| Limitation | Description | Target Phase |
| :--- | :--- | :--- |
| **Nonce-only execution** | No user-visible VM; payloads are ignored | TestNet Alpha |
| **No fee market / priority mempool** | FIFO ordering only (R5); gas model designed in T167; T168 implements initial VM v0 gas enforcement for TestNet only; T169 adds a config-gated fee-priority mempool for TestNet, DevNet remains FIFO-only | TestNet Beta |
| **DAG v0 only** | No availability certificates; no leaderless data plane | TestNet Alpha |
| **Static mesh networking** | No dynamic P2P layer. Future P2P design in [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) (T170); implementation will be staged across TestNet Alpha/Beta. | TestNet Beta |
| **Single-machine cluster harness** | T160 harness is local only; not a distributed staging environment | TestNet Alpha |
| **Loopback remote signer only** | No real networked remote signer or HSM integration | TestNet Beta |
| **No Stage B parallelism** | Conflict-graph-based VM parallelism deferred until VM is available | MainNet |

---

## 4. TestNet Alpha Roadmap (Task Buckets)

> **For up-to-date TestNet Alpha risk status and readiness, see [QBIND_TESTNET_ALPHA_AUDIT.md](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md).**

This section defines the work buckets required to evolve DevNet v0 into TestNet Alpha. Each bucket will correspond to one or more future implementation tasks.

### 4.1 Execution / VM

**Goal**: Evolve from nonce-only engine to a minimal deterministic VM.

| Work Item | Description | Risks Addressed | Status |
| :--- | :--- | :--- | :--- |
| **Minimal VM (T163)** | VM v0 with account balances and transfer semantics | New capability | ✅ Done |
| **State Persistence (T164)** | Persist execution state to disk (RocksDB) | New capability | ✅ Done |
| **Stage B Parallelism** | Conflict-graph-based parallel execution when VM is in place | R6 | Planned |

**T163 Status**: ✅ Implemented — See [QBIND_TESTNET_ALPHA_SPEC.md](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) for VM v0 semantics.

**T164 Status**: ✅ Implemented — See [QBIND_TESTNET_ALPHA_SPEC.md](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) §4.4 for persistence details.

**References**: [QBIND_PARALLEL_EXECUTION_DESIGN.md](./QBIND_PARALLEL_EXECUTION_DESIGN.md) §4.2

### 4.2 Mempool & DAG

**Goal**: Evolve from DAG v0 to a full DAG with availability certificates.

| Work Item | Description | Risks Addressed |
| :--- | :--- | :--- |
| **Availability Certificates** | Implement 2f+1 acknowledgment protocol for batches | R2 |
| **Cross-Node Certificate Protocol** | Validators exchange batch acks and form certificates | R2 |
| **DAG Default for TestNet** | Switch TestNet default from FIFO to DAG once stable | R2, R6 |
| **Fee Market / Priority Ordering** | Implement fee-based transaction prioritization | R5 |

**References**: [QBIND_DAG_MEMPOOL_DESIGN.md](./QBIND_DAG_MEMPOOL_DESIGN.md) §3, §6

### 4.3 Networking / P2P

**Goal**: Evolve from static mesh to a basic P2P overlay.

| Work Item | Description | Risks Addressed |
| :--- | :--- | :--- |
| **P2P Network Design (T170)** | Canonical networking design spec for TestNet+ evolution | R4 |
| **P2P Transport v1 (T172)** | Minimal PQC KEMTLS transport with static peers, config-gated | R4 |
| **Consensus & DAG over P2P (T173)** | Wire consensus/DAG messages through P2P transport when enabled | R4 |
| **P2P Receive Path (T174)** | Inbound message demuxing + cluster harness P2P mode | R4 |
| **Dynamic Peer Discovery** | Basic P2P overlay with peer exchange | R4 |
| **Gossip for DAG Batches** | Efficient batch/certificate dissemination | R4, R6 |
| **Multi-Machine Deployments** | Distributed test deployments beyond T160 single-machine harness | R4 |
| **NAT Traversal (Optional)** | Enable connectivity through NAT when needed | R4 |

**T172 Implementation Note**: T172 implements P2P v1 transport, but DevNet stays on static harness with `enable_p2p = false`. The transport is available for testing but does not change DevNet's frozen behavior.

**T173 Implementation Note**: T173 wires consensus and DAG messages through P2P transport when enabled via `network_mode = P2p`. DevNet v0 default remains `LocalMesh` (static mesh) networking. P2P mode is opt-in only and intended for TestNet Alpha / Beta experimentation.

**T174 Implementation Note**: T174 completes the P2P receive path with `P2pInboundDemuxer` for message routing and adds P2P mode to the TestNet Alpha cluster harness via `ClusterNetworkMode::P2p`. DevNet v0 remains unchanged with static mesh as the default. P2P cluster testing is available for TestNet Alpha experimentation.

**T175 Implementation Note**: T175 wires P2P transport into the real `qbind-node` binary with CLI flags (`--network-mode`, `--enable-p2p`, `--p2p-listen-addr`, `--p2p-peer`) and provides a multi-process TestNet Alpha runbook. DevNet v0 remains unchanged: defaults are `LocalMesh` + `enable_p2p = false`. See [QBIND_P2P_TESTNET_ALPHA_GUIDE.md](../network/QBIND_P2P_TESTNET_ALPHA_GUIDE.md) for the runbook.

**References**: [QBIND_P2P_NETWORK_DESIGN.md](../network/QBIND_P2P_NETWORK_DESIGN.md) (T170), [QBIND_DEVNET_V0_SPEC.md](./QBIND_DEVNET_V0_SPEC.md) §3

### 4.4 Keys & Remote Signer

**Goal**: Evolve from loopback remote signer to real networked signer support.

| Work Item | Description | Risks Addressed |
| :--- | :--- | :--- |
| **Networked Remote Signer** | Real gRPC/HTTP transport for remote signing | R1 (hardening) |
| **HSM Basic Support** | HSM-backed signing for TestNet validators | R1 (hardening) |
| **Key Rotation Support** | Mechanism for rotating validator keys | New capability |

**References**: [QBIND_DEVNET_V0_SPEC.md](./QBIND_DEVNET_V0_SPEC.md) §1

### 4.5 Observability & Ops

**Goal**: Harden metrics, logging, and operational tooling for TestNet scale.

| Work Item | Description | Risks Addressed |
| :--- | :--- | :--- |
| **Metrics Hardening** | Review and expand metrics for TestNet-scale observability | Ops |
| **Structured Logging** | Consistent, queryable log format across all components | Ops |
| **Operational Runbooks** | Cluster bring-up, upgrade procedures, incident response | Ops |
| **Alerting Integration** | Prometheus/Grafana alerting for key metrics | Ops |

**References**: [QBIND_DEVNET_V0_SPEC.md](./QBIND_DEVNET_V0_SPEC.md) §Performance & Metrics

---

## 5. Roadmap Summary

> **Note (T178)**: For detailed TestNet specifications, see:
> - **TestNet Alpha**: [QBIND_TESTNET_ALPHA_SPEC.md](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) + [QBIND_TESTNET_ALPHA_AUDIT.md](../testnet/QBIND_TESTNET_ALPHA_AUDIT.md)
> - **TestNet Beta** (next step): [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) + [QBIND_TESTNET_BETA_AUDIT_SKELETON.md](../testnet/QBIND_TESTNET_BETA_AUDIT_SKELETON.md)
>
> **Note (T184)**: For MainNet specifications, see:
> - **MainNet v0**: [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) + [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md)

| Phase | Network | Key Changes from DevNet v0 |
| :--- | :--- | :--- |
| **TestNet Alpha** | TestNet | Minimal VM, DAG with availability certs (opt-in), basic P2P, networked remote signer |
| **TestNet Beta** | TestNet | DAG as default, fee market, multi-machine staging, HSM support |
| **MainNet** | MainNet | Full VM, Stage B parallelism, DoS protection, production HSM, full security audit |

---

## Appendix: Risk Summary (from DevNet Audit)

| ID | Description | DevNet v0 Status | TestNet Target |
| :--- | :--- | :--- | :--- |
| R1 | Key Management (plain JSON keys) | Mitigated (EncryptedFsV1) | HSM support |
| R2 | Single-leader HotStuff liveness | Partially mitigated (DAG v0) | DAG with certs |
| R3 | Execution coupled to consensus | Mitigated (async pipeline) | — |
| R4 | Loopback/local networking only | Partially mitigated (T160 harness) | Dynamic P2P |
| R5 | FIFO mempool without priority | Partially mitigated (DAG v0 opt-in) | Fee market |
| R6 | Performance (no full parallelism) | Partially mitigated (Stage A) | Stage B + DAG |
| R7 | Weak domain separation | Mitigated (chain-aware tags) | — |

---

*End of Document*