# QBIND DevNet Audit Log

## Introduction
This document tracks the audit status, completed tasks, and identified risks for **QBIND DevNet v0**. It serves as an append-only log of changes affecting the DevNet environment.

**Maintenance**:
*   Append new tasks (Txxx) to the **Audit Index**.
*   Update the **Risk & Mitigation Table** when risks are identified or mitigated.
*   Update **Readiness Overview** as components mature.

## Audit Index

| Task | Area | Summary | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| T143 | Keys | ValidatorSigningKey integration (ML-DSA-44) | DevNet-ready | Key generation & basic signing. |
| T144 | Keys/Keystore | FsValidatorKeystore, key loading | DevNet-ready | JSON-based local keystore. |
| T145 | Keys/Identity | LocalValidatorIdentity self-check | DevNet-ready | Startup identity verification. |
| T146 | Consensus | Timeout + View-Change Protocol | DevNet-ready | TimeoutMsg, TimeoutCertificate, pacemaker integration. |
| T147 | Consensus | Parallel Signature Verification | DevNet-ready | ConsensusVerifyPool for off-thread PQ verification. |
| T148 | Keys/Signer | ValidatorSigner Trait Abstraction | DevNet-ready | Enables future HSM/Remote integration. |
| T149 | Keys/Signer | RemoteSignerClient + Loopback | DevNet-ready | Loopback transport for testing remote signer flows. |
| T150 | Execution | Transaction Execution Adapter | DevNet-ready | Wiring consensus commits to execution engine. |
| T151 | Mempool | Mempool & Proposer Pipeline | DevNet-ready | InMemoryMempool, signature checks, nonce tracking. |
| T153 | Keys/Keystore | Encrypted validator keystore v1 + backend selection | DevNet-ready | AEAD-encrypted keystores, PBKDF2 KDF, backend abstraction. |
| T154 | Performance / Observability | DevNet metrics + TPS harness | DevNet-ready | Metrics for consensus, mempool, execution, signer/keystore; TPS benchmark harness. |
| T155 | Execution | Async execution pipeline (off consensus thread) | DevNet-ready | Dedicated execution worker thread, non-blocking commit hook, queue metrics. |
| T156 | Execution / Mempool | Parallel execution & DAG mempool design spec | DevNet-ready (design) | Design docs for Stage A/B parallel execution and DAG mempool; implementation in T157+. |
| T157 | Execution | Stage A parallel execution (sender-partitioned nonce engine) | DevNet-ready | Sender-partitioned parallelism for nonce-only engine; rayon thread pool; deterministic; metrics. |

## Risk & Mitigation Table

| ID | Category | Description | Severity | Mitigation / Plan | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| R1 | Key Management | Keys stored as plain JSON on disk (when using PlainFs backend) | High | Use EncryptedFsV1 backend (T153) for DevNet; require encrypted keystore + HSM for MainNet. | Mitigated (T153) |
| R2 | Liveness | Single-leader HotStuff (rotate-on-view) | Medium | Robustness improvements, potential DAG-based mempool. | Open |
| R3 | Execution | Execution coupled to consensus thread | Low | Execution moved to async worker thread (T155); still single-threaded but decoupled from consensus. | Mitigated (T155) |
| R4 | Networking | Loopback/Local TCP only tested extensively | Medium | Scale up to real distributed cluster testing (TestNet phase). | Open |
| R5 | Mempool | Basic FIFO without priority/fees | Low | Implement fee market and priority ordering for TestNet. | Open |
| R6 | Performance | No DAG/full VM parallelism yet; TPS improved by Stage A parallel execution | Medium | Stage A sender-partitioned parallel execution implemented in T157 for DevNet. Multi-core speedup for workloads with many distinct senders. DAG mempool + VM parallelism (Stage B) planned for future. Initial baseline established by T154. T155 lays foundation with async execution. **T156** design spec documents staged approach; **T157** implements Stage A for nonce engine. See [QBIND_PARALLEL_EXECUTION_DESIGN.md](./QBIND_PARALLEL_EXECUTION_DESIGN.md) and [QBIND_DAG_MEMPOOL_DESIGN.md](./QBIND_DAG_MEMPOOL_DESIGN.md). | Partially Mitigated (T157) |

## DevNet vs TestNet/MainNet Readiness

| Component | DevNet | TestNet | MainNet |
| :--- | :--- | :--- | :--- |
| **Consensus Core** | Ready (HotStuff) | Planned | Planned |
| **Mempool** | Ready (FIFO) | Planned | Planned |
| **Execution** | Ready (Nonce + Async Pipeline + Stage A Parallel) | Planned | Planned |
| **Keys/Signer** | Ready (Local/Loopback) | Planned (HSM Basic) | Planned (HSM Full) |
| **Networking** | Ready (Static Mesh) | Planned (Dynamic) | Planned (Public P2P) |
| **Monitoring** | Ready (T154/T155/T157 Metrics) | Planned | Planned |

## Future Work
For tracking future network phases, see:
*   [TestNet Audit Skeleton](../testnet/QBIND_TESTNET_AUDIT_SKELETON.md)
*   [MainNet Audit Skeleton](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md)