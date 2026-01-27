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

## Risk & Mitigation Table

| ID | Category | Description | Severity | Mitigation / Plan | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| R1 | Key Management | Keys stored as plain JSON on disk (mock HSM) | High | Implement encrypted keystore or true HSM support (MainNet req). | Open |
| R2 | Liveness | Single-leader HotStuff (rotate-on-view) | Medium | Robustness improvements, potential DAG-based mempool. | Open |
| R3 | Execution | Serial execution on main thread | Low | Move execution to async task or separate thread pool if blocking increases. | Open |
| R4 | Networking | Loopback/Local TCP only tested extensively | Medium | Scale up to real distributed cluster testing (TestNet phase). | Open |
| R5 | Mempool | Basic FIFO without priority/fees | Low | Implement fee market and priority ordering for TestNet. | Open |

## DevNet vs TestNet/MainNet Readiness

| Component | DevNet | TestNet | MainNet |
| :--- | :--- | :--- | :--- |
| **Consensus Core** | Ready (HotStuff) | Planned | Planned |
| **Mempool** | Ready (FIFO) | Planned | Planned |
| **Execution** | Ready (Nonce) | Planned | Planned |
| **Keys/Signer** | Ready (Local/Loopback) | Planned (HSM Basic) | Planned (HSM Full) |
| **Networking** | Ready (Static Mesh) | Planned (Dynamic) | Planned (Public P2P) |
| **Monitoring** | Basic Metrics | Planned | Planned |

## Future Work
For tracking future network phases, see:
*   [TestNet Audit Skeleton](../testnet/QBIND_TESTNET_AUDIT_SKELETON.md)
*   [MainNet Audit Skeleton](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md)
