# QBIND P2P Network Design Specification

**Task**: T170  
**Status**: Design Document (Architecture)  
**Author**: QBIND Engineering  
**Date**: 2026-01-30

---

## Table of Contents

1. [Objectives and Constraints](#1-objectives-and-constraints)
2. [Current Networking Model](#2-current-networking-model)
3. [Node Roles and Identities](#3-node-roles-and-identities)
4. [Overlay Topology and Peer Model](#4-overlay-topology-and-peer-model)
5. [Protocol Layering](#5-protocol-layering)
6. [Threat Model and Mitigations](#6-threat-model-and-mitigations)
7. [Phased Rollout Plan](#7-phased-rollout-plan)
8. [Code-Level Skeletons](#8-code-level-skeletons)
9. [Appendices](#appendices)

---

## 1. Objectives and Constraints

### 1.1 Security Goals

QBIND is a **PQC-only** (Post-Quantum Cryptography) Layer 1 blockchain. All networking primitives must maintain quantum resistance:

| Security Goal | Requirement |
| :--- | :--- |
| **PQC-Only** | No classical cryptographic primitives (no TLS 1.2, no secp256k1, no ECDSA). All transport security uses KEMTLS with ML-KEM-768 + AEAD. |
| **Eclipse Attack Resistance** | Validators must maintain minimum peer diversity. Connection limits and peer scoring prevent attackers from isolating validators. |
| **DoS / Bandwidth Exhaustion** | Per-peer rate limiting, bounded queues, and backpressure mechanisms prevent untrusted peers from overwhelming validators. |
| **Identity Spoofing Resistance** | Node identities are cryptographically bound to KEM public keys. Network authentication uses KEMTLS handshakes. |
| **Key Separation** | Consensus signing keys (ML-DSA-44) are separate from network transport keys (ML-KEM-768). |

### 1.2 Functional Goals

The P2P layer must support the following operational modes across QBIND's deployment phases:

| Phase | Network | P2P Requirements |
| :--- | :--- | :--- |
| **DevNet v0** | DevNet | Static KEMTLS mesh for local testing. Single-machine cluster harness. |
| **TestNet Alpha** | TestNet | Small validator set (~4-7 nodes), mostly manual peer configuration, single-region acceptable. |
| **TestNet Beta** | TestNet | Dynamic discovery for validators and full nodes, multi-region support, gossip for DAG batches. |
| **MainNet** | MainNet | Production-grade P2P overlay with full discovery, gossip, DoS protection, and multi-region resilience. |

**Supported Message Types**:

The P2P layer transports existing application messages without modification:

- **Consensus Messages**: Proposals, votes, timeouts, new-view (HotStuff BFT)
- **DAG Mempool Messages**: Batches, batch acknowledgments, availability certificates
- **Control Messages**: Heartbeats, peer discovery, health checks

### 1.3 Non-Goals for This Version (T170)

This design document explicitly excludes:

| Non-Goal | Rationale |
| :--- | :--- |
| **Global-Scale DHT / Kademlia** | TestNet Beta will use simpler discovery mechanisms; DHT is future work for MainNet scale. |
| **Complex NAT Hole-Punching** | Basic TCP/UDP assumptions only; advanced NAT traversal (STUN/TURN/ICE) is future work. |
| **New Classical Primitives** | No TLS 1.2, secp256k1, or other classical crypto. All primitives remain PQC-safe. |
| **Full Implementation** | T170 produces design + skeletons only. Actual P2P stack implementation is staged across future tasks. |

### 1.4 Relationship to DevNet Freeze Roadmap

Per the [QBIND DevNet v0 Freeze Capsule](../devnet/QBIND_DEVNET_V0_FREEZE.md):

- DevNet v0 is **frozen** with "static mesh networking" as an accepted limitation.
- The "Networking / P2P" roadmap bucket (§4.3) targets dynamic peer discovery, gossip, and multi-machine deployments for TestNet+.
- Risk R4 ("Loopback/local networking only") is addressed by this design.

This document serves as the canonical networking design spec for the TestNet Alpha → Beta → MainNet evolution.

---

## 2. Current Networking Model

### 2.1 Static KEMTLS Mesh

The current QBIND networking implementation (DevNet v0) uses a **static KEMTLS mesh** between validators:

```
┌─────────────┐       KEMTLS        ┌─────────────┐
│  Validator  │◄────────────────────►│  Validator  │
│     V1      │                      │     V2      │
└──────┬──────┘                      └──────┬──────┘
       │                                    │
       │           KEMTLS                   │
       │◄──────────────────────────────────►│
       │                                    │
       ▼                                    ▼
┌─────────────┐       KEMTLS        ┌─────────────┐
│  Validator  │◄────────────────────►│  Validator  │
│     V3      │                      │     V4      │
└─────────────┘                      └─────────────┘
```

**Properties**:

- Full mesh: Every validator connects to every other validator
- Static configuration: Peer addresses are hardcoded or read from config files
- KEMTLS transport: All connections use ML-KEM-768 key exchange + AEAD encryption
- Single-machine deployment: T160/T166 cluster harnesses run on one machine

### 2.2 Local Cluster Harness

The current test infrastructure provides:

| Component | Implementation | Scope |
| :--- | :--- | :--- |
| **T160 DevNet Harness** | `t160_devnet_cluster_harness.rs` | 4-node local DevNet cluster |
| **T166 TestNet Alpha Harness** | `t166_testnet_alpha_cluster_harness.rs` | TestNet Alpha with VM v0 |
| **In-Memory Transport** | `LoopbackNetService` | Testing without real sockets |
| **Local TCP/KEMTLS** | `NetService` + `AsyncPeerManager` | Local KEMTLS connections |

### 2.3 Existing Message Types

The P2P layer will transport the following existing message types:

**Consensus Messages** (defined in `qbind-wire`):

```rust
// Simplified representation
pub enum ConsensusMessage {
    Proposal(BlockProposal),
    Vote(Vote),
    Timeout(TimeoutMessage),
    NewView(NewViewMessage),
}
```

**DAG Mempool Messages** (defined in `qbind-node`):

```rust
// Simplified representation
pub enum DagMessage {
    Batch(QbindBatch),
    BatchAck(BatchAck),
    BatchCertificate(BatchCertificate),
}
```

**Clarification**: T170 does **not** modify any of these message types. It defines how they move over a P2P substrate.

---

## 3. Node Roles and Identities

### 3.1 Node Roles

QBIND defines three node roles:

| Role | Description | TestNet Alpha | MainNet |
| :--- | :--- | :--- | :--- |
| **Validator Node** | Participates in consensus (proposes, votes, commits). Has on-chain stake and signing keys. | ✅ Supported | ✅ Required |
| **Full Node** | Validates and stores all blocks. Does not vote in consensus. Relays transactions. | ⏳ Future | ✅ Supported |
| **Light Client** | Verifies headers and proofs only. Does not store full state. | ⏳ Future | ⏳ Future |

For TestNet Alpha/Beta, the primary focus is **validator nodes**. Full node support will be added in TestNet Beta.

### 3.2 Key Separation

QBIND enforces strict separation between consensus and network keys:

| Key Type | Primitive | Purpose | Storage |
| :--- | :--- | :--- | :--- |
| **Consensus Signing Key** | ML-DSA-44 | Signs votes, proposals, DAG batches. On-chain validator identity. | `EncryptedFsV1` keystore |
| **Network Transport Key** | ML-KEM-768 | KEMTLS handshake. Establishes encrypted channels. | Separate keystore entry |

**Rationale**:

- Consensus keys are high-value targets; compromise affects chain safety.
- Network keys are exposed more frequently (every connection handshake).
- Separate keys allow network key rotation without consensus key changes.

### 3.3 Node Identity

Each node has a unique **NodeId** that identifies it on the network:

```rust
/// A 32-byte node identifier.
///
/// For validators: derived from ValidatorId or network public key hash.
/// For full nodes: derived from network public key hash only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId([u8; 32]);
```

**Derivation Rules**:

| Node Type | NodeId Derivation |
| :--- | :--- |
| **Validator** | `SHA3-256(network_public_key)` — maps 1:1 to `ValidatorId` |
| **Full Node** | `SHA3-256(network_public_key)` — no corresponding `ValidatorId` |

**Relationship to ValidatorId**:

- For validators, `NodeId` and `ValidatorId` have a **1:1 relationship**.
- The mapping is established during node startup via the validator config.
- Full nodes have `NodeId` only; they are not part of the consensus validator set.

### 3.4 Identity Verification

During KEMTLS handshake:

1. Initiator receives responder's KEM public key.
2. Initiator derives `expected_node_id = SHA3-256(kem_public_key)`.
3. If connecting to a known validator, initiator verifies `expected_node_id` matches configured `ValidatorId`.
4. If mismatch → reject connection (potential identity spoofing).

This ensures consensus keys are not reused for network authentication while maintaining identity binding.

---

## 4. Overlay Topology and Peer Model

### 4.1 Transport Assumptions

| Transport | Status | Notes |
| :--- | :--- | :--- |
| **TCP** | ✅ Primary | Reliable delivery, widely supported |
| **QUIC** | ⏳ Future | Lower latency, built-in multiplexing |
| **UDP** | ⏳ Optional | For gossip protocols (future) |

**Security**: All transports are wrapped in **KEMTLS**. No plaintext control channels.

### 4.2 Topology by Phase

#### DevNet (Current)

```
┌─────────────────────────────────────┐
│          Full Static Mesh           │
│                                     │
│   V1 ◄───────► V2 ◄───────► V3     │
│    │            ▲            │      │
│    │            │            │      │
│    └───────► V4 ◄───────────┘      │
│                                     │
│   All connections bidirectional     │
│   Single machine, local harness     │
└─────────────────────────────────────┘
```

#### TestNet Alpha

```
┌─────────────────────────────────────┐
│    Config-Driven Validator Mesh     │
│                                     │
│   static_peers:                     │
│     - validator1.testnet.qbind:9000 │
│     - validator2.testnet.qbind:9000 │
│     - validator3.testnet.qbind:9000 │
│     - validator4.testnet.qbind:9000 │
│                                     │
│   Mostly fully-connected graph      │
│   Manual peer configuration         │
│   Single-region acceptable          │
└─────────────────────────────────────┘
```

#### TestNet Beta / MainNet

```
┌─────────────────────────────────────────────────────────────┐
│                    Dual Overlay Network                      │
├──────────────────────────────┬──────────────────────────────┤
│      Consensus Overlay       │       DAG/Mempool Overlay     │
│    (Validators Only)         │   (Validators + Full Nodes)   │
│                              │                               │
│   • Low latency              │   • Higher bandwidth          │
│   • Smaller messages         │   • Gossip for batches        │
│   • Proposals, votes         │   • Batch acks, certs         │
│   • Limited connections      │   • Higher fanout             │
│                              │                               │
│   max_outbound: 8            │   gossip_fanout: 6            │
│   max_inbound: 16            │   max_inbound: 64             │
└──────────────────────────────┴──────────────────────────────┘
```

### 4.3 Connection Limits

| Parameter | DevNet | TestNet Alpha | TestNet Beta | MainNet |
| :--- | :--- | :--- | :--- | :--- |
| `max_outbound` | N-1 (full mesh) | 8 | 16 | 16 |
| `max_inbound` | N-1 (full mesh) | 16 | 64 | 64 |
| `gossip_fanout` | N/A | N/A | 6 | 8 |

### 4.4 Peer Lifecycle

**Peer Addition**:

| Phase | Mechanism |
| :--- | :--- |
| DevNet | Hardcoded in harness |
| TestNet Alpha | `static_peers` config list |
| TestNet Beta | Static config + basic discovery (peer exchange) |
| MainNet | Full discovery protocol (future design) |

**Peer Removal**:

| Trigger | Action |
| :--- | :--- |
| **Connection Timeout** | Remove from active peers; mark as unreachable |
| **Handshake Failure** | Increment failure counter; temporary backoff |
| **Misbehavior Detection** | Add to banlist (placeholder for future scoring) |
| **Health Check Failure** | Remove from active peers; attempt reconnection |

**Scoring / Banlist** (Placeholder):

```rust
/// Peer scoring state (future implementation).
pub struct PeerScore {
    pub reputation: i32,      // Positive = good, negative = bad
    pub last_seen: Instant,
    pub misbehavior_count: u32,
    pub banned_until: Option<Instant>,
}
```

The scoring system shape is defined here; actual logic is future work.

---

## 5. Protocol Layering

### 5.1 Protocol Stack

```
┌──────────────────────────────────────────────────────────────┐
│                    Application Layer                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Consensus Messages  │  DAG Messages  │  Control Msgs  │  │
│  │  (CBOR/Bincode)      │  (CBOR/Bincode) │  (Bincode)    │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                    Application Frame                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  stream_id (2B) │ msg_type (2B) │ length (4B) │ payload │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                   Multiplexing Layer                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Stream IDs:                                            │  │
│  │    0x0001 - consensus                                   │  │
│  │    0x0002 - dag_batches                                 │  │
│  │    0x0003 - dag_availability                            │  │
│  │    0x0004 - control                                     │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                  PQC Secure Channel                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  KEMTLS (ML-KEM-768 + ChaCha20-Poly1305)               │  │
│  │  - Authenticated key exchange                           │  │
│  │  - Encrypted + authenticated payloads                   │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                   Physical Transport                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  TCP Sockets (OS-level)                                 │  │
│  │  - Tokio async I/O                                      │  │
│  │  - Connection management                                │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Stream Identifiers

| Stream ID | Name | Purpose |
| :--- | :--- | :--- |
| `0x0001` | `consensus` | HotStuff proposals, votes, timeouts, new-view |
| `0x0002` | `dag_batches` | DAG mempool batch dissemination |
| `0x0003` | `dag_availability` | Batch acknowledgments and certificates |
| `0x0004` | `control` | Heartbeats, peer exchange, health checks |

### 5.3 Application Frame Format

```
┌─────────┬──────────┬────────┬─────────────────────────┐
│ stream  │ msg_type │ length │        payload          │
│  (2B)   │   (2B)   │  (4B)  │     (variable)          │
└─────────┴──────────┴────────┴─────────────────────────┘
```

| Field | Size | Description |
| :--- | :--- | :--- |
| `stream_id` | 2 bytes | Identifies the logical stream (see §5.2) |
| `msg_type` | 2 bytes | Message type within the stream |
| `length` | 4 bytes | Payload length in bytes (big-endian) |
| `payload` | variable | Serialized message (existing CBOR/Bincode format) |

### 5.4 Chain ID and Domain Separation

Chain ID and domain separation are enforced **at the cryptographic level**, not the network level:

| Enforcement Point | Mechanism |
| :--- | :--- |
| **Signing Preimages** | All signed messages include `QBIND:<SCOPE>:<MSG_TYPE>:v1` prefix |
| **Chain ID in State** | `NodeConfig.chain_id()` returns environment-specific chain ID |
| **Cross-Chain Replay** | Signatures from DevNet are invalid on TestNet due to different scope |

**Not Enforced in P2P Handshake**:

- The KEMTLS handshake does **not** branch on chain-id.
- Chain-id is verified at the application layer when processing messages.
- This allows debugging tools to connect across environments (with obvious signature failures).

See [QBIND Chain ID and Domains](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) for the complete domain separation scheme.

---

## 6. Threat Model and Mitigations

### 6.1 Threat Summary

| Threat | Severity | Mitigation Status |
| :--- | :--- | :--- |
| **Sybil Attack** | High | Permissioned validator set (on-chain) |
| **Eclipse Attack** | High | Minimum peer diversity + multi-region guidelines |
| **DoS / Bandwidth** | High | Rate limiting + bounded queues |
| **Identity Spoofing** | Medium | KEMTLS authentication + NodeId verification |
| **Key Compromise** | Critical | Key rotation hooks + compromised key handling |

### 6.2 Sybil Attack Mitigation

**Assumption**: QBIND uses a **permissioned validator set** defined on-chain.

| Phase | Sybil Mitigation |
| :--- | :--- |
| **DevNet / TestNet Alpha** | Validator set is hardcoded or config-driven. No open joining. |
| **TestNet Beta** | Validator set is on-chain. Requires governance approval to join. |
| **MainNet** | Stake-weighted validator set. Economic cost to Sybil attack. |

**Full Node Discovery**:

- Full node discovery is **not Sybil-resistant** in TestNet Beta.
- Validators prioritize connections to known validators over full nodes.
- Sybil-resistant full node discovery is MainNet work.

### 6.3 Eclipse Attack Mitigation

**Definition**: Eclipse attack = attacker controls all of a validator's peer connections.

**Mitigations**:

| Mitigation | Implementation Phase |
| :--- | :--- |
| **Minimum Outbound Degree** | TestNet Alpha: Validators maintain minimum 4 outbound connections |
| **Peer Diversity Scoring** | TestNet Beta: Prefer peers from different IP ranges / ASNs |
| **Multi-Region Peers** | Guideline (doc): Validators should have peers in 2+ regions |
| **Random Peer Selection** | TestNet Beta: Random selection from peer pool for new connections |

**Recommended Validator Deployment**:

> Validators SHOULD maintain peers in at least 2 geographic regions and 2 autonomous systems (ASNs). This is a soft guideline for operators, not protocol-enforced.

### 6.4 DoS / Bandwidth Exhaustion Mitigation

| Mitigation | Target Values | Implementation Phase |
| :--- | :--- | :--- |
| **Per-Peer Rate Limiting** | 100 msgs/sec, 10MB/sec | TestNet Alpha (existing `PeerRateLimiter`) |
| **Bounded Inbound Queues** | 1000 messages max | TestNet Alpha |
| **Backpressure Strategy** | Drop oldest on overflow | TestNet Alpha |
| **Connection Close on Violation** | 3 strikes → close | TestNet Beta |
| **Pending Handshake Limit** | 50 concurrent | TestNet Alpha |

**Existing Implementation**:

The `PeerRateLimiter` (T90) already provides per-peer rate limiting:

```rust
pub struct PeerRateLimiterConfig {
    pub max_messages_per_second: u32,  // Default: 1000
    pub burst_allowance: u32,          // Default: 100
}
```

### 6.5 Key Compromise Handling

**Network Key Compromise**:

| Scenario | Response |
| :--- | :--- |
| **Suspected Compromise** | Operator rotates network key; NodeId changes |
| **Confirmed Compromise** | Peers add old NodeId to banlist; new handshakes rejected |
| **Key Rotation Hooks** | `NetworkTransportConfig` includes key rotation version field |

**Consensus Key Compromise**:

- Not handled by P2P layer.
- Requires governance action to remove validator from on-chain set.
- See consensus documentation for slashing/removal procedures.

### 6.6 Implementation Timeline

| Mitigation | TestNet Alpha | TestNet Beta | MainNet |
| :--- | :--- | :--- | :--- |
| Permissioned Validator Set | ✅ Config-driven | ✅ On-chain | ✅ Stake-weighted |
| Per-Peer Rate Limiting | ✅ Existing | ✅ Tuned | ✅ Production values |
| Bounded Queues | ✅ Implementation | ✅ Tuned | ✅ Production values |
| Peer Diversity Scoring | ❌ Not implemented | ⏳ Basic | ✅ Full |
| Sybil-Resistant Discovery | ❌ Not needed | ❌ Not needed | ⏳ Future |

---

## 7. Phased Rollout Plan

### 7.1 Phase Overview

| Phase | Network | P2P Capabilities | Status |
| :--- | :--- | :--- | :--- |
| **0** | DevNet v0 | Static KEMTLS mesh, local harness | ✅ Complete (Frozen) |
| **1** | TestNet Alpha | Config-driven static mesh, multi-machine | ⏳ In Progress |
| **2** | TestNet Beta | Basic discovery, gossip for DAG | 📋 Planned |
| **3** | MainNet | Full P2P with DoS protection | 📋 Planned |

### 7.2 Phase 1: TestNet Alpha (Current Target)

**Goals**:

- Extend DevNet harness to multi-machine deployments
- Maintain static peer configuration
- Add NetworkTransportConfig skeleton
- Document P2P architecture (this document)

**Deliverables**:

- [x] P2P design document (T170)
- [x] NetworkTransportConfig skeleton
- [x] P2pService trait skeleton
- [ ] Multi-machine deployment guide (future task)
- [ ] Basic peer health monitoring (future task)

### 7.3 Phase 2: TestNet Beta

**Goals**:

- Basic peer discovery (peer exchange protocol)
- Separate consensus and DAG overlays
- Gossip protocol for DAG batch dissemination
- Multi-region validator support

**Deliverables**:

- [ ] Peer exchange protocol implementation
- [ ] Gossip protocol for DAG messages
- [ ] Dual overlay support
- [ ] Enhanced peer scoring

### 7.4 Phase 3: MainNet

**Goals**:

- Production-grade DoS protection
- Full peer discovery protocol
- Sybil-resistant full node discovery
- Comprehensive monitoring and alerting

**Deliverables**:

- [ ] Full discovery protocol
- [ ] Advanced peer scoring and banning
- [ ] Comprehensive DoS mitigations
- [ ] Operational runbooks

---

## 8. Code-Level Skeletons

### 8.1 NetworkTransportConfig

Added to `qbind-node/src/node_config.rs`:

```rust
/// Configuration for the P2P network transport layer (T170).
///
/// This struct controls the behavior of the P2P networking stack.
/// For DevNet and TestNet Alpha, P2P is disabled by default (static mesh).
/// For TestNet Beta and MainNet, P2P will be enabled.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkTransportConfig {
    /// Whether the P2P overlay is enabled.
    ///
    /// - `false` (default): Uses static mesh (DevNet, TestNet Alpha)
    /// - `true`: Uses dynamic P2P overlay (TestNet Beta, MainNet)
    pub enable_p2p: bool,

    /// Maximum number of outbound connections.
    ///
    /// Default: 16. For validators, this should be at least 2f+1 for liveness.
    pub max_outbound: usize,

    /// Maximum number of inbound connections.
    ///
    /// Default: 64. Higher than outbound to allow full nodes to connect.
    pub max_inbound: usize,

    /// Gossip fanout for DAG/mempool overlay.
    ///
    /// Default: 6. Number of peers to forward gossip messages to.
    pub gossip_fanout: usize,
}
```

### 8.2 P2pService Trait

Added in `qbind-node/src/p2p.rs`:

```rust
/// Node identifier for P2P networking (T170).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId([u8; 32]);

/// P2P message wrapper for transport (T170).
pub enum P2pMessage {
    Consensus(ConsensusNetMsg),
    Dag(DagNetMsg),
    Control(ControlMsg),
}

/// P2P service trait for network operations (T170).
///
/// This trait defines the interface for sending messages over the P2P network.
/// Implementations will handle routing, multiplexing, and transport.
pub trait P2pService: Send + Sync {
    /// Broadcast a message to all connected peers.
    fn broadcast(&self, msg: P2pMessage);

    /// Send a message to a specific peer.
    fn send_to(&self, peer: NodeId, msg: P2pMessage);
}
```

### 8.3 Integration Points

The following integration points are prepared but **not wired** in T170:

| Component | Integration Point | Status |
| :--- | :--- | :--- |
| `NodeConfig` | `network_transport: NetworkTransportConfig` field | ✅ Added (optional) |
| `ConsensusNetworkFacade` | `Option<Arc<dyn P2pService>>` field | 📋 Documented |
| `DagMempool` | `Option<Arc<dyn P2pService>>` field | 📋 Documented |
| Startup | Read `NetworkTransportConfig` from config | 📋 Future task |

---

## Appendices

### Appendix A: Glossary

| Term | Definition |
| :--- | :--- |
| **KEMTLS** | Key Encapsulation Mechanism TLS — PQC-safe transport protocol using ML-KEM-768 |
| **NodeId** | 32-byte identifier for a P2P network node |
| **ValidatorId** | On-chain identifier for a consensus validator |
| **Gossip** | Epidemic protocol for message dissemination |
| **Overlay** | Logical network topology built on top of physical connections |
| **Fanout** | Number of peers a message is forwarded to in gossip protocols |

### Appendix B: Related Documents

- [QBIND DevNet v0 Freeze Capsule](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet v0 specification and roadmap
- [QBIND TestNet Alpha Specification](../testnet/QBIND_TESTNET_ALPHA_SPEC.md) — TestNet Alpha features
- [QBIND DAG Mempool Design](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) — DAG mempool architecture
- [QBIND Chain ID and Domains](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) — Domain separation scheme
- [QBIND Ignored Tests Audit](../QBIND_IGNORED_TESTS_AUDIT.md) — Performance test catalog

### Appendix C: Open Questions (Future Tasks)

| Question | Notes |
| :--- | :--- |
| **Discovery Protocol** | What protocol for TestNet Beta peer discovery? (peer exchange, rendezvous, etc.) |
| **Gossip Implementation** | Which gossip variant? (epidemic, plumtree, etc.) |
| **NAT Traversal** | When to add STUN/TURN/ICE for NAT hole-punching? |
| **QUIC Support** | Timeline for QUIC transport option? |
| **Peer Reputation** | Detailed scoring algorithm for TestNet Beta |

---

*End of Document*
