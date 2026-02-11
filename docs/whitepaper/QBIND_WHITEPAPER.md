# QBIND Whitepaper
Version: Draft v2 (Code-Mapped)
Status: Technical Specification (No Tokenomics)

---

# 1. Abstract

QBIND is a post-quantum-secure Layer-1 blockchain implemented in Rust, designed for long-horizon security, cryptographic agility, and production-grade validator operation.

The system integrates:
- Post-quantum cryptography for authentication and key establishment
- A KEM-based secure networking layer
- A HotStuff-style BFT consensus engine
- A modular transaction execution runtime
- Persistent storage with explicit schema control

QBIND operates through three network environments:

- DevNet – development and rapid iteration
- TestNet – adversarial testing and performance validation
- MainNet – production-grade operation with strict safety rails

This document specifies the system architecture, networking model, consensus design, state model, and forward roadmap.

---

# 2. Design Philosophy

## 2.1 Security First

Security invariants are explicit and enforced in code:
- Quorum certificate validation
- Lock safety rules
- Nonce monotonicity
- Overflow protection
- Key zeroization

Performance improvements must not violate safety constraints.

## 2.2 Post-Quantum by Default

Authentication and session establishment are built around post-quantum primitives.  
The networking layer derives transcript-bound session keys and enforces strict nonce uniqueness.

## 2.3 Cryptographic Agility

Cryptographic suites are versioned and treated as first-class protocol components.  
Upgrades are governed and designed to avoid ambiguous consensus transitions.

## 2.4 Modular Architecture

QBIND separates:
- Networking
- Consensus
- Execution
- State management
- Storage
- Governance tooling

Each layer has clear responsibility boundaries.

## 2.5 Code-Driven Specification

This whitepaper reflects the current repository structure.  
Incomplete components are explicitly documented in the roadmap section.

---

# 3. System Overview

QBIND is structured as a layered architecture:

• Foundation Layer  
  - Types, hashing, and wire encoding  
  - Cryptographic primitives  

• Secure Networking Layer  
  - KEM-based handshake  
  - Transcript-bound key schedule  
  - AEAD encrypted transport framing  

• Consensus Layer  
  - HotStuff-style BFT  
  - 3-chain commit rule  
  - Quorum certificate formation  

• Execution & State Layer  
  - Account-based state model  
  - System programs  
  - Optional EVM execution  

• Node Layer  
  - P2P networking  
  - Mempool (including DAG module)  
  - Consensus driver  
  - RocksDB persistence  
  - Metrics & observability  

---

# 4. QBIND Node Architecture

<img src="diagrams/node-architecture.svg" alt="QBIND Node Architecture Diagram" />

The QBIND node integrates:

- RPC & CLI configuration
- Peer manager and P2P transport
- Secure session management
- Mempool (FIFO + DAG)
- Consensus engine
- Runtime execution
- Persistent storage

All network traffic passes through the secure session layer.
Consensus messages are validated before state transition.
Committed blocks are persisted before final acknowledgment.

---

# 5. Networking Security Properties

The secure channel derives independent client-to-server and server-to-client session keys.

Nonce structure:
flag (1 byte) || session_id (3 bytes) || counter (8 bytes)

The counter is monotonic and overflow results in session termination.

Handshake transcript binding ensures session keys depend on both parties' contributions.

---

# 6. Known Gaps (Current Implementation)

- DoS cookie enforcement in handshake is defined but not yet enforced.
- Timeout/view-change mechanics in the consensus driver are marked TODO.
- Slashing penalties are partially implemented; enforcement expansion is planned.

These are tracked roadmap items, not assumed guarantees.

---

# 7. Node Internal Architecture and Execution Flow

This section formalizes the internal runtime structure of a QBIND validator node based on the implemented codebase.

<img src="diagrams/node-runtime-flow.svg" alt="QBIND Node Runtime and Execution Flow Diagram" />

---

## 7.1 Async Runtime Model

QBIND uses a multi-threaded Tokio runtime initialized via:

    #[tokio::main]
    async fn main()

The runtime spawns independent asynchronous services responsible for networking, consensus progression, execution, and observability.

### Primary Services

- P2P demultiplexer loop
- Async consensus runner
- Metrics HTTP server (optional)
- Async execution worker
- Secure channel read/write workers
- Signature verification worker pool

Service communication follows an event-driven architecture.

### Communication Primitives

1. Bounded mpsc Channels  
   - Default capacity: 1024  
   - Used for consensus events and P2P message routing  
   - Provides built-in backpressure  

2. Shared State with Locking  
   - Mempool uses Arc