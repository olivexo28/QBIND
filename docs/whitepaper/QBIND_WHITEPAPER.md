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
   - Mempool uses Arc<RwLock<...>> for concurrent access

---

# 8. Consensus Protocol Specification

QBIND implements a HotStuff-style Byzantine Fault Tolerant (BFT) consensus protocol with deterministic leader rotation and quorum certificate formation.

This section formalizes the protocol behavior as implemented.

<img src="diagrams/hotstuff-3chain.svg" alt="HotStuff 3-Chain Commit Rule Diagram" />

---

## 8.1 System Model

Let:

- N = number of validators
- f = maximum Byzantine validators tolerated
- Quorum threshold = 2f + 1 voting power

Assumption:
N ≥ 3f + 1

Validators communicate over authenticated channels established via the secure networking layer.

---

## 8.2 Leader Election

Leader selection is deterministic:

leader(view) = validators[ view mod N ]

Each view has exactly one designated proposer.

No VRF-based or stake-weighted randomness is currently implemented.

---

## 8.3 Proposal Structure

A proposal contains:

- block_id
- parent block reference
- transaction payload
- justify QC (quorum certificate for previous block)

The justify QC binds the proposal to a previously certified block.

---

## 8.4 Voting Rule

A validator votes for proposal P in view v if:

1. P.justify_qc.height ≥ locked_height
2. P extends from the locked block
3. The validator has not voted for another proposal at (height, view)

Double-vote attempts are rejected.

---

## 8.5 Quorum Certificate (QC)

A QC is formed when ≥ 2f + 1 validators sign the same block hash at the same height and view.

QC structure:

- block_id
- height
- view
- aggregated signatures

QC validation is required before advancing to the next view.

---

## 8.6 3-Chain Commit Rule

QBIND follows a 3-chain commit rule:

If blocks B₀ → B₁ → B₂ → B₃ form a chain of consecutive QCs:

then B₀ becomes committed.

Commit occurs when a QC is observed for the grandchild of a block.

This guarantees safety under partial synchrony.

---

## 8.7 Locking Rule

Each validator maintains a locked_height.

Upon observing a QC at height h:

locked_height := h

Validators must not vote for proposals extending below locked_height.

This prevents conflicting commits.

---

## 8.8 Safety Property (Informal)

Under the assumption that at most f validators are Byzantine:

No two honest validators will commit conflicting blocks.

Reason:

- 2f + 1 quorum intersection ensures at least f + 1 honest overlap
- Lock rule prevents divergence
- 3-chain commit rule ensures finality consistency

---

## 8.9 Liveness Assumptions

Liveness requires:

- Eventually synchronous network
- Leader eventually honest
- Timeout/view-change mechanism functioning

Note:
Timeout/view-change logic is partially implemented and marked as TODO in driver components. Liveness under prolonged asynchrony is therefore not fully guaranteed in the current implementation.

---

## 8.10 Known Consensus Gaps

- Timeout and view-change logic incomplete
- Slashing penalties infrastructure present but not fully enforced
- Equivocation penalties deferred to future milestone

These limitations are explicitly tracked as roadmap items.