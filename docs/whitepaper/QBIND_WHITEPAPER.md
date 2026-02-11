# QBIND Whitepaper
Version: Draft v3 (Full Technical Baseline)
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

---

# 9. Cryptographic Architecture

QBIND is designed as a post-quantum-secure blockchain.  
All authentication and key establishment mechanisms are built around post-quantum cryptographic primitives.

This section formalizes the cryptographic roles and security boundaries.

<img src="diagrams/crypto-roles.svg" alt="QBIND Cryptographic Roles Diagram" />

---

## 9.1 Cryptographic Roles

QBIND defines distinct cryptographic roles:

1. Validator Signing Key  
   - Used for block proposals and votes  
   - Produces consensus signatures  

2. Network Key (KEM)  
   - Used for handshake-based session establishment  
   - Derives symmetric session keys  

3. Session AEAD Keys  
   - Derived per connection  
   - Used for encrypted message transport  

4. Governance / Council Keys  
   - Used to sign upgrade envelopes and parameter changes  

Key role separation prevents cross-layer compromise propagation.

---

## 9.2 Secure Networking (KEM-Based Handshake)

The secure channel is established via a KEM-based handshake.

Properties:

- Transcript-bound key derivation
- Per-direction symmetric keys
- Explicit nonce structure
- Overflow detection

Nonce format:

flag (1 byte) || session_id (3 bytes) || counter (8 bytes)

Session termination occurs on counter overflow to prevent nonce reuse.

Handshake keys are bound to both participants via transcript hashing.

---

## 9.3 Key Storage and Protection

QBIND supports:

- Plaintext keystore (development use)
- Encrypted keystore (PBKDF2 + AEAD)
- Remote signer daemon (HSM / airgapped support)

All private key material is wrapped with ZeroizeOnDrop semantics in memory.

MainNet safety rails require encrypted keystore or remote signer.

---

## 9.4 Remote Signer Isolation

The remote signer daemon:

- Isolates validator signing keys
- Signs consensus messages via authenticated channel
- Reduces risk of key exfiltration from validator node process

Remote signer failure behavior is configurable:
- Development mode: warning
- MainNet mode: process termination

---

## 9.5 Suite Versioning and Downgrade Protection

Cryptographic suites are versioned.

Runtime suite downgrade across epochs is rejected.

Suite downgrade attempts are treated as fatal security violations.

This prevents rollback attacks to weaker cryptographic parameters.

---

## 9.6 Cryptographic Agility Model

QBIND is designed to allow future suite upgrades without chain resets.

Upgrade path requirements:

- Governance-approved suite transition
- Epoch boundary activation
- Explicit compatibility rules
- State persistence compatibility

Cryptographic changes are treated as protocol events, not silent upgrades.

---

## 9.7 Known Gaps

- Full HSM PKCS#11 integration partially implemented
- Cookie-based DoS protection in handshake not enforced
- Expanded slashing for equivocation pending

These are roadmap items.

---

# 10. Transaction and State Model

QBIND uses an account-based state model with deterministic transaction execution.

This section formalizes the transaction format, execution semantics, and state persistence guarantees.

<img src="diagrams/tx-state-flow.svg" alt="QBIND Transaction and State Flow Diagram" />

---

## 10.1 Transaction Structure

A transaction contains:

- msg_type
- version
- chain_id
- payer (account ID)
- nonce
- fee_limit
- account list
- program_id
- call_data
- authentication signatures

The transaction format is deterministic and fully serialized prior to consensus inclusion.

Replay protection is enforced via (payer, nonce).

---

## 10.2 Account Model

Each account contains:

- account_id (32 bytes)
- owner (program identifier)
- balance (lamports)
- executable flag
- rent_epoch
- arbitrary data payload

Accounts are modified only through program execution.

State transitions are deterministic across validators.

---

## 10.3 Execution Model

Transaction execution occurs only after block commit.

Execution flow:

1. Decode transactions from committed block
2. Validate signatures and nonce
3. Execute via runtime
4. Apply state changes
5. Remove committed transactions from mempool

Execution is deterministic given identical input state.

Optional EVM execution is supported via integration with the runtime engine.

---

## 10.4 Gas Accounting

Each transaction specifies:

- fee_limit
- effective gas cost

Execution fails if gas exceeds fee_limit.

Gas prevents:

- Infinite loops
- Resource exhaustion
- Denial-of-service via heavy computation

MainNet enforces gas accounting strictly.

---

## 10.5 Persistence Guarantees

Upon commit:

1. State changes applied in memory
2. Block persisted
3. QC persisted
4. last_committed updated

Restart safety is guaranteed via durable RocksDB writes.

Schema version mismatches prevent startup.

---

## 10.6 Determinism Requirements

Consensus safety requires:

- Identical transaction ordering within block
- Deterministic execution engine
- Deterministic gas metering
- Deterministic serialization

Non-deterministic execution would violate safety.

---

## 10.7 Known Gaps

- Advanced state pruning not yet implemented
- Full formal gas model documentation pending
- Expanded slashing economics pending

---

# 11. Upgrade and Governance Safety Model

QBIND treats protocol upgrades and cryptographic suite transitions as explicit, consensus-aware events.

Upgrades are not silent software changes; they are state transitions governed by protocol rules.

<img src="diagrams/upgrade-flow.svg" alt="QBIND Upgrade and Governance Flow Diagram" />

---

## 11.1 Upgrade Activation Model

Upgrades are activated at epoch boundaries.

An upgrade must satisfy:

1. Governance approval
2. Inclusion in a committed block
3. Activation height or epoch specification
4. Validator compatibility enforcement

Nodes that do not support the activated upgrade will fail startup or halt.

This prevents ambiguous fork conditions.

---

## 11.2 Governance Envelope

Governance actions are packaged in signed envelopes.

Envelope properties:

- Versioned format
- Signed by authorized council keys
- Verifiable before application
- Persisted for auditability

Upgrade envelopes may modify:

- Cryptographic suite parameters
- Network configuration
- Economic parameters
- Validator set rules

---

## 11.3 Cryptographic Suite Transition Safety

Suite transitions must:

- Occur at epoch boundary
- Be forward-compatible
- Reject downgrade attempts
- Maintain deterministic state compatibility

Suite downgrade across epochs is rejected as a fatal violation.

---

## 11.4 MainNet Safety Rails

MainNet enforces stricter conditions than DevNet/TestNet:

- Gas accounting must be enabled
- P2P networking must be enabled
- Encrypted keystore or remote signer required
- Genesis hash validated at startup
- Schema version compatibility enforced

Nodes violating these conditions terminate.

---

## 11.5 Failure Containment

If an upgrade activation fails validation:

- The block is rejected
- The QC is invalidated
- No state transition occurs

This prevents partial upgrade activation.

---

## 11.6 Future Governance Enhancements

Planned improvements include:

- Expanded slashing enforcement
- Formalized economic governance specification
- Automated upgrade simulation in TestNet
- Cryptographic agility test harness

Governance evolution is designed to remain deterministic and auditable.

---

# 12. Adversarial Analysis

This section models adversarial conditions under which QBIND must preserve safety and, where possible, liveness.

<img src="diagrams/threat-model.svg" alt="QBIND Threat Model Diagram" />

---

## 12.1 Threat Model

QBIND assumes:

- Up to f Byzantine validators (where N ≥ 3f + 1)
- Adversarial network capable of:
  - Message delay
  - Message reordering
  - Packet dropping
  - Partitioning
- Malicious clients submitting invalid transactions
- Attempted cryptographic downgrade or replay attacks

The protocol does not assume trusted networking infrastructure.

---

## 12.2 Byzantine Validator Behavior

Possible malicious behaviors:

- Double voting at same height/view
- Proposing conflicting blocks
- Withholding votes
- Delaying quorum formation

Mitigations:

- Double-vote rejection at validator level
- Lock rule prevents conflicting commits
- 2f + 1 quorum intersection ensures safety
- Slashing infrastructure (partial implementation)

Safety remains intact if ≤ f validators are Byzantine.

---

## 12.3 Network-Level Attacks

### Replay Attacks

Mitigated by:

- Nonce-based replay protection in transactions
- Monotonic session nonce in secure channel

Session termination occurs on nonce overflow.

---

### Message Reordering / Delay

HotStuff safety is preserved under partial synchrony.

Liveness depends on eventual synchrony and functional timeout mechanisms.

Timeout/view-change is partially implemented and remains a roadmap item.

---

### DoS Attacks

Potential vectors:

- Flooding mempool
- Handshake resource exhaustion
- Oversized blocks
- Execution-heavy transactions

Mitigations:

- Gas limits per transaction
- Bounded mpsc channels (backpressure)
- Session-level AEAD framing
- MainNet gas enforcement

Cookie-based handshake DoS mitigation is defined but not yet enforced.

---

## 12.4 Key Compromise Scenarios

### Validator Signing Key Compromise

Impact:
- Malicious votes or proposals from compromised validator

Mitigation:
- BFT threshold prevents unilateral commit
- Slashing planned for economic deterrence
- Remote signer isolation reduces exposure surface

---

### Network KEM Key Compromise

Impact:
- Impersonation or MITM attempt

Mitigation:
- Transcript-bound key derivation
- Identity binding via delegation certificates
- Session re-establishment required

---

## 12.5 Crash and Restart Safety

Crash during commit:

- Durable RocksDB writes ensure restart consistency
- last_committed marker prevents state regression
- Schema mismatch prevents unsafe startup

Epoch transition writes storage before in-memory update to preserve atomicity.

---

## 12.6 Upgrade Attack Scenarios

### Partial Upgrade Activation

Mitigation:
- Activation only at epoch boundary
- Invalid upgrade blocks rejected
- Non-compatible nodes halt

---

### Suite Downgrade Attempt

Mitigation:
- Downgrade rejected as fatal violation
- Versioned suite enforcement

---

## 12.7 Residual Risks

- Liveness under prolonged asynchrony until timeout logic finalized
- Incomplete slashing economics
- Cookie-based DoS protection not yet active
- Future cryptographic breakthroughs

QBIND explicitly tracks these risks as roadmap items rather than silent assumptions.

---

# 13. Performance and Scalability Model

QBIND is designed for high throughput and low latency under adversarial conditions, not merely under ideal networking.

This section describes performance characteristics and scalability constraints.

<img src="diagrams/performance-model.svg" alt="QBIND Performance Model Diagram" />

---

## 13.1 Throughput Determinants

Throughput is influenced by:

- Block size
- Transaction size
- Execution cost per transaction
- Signature verification throughput
- Network propagation delay
- Quorum formation latency

Consensus throughput is bounded by the slowest of:

1. Proposal dissemination
2. Vote aggregation
3. Execution and state persistence

---

## 13.2 Latency Model

Finality latency (ideal case):

≈ 3 consensus rounds (3-chain rule)

Latency increases under:

- Network delay
- View changes
- Leader failures

Timeout/view-change optimization is a roadmap item.

---

## 13.3 Parallelism Strategy

QBIND employs:

- Parallel signature verification workers
- Async execution worker
- Bounded channel backpressure
- Optional DAG-based mempool for improved block assembly

Future scalability enhancements may include:

- Optimized async peer management
- Enhanced DAG-to-consensus coupling
- Parallel transaction execution (subject to deterministic constraints)

---

## 13.4 Bottlenecks

Primary scaling bottlenecks:

- Cryptographic verification cost
- State write amplification in RocksDB
- Network bandwidth limits
- Execution engine complexity

These are explicitly acknowledged rather than abstracted away.

---

## 13.5 Scalability Roadmap

Planned improvements:

- Timeout/view-change optimization
- Expanded slashing and penalty enforcement
- Improved DoS cookie enforcement
- Enhanced HSM integration
- Advanced state pruning
- Deterministic parallel execution exploration

All scalability improvements must preserve safety invariants defined in Sections 8–12.

---

# 14. Long-Term Cryptographic Roadmap

QBIND is designed for long-horizon cryptographic resilience.

---

## 14.1 Post-Quantum Commitment

All authentication and key establishment mechanisms are based on post-quantum primitives.

QBIND does not rely on classical hardness assumptions for validator authentication.

---

## 14.2 Suite Evolution

Future suite upgrades may include:

- Parameter strength increases
- Alternative PQ signature schemes
- Alternative KEM constructions
- Aggregation optimizations

All transitions must follow governance-controlled epoch activation.

---

## 14.3 Research Alignment

QBIND monitors:

- NIST post-quantum standardization outcomes
- Cryptanalysis developments
- Performance improvements in PQ primitives

Suite transitions are designed to be non-disruptive and deterministic.

---

## 14.4 Conservative Upgrade Philosophy

QBIND prioritizes:

- Stability over novelty
- Security over speculative performance gains
- Formal review before activation

Long-term viability depends on disciplined upgrade control.

---

# 15. Conclusion

QBIND is a post-quantum-secure Layer-1 blockchain designed with explicit safety invariants, deterministic execution, and cryptographic agility as foundational principles.

The system integrates:

- A KEM-based secure networking layer
- A HotStuff-style BFT consensus protocol
- Deterministic account-based execution
- Strict nonce and replay protections
- Governance-controlled upgrade activation
- Explicit adversarial modeling

Known gaps are documented transparently and treated as roadmap items rather than implicit guarantees.

QBIND prioritizes:

- Safety over speculative throughput
- Upgrade discipline over silent transitions
- Cryptographic resilience over short-term optimization

The long-term viability of QBIND depends on continued cryptographic review, rigorous adversarial testing, and conservative protocol evolution.

This document reflects the current implemented architecture and serves as a technical specification baseline for further development, audit, and deployment.

---

# 16. Formal State Transition Model

This section defines QBIND's consensus-critical global state and the deterministic state transition rules applied at commit.

QBIND's state is modeled as a tuple. Some components are persisted (durable) and others are in-memory only (runtime), but both can be consensus-relevant.

---

## 16.1 Global State Tuple

Define the global protocol state **S** as:

```
S = (
    Accounts,           // Map<AccountId, Account>
    Nonces,             // Map<AccountId, u64>
    ValidatorSet,       // Set<ValidatorSetEntry>
    Epoch,              // EpochId (u64)
    SuiteRegistry,      // SuiteRegistry
    ParamRegistry,      // ParamRegistry
    MonetaryState,      // MonetaryEpochState
    SlashingState,      // Map<ValidatorId, ValidatorSlashingState>
    KeyRotationState,   // KeyRotationRegistry

    // Consensus-specific
    LockedQC,           // Option<QuorumCertificate>
    LockedHeight,       // u64
    LastCommittedBlock, // Option<BlockId>
    CommittedHeight,    // u64

    // View state
    CurrentView,        // u64
    LastVoted,          // Option<(Height, Round, BlockId)>

    // Persistence markers
    SchemaVersion       // u32
)
```

---

## 16.2 Durable vs Runtime State

| Component | Persistence | Consensus-Critical | Location |
|-----------|-------------|-------------------|----------|
| Accounts | Durable | ✅ Yes | RocksDB `acct:<id>` |
| Nonces | Durable | ✅ Yes | RocksDB `nonce:<id>` |
| ValidatorSet | Runtime* | ✅ Yes | Loaded from genesis/config |
| Epoch | Durable | ✅ Yes | RocksDB `meta:current_epoch` |
| SuiteRegistry | Durable | ✅ Yes | Account data |
| ParamRegistry | Durable | ✅ Yes | Account data |
| MonetaryState | Mixed | ✅ Yes | Account data / in-memory |
| SlashingState | Runtime | ✅ Yes | In-memory (T230) |
| KeyRotationState | Runtime | ✅ Yes | In-memory until epoch advance |
| LockedQC | Runtime | ✅ Yes | Reconstructed from last committed |
| LockedHeight | Runtime | ✅ Yes | Derived from LockedQC |
| LastCommittedBlock | Durable | ✅ Yes | RocksDB `meta:last_committed` |
| CommittedHeight | Runtime | ✅ Yes | Derived from last committed |
| CurrentView | Runtime | ⚠️ Liveness | Pacemaker state |
| LastVoted | Runtime | ✅ Yes | Double-vote prevention |
| SchemaVersion | Durable | ⚠️ Startup | RocksDB `meta:schema_version` |

*ValidatorSet is loaded at startup but may be updated at epoch boundaries.

---

## 16.3 State Transition Function

The global state transition function is defined as:

```
δ: S × Input → S' × Output
```

Where **Input** is one of:

- `Transaction(tx)` — User transaction execution
- `BlockCommit(block, qc)` — Finalization of a committed block
- `EpochBoundary(new_epoch)` — Epoch transition event
- `UpgradeActivation(upgrade)` — Governance-approved protocol upgrade
- `SlashingEvidence(evidence)` — Byzantine behavior evidence
- `ViewChange(new_view)` — Consensus view advancement

And **Output** captures:

- State mutation records
- Emitted events
- Error conditions

---

## 16.4 State Mutation Rules

### 16.4.1 Transaction Execution

Upon transaction `tx` applied to state `S`:

1. Verify `tx.nonce == Nonces[tx.payer]`
2. Verify `Accounts[tx.payer].balance >= tx.fee_limit`
3. Execute via runtime
4. Deduct gas from payer balance
5. Apply account mutations
6. Increment `Nonces[tx.payer]`

Execution is deterministic given identical input state.

### 16.4.2 Block Commit

Upon committing block `B` with quorum certificate `QC`:

```
S' = S with:
    LastCommittedBlock := B.id
    CommittedHeight := B.height
    Accounts := apply_transactions(S.Accounts, B.transactions)
    Nonces := increment_nonces(S.Nonces, B.transactions)
    LockedQC := QC  (if QC.height > S.LockedHeight)
    LockedHeight := max(S.LockedHeight, QC.height)
```

Persistence order:

1. Persist block at `b:<block_id>`
2. Persist QC at `q:<block_id>`
3. Update `meta:last_committed`

### 16.4.3 Epoch Transition

Upon epoch boundary from epoch `e` to `e + 1`:

```
S' = S with:
    Epoch := e + 1
    ValidatorSet := compute_next_validator_set(S)
    MonetaryState := compute_monetary_epoch(S, e + 1)
    KeyRotationState := advance_key_rotations(S.KeyRotationState, e + 1)
    SlashingState := process_unjails(S.SlashingState, e + 1)
```

Epoch is persisted to storage before in-memory state is updated.

### 16.4.4 Slashing Evidence

Upon valid slashing evidence `E` for validator `V`:

```
S' = S with:
    SlashingState[V].offense_count := S.SlashingState[V].offense_count + 1
    SlashingState[V].jailed := true  (if penalty threshold exceeded)
```

Note: Actual stake burning is deferred to T229+ implementation.

---

## 16.5 Commit Procedure

The commit procedure ensures atomicity and crash safety:

1. **Pre-commit validation**
   - Verify 3-chain rule satisfied
   - Verify QC has sufficient voting power

2. **Durable writes (atomic batch)**
   - Write block to `b:<block_id>`
   - Write QC to `q:<block_id>`
   - Update `meta:last_committed`

3. **In-memory state update**
   - Update LockedQC, LockedHeight
   - Apply account mutations
   - Update nonces

4. **Post-commit cleanup**
   - Remove committed transactions from mempool
   - Emit commit notification

Writes 1-3 MUST complete before in-memory updates proceed.

---

## 16.6 Determinism Requirements

Consensus safety requires all validators to compute identical state from identical input.

| Requirement | Enforcement |
|-------------|-------------|
| Transaction ordering | Block defines canonical order |
| Execution semantics | Deterministic runtime |
| Gas metering | Fixed cost model |
| Serialization | Canonical wire format |
| Floating-point | Prohibited in consensus path |
| Time-dependent logic | Uses block height/epoch, not wall-clock |

Non-deterministic execution violates safety and would cause chain forks.

---

## 16.7 Crash Recovery Model

Upon restart, state is recovered as follows:

| State Component | Recovery Method |
|-----------------|-----------------|
| LastCommittedBlock | Read `meta:last_committed` |
| Epoch | Read `meta:current_epoch` |
| LockedQC | Reconstruct from committed chain |
| LockedHeight | Derive from LockedQC |
| CurrentView | Start from committed view + 1 |
| LastVoted | Reset (conservative: may re-vote) |
| Mempool | Empty (clients resubmit) |
| SlashingState | Lost (T230 limitation) |

Recovery invariant: A restarted node MUST NOT commit a block that conflicts with its pre-crash commits.

---

## 16.8 Known Limitations

- Slashing state is in-memory only; evidence lost on restart (T230)
- Vote history subject to memory eviction
- Key rotation state not persisted until epoch advance
- Epoch transition has narrow crash-vulnerability window

These are tracked as roadmap items.