# QBIND DAG–HotStuff Consensus Coupling Design

**Task**: T188  
**Status**: Design Document (MainNet v0)  
**Date**: 2026-02-02

---

## Table of Contents

1. [Problem Statement and Scope](#1-problem-statement-and-scope)
2. [Objects and Invariants](#2-objects-and-invariants)
3. [Protocol Flow with Coupling](#3-protocol-flow-with-coupling)
4. [Block and Header Structure Implications](#4-block-and-header-structure-implications)
5. [Safety and Liveness Discussion](#5-safety-and-liveness-discussion)
6. [Configuration and Phase Behavior](#6-configuration-and-phase-behavior)
7. [Implementation Plan Outline](#7-implementation-plan-outline)
8. [Notes and Open Questions](#8-notes-and-open-questions)

---

## 1. Problem Statement and Scope

### 1.1 What "Consensus-Coupled DAG" Means for QBIND

In prior network phases (DevNet, TestNet Alpha, TestNet Beta), QBIND's DAG mempool operates as a **data-plane** feature: validators create batches, exchange availability acknowledgments (BatchAck), and form availability certificates (BatchCertificate) with 2f+1 signatures. However, the consensus layer (HotStuff BFT) does not **require** these certificates—blocks can be proposed and committed without verifying that the included transactions belong to certified batches.

**Consensus-coupled DAG** changes this relationship fundamentally:

| Aspect | Data-Plane Only (Beta) | Consensus-Coupled (MainNet v0) |
| :--- | :--- | :--- |
| **Certificate Formation** | Best-effort; improves availability | Required before proposal |
| **Proposal Construction** | Leader can propose any valid txs | Leader MUST reference certified batches only |
| **Vote Validation** | Txs verified; certs optional | Txs AND certs MUST be valid |
| **Commit Rule** | 3-chain HotStuff (unchanged) | 3-chain + DAG-coupling invariants |
| **Liveness Dependency** | Consensus doesn't wait for certs | Consensus waits for cert availability |

In essence, **consensus-coupled DAG** means that the availability layer's certificates become a **prerequisite** for consensus ordering, not merely an optimization.

### 1.2 Network Phases and Applicability

This design applies **exclusively to MainNet v0**. The coupling mode differs by network phase:

| Phase | DAG Mode | Availability Certs | Consensus Coupling |
| :--- | :--- | :--- | :--- |
| **DevNet v0** | FIFO (default), DAG opt-in | None | None |
| **TestNet Alpha** | FIFO + DAG opt-in | v1 (opt-in) | None |
| **TestNet Beta** | DAG (default) | v1 (default, data-plane) | None (Off) |
| **MainNet v0** | DAG (**only**) | v1 (**required**) | **Enforce** |

### 1.3 MainNet v0 Spec Requirements Addressed

This design document addresses the following requirements from [QBIND_MAINNET_V0_SPEC.md](./QBIND_MAINNET_V0_SPEC.md):

**From §4.2 Availability Certificates:**
> DAG availability certificates are **required** components for MainNet v0.

**From §4.3 Consensus Coupling to DAG:**
> **MainNet v0 requirement**: HotStuff proposals MUST only commit batches that have valid availability certificates.
>
> | Rule | Description | Enforcement |
> | :--- | :--- | :--- |
> | **Certificate Required** | Batches without certificates cannot be proposed | Block validation |
> | **Certificate Validity** | Certificates must have 2f+1 valid signatures | Block validation |
> | **No Uncertified Batches** | Leader cannot include uncertified data | Block construction |

**From §6.3 DAG Availability and Consensus Coupling (Risk MN-R1):**
> **Fork on consensus coupling**: DAG consensus coupling is new; may introduce consensus bugs [Critical, Open]

This document specifies the coupling semantics fully, enabling T189+ implementation tasks to close this risk.

---

## 2. Objects and Invariants

### 2.1 Relevant Objects

The following objects participate in DAG–consensus coupling:

#### 2.1.1 DAG Layer Objects

| Object | Description | Reference |
| :--- | :--- | :--- |
| **QbindBatch** | A collection of transactions created and signed by a single validator. Contains `author`, `batch_id`, `transactions`, `parent_refs`, `timestamp`, and `signature` (ML-DSA-44). | [QBIND_DAG_MEMPOOL_DESIGN.md §3.2.1](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) |
| **BatchId** | Unique identifier for a batch, typically `H(batch_content)` (SHA3-256). | T158 implementation |
| **BatchRef** | Reference tuple `(creator: ValidatorId, batch_id: BatchId)` uniquely identifying a batch. | T165 implementation |
| **BatchAck** | Validator acknowledgment of batch receipt: `(batch_ref, validator_id, view_hint, signature)`. | T165 implementation |
| **BatchCertificate** | Proof that 2f+1 validators acknowledged a batch: `(batch_ref, view, signers, signatures)`. | T165 implementation |

#### 2.1.2 Consensus Layer Objects

| Object | Description | Reference |
| :--- | :--- | :--- |
| **QbindBlock / Proposal** | Block proposed by the HotStuff leader, containing header and transaction payload. | Consensus core |
| **BlockHeader** | Metadata including `parent_hash`, `view`, `proposer`, `state_root`, `tx_root`, and (new) `batch_commitment`. | T189 extension |
| **View** | HotStuff view number; monotonically increasing. | Consensus core |
| **VoteMessage** | Validator vote for a proposal: `(block_hash, view, voter, signature)`. | Consensus core |
| **QuorumCertificate (QC)** | 2f+1 votes for a block, enabling the 3-chain commit rule. | Consensus core |
| **ValidatorSet** | The set of n=3f+1 validators with their public keys and stake weights. | Consensus core |

#### 2.1.3 New Objects for Coupling (MainNet v0)

| Object | Description | Purpose |
| :--- | :--- | :--- |
| **CertifiedBatchRef** | Tuple `(batch_ref: BatchRef, cert_digest: H(BatchCertificate))` binding a batch to its certificate. | Compact commitment in proposals |
| **BatchCommitment** | Merkle root over the ordered list of `CertifiedBatchRef` in a block. | Header commitment to DAG content |
| **CouplingMode** | Enum `{Off, Warn, Enforce}` controlling validation behavior per network phase. | Configuration switch |

### 2.2 Key Invariants for MainNet v0

The following invariants MUST hold for any valid MainNet v0 chain:

---

#### **I1: Certified Transaction Inclusion**

> Every transaction in a committed block belongs to at least one batch that has a valid BatchCertificate with 2f+1 signatures.

**Formal Statement:**
```
∀ block B committed on the chain:
  ∀ tx ∈ B.transactions:
    ∃ batch_ref R such that:
      - R ∈ B.certified_batch_refs
      - tx ∈ batch(R).transactions
      - valid_certificate(R)
```

**Enforcement Points:**
- Proposer: Must only include txs from certified batches
- Validator (pre-vote): Must verify all batch certs before voting
- Validator (commit): Must have all batch data locally

---

#### **I2: Certificate Unforgeability and Binding**

> Certificates are unforgeable and bound to exactly one batch via proper domain separation and hashing.

**Formal Statement:**
```
∀ BatchCertificate cert:
  - cert.batch_ref uniquely identifies exactly one QbindBatch
  - cert.signatures are valid ML-DSA-44 signatures over:
      domain_tag || batch_ref.creator || batch_ref.batch_id || view_hint
  - |cert.signers| >= 2f+1
  - All signers are in the current ValidatorSet
```

**Domain Tag Format:**
```
QBIND:MAIN:BATCH_ACK:v1  (MainNet scope)
QBIND:TST:BATCH_ACK:v1   (TestNet scope)
QBIND:DEV:BATCH_ACK:v1   (DevNet scope)
```

**Enforcement Points:**
- BatchAck creation: Sign with proper domain tag
- Certificate formation: Verify 2f+1 distinct valid signatures
- Certificate validation: Re-verify all signatures before voting

---

#### **I3: Vote Integrity (No Unknown/Uncertified Batches)**

> A validator will never vote to commit a block that references unknown or uncertified batches.

**Formal Statement:**
```
∀ validator V, ∀ proposal P:
  V.vote(P) implies:
    ∀ R ∈ P.certified_batch_refs:
      - V.has_batch(R.batch_ref)
      - V.has_certificate(R.batch_ref)
      - V.verify_certificate(R.batch_ref) == true
```

**Enforcement Points:**
- Pre-vote check: Reject proposals with missing batches or invalid certs
- Fetch-on-miss: Allow bounded time to retrieve missing data before rejection
- Vote signing: Only sign after all verifications pass

---

#### **I4: Liveness Under Certified Frontier**

> Honest validators that have all certified batches can continue making progress (no deadlocks from over-strict rules).

**Formal Statement:**
```
If:
  - |honest_validators| >= 2f+1
  - All honest validators have the same certified frontier F
  - Network is eventually synchronous
Then:
  - Eventually a block B with certified_batch_refs ⊆ F will be committed
```

**Design Implications:**
- Proposals should reference only widely-available certified batches
- Fetch-on-miss provides recovery for temporarily missing data
- Timeout/view-change allows progress even if some batches never certify

---

#### **I5: HotStuff Safety Preservation**

> DAG + consensus coupling does not break HotStuff safety (no two conflicting blocks can be committed at the same height/view).

**Formal Statement:**
```
Standard HotStuff safety:
  ∀ heights h: |{B : committed(B) ∧ B.height == h}| <= 1

Extended with DAG coupling:
  The DAG-coupling validation rules do not create new commit paths
  that could bypass the 3-chain rule.
```

**Key Insight:** DAG coupling adds **additional preconditions** for voting (batch availability + certificate validity) but does not change the **commit rule** (3-chain). Since we only add restrictions, safety is preserved.

---

## 3. Protocol Flow with Coupling

This section describes the MainNet v0 steady-state protocol flow with consensus-coupled DAG.

### 3.1 Batch Creation and Diffusion

#### 3.1.1 How Validators Package Transactions into Batches

1. **Transaction Collection**: Validator receives transactions from clients via P2P or RPC.

2. **Admission Checks**: Each transaction undergoes:
   - ML-DSA-44 signature verification
   - Nonce validity check (against local state)
   - Balance sufficiency check (`balance >= amount + gas_limit × max_fee_per_gas`)
   - Gas limit validity (`gas_limit >= MINIMUM_GAS_LIMIT`)

3. **Batch Formation**: Periodically (or when batch reaches target size), validator:
   - Selects top N transactions by fee priority
   - Creates `QbindBatch` structure:
     ```
     QbindBatch {
         author: self.validator_id,
         batch_id: H(batch_content),
         round: current_dag_round,
         transactions: selected_txs,
         parent_refs: certified_batches_from_previous_round,
         timestamp: now(),
         signature: sign(QBIND:MAIN:BATCH:v1 || batch_content)
     }
     ```

4. **Batch Size Limits**:
   - `MAX_BATCH_SIZE_TXS`: 1000 transactions (configurable)
   - `MAX_BATCH_SIZE_BYTES`: 1 MB (configurable)

#### 3.1.2 Batch Broadcast

1. **Gossip Protocol**: Batch is broadcast to all validators via the DAG P2P overlay (stream `0x0002`).

2. **Propagation Strategy**: Reliable broadcast with:
   - Direct send to all known peers
   - Peers forward to their peers (bounded fan-out)
   - Deduplication by batch_id

#### 3.1.3 Batch Reception and Storage

Upon receiving a batch, validators:

1. **Verify Batch Signature**: Check ML-DSA-44 signature against author's public key.

2. **Verify Parent References**: Confirm all `parent_refs` are certified batches we have locally (or trigger fetch-on-miss).

3. **Verify Transaction Validity** (optional, can defer to execution):
   - Signature validity
   - Basic format checks

4. **Store Batch**: Add to local `InMemoryDagMempool` indexed by `batch_ref`.

5. **Issue Acknowledgment**: If batch is valid, proceed to acknowledge (§3.2).

### 3.2 Availability Certificates

#### 3.2.1 BatchAck Production and Signing

Upon receiving and validating a batch, a validator issues a `BatchAck`:

```
BatchAck {
    batch_ref: (author, batch_id),
    validator_id: self.id,
    view_hint: current_view,  // Helps certificate formation track view
    suite_id: 100,            // ML-DSA-44
    signature: sign(QBIND:MAIN:BATCH_ACK:v1 || batch_ref || validator_id || view_hint)
}
```

**Signing Preimage** (domain-separated):
```
QBIND:MAIN:BATCH_ACK:v1     (17 bytes, domain tag)
batch_ref.creator           (8 bytes, little-endian)
batch_ref.batch_id          (32 bytes)
validator_id                (8 bytes, little-endian)
view_hint                   (8 bytes, little-endian)
```

**Delivery**: Ack is sent directly to the batch author (stream `0x0003`).

#### 3.2.2 BatchCertificate Formation

The batch author collects acks and forms a certificate when quorum is reached:

```
BatchCertificate {
    batch_ref: (author, batch_id),
    view: view_at_formation,
    signers: [v1, v2, ..., v_{2f+1}],  // At least 2f+1 validators
    signatures: [sig1, sig2, ..., sig_{2f+1}]  // Corresponding signatures
}
```

**Quorum Requirement**: `|signers| >= 2f+1` where `n = 3f+1` total validators.

**Certificate Validity Check**:
```python
def verify_certificate(cert, validator_set):
    if len(cert.signers) < 2*f + 1:
        return False
    for i, (signer, sig) in enumerate(zip(cert.signers, cert.signatures)):
        if signer not in validator_set:
            return False
        preimage = build_ack_preimage(cert.batch_ref, signer, cert.view)
        if not verify_mldsa44(validator_set[signer].pubkey, preimage, sig):
            return False
    return True
```

#### 3.2.3 Certificate Storage and Indexing

Certificates are stored in the `InMemoryDagMempool` with indexes:

| Index | Key | Value |
| :--- | :--- | :--- |
| **By BatchRef** | `batch_ref` | `BatchCertificate` |
| **By View** | `view` | `[BatchCertificate]` |
| **Certified Frontier** | — | Set of `batch_ref` for most recent certified batches |

#### 3.2.4 Certificate Broadcast

After forming a certificate, the author broadcasts it to all validators:
- Via DAG P2P overlay (stream `0x0002`)
- Validators store certificates and update their certified frontier

### 3.3 Proposal Construction (Leader)

When a validator is selected as HotStuff leader for a view, it constructs a proposal:

#### 3.3.1 Selecting Certified Frontier Batches

1. **Identify Certified Frontier**: Collect all certified batches not yet committed.

2. **Apply Selection Criteria**:
   - **Certificate Validity**: All selected batches MUST have valid certificates
   - **Block Gas Limit**: Total gas of included txs ≤ `BLOCK_GAS_LIMIT`
   - **Fee Priority**: Prefer batches with higher aggregate fees
   - **Availability**: Prefer batches likely to be available at all validators

3. **Ordering**: Sort selected batches deterministically by `(view, batch_ref.creator, batch_ref.batch_id)`.

#### 3.3.2 Proposal Structure (MainNet v0)

```
QbindBlockProposal {
    // Standard HotStuff fields
    parent_hash: H(parent_block),
    view: current_view,
    proposer: self.validator_id,
    
    // DAG-coupling fields (MainNet v0)
    certified_batch_refs: [(batch_ref_1, cert_digest_1), ..., (batch_ref_k, cert_digest_k)],
    batch_commitment: merkle_root(certified_batch_refs),
    
    // Transaction payload (derived from batches)
    transactions: flatten_and_dedupe(batches),
    tx_root: merkle_root(transactions),
    
    // Execution results
    state_root: H(post_execution_state),
    
    // Full certificates (optional, for convenience)
    certificates: [cert_1, ..., cert_k],  // Can be omitted if validators have them
    
    // Proposal signature
    signature: sign(QBIND:MAIN:PROPOSE:v1 || proposal_hash)
}
```

**Key Design Choice**: Proposals carry `certified_batch_refs` (compact) and optionally full `certificates`. Validators that already have certificates can verify using the `cert_digest`; others can fetch from the proposal or via fetch-on-miss.

#### 3.3.3 Gas Limit and Fee Priority Interaction

1. **Per-Block Gas Limit**: `sum(tx.gas) <= BLOCK_GAS_LIMIT` (default 30M)

2. **Batch Selection for Gas**: If including a batch would exceed gas limit:
   - Option A: Partial batch inclusion (include txs until gas limit)
   - Option B: Skip batch entirely (simpler, recommended for v0)

3. **Fee Priority Within Batch Ordering**:
   - Batches ordered by aggregate `max_fee_per_gas`
   - Within a batch, tx order is preserved from batch author

### 3.4 Vote and QC Formation

#### 3.4.1 Validator Checks Before Voting

Upon receiving a proposal, a validator performs:

**Phase 1: Standard HotStuff Checks**
1. View is current or next view
2. Proposer is correct leader for this view
3. Parent hash references known block
4. Proposal signature is valid

**Phase 2: DAG-Coupling Checks (MainNet v0 only)**
1. **Certificate Presence**: For each `batch_ref` in `certified_batch_refs`:
   - Validator has the certificate locally, OR
   - Certificate is included in the proposal, OR
   - Validator can fetch certificate (bounded time)

2. **Certificate Validity**: For each certificate:
   - `|signers| >= 2f+1`
   - All signatures are valid ML-DSA-44
   - All signers are in current `ValidatorSet`

3. **Batch Data Presence**: For each certified batch:
   - Validator has batch data locally, OR
   - Validator can fetch batch (bounded time)

4. **Commitment Consistency**:
   - `batch_commitment == merkle_root(certified_batch_refs)`
   - `tx_root == merkle_root(transactions)`
   - `transactions` matches the flattened, deduplicated tx set from referenced batches

**Phase 3: Execution Verification**
1. Re-execute transactions against local state
2. Verify `state_root` matches local execution result

#### 3.4.2 Fetch-on-Miss Before Voting

If a validator is missing batch data or certificates:

1. **Trigger Fetch Request**: `BatchRequest { batch_refs: [missing_refs] }`

2. **Wait with Timeout**: Allow up to `FETCH_TIMEOUT` (default: 5 seconds) for response

3. **Decision**:
   - If data arrives: Continue with verification
   - If timeout: Reject proposal (do not vote)

4. **Metrics**: Track `dag_vote_fetch_triggered`, `dag_vote_fetch_success`, `dag_vote_fetch_timeout`

#### 3.4.3 Vote Signing Preimage

Votes bind to the block hash, which transitively commits to all DAG content:

```
VoteMessage {
    block_hash: H(proposal),  // Commits to batch_commitment, tx_root, etc.
    view: current_view,
    voter: self.validator_id,
    signature: sign(QBIND:MAIN:VOTE:v1 || block_hash || view || voter)
}
```

**Key Point**: The vote signs over `block_hash`, which is computed as:
```
block_hash = H(
    QBIND:MAIN:BLOCK:v1 ||
    parent_hash ||
    view ||
    proposer ||
    batch_commitment ||    // Commits to DAG batches
    tx_root ||
    state_root
)
```

Thus, a valid vote **implicitly** asserts that all DAG-coupling invariants were verified.

### 3.5 Commit and Execution

#### 3.5.1 3-Chain Commit Trigger

A block B is committed when the 3-chain rule is satisfied:
```
B ← B' ← B'' (consecutive views, each with QC)
```

Upon commit of B:

1. **Mark Batches as Committed**: All batches referenced by B are marked committed
2. **Execute Transactions**: Apply all txs from B to state
3. **Prune Certified Frontier**: Remove committed batches from active tracking

#### 3.5.2 Deriving Committed Transaction Set

The committed tx set is derived deterministically from DAG batches:

```python
def derive_committed_txs(block):
    txs = []
    seen_tx_ids = set()
    
    # Process batches in deterministic order
    for batch_ref in sorted(block.certified_batch_refs):
        batch = get_batch(batch_ref)
        for tx in batch.transactions:
            tx_id = H(tx)
            if tx_id not in seen_tx_ids:
                txs.append(tx)
                seen_tx_ids.add(tx_id)
    
    return txs
```

**Ordering Rules**:
1. **Inter-Batch**: Batches ordered by `(batch_ref.creator, batch_ref.batch_id)` lexicographically
2. **Intra-Batch**: Transaction order preserved from batch author
3. **Deduplication**: If a tx appears in multiple batches, include only first occurrence

#### 3.5.3 Stage B Parallel Execution Integration

When Stage B is enabled (MainNet v0 default):

1. **Conflict Graph Construction**: Build graph from tx read/write sets
2. **Parallel Schedule**: Generate topological layers
3. **Parallel Execution**: Execute independent layers in parallel
4. **Deterministic Merge**: Merge results in deterministic order

**Critical**: Stage B execution order must be **derived from the same batch ordering** used for serial execution. The ordering is:
```
ordering = flatten(sorted_batches)  // Same for serial and parallel
```

Stage B only changes **how** transactions are executed, not **which** transactions or their **logical order**.

---

## 4. Block and Header Structure Implications

### 4.1 MainNet v0 Block Hash Definition

For MainNet v0, the block hash commits to DAG content via the `batch_commitment`:

```
BlockHeader {
    // Chain linkage
    parent_hash: [u8; 32],
    height: u64,
    view: u64,
    
    // Proposer identity
    proposer: ValidatorId,
    
    // DAG commitment (MainNet v0 addition)
    batch_commitment: [u8; 32],  // Merkle root over CertifiedBatchRefs
    
    // Execution commitment
    tx_root: [u8; 32],           // Merkle root over transactions
    state_root: [u8; 32],        // Post-execution state root
    
    // Timing
    timestamp: u64,
}

block_hash = SHA3-256(
    QBIND:MAIN:BLOCK:v1 ||
    header.parent_hash ||
    header.height ||
    header.view ||
    header.proposer ||
    header.batch_commitment ||   // NEW: DAG coupling
    header.tx_root ||
    header.state_root ||
    header.timestamp
)
```

### 4.2 Batch Commitment Structure

The `batch_commitment` is a Merkle root over the ordered list of `CertifiedBatchRef`:

```
CertifiedBatchRef {
    batch_ref: BatchRef,              // (creator, batch_id)
    cert_digest: [u8; 32],            // H(BatchCertificate)
}

batch_commitment = merkle_root([
    H(cbr_1) || H(cbr_2) || ... || H(cbr_k)
])
```

This structure ensures:
- **Completeness**: All referenced batches are enumerated
- **Ordering**: Batch order is deterministic and committed
- **Certificate Binding**: Each batch is bound to its specific certificate

### 4.3 Proof of DAG Invariant Compliance

Given a valid `block_hash`, we can prove:

1. **I1 (Certified Transaction Inclusion)**:
   - `batch_commitment` commits to `CertifiedBatchRefs`
   - Each `CertifiedBatchRef` includes `cert_digest`
   - `cert_digest` binds to a valid `BatchCertificate` with 2f+1 sigs
   - Therefore, all txs are from certified batches ✓

2. **I2 (Certificate Unforgeability)**:
   - Certificate signatures are ML-DSA-44 (PQ-secure)
   - Domain separation prevents cross-chain replay
   - `cert_digest` uniquely identifies the certificate
   - Therefore, certificates are unforgeable ✓

3. **I3 (Vote Integrity)**:
   - Votes sign over `block_hash`
   - `block_hash` commits to `batch_commitment`
   - Validators verify certificates before voting
   - Therefore, votes only exist for blocks with valid certs ✓

### 4.4 Block Body Structure

The full block body for MainNet v0:

```
QbindBlock {
    header: BlockHeader,
    
    // DAG references (compact)
    certified_batch_refs: Vec<CertifiedBatchRef>,
    
    // Full certificates (for convenience / missing data recovery)
    certificates: Vec<BatchCertificate>,  // Optional based on config
    
    // Transaction payload
    transactions: Vec<QbindTransaction>,
    
    // Proposal signature (not part of block_hash)
    proposer_signature: Signature,
}
```

---

## 5. Safety and Liveness Discussion

### 5.1 Safety Argument

#### 5.1.1 HotStuff Safety Preservation

**Theorem**: If HotStuff is safe without DAG coupling, it remains safe with DAG coupling.

**Proof Sketch**:

1. **HotStuff Safety** depends on:
   - Honest validators only vote once per view
   - QC formation requires 2f+1 votes
   - 3-chain commit rule ensures linearizability

2. **DAG coupling adds preconditions**:
   - Validators only vote if DAG invariants are satisfied
   - This is a **stricter** condition than voting unconditionally

3. **No new commit paths**:
   - DAG coupling does not create any alternative commit mechanism
   - Commits still require 3-chain with valid QCs
   - QCs still require 2f+1 honest votes

4. **Conclusion**: Since DAG coupling only adds preconditions for voting (making it harder to vote, not easier), and does not change the commit rule, HotStuff safety is preserved. ∎

#### 5.1.2 Double-Spend Prevention via DAG Coupling

**Claim**: Consensus-coupled DAG prevents double-spend attacks that exploit uncertified data.

**Scenario Without Coupling**:
- Malicious leader proposes block B with uncertified batch containing double-spend
- Honest validators might not have the batch data
- If validators vote anyway (trusting the leader), double-spend could commit

**Scenario With Coupling**:
- Malicious leader proposes block B with uncertified batch
- Honest validators check: certificate missing or invalid
- Validators refuse to vote (I3 enforced)
- Block B cannot get 2f+1 votes, cannot form QC, cannot commit

### 5.2 Liveness Discussion

#### 5.2.1 Liveness Under Normal Conditions

**Claim**: Under synchronous network conditions with honest supermajority, consensus makes progress.

**Argument**:

1. **Batch Certification**: Honest validators issue acks for valid batches
   - With 2f+1 honest validators, every valid batch gets certified

2. **Certified Frontier Growth**: As batches certify, frontier expands
   - Leader has non-empty set of certified batches to propose

3. **Proposal Acceptance**: Honest leader proposes only certified batches
   - All honest validators have (or can fetch) the batch data
   - All honest validators verify certificates and vote

4. **QC Formation**: With 2f+1 honest votes, QC forms
   - 3-chain progress leads to commits

#### 5.2.2 Handling Slow Acks and Batches

**Scenario**: Some validators are slow to send acks or batches.

**Mitigations**:

1. **Timeout Before Proposal**: Leader waits for certificate formation
   - `CERT_WAIT_TIMEOUT`: Max time to wait for batch to certify
   - If timeout: Proceed with available certified batches

2. **Fetch-on-Miss Before Vote**: Validators fetch missing data
   - `FETCH_TIMEOUT`: Max time to wait for fetch
   - If timeout: Reject proposal (don't vote)

3. **View Change**: If proposal fails to get QC:
   - Timeout triggers view change
   - New leader proposes (possibly with different batches)

**Timeline Example**:

```
Time    Event
0ms     Validator A creates batch B_a
10ms    B_a propagates to all validators
50ms    2f+1 acks received, cert C_a formed
100ms   Leader starts proposal construction
110ms   Leader includes B_a (has C_a)
150ms   Proposal P received by validators
160ms   Validators verify C_a, vote
200ms   QC formed
...     (3-chain continues)
```

#### 5.2.3 DoS Considerations

**Attack**: Malicious leader proposes non-certified batches.

**Defense**:
1. Honest validators reject proposal immediately (I3)
2. No QC forms for malicious proposal
3. View change timeout triggers
4. New (potentially honest) leader takes over
5. Network continues with honest leader's proposal

**Impact**: Single malicious proposal causes at most one view timeout delay.

**Metric**: Track `dag_proposals_rejected_invalid_cert` to detect attack patterns.

**Attack**: Adversary prevents batch certification by withholding acks.

**Defense**:
1. With ≤f malicious validators, 2f+1 honest acks still available
2. Batches from honest validators will certify
3. Leader can propose blocks with honest validator batches only
4. Progress continues (though adversary's txs may be delayed)

---

## 6. Configuration and Phase Behavior

### 6.1 Coupling Mode Configuration

DAG–consensus coupling is controlled by a configuration parameter:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DagCouplingMode {
    /// Off: No coupling; consensus ignores DAG certificates
    /// Used in: DevNet v0, TestNet Alpha, TestNet Beta
    Off,
    
    /// Warn: Log warnings for uncertified batches but don't reject
    /// Used in: Testing/transition scenarios
    Warn,
    
    /// Enforce: Reject proposals with uncertified batches
    /// Used in: MainNet v0
    Enforce,
}
```

### 6.2 Phase-by-Phase Configuration

| Phase | `dag_coupling_mode` | Behavior |
| :--- | :--- | :--- |
| **DevNet v0** | `Off` | Certificates not checked; FIFO mempool default |
| **TestNet Alpha** | `Off` | Certificates tracked (data-plane) but not enforced |
| **TestNet Beta** | `Off` (or optionally `Warn` for testing) | Certificates tracked; warnings logged if missing |
| **MainNet v0** | `Enforce` | Certificates required; proposals rejected without valid certs |

### 6.3 Configuration Integration

The coupling mode integrates with existing profile system:

```rust
impl NodeConfig {
    pub fn devnet_preset() -> Self {
        Self {
            dag_coupling_mode: DagCouplingMode::Off,
            // ... other DevNet settings
        }
    }
    
    pub fn testnet_alpha_preset() -> Self {
        Self {
            dag_coupling_mode: DagCouplingMode::Off,
            // ... other Alpha settings
        }
    }
    
    pub fn testnet_beta_preset() -> Self {
        Self {
            dag_coupling_mode: DagCouplingMode::Off,  // Or Warn for testing
            // ... other Beta settings
        }
    }
    
    pub fn mainnet_preset() -> Self {
        Self {
            dag_coupling_mode: DagCouplingMode::Enforce,  // Required for MainNet
            // ... other MainNet settings
        }
    }
}
```

### 6.4 MainNet Invariant Validation

For MainNet profile, the coupling mode is enforced at startup:

```rust
fn validate_mainnet_invariants(config: &NodeConfig) -> Result<(), ConfigError> {
    // ... existing checks ...
    
    // T189: DAG coupling must be enforced for MainNet
    if config.dag_coupling_mode != DagCouplingMode::Enforce {
        return Err(ConfigError::MainNetInvariantViolation(
            "dag_coupling_mode must be Enforce for MainNet".into()
        ));
    }
    
    Ok(())
}
```

### 6.5 CLI Flag

A CLI flag allows explicit coupling mode configuration:

```bash
# MainNet (default: Enforce)
qbind-node --profile mainnet --data-dir /data/qbind

# Override for testing (would fail MainNet validation)
qbind-node --profile mainnet --dag-coupling-mode warn --data-dir /data/qbind
# Error: MainNet invariant violation: dag_coupling_mode must be Enforce

# Beta with Warn (for transition testing)
qbind-node --profile testnet-beta --dag-coupling-mode warn --data-dir /data/qbind
```

---

## 7. Implementation Plan Outline

This section outlines concrete steps for follow-up implementation tasks. No Rust code is written as part of T188.

### 7.1 T189: Wire `dag_coupling_mode` Config + Block Format Changes

**Scope**: Configuration infrastructure and block format updates for DAG coupling.

**Changes**:
- Add `DagCouplingMode` enum to `qbind-common` or config module
- Add `dag_coupling_mode` field to `NodeConfig`
- Update profile presets (DevNet, Alpha, Beta, MainNet) with appropriate defaults
- Extend `validate_mainnet_invariants()` to check coupling mode
- Add CLI flag `--dag-coupling-mode {off,warn,enforce}`
- Extend `BlockHeader` with `batch_commitment` field
- Update `block_hash` computation to include `batch_commitment`
- Add `CertifiedBatchRef` type

**Test Impact**:
- Unit tests for config parsing and validation
- Unit tests for new block hash computation
- Integration test: MainNet profile rejects `coupling_mode != Enforce`

### 7.2 T190: Implement Proposer-Side Enforcement

**Scope**: Ensure block proposals only include certified batches.

**Changes**:
- Update `construct_proposal()` in consensus module to:
  - Filter batches: only certified ones
  - Build `certified_batch_refs` list
  - Compute `batch_commitment` Merkle root
  - Include certificates in proposal (configurable)
- Add metrics: `dag_proposer_batches_available`, `dag_proposer_batches_certified`, `dag_proposer_batches_included`
- Add logging for dropped uncertified batches

**Test Impact**:
- Unit tests for proposal construction with coupling
- Integration test: proposal with uncertified batch should not be created
- Property test: all transactions in proposals belong to certified batches

### 7.3 T191: Implement Validator-Side Enforcement

**Scope**: Verify certificates before voting; reject invalid proposals.

**Changes**:
- Update `validate_proposal()` in consensus module to:
  - Check coupling mode (if `Off`, skip DAG checks)
  - Verify all `certified_batch_refs` have valid certificates
  - Verify all batch data is available (or trigger fetch-on-miss)
  - Verify `batch_commitment` matches computed Merkle root
- Integrate fetch-on-miss with voting path
- Add timeout handling for missing data
- Add metrics: `dag_votes_accepted`, `dag_votes_rejected_missing_cert`, `dag_votes_rejected_invalid_cert`, `dag_vote_fetch_triggered`

**Test Impact**:
- Unit tests for proposal validation with coupling
- Integration test: validator rejects proposal with invalid cert
- Integration test: validator fetches missing batch before voting
- Integration test: validator rejects if fetch times out

### 7.4 T192: Extend Cluster Harness Tests for Consensus-Coupled DAG

**Scope**: End-to-end tests validating full DAG–consensus coupling.

**Changes**:
- Add cluster harness test: `test_mainnet_dag_coupling_happy_path`
  - 4 validators, MainNet profile, full DAG + coupling
  - Verify blocks commit, all certs valid
- Add cluster harness test: `test_mainnet_dag_coupling_cert_latency`
  - Simulate slow cert formation
  - Verify progress continues with available certs
- Add cluster harness test: `test_mainnet_dag_coupling_malicious_proposal`
  - Leader proposes uncertified batch
  - Verify proposal rejected, view change occurs
- Add cluster harness test: `test_mainnet_dag_coupling_fetch_on_miss`
  - Validator missing batch data
  - Verify fetch triggers, vote succeeds after fetch

**Test Impact**:
- 4 new cluster harness tests
- Tests should run in CI with MainNet profile
- Tests should verify metrics are correctly updated

---

## 8. Notes and Open Questions

### 8.1 Observations During Design

1. **Batch Ordering Determinism**: The design assumes batches are ordered by `(creator, batch_id)` lexicographically. This matches the existing DAG mempool behavior but should be explicitly documented in implementation.

2. **Certificate Size**: With n=100 validators and 2f+1=67 signers, a certificate contains 67 ML-DSA-44 signatures (67 × 2420 bytes ≈ 162 KB). For MainNet, consider:
   - Certificate compression in network layer
   - Future: Aggregate signatures (when PQ standards mature)

3. **Fetch-on-Miss Timeout**: The 5-second default may need tuning based on:
   - Network latency in production
   - Expected batch propagation time
   - View timeout configuration

### 8.2 Open Questions

1. **Q: Should `batch_commitment` use a sparse Merkle tree for efficient proofs?**
   - Current design uses simple Merkle root
   - Sparse tree could enable batch-inclusion proofs
   - Decision: Defer to implementation (T189); simple root is sufficient for v0

2. **Q: Should proposals include full certificates or just references?**
   - Full certs: Simpler, but larger proposals
   - References only: Smaller, but requires fetch-on-miss
   - Recommendation: Include full certs by default, make configurable

3. **Q: How does coupling interact with validator set changes (dynamic membership)?**
   - Current design assumes static validator set
   - MainNet v0 uses static governance-approved set
   - Future work: Document certificate validity across reconfiguration

4. **Q: Should there be a "grace period" for coupling mode transition?**
   - E.g., `Warn` mode for first N blocks on MainNet
   - Risk: Could allow uncertified batches during transition
   - Recommendation: No grace period; MainNet launches with `Enforce` from genesis

### 8.3 Potential Spec Inconsistencies Noted

1. **MainNet Spec §4.3 vs Audit Skeleton §3.2**: The MainNet spec states coupling is "required" while the audit skeleton marks it as "Open – no detailed design". This document resolves the inconsistency by providing the detailed design.

2. **Fetch-on-miss v0 limitations**: The existing fetch-on-miss (T182, T183) uses broadcast to all peers. For MainNet, targeted fetch to specific validators (those who sent acks) would be more efficient. This is noted for future enhancement.

---

## References

| Document | Path | Description |
| :--- | :--- | :--- |
| MainNet v0 Spec | [QBIND_MAINNET_V0_SPEC.md](./QBIND_MAINNET_V0_SPEC.md) | MainNet architecture |
| MainNet Audit | [QBIND_MAINNET_AUDIT_SKELETON.md](./QBIND_MAINNET_AUDIT_SKELETON.md) | MainNet risk tracker |
| TestNet Beta Spec | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | Beta architecture |
| DAG Mempool Design | [QBIND_DAG_MEMPOOL_DESIGN.md](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) | DAG architecture |
| Parallel Execution Design | [QBIND_PARALLEL_EXECUTION_DESIGN.md](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) | Stage A/B parallelism |
| Chain ID and Domains | [QBIND_CHAIN_ID_AND_DOMAINS.md](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) | Domain separation |
| DevNet v0 Freeze | [QBIND_DEVNET_V0_FREEZE.md](../devnet/QBIND_DEVNET_V0_FREEZE.md) | DevNet baseline |

---

*End of Document*