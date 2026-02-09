# QBIND Slashing & PQC Offenses Design

**Task**: T227  
**Status**: Design Ready  
**Date**: 2026-02-09

---

## Table of Contents

1. [Objectives & Threat Model](#1-objectives--threat-model)
2. [Offense Taxonomy](#2-offense-taxonomy)
3. [Slash Magnitudes & Economic Rationale](#3-slash-magnitudes--economic-rationale)
4. [Evidence Model & Proof Format](#4-evidence-model--proof-format)
5. [Interaction with Existing Slashing Rules](#5-interaction-with-existing-slashing-rules)
6. [Operational & Governance Considerations](#6-operational--governance-considerations)
7. [Related Documents](#7-related-documents)

---

## 1. Objectives & Threat Model

### 1.1 Objectives

The slashing model for PQC-specific offenses is designed to achieve the following goals:

1. **Ensure verification is economically dominant**: Validators must find it more profitable to verify all signatures and certificates than to skip verification to save CPU cycles.

2. **Prevent safety violations from lazy validators**: Validators accepting invalid blocks or certificates without proper verification can compromise network safety.

3. **Maintain predictable and transparent slashing rules**: All slashable offenses must be objectively provable on-chain with well-defined evidence requirements. No "vague misbehavior" slashes that could be abused.

4. **Integrate with existing BFT safety guarantees**: PQC-specific slashing complements classical double-signing rules without creating ambiguity or overlap.

5. **Account for PQC computational overhead**: ML-DSA-44 signature verification is 5–10× more expensive than classical EdDSA/ECDSA. Slashing penalties must be large enough to make skipping this verification uneconomical even under MEV pressure.

### 1.2 Threat Model

The following threats motivate the PQC-specific slashing design:

| Threat | Description | Impact |
| :--- | :--- | :--- |
| **Lazy Verification** | Validators skip ML-DSA-44 verification to save 5–10× CPU cycles per block, accepting blocks/votes without checking signatures | Safety violations if invalid blocks are accepted |
| **DAG Certificate Relaying** | Validators relay DAG availability certificates without checking batch commitments or signature validity | Data availability guarantees broken; consensus coupling violated |
| **Coordinated Cartel Attacks** | A cartel of validators accepts each other's invalid blocks to extract MEV or censor transactions | Economic attacks, safety violations, censorship |
| **Malicious Proposer** | Proposer deliberately crafts blocks with invalid signatures or certificates | Consensus stall or safety violation if validators don't verify |
| **Systematic Laziness** | Validators configure "fast-path" modes that systematically skip verification for performance gains | Gradual erosion of network security |

### 1.3 PQC-Specific Considerations

QBIND uses **ML-DSA-44** (FIPS 204) for all consensus signatures. This provides post-quantum security but introduces computational overhead:

| Operation | Classical (Ed25519) | PQC (ML-DSA-44) | Overhead Factor |
| :--- | :--- | :--- | :--- |
| Sign | ~1μs | ~10μs | ~10× |
| Verify | ~1μs | ~5μs | ~5× |
| Signature Size | 64 bytes | 2,420 bytes | ~38× |
| Public Key Size | 32 bytes | 1,312 bytes | ~41× |

This overhead creates an incentive for validators to skip verification when:
- Block frequency is high
- Validator count is large (many signatures per QC)
- MEV opportunities make speed critical

The slashing model must counteract this incentive by making the expected cost of skipping verification exceed the expected savings.

### 1.4 Economic Rationale Summary

For a validator with stake `S` and verification cost savings `C_skip`:

- **Expected benefit of skipping**: `C_skip × block_rate × time_horizon`
- **Expected cost of slashing**: `slash_rate × detection_probability × S`

For honest verification to be dominant strategy:

```
slash_rate × detection_probability × S > C_skip × block_rate × time_horizon
```

This inequality informs the slash percentages in §3.

---

## 2. Offense Taxonomy

### 2.1 Overview

| ID | Offense | Category | Severity | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **O1** | Classical Double-Signing | BFT Safety | Critical | Existing rules, summarized for completeness |
| **O2** | Invalid Consensus Signature as Proposer | PQC-Specific | High | Proposer issues block with invalid ML-DSA-44 signature |
| **O3** | Voting for Invalid Blocks (Lazy Voting) | PQC-Specific | Medium–High | Validator votes without verifying block/QC |
| **O4** | Invalid DAG Certificate Propagation | PQC-Specific | High | Validator gossips invalid DAG certificates |
| **O5** | DAG/Consensus Coupling Violations | PQC-Specific | Medium–High | Proposer includes invalid batch_commitment |

---

### 2.2 O1 – Classical Double-Signing (Existing)

**Definition**: A validator signs two different blocks or votes for the same view/height.

**Preconditions**:
- Same validator ID
- Same view and height
- Two distinct signed messages (blocks or votes)

**Impact**: Critical safety violation—can cause chain fork if more than f validators double-sign.

**Detection**: Objective; anyone can detect by comparing signed messages.

**Status**: This offense is already covered by standard HotStuff BFT slashing rules. The PQC slashing model references but does not modify these rules.

**Cross-Reference**: See HotStuff BFT safety rules in [QBIND_CONSENSUS_DESIGN.md](../devnet/QBIND_CONSENSUS_DESIGN.md).

---

### 2.3 O2 – Invalid Consensus Signature as Proposer

**Definition**: The proposer issues a block where the block signature fails ML-DSA-44 verification under the proposer's advertised consensus public key.

**Preconditions**:
- Block header contains proposer ID
- Block signature present
- Proposer's public key available in validator registry

**Verification**:
```
ML_DSA_44_Verify(proposer_pk, block_header_preimage, signature) == FAIL
```

**Impact**:
- **Safety**: If validators accept without verifying, invalid state transitions may be committed
- **Liveness**: If validators correctly reject, consensus continues but proposer wastes network bandwidth
- **Classification**: High severity—this is a direct attack or severe operational failure

**Detection**:
- **Objective**: Fully provable from block header + validator registry
- **Detector**: Any validator or monitoring node
- **Detection Time**: Immediate (on block receipt)

**Notes**:
- This offense is strictly objective—no interpretation required
- A single instance is sufficient for slashing (no "accident" excuse—proposers sign their own blocks)
- May indicate key compromise or malicious intent

---

### 2.4 O3 – Voting for Invalid Blocks (Lazy Voting)

Validators that vote for blocks without properly verifying signatures or quorum certificates undermine the BFT safety guarantees.

#### O3a – Single Lazy Vote (First Offense)

**Definition**: A validator casts a vote on a block where:
- The block signature is invalid (O2 applies to proposer), OR
- The quorum certificate (QC) in the block contains invalid signatures

**Preconditions**:
- Vote message with validator ID
- Underlying block or QC that fails verification
- Validator's vote signature is valid (they did sign the vote)

**Impact**:
- **Safety**: Single lazy vote typically not critical (requires >f lazy voters to compromise safety)
- **Operational**: Indicates misconfiguration or careless operation
- **Classification**: Medium severity—could be operational error

**Detection**:
- **Objective**: Block/QC invalidity is provable; vote linkage is provable
- **Notes**: Distinguishes from honest disagreement (honest validators might vote on valid block that later seems incorrect due to partial info)

#### O3b – Repeated Lazy Votes (Systematic Laziness)

**Definition**: A validator has cast lazy votes (O3a) on N ≥ 3 distinct blocks within a rolling window of W blocks.

**Preconditions**:
- Same validator ID
- N ≥ 3 instances of O3a within W blocks (default: W = 1,000)
- Each instance independently provable

**Impact**:
- **Safety**: Systematic laziness significantly increases risk of safety violations
- **Trust**: Indicates intentional misconfiguration or malicious intent
- **Classification**: High severity—pattern indicates deliberate behavior

**Detection**:
- **Objective**: Multiple O3a proofs for same validator
- **Aggregation**: On-chain accumulator or slashing contract tracks per-validator counts

**Governance Parameter**:
- `MIN_LAZY_VOTES_FOR_O3B`: Minimum count for O3b (default: 3)
- `LAZY_VOTE_WINDOW`: Rolling window in blocks (default: 1,000)

---

### 2.5 O4 – Invalid DAG Certificate Propagation

**Definition**: A validator gossips or certifies DAG availability certificates that fail verification.

**Sub-cases**:

#### O4a – Invalid Certificate Signatures

The DAG certificate contains a signature set where:
- Fewer than 2f+1 valid signatures (quorum not met)
- One or more signatures fail ML-DSA-44 verification

**Preconditions**:
- DAG certificate with claimed signers and signature set
- Signers' public keys in validator registry

**Verification**:
```
for (signer_id, signature) in certificate.signatures:
    if ML_DSA_44_Verify(signer_pk[signer_id], cert_preimage, signature) == FAIL:
        return INVALID
if len(valid_signatures) < 2f+1:
    return INVALID
```

#### O4b – Batch Commitment Mismatch

The DAG certificate's batch_commitment does not match the computed commitment from the included batches or DAG frontier.

**Preconditions**:
- DAG certificate with batch_commitment field
- Access to the batches claimed to be committed

**Verification**:
```
computed_commitment = Hash(batch_1 || batch_2 || ... || batch_n)
if certificate.batch_commitment != computed_commitment:
    return INVALID
```

**Impact**:
- **Availability**: Invalid certificates can break data availability guarantees
- **Consensus Coupling**: Violates the DAG–HotStuff coupling invariant (T188–T192)
- **Classification**: High severity—directly undermines availability layer

**Detection**:
- **O4a**: Objective (signature verification)
- **O4b**: Requires batch data availability (more complex proof)

---

### 2.6 O5 – DAG/Consensus Coupling Violations

**Definition**: The proposer includes a `batch_commitment` in the block header that does not correspond to any valid certified DAG frontier.

**Preconditions** (per T188–T192):
- Block contains `batch_commitment` field
- `DagCouplingMode` is `Warn` or `Enforce`
- No valid DAG certificate exists for the claimed commitment

**Verification**:
```
if dag_coupling_mode != Off:
    valid_cert = lookup_certificate(block.batch_commitment)
    if valid_cert is None:
        return COUPLING_VIOLATION
    if !verify_certificate(valid_cert):
        return COUPLING_VIOLATION
```

**Impact**:
- **Consensus Integrity**: Breaks the guarantee that committed blocks reference available data
- **Safety**: May allow proposers to include unavailable transactions
- **Classification**: Medium–High severity—depends on impact

**Detection**:
- **Objective**: Certificate lookup and verification are deterministic
- **Complexity**: Requires DAG state access (may need succinct proof for on-chain verification)

**Notes**:
- T191 (validator-side enforcement) already causes honest validators to reject such blocks
- O5 slashing provides economic penalty in addition to block rejection

---

## 3. Slash Magnitudes & Economic Rationale

### 3.1 Slash Parameter Table

| Offense | Slash (Stake %) | Jailing Period | Rationale |
| :--- | :--- | :--- | :--- |
| **O1**: Double-sign | 5–10% | 7 days | Classical BFT safety violation; industry standard |
| **O2**: Invalid proposal sig | 5% | 3 days | Proposer safety risk; fully objective; inexcusable |
| **O3a**: Single lazy vote | 0–0.5% | Warning only | One-off; possible operational error |
| **O3b**: Repeated lazy votes | 1–3% | 1 day | Systematic failure; intentional or negligent |
| **O4**: Invalid DAG cert | 5–10% | 3 days | Breaks availability guarantees; high impact |
| **O5**: Coupling violation | 1–5% | 1–3 days | Undermines DAG–consensus invariant; severity varies |

### 3.2 Economic Model

#### Assumptions (MainNet v0 parameters)

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| Block time | 5 seconds | ~17,280 blocks/day |
| Validator stake (median) | 1,000,000 QBIND | Example stake size |
| Annual staking yield | ~5% | Expected honest validator return |
| ML-DSA-44 verify cost | ~5μs | Per-signature CPU time |
| Signatures per QC | ~100 | Typical validator set |
| MEV opportunity (high) | ~1,000 QBIND/block | Upper bound |

#### Verification Cost Analysis

Cost to verify a single block (signatures only):
```
block_sig_cost = 5μs × 1 = 5μs
qc_sig_cost = 5μs × 100 = 500μs
total_verify_cost = 505μs per block
```

Over one year (~6.3M blocks):
```
annual_verify_cost = 505μs × 6.3M = ~53 minutes CPU time
```

This is negligible compared to staking rewards of ~50,000 QBIND/year.

#### Skipping Incentive Analysis

If a validator could capture MEV by being first to validate (skipping verification):
```
MEV_gain = 1,000 QBIND × 0.01 (1% of blocks as proposer) × 6.3M blocks
         = ~63,000 QBIND/year (upper bound)
```

With 5% slash rate and 10% detection probability:
```
expected_slash_cost = 5% × 10% × 1,000,000 QBIND = 5,000 QBIND per offense
```

If caught once per year, still net positive for attacker. Hence:
- **Slash rates must be significant** (5%+ for serious offenses)
- **Detection probability must be high** (monitor nodes, automatic detection)
- **Repeated offenses should escalate** (O3b vs O3a)

### 3.3 Rationale by Offense

#### O1 (Double-Sign): 5–10%

- Industry standard for BFT protocols (Cosmos, Ethereum 2.0)
- Critical safety violation—single double-sign can cause fork with enough stake
- Jailing prevents immediate re-offense
- 7-day jail allows governance response time

#### O2 (Invalid Proposal): 5%

- Proposer is solely responsible for their own signature
- No legitimate "accident" scenario—proposers must sign correctly
- Lower than double-sign because impact is contained (honest validators reject)
- Significant enough to deter malicious proposers or key compromise exploitation

#### O3a (Single Lazy Vote): 0–0.5%

- First offense may be operational error (e.g., temporary misconfiguration)
- Warning mechanism allows correction before economic penalty
- Low slash prevents over-penalizing honest mistakes
- Logged for monitoring; repeated offenses escalate to O3b

#### O3b (Repeated Lazy Votes): 1–3%

- Pattern indicates systematic problem (intentional or negligent)
- Must exceed O3a significantly to deter "just pay the fine" strategy
- 1-day jail forces operational response
- Window-based accumulator prevents ancient history from penalizing

#### O4 (Invalid DAG Cert): 5–10%

- Direct attack on data availability layer
- Can break consensus coupling guarantees (T188–T192)
- Higher severity because impact extends beyond single block
- Range allows governance adjustment based on observed attack patterns

#### O5 (Coupling Violation): 1–5%

- Proposer responsibility (similar to O2)
- Impact depends on whether validators correctly enforce (T191)
- Lower than O4 because T191 should catch at voting layer
- Serves as backstop incentive for proposer honesty

### 3.4 Governance-Controlled Parameters

The following slash parameters are intended to be governance-controlled in MainNet v0.x:

| Parameter | Default | Min | Max | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `SLASH_O1_PERCENT` | 7.5% | 5% | 15% | Double-sign |
| `SLASH_O2_PERCENT` | 5% | 3% | 10% | Invalid proposal sig |
| `SLASH_O3A_PERCENT` | 0.25% | 0% | 1% | Single lazy vote |
| `SLASH_O3B_PERCENT` | 2% | 1% | 5% | Repeated lazy votes |
| `SLASH_O4_PERCENT` | 7.5% | 5% | 15% | Invalid DAG cert |
| `SLASH_O5_PERCENT` | 3% | 1% | 10% | Coupling violation |
| `MIN_LAZY_VOTES_FOR_O3B` | 3 | 2 | 10 | Threshold for O3b |
| `LAZY_VOTE_WINDOW` | 1,000 | 100 | 10,000 | Rolling window (blocks) |

---

## 4. Evidence Model & Proof Format

### 4.1 General Requirements

All slashing proofs must be:

1. **Self-contained**: Include all data necessary for verification
2. **Objectively verifiable**: No off-chain state required beyond validator registry
3. **Compact**: Bounded size to prevent DoS via large proofs
4. **Timestamped**: Include block height / view number for ordering

### 4.2 O1 – Double-Sign Proof

**Required Evidence**:

```
DoubleSignProof {
    validator_id: ValidatorId,
    view: ViewNumber,
    height: BlockHeight,
    message_1: SignedMessage,  // First conflicting message
    message_2: SignedMessage,  // Second conflicting message
}

SignedMessage {
    message_type: enum { Block, Vote },
    payload_hash: Hash256,     // Hash of block header or vote payload
    signature: MlDsa44Signature,
}
```

**On-Chain Verification**:
1. Verify `validator_id` is active validator
2. Verify `message_1.view == message_2.view` and `message_1.height == message_2.height`
3. Verify `message_1.payload_hash != message_2.payload_hash`
4. Verify both signatures are valid under `validator_id`'s public key
5. If all pass → slash `validator_id`

### 4.3 O2 – Invalid Proposal Signature Proof

**Required Evidence**:

```
InvalidProposalSigProof {
    block_header: BlockHeader,
    proposer_pubkey: MlDsa44PublicKey,  // From validator registry at block height
}

BlockHeader {
    height: BlockHeight,
    view: ViewNumber,
    proposer_id: ValidatorId,
    parent_hash: Hash256,
    state_root: Hash256,
    batch_commitment: Hash256,
    signature: MlDsa44Signature,
    // ... other fields
}
```

**On-Chain Verification**:
1. Verify `proposer_id` matches expected proposer for `view` (leader rotation)
2. Retrieve `proposer_pubkey` from validator registry at `height`
3. Compute `preimage = domain_sep("QBIND-BLOCK") || serialize(block_header_unsigned)`
4. Verify `ML_DSA_44_Verify(proposer_pubkey, preimage, signature) == FAIL`
5. If verification fails → slash `proposer_id`

### 4.4 O3 – Lazy Vote Proof

**Required Evidence**:

```
LazyVoteProof {
    vote: SignedVote,
    invalid_block_proof: InvalidBlockEvidence,
}

SignedVote {
    validator_id: ValidatorId,
    view: ViewNumber,
    height: BlockHeight,
    block_hash: Hash256,
    signature: MlDsa44Signature,
}

InvalidBlockEvidence {
    // One of:
    invalid_proposal_sig: Option<InvalidProposalSigProof>,
    invalid_qc: Option<InvalidQcProof>,
}

InvalidQcProof {
    qc: QuorumCertificate,
    invalid_signer_id: ValidatorId,
    invalid_signature: MlDsa44Signature,
    signer_pubkey: MlDsa44PublicKey,
}
```

**On-Chain Verification**:
1. Verify `vote.signature` is valid (validator did sign this vote)
2. Verify `invalid_block_proof` shows the block was invalid:
   - If `invalid_proposal_sig`: verify per O2 rules
   - If `invalid_qc`: verify signature fails for claimed signer
3. Verify `vote.block_hash` matches the invalid block
4. If all pass → record O3a offense for `vote.validator_id`

For O3b aggregation:
1. Query on-chain accumulator for validator's O3a count in window
2. If count ≥ `MIN_LAZY_VOTES_FOR_O3B` → slash for O3b

### 4.5 O4 – Invalid DAG Certificate Proof

**Required Evidence**:

```
InvalidDagCertProof {
    certificate: DagAvailabilityCertificate,
    invalidity_reason: DagCertInvalidityReason,
}

DagAvailabilityCertificate {
    batch_commitment: Hash256,
    signers: Vec<ValidatorId>,
    signatures: Vec<MlDsa44Signature>,
    dag_round: u64,
}

DagCertInvalidityReason {
    // One of:
    invalid_signature: Option<InvalidSignatureDetail>,
    quorum_not_met: Option<QuorumNotMetDetail>,
    commitment_mismatch: Option<CommitmentMismatchDetail>,
}

InvalidSignatureDetail {
    signer_index: u32,
    signer_pubkey: MlDsa44PublicKey,
}

CommitmentMismatchDetail {
    expected_commitment: Hash256,
    batch_data_hash: Hash256,  // Or succinct proof
}
```

**On-Chain Verification**:

For `invalid_signature`:
1. Retrieve `preimage = domain_sep("QBIND-DAG-CERT") || certificate.batch_commitment || certificate.dag_round`
2. Verify `ML_DSA_44_Verify(signer_pubkey, preimage, signatures[signer_index]) == FAIL`
3. Verify `signer_pubkey` matches `signers[signer_index]` in registry
4. If fails → slash all validators who propagated this certificate

For `quorum_not_met`:
1. Count valid signatures (verify each)
2. If count < 2f+1 → slash propagators

For `commitment_mismatch`:
1. Verify provided batch data produces `batch_data_hash`
2. Verify `batch_data_hash != certificate.batch_commitment`
3. If mismatch confirmed → slash propagators

**Note**: Commitment mismatch proofs may require succinct proofs (e.g., Merkle proofs) for on-chain efficiency. Full specification deferred to T228+ implementation.

### 4.6 O5 – Coupling Violation Proof

**Required Evidence**:

```
CouplingViolationProof {
    block_header: BlockHeader,
    dag_state_proof: DagStateProof,
}

DagStateProof {
    // Proof that no valid certificate exists for block.batch_commitment
    // at the DAG state when block was proposed
    dag_round: u64,
    frontier_commitments: Vec<Hash256>,  // Valid commitments at that round
    merkle_proof: Option<MerkleExclusionProof>,
}
```

**On-Chain Verification**:
1. Verify `block_header.batch_commitment` not in `frontier_commitments`
2. Verify `merkle_proof` (if provided) proves exclusion from DAG state
3. If commitment not present and no valid certificate provided → slash proposer

**Complexity Note**: This proof may be expensive on-chain. For MainNet v0, may be handled via:
- Optimistic verification (assume valid, challenge within window)
- Succinct proofs (ZK or Merkle-based)
- Off-chain dispute resolution with on-chain settlement

Implementation details to be specified in T228+.

### 4.7 Proof Size Bounds

| Proof Type | Max Size (bytes) | Notes |
| :--- | :--- | :--- |
| O1 (Double-sign) | ~6,000 | 2 signatures + headers |
| O2 (Invalid proposal) | ~4,000 | 1 block header + pubkey |
| O3 (Lazy vote) | ~10,000 | Vote + block evidence |
| O4 (Invalid DAG cert) | ~50,000 | Certificate + batch proofs |
| O5 (Coupling violation) | ~20,000 | Block + DAG state proof |

These bounds ensure proof submission gas costs are bounded.

---

## 5. Interaction with Existing Slashing Rules

### 5.1 Priority Order

If multiple offenses apply to the same validator for the same event, apply the **highest severity slash once**:

| Scenario | Offenses | Applied Slash |
| :--- | :--- | :--- |
| Proposer double-signs AND invalid sig | O1 + O2 | O1 (higher) |
| Validator lazy votes on double-sign block | O3 + O1 (for proposer) | O3 for voter, O1 for proposer |
| Invalid DAG cert contains double-sign evidence | O4 + O1 | Both (different validators) |

### 5.2 Non-Overlapping Design

The offense classes are designed to be non-overlapping:

- **O1** covers equivocation (same view, different content)
- **O2** covers signature invalidity (cryptographic failure)
- **O3** covers voting behavior (accepting invalid blocks)
- **O4** covers DAG certificate invalidity
- **O5** covers consensus coupling (proposer responsibility)

A single action by a validator maps to at most one offense class.

### 5.3 Downtime vs Slashing

QBIND's liveness scoring (T175) may penalize offline validators through reduced priority or soft penalties. This is **distinct from slashing**:

| Behavior | Penalty Mechanism | Economic Impact |
| :--- | :--- | :--- |
| Offline / slow | Liveness score reduction | Reduced proposer selection |
| Lazy verification | Slashing (O3) | Stake loss |
| Malicious action | Slashing (O1, O2, O4, O5) | Stake loss + jailing |

Downtime alone is not slashable—only active misbehavior triggers slashing.

### 5.4 Existing Rule Confirmation

The following existing rules remain unchanged:

1. **HotStuff BFT safety**: 3-chain commit rule prevents forks given <f Byzantine validators
2. **Domain-separated preimages** (T159): Prevents signature replay across message types
3. **Quorum thresholds**: 2f+1 signatures required for QCs and certificates
4. **View-change protocol**: Ensures liveness under leader failure

PQC slashing adds economic incentives on top of these protocol-level guarantees.

---

## 6. Operational & Governance Considerations

### 6.1 Proof Submission

#### Who Can Submit Slashing Proofs?

| Submitter Type | Allowed | Notes |
| :--- | :--- | :--- |
| Validators | ✅ Yes | Primary expected submitters |
| Watchtowers | ✅ Yes | Third-party monitoring services |
| Any account | ✅ Yes | Permissionless submission |

#### Finder's Fee

To incentivize prompt reporting:

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| `SLASH_FINDER_FEE_PERCENT` | 10% | Percentage of slash paid to proof submitter |
| `MIN_FINDER_FEE` | 100 QBIND | Minimum fee regardless of slash size |
| `MAX_FINDER_FEE` | 10,000 QBIND | Cap to prevent outsized rewards |

Example: 5% slash on 1,000,000 stake = 50,000 QBIND slash → 5,000 QBIND finder's fee (capped at max).

### 6.2 Invalid/Spam Proof Handling

| Proof Outcome | Penalty | Notes |
| :--- | :--- | :--- |
| Valid proof | Finder's fee paid | Slash executed |
| Invalid proof (honest error) | Gas cost only | Submitter loses tx fee |
| Repeated invalid proofs | Soft rate limit | IP/account-based throttling |
| Malicious proof spam | Gas cost + deposit slash | Optional: require deposit for submission |

For MainNet v0, only gas cost penalty is implemented. Deposit requirement is a future governance option.

### 6.3 Governance Controls

#### Immediate Governance (via Council multisig)

The following can be adjusted via governance transaction:

- Slash percentages (within min/max bounds)
- Jailing periods
- O3b thresholds (minimum count, window size)
- Finder's fee parameters

#### Future Governance (v0.x+)

- Enable/disable specific offense classes
- Adjust min/max bounds for parameters
- Implement forgiveness/appeals process
- Modify evidence requirements

### 6.4 Forgiveness & Appeals (Future Work)

MainNet v0 does **not** implement forgiveness or appeals. This is explicitly marked as future work:

| Feature | MainNet v0 Status | Future Consideration |
| :--- | :--- | :--- |
| Appeal process | ❌ Not implemented | Governance-based review possible in v0.x |
| Slash reversal | ❌ Not implemented | Requires strong evidence of false positive |
| Gradual unjailing | ❌ Not implemented | Time-based reputation recovery |

Rationale: Appeals introduce subjectivity that conflicts with the "objectively provable" principle. If needed, appeals should be a governance decision, not an automated process.

### 6.5 Operator Responsibilities

Validators must:

1. **Run compliant software**: No "fast-path" verification skipping
2. **Monitor slashing events**: Track `qbind_slash_events_total` metric
3. **Respond to warnings**: O3a warnings should trigger configuration review
4. **Maintain key security**: Key compromise can lead to O1 or O2 slashes
5. **Understand DAG coupling**: Ensure proper DAG certificate handling (O4, O5)

### 6.6 Hard-Coded vs Governance-Controlled

| Category | Hard-Coded (MainNet v0) | Governance-Controlled |
| :--- | :--- | :--- |
| Offense definitions (O1–O5) | ✅ | - |
| Verification algorithms | ✅ | - |
| Slash percentage ranges | ✅ (min/max bounds) | ✅ (values within bounds) |
| Jailing periods | - | ✅ |
| O3b thresholds | ✅ (reasonable defaults) | ✅ |
| Finder's fee parameters | ✅ (defaults) | ✅ |

---

## 7. Related Documents

### 7.1 Normative References

- [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) — MainNet v0 specification
- [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) — Audit and readiness tracking
- [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) — Operational procedures
- [QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md](../mainnet/QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md) — DAG–HotStuff coupling (T188)

### 7.2 Informative References

- [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) — Key management and signer architecture
- [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) — Monetary policy and staking economics
- [QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md) — Governance model

### 7.3 Implementation Roadmap

| Task | Description | Status |
| :--- | :--- | :--- |
| **T227** | Slashing & PQC Offenses Design (this document) | ✅ Design Ready |
| **T228** | Slashing infrastructure implementation | Planned |
| **T229** | O1/O2 slashing implementation | Planned |
| **T230** | O3/O4/O5 slashing implementation | Planned |
| **T231** | Slashing proofs on-chain verification | Planned |

---

## Appendix A: Glossary

| Term | Definition |
| :--- | :--- |
| **Lazy Voting** | Accepting and voting for blocks without verifying signatures |
| **ML-DSA-44** | FIPS 204 post-quantum digital signature algorithm |
| **QC** | Quorum Certificate—aggregated signatures from 2f+1 validators |
| **DAG Certificate** | Availability certificate for a batch of transactions |
| **Jailing** | Temporary exclusion from validator set after slashing |
| **Finder's Fee** | Reward paid to entity that submits valid slashing proof |

---

## Appendix B: Changelog

| Date | Version | Changes |
| :--- | :--- | :--- |
| 2026-02-09 | 1.0 | Initial design document (T227) |

---