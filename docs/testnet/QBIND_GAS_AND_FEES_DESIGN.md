# QBIND Gas and Fee Model Design

**Task**: T167  
**Status**: Design Specification  
**Date**: 2026-01-28

---

## Table of Contents

1. [Goals & Constraints](#1-goals--constraints)
2. [Gas Model for VM v0](#2-gas-model-for-vm-v0)
3. [Gas Limits & Block Limits](#3-gas-limits--block-limits)
4. [Fee Representation](#4-fee-representation)
5. [Fee Flows](#5-fee-flows)
6. [Mempool & DAG Integration](#6-mempool--dag-integration)
7. [Execution Semantics with Gas (VM v1)](#7-execution-semantics-with-gas-vm-v1)
8. [Migration Path](#8-migration-path)

---

## 1. Goals & Constraints

### 1.1 Goals

The QBIND gas and fee model aims to:

| Goal | Description |
| :--- | :--- |
| **DoS Prevention** | Make all resource usage (CPU, signature verification, storage I/O) paid, preventing abuse. |
| **Simplicity for VM v0** | Start with a minimal model that works for transfer-only transactions, avoiding unnecessary complexity. |
| **Extensibility for VM v1+** | Design structures that scale to smart contracts, complex state access patterns, and variable computation. |
| **Determinism** | Gas accounting must be fully deterministic so all validators compute identical gas usage for any transaction. |
| **DAG Compatibility** | Gas limits must integrate cleanly with DAG mempool batching and parallel execution models. |
| **High-TPS Compatibility** | Gas overhead must not become a bottleneck; pre-computable costs are preferred. |

### 1.2 Constraints

| Constraint | Rationale |
| :--- | :--- |
| **Pure PQC** | No classical cryptographic assumptions in gas accounting or fee rules. All signature costs assume ML-DSA-44 verification. |
| **Chain-ID Aware** | Gas model fits within existing domain-separated `QbindTransaction` format and signing preimages (see [QBIND_CHAIN_ID_AND_DOMAINS.md](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md)). |
| **Backward Compatibility** | DevNet v0 and early TestNet Alpha continue to function without fees. Gas enforcement is opt-in until VM v1. |
| **No Classical Signature Discounts** | Unlike Ethereum, there is no ECDSA recovery discount. All transactions pay the same base verification cost (ML-DSA-44). |

### 1.3 Design Principles

1. **Gas is abstract work**: Gas units do not map 1:1 to CPU cycles. They represent a normalized cost for resource consumption.

2. **Costs are pre-computable**: For VM v0 (transfers), gas cost can be computed before execution from transaction metadata alone.

3. **Fees are orthogonal to gas**: Gas measures resource consumption; fees convert gas to economic cost. These can evolve independently.

4. **Simplicity first**: Start with the simplest model that prevents DoS, then iterate.

---

## 2. Gas Model for VM v0

### 2.1 Gas Units

Gas is measured in abstract units. One "gas unit" represents a normalized cost quantum. The absolute value is arbitrary; what matters is the relative cost ratios.

**Base Reference**: 1 gas unit ≈ cost of one simple arithmetic operation (conceptually).

### 2.2 Cost Components for VM v0

VM v0 supports only transfer transactions. The gas cost formula is:

```
gas(tx) = GAS_BASE_TX
        + GAS_PER_ACCOUNT_READ  × num_reads
        + GAS_PER_ACCOUNT_WRITE × num_writes
        + GAS_PER_BYTE_PAYLOAD  × payload_len
```

#### Cost Parameter Definitions

| Parameter | Description | Suggested Value |
| :--- | :--- | :--- |
| `GAS_BASE_TX` | Fixed cost for transaction inclusion: signature verification (ML-DSA-44), nonce check, transaction parsing. | 21,000 |
| `GAS_PER_ACCOUNT_READ` | Cost to read one account state from storage. | 2,600 |
| `GAS_PER_ACCOUNT_WRITE` | Cost to write one account state to storage. | 5,000 |
| `GAS_PER_BYTE_PAYLOAD` | Cost per byte of transaction payload (linear size cost). | 16 |

**Note**: These values are illustrative. Final tuning will occur during TestNet Beta based on benchmarking.

### 2.3 VM v0 Transfer Gas Calculation

For a transfer transaction:

| Operation | Reads | Writes | Notes |
| :--- | :--- | :--- | :--- |
| Fetch sender state | 1 | 0 | Always required |
| Update sender (nonce + balance) | 0 | 1 | Always required |
| Fetch recipient state | 0 or 1 | 0 | 0 if recipient == sender (self-transfer); 1 otherwise |
| Update recipient balance | 0 | 0 or 1 | 0 if recipient == sender; 1 otherwise |

**Typical Transfer (sender ≠ recipient)**:

```
reads  = 2  (sender + recipient)
writes = 2  (sender + recipient)
payload_len = 48  (TransferPayload: 32-byte recipient + 16-byte amount)

gas(tx) = 21,000                          # GAS_BASE_TX
        + 2,600 × 2                        # 2 reads
        + 5,000 × 2                        # 2 writes
        + 16 × 48                          # payload bytes
        = 21,000 + 5,200 + 10,000 + 768
        = 36,968 gas
```

**Self-Transfer (sender == recipient)**:

```
reads  = 1  (sender only)
writes = 1  (sender only)

gas(tx) = 21,000 + 2,600 + 5,000 + 768
        = 29,368 gas
```

### 2.4 Signature Verification Cost

The `GAS_BASE_TX` includes the cost of ML-DSA-44 signature verification. This is significant compared to classical ECDSA:

| Signature Scheme | Approximate Verification Time | Gas Allocation |
| :--- | :--- | :--- |
| ECDSA (classical) | ~0.1 ms | ~3,000 gas (EIP baseline) |
| ML-DSA-44 (PQC) | ~0.5–1.0 ms | Included in 21,000 base |

The higher base cost reflects the inherently higher computational cost of post-quantum signature verification. This is a fundamental trade-off for PQ security.

### 2.5 Account Creation Cost

When a transfer creates a new recipient account (balance was 0, nonce was 0):

- No additional "account creation" surcharge in VM v0.
- The write cost (`GAS_PER_ACCOUNT_WRITE`) applies regardless of whether the account existed.

**Future consideration**: VM v1 may introduce a storage deposit or creation surcharge to discourage state bloat.

---

## 3. Gas Limits & Block Limits

### 3.1 Per-Transaction Gas Limit

Each transaction specifies a `gas_limit`: the maximum gas the sender is willing to consume.

**Semantics**:

```
if gas(tx) > tx.gas_limit:
    reject transaction (invalid)
```

- **At mempool admission**: Transactions with `gas(tx) > gas_limit` are rejected with `MempoolError::InsufficientGasLimit`.
- **At execution**: If somehow a transaction reaches execution with insufficient gas limit, it fails immediately with no state change.

**VM v0 Behavior**: Since gas costs are pre-computable for transfers, the gas limit check is a simple admission filter.

### 3.2 Per-Block Gas Limit

The protocol defines a `BLOCK_GAS_LIMIT`: the maximum total gas that can be consumed by all transactions in a single block.

**Suggested Initial Value**: `30,000,000` gas (approximately 800–1,000 transfer transactions per block).

**Semantics**:

```
let total_gas = sum(gas(tx) for tx in block.transactions)
if total_gas > BLOCK_GAS_LIMIT:
    block is invalid
```

### 3.3 Block Gas Limit Governance

| Phase | Block Gas Limit Policy |
| :--- | :--- |
| TestNet Alpha | Not enforced (no gas accounting) |
| TestNet Beta | Fixed constant (e.g., 30M gas) |
| MainNet | Governance-adjustable parameter (validators vote on limit changes) |

**Rationale**: A fixed limit is simplest for TestNet. MainNet may allow dynamic adjustment based on network capacity and demand.

### 3.4 Proposer Block Construction

When a proposer (HotStuff leader) constructs a block:

1. Select transactions from mempool (FIFO or DAG batches).
2. Accumulate gas: `running_gas += gas(tx)`.
3. Stop including transactions when `running_gas` would exceed `BLOCK_GAS_LIMIT`.
4. Remaining transactions stay in mempool for future blocks.

```
fn build_block(mempool: &Mempool, limit: u64) -> Vec<Transaction> {
    let mut block_txs = Vec::new();
    let mut running_gas = 0;

    for tx in mempool.iter_by_priority() {
        let tx_gas = compute_gas(&tx);
        if running_gas + tx_gas > limit {
            break;  // Block full
        }
        block_txs.push(tx);
        running_gas += tx_gas;
    }
    block_txs
}
```

### 3.5 Minimum Gas Limit

To prevent trivially small gas limits:

```
MINIMUM_GAS_LIMIT = 21,000  (equal to GAS_BASE_TX)
```

Transactions with `gas_limit < MINIMUM_GAS_LIMIT` are rejected at admission.

---

## 4. Fee Representation

### 4.1 Current VM v0 Format (No Fees)

The current `TransferPayload` (VM v0) has no fee fields:

```rust
// Current: VM v0 (TestNet Alpha)
pub struct TransferPayload {
    pub recipient: AccountId,  // [u8; 32]
    pub amount: u128,          // big-endian
}
// Wire: 48 bytes total
```

### 4.2 Proposed VM v1 Format (With Fees)

VM v1 introduces explicit gas and fee fields:

```rust
// Proposed: VM v1 (TestNet Beta / MainNet)
pub struct TransferPayloadV1 {
    pub recipient: AccountId,     // [u8; 32]
    pub amount: u128,             // Transfer amount
    pub gas_limit: u64,           // Max gas sender will pay
    pub max_fee_per_gas: u128,    // Max fee per gas unit (in native token)
}
```

**Wire Format** (72 bytes):

```
Bytes 0..32:  recipient (AccountId)
Bytes 32..48: amount (u128, big-endian)
Bytes 48..56: gas_limit (u64, big-endian)
Bytes 56..72: max_fee_per_gas (u128, big-endian)
```

### 4.3 Payload Version Discrimination

To support both v0 and v1 payloads during transition:

**Option A: Length-Based Discrimination**

- 48 bytes → `TransferPayload` (v0, fee-less)
- 72 bytes → `TransferPayloadV1` (v1, fee-aware)

**Option B: Explicit Version Byte**

Add a version prefix to all payloads:

```
Byte 0: version (0x00 = v0, 0x01 = v1)
Bytes 1..N: version-specific payload
```

**Recommendation**: Use length-based discrimination for simplicity. The 24-byte difference is unambiguous.

### 4.4 Fee Calculation

The maximum fee a transaction can incur:

```
max_fee = gas_limit × max_fee_per_gas
```

The actual fee paid:

```
actual_fee = gas_used × effective_fee_per_gas
```

Where `effective_fee_per_gas ≤ max_fee_per_gas` (may be lower in a future EIP-1559-style mechanism).

### 4.5 Balance Requirement

For a transaction to be valid:

```
sender.balance >= amount + (gas_limit × max_fee_per_gas)
```

This ensures the sender can cover the worst-case fee even if all gas is consumed.

---

## 5. Fee Flows

### 5.1 Fee Distribution Options

| Option | Description | Complexity |
| :--- | :--- | :--- |
| **Burn** | All fees are destroyed (removed from circulation). | Simplest |
| **Fee Sink** | Fees go to a designated "fee sink" account (treasury). | Simple |
| **Proposer Reward** | Fees go to the block proposer (HotStuff leader). | Moderate |
| **Validator Distribution** | Fees distributed among all validators proportionally. | Complex |
| **Hybrid** | Part burned, part to proposer, part to treasury. | Most flexible |

### 5.2 TestNet Alpha / Beta Policy

For non-economic test networks:

```
Fee Policy: BURN (all fees destroyed)
```

**Rationale**:
- Simplest implementation.
- No need to track proposer rewards or treasury.
- Prevents gaming of fee mechanisms during testing.
- Test tokens have no real value; burning is inconsequential.

**Implementation**:

```rust
fn apply_fee(tx: &Transaction, gas_used: u64, state: &mut State) {
    let fee = gas_used * tx.effective_fee_per_gas();
    state.deduct_balance(tx.sender, fee);
    // Fee is simply removed from circulation (burn)
    // No credit to any account
}
```

### 5.3 MainNet Policy (Sketch)

For MainNet, a hybrid model is recommended:

| Component | Percentage | Recipient |
| :--- | :--- | :--- |
| **Base Fee** | 50% | Burned (deflationary pressure) |
| **Priority Fee** | 50% | Block proposer (incentive to include tx) |

**Alternative**: Treasury allocation for protocol development funding.

**Governance**: Fee distribution percentages should be governance-adjustable parameters.

### 5.4 Fee Sink Account (TestNet Option)

If burning is undesirable for testing (e.g., to track total fees collected):

```
FEE_SINK_ACCOUNT = AccountId([0xFF; 32])  // Well-known address
```

All fees are credited to this account. The account cannot initiate transactions.

---

## 6. Mempool & DAG Integration

### 6.1 Mempool Admission Policy

A transaction must satisfy the following to enter the mempool:

| Check | Description | Error |
| :--- | :--- | :--- |
| **Well-formed payload** | Payload parses as valid v0 or v1 format. | `MempoolError::MalformedPayload` |
| **Gas limit sufficient** | `gas_limit >= gas(tx)` | `MempoolError::InsufficientGasLimit` |
| **Balance sufficient** | `sender.balance >= amount + max_fee` | `MempoolError::InsufficientBalance` |
| **Minimum gas price** (optional) | `max_fee_per_gas >= MIN_FEE_PER_GAS` | `MempoolError::FeeTooLow` |

**Balance Check Timing**:
- At admission: Check against current confirmed state.
- At execution: Re-check against execution-time state (balance may have changed).

### 6.2 Handling Invalid/Out-of-Gas Transactions

| Scenario | Handling |
| :--- | :--- |
| **Rejected at admission** | Transaction not added to mempool; error returned to submitter. |
| **Fails at execution** | Transaction marked as failed; not re-queued; nonce consumed; fee deducted (per §7). |
| **Evicted for low fee** | Transaction removed from mempool; submitter may resubmit with higher fee. |

### 6.3 Transaction Ordering

#### Short-Term (TestNet Alpha/Beta): FIFO

- Transactions ordered by arrival time within the fee-valid set.
- No fee-based prioritization.
- Simple and predictable.

#### Medium-Term (TestNet Beta/MainNet): Fee-Based Priority

```
priority(tx) = (max_fee_per_gas, arrival_time)
```

Transactions with higher `max_fee_per_gas` are included first. Ties broken by arrival time (earlier wins).

```rust
fn compare_priority(a: &Transaction, b: &Transaction) -> Ordering {
    // Higher fee_per_gas is better
    match b.max_fee_per_gas.cmp(&a.max_fee_per_gas) {
        Ordering::Equal => a.arrival_time.cmp(&b.arrival_time),
        other => other,
    }
}
```

#### Long-Term (MainNet): EIP-1559-Style Mechanism (Optional)

Consider a base fee + priority fee model:

- `base_fee_per_gas`: Protocol-determined, adjusts based on block utilization.
- `priority_fee_per_gas`: User tip to incentivize inclusion.
- `effective_fee_per_gas = base_fee_per_gas + priority_fee_per_gas`

This provides more predictable fees and smoother fee market dynamics.

### 6.4 DAG Batching & Gas

In DAG mempool mode, transactions are grouped into batches before consensus ordering.

#### Batch Construction

- Batches do not carry a "batch gas limit."
- Batches contain transactions; gas is a property of individual transactions.
- Batch creators may preferentially include higher-fee transactions.

#### Block Construction from DAG

When consensus orders DAG batches into blocks:

```rust
fn build_block_from_dag(frontier: &[BatchCertificate], limit: u64) -> Block {
    let mut block_txs = Vec::new();
    let mut running_gas = 0;

    for batch in frontier.iter() {
        for tx in batch.transactions.iter() {
            // Skip gas-invalid transactions
            let tx_gas = compute_gas(&tx);
            if tx_gas > tx.gas_limit {
                continue;  // Invalid, skip
            }

            // Check block gas limit
            if running_gas + tx_gas > limit {
                // Block is full; remaining txs go to next block
                return Block::new(block_txs);
            }

            block_txs.push(tx.clone());
            running_gas += tx_gas;
        }
    }
    Block::new(block_txs)
}
```

#### Gas Constraints Enforcement

| Level | Gas Constraint | Enforcement |
| :--- | :--- | :--- |
| **Per-Transaction** | `gas(tx) <= gas_limit` | Mempool admission + execution |
| **Per-Block** | `sum(gas) <= BLOCK_GAS_LIMIT` | Block builder + validation |
| **Per-Batch** | None | Batches are just containers |

### 6.5 Eviction Policy

When mempool is full, evict transactions with lowest fee priority:

```rust
fn evict_lowest_priority(mempool: &mut Mempool, count: usize) {
    let mut candidates: Vec<_> = mempool.iter().collect();
    candidates.sort_by(|a, b| compare_priority(a, b).reverse());
    
    for tx in candidates.iter().take(count) {
        mempool.remove(tx.hash());
    }
}
```

---

## 7. Execution Semantics with Gas (VM v1)

This section specifies execution behavior for the future gas-aware VM v1.

### 7.1 Pre-Execution Phase

Before executing a transaction:

1. **Compute gas cost**:
   ```rust
   let gas_cost = compute_gas(&tx);
   ```

2. **Check gas limit**:
   ```rust
   if gas_cost > tx.gas_limit {
       return Err(VmError::InsufficientGasLimit { required: gas_cost, provided: tx.gas_limit });
   }
   ```

3. **Reserve fee budget**:
   ```rust
   let max_fee = tx.gas_limit * tx.max_fee_per_gas;
   if sender.balance < tx.amount + max_fee {
       return Err(VmError::InsufficientBalance { balance: sender.balance, needed: tx.amount + max_fee });
   }
   // Reserve the max fee (will refund unused portion)
   sender.balance -= max_fee;
   ```

### 7.2 Execution Phase

For VM v0 transfers, execution is straightforward:

1. **Deduct amount** from sender.
2. **Credit amount** to recipient.
3. **Increment sender nonce**.

Gas tracking for transfers is pre-computed (no dynamic metering needed).

For future VM v1 with smart contracts:

1. **Initialize gas counter**: `gas_used = 0`
2. **Execute opcodes**, incrementing `gas_used` per operation.
3. **If `gas_used > gas_limit`**: Halt with out-of-gas error.

### 7.3 Post-Execution Phase

After execution completes (success or failure):

1. **Calculate actual fee**:
   ```rust
   let actual_fee = gas_used * effective_fee_per_gas;
   ```

2. **Refund unused gas**:
   ```rust
   let refund = max_fee - actual_fee;
   sender.balance += refund;
   ```

3. **Apply fee distribution** (per §5):
   ```rust
   // For TestNet: burn
   // For MainNet: distribute per policy
   apply_fee_distribution(actual_fee);
   ```

### 7.4 Failure Handling

| Failure Type | State Changes | Fee Charged |
| :--- | :--- | :--- |
| **Insufficient gas limit** | None | None (tx invalid) |
| **Insufficient balance** | None | None (tx invalid) |
| **Out-of-gas during execution** | Reverted | Full `gas_limit × fee_per_gas` |
| **Execution error (e.g., bad opcode)** | Reverted | Gas used up to failure point |
| **Transfer to self with 0 amount** | Nonce incremented only | Base gas fee |

### 7.5 Nonce Semantics with Gas

- **Successful transaction**: Nonce incremented.
- **Failed transaction (out-of-gas, execution error)**: Nonce still incremented.
- **Invalid transaction (rejected at admission)**: Nonce NOT incremented.

This ensures that failed transactions cannot be replayed and that nonces advance monotonically.

---

## 8. Migration Path

### 8.1 Phase Overview

| Phase | Network | Gas Enforcement | Fee Enforcement | Transaction Format |
| :--- | :--- | :--- | :--- | :--- |
| **DevNet v0** | DevNet | None | None | N/A (nonce-only) |
| **TestNet Alpha** | TestNet | None | None | `TransferPayload` (v0) |
| **TestNet Beta** | TestNet | Enforced | Enforced (burn) | `TransferPayloadV1` (v1) |
| **MainNet** | MainNet | Enforced | Enforced (hybrid) | `TransferPayloadV1` (v1) |

### 8.2 TestNet Alpha → TestNet Beta Migration

#### Code Changes Required

1. **Add gas cost computation** to execution engine.
2. **Add v1 payload parsing** with gas fields.
3. **Add mempool admission checks** for gas/fee validity.
4. **Add block gas limit enforcement** to proposer and validator.
5. **Add fee deduction** to execution (burn policy).

#### Wire Format Compatibility

- TestNet Beta nodes accept both v0 and v1 payloads.
- v0 payloads are assigned default gas values:
  ```rust
  impl TransferPayload {
      fn to_v1_defaults(&self) -> TransferPayloadV1 {
          TransferPayloadV1 {
              recipient: self.recipient,
              amount: self.amount,
              gas_limit: DEFAULT_TRANSFER_GAS_LIMIT,  // e.g., 50,000
              max_fee_per_gas: 0,  // Free for backward compat
          }
      }
  }
  ```
- This allows old clients to continue submitting during transition.

#### Deprecation Schedule

1. **TestNet Beta Launch**: Both v0 and v1 accepted.
2. **TestNet Beta + 2 weeks**: Warning logged for v0 payloads.
3. **TestNet Beta + 4 weeks**: v0 payloads rejected; v1 required.

### 8.3 TestNet Beta → MainNet Migration

#### Fee Policy Change

- TestNet Beta: Fees burned.
- MainNet: Hybrid distribution (burn + proposer reward).

#### Governance Parameters

MainNet introduces governance-adjustable parameters:

| Parameter | Default | Governance |
| :--- | :--- | :--- |
| `BLOCK_GAS_LIMIT` | 30,000,000 | Adjustable by validator vote |
| `MIN_FEE_PER_GAS` | 1 | Adjustable |
| `BURN_PERCENTAGE` | 50% | Adjustable |
| `PROPOSER_PERCENTAGE` | 50% | Adjustable |

### 8.4 Backward Compatibility Summary

| Component | DevNet v0 | TestNet Alpha | TestNet Beta | MainNet |
| :--- | :--- | :--- | :--- | :--- |
| **Old tests (nonce-only)** | ✅ Work | ✅ Work | ✅ Work (NonceOnly profile) | ✅ Work |
| **v0 transfer tests** | N/A | ✅ Work | ✅ Work (with defaults) | ❌ v1 required |
| **v1 transfer tests** | N/A | N/A | ✅ Work | ✅ Work |

---

## Appendix A: Gas Cost Reference Table

| Operation | Gas Cost | Notes |
| :--- | :--- | :--- |
| **Base transaction** | 21,000 | Includes ML-DSA-44 verification |
| **Account read** | 2,600 | Per account accessed |
| **Account write** | 5,000 | Per account modified |
| **Payload byte** | 16 | Per byte of payload |
| **Typical transfer** | ~37,000 | Sender ≠ recipient |
| **Self-transfer** | ~29,000 | Sender == recipient |

---

## Appendix B: Error Codes

| Error | Code | Description |
| :--- | :--- | :--- |
| `MempoolError::InsufficientGasLimit` | `E_GAS_LIMIT` | `gas(tx) > gas_limit` |
| `MempoolError::InsufficientBalance` | `E_BALANCE` | Cannot cover `amount + max_fee` |
| `MempoolError::FeeTooLow` | `E_FEE_LOW` | `max_fee_per_gas < MIN_FEE_PER_GAS` |
| `MempoolError::MalformedPayload` | `E_PAYLOAD` | Payload parsing failed |
| `VmError::OutOfGas` | `E_OUT_OF_GAS` | Gas exhausted during execution |

---

## Appendix C: Open Questions (Future Tasks)

| Question | Notes | Target |
| :--- | :--- | :--- |
| **EIP-1559-style base fee** | Dynamic base fee adjustment based on utilization | MainNet |
| **Storage deposit** | Charge for state expansion (new accounts) | MainNet |
| **Gas refunds** | Refund for state cleanup (balance → 0) | MainNet |
| **Smart contract gas metering** | Opcode-level gas costs for VM v1+ | VM v1 |
| **Cross-shard gas** | Gas accounting for cross-shard transactions | Future |

---

## Appendix D: Related Documents

- [QBIND TestNet Alpha Spec](./QBIND_TESTNET_ALPHA_SPEC.md) — Current VM v0 semantics
- [QBIND DAG Mempool Design](../devnet/QBIND_DAG_MEMPOOL_DESIGN.md) — DAG architecture
- [QBIND Parallel Execution Design](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) — Stage A/B parallelism
- [QBIND Chain ID and Domains](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) — Domain separation
- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet baseline

---

*End of Document*
