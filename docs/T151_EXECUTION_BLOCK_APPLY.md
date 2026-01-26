# T151 – QBIND Block Execution Architecture

## Overview

T151 wires the Revm execution engine (from T150) into the QBIND block commit
path. When a block is finalized by HotStuff consensus, its transactions are
executed against the EVM state, and Merkle roots are computed for verification.

## Canonical Block Structure

### QbindBlockHeader

```rust
pub struct QbindBlockHeader {
    pub parent_hash: H256,
    pub state_root: H256,
    pub tx_root: H256,
    pub receipts_root: H256,
    pub number: u64,
    pub timestamp: u64,
    pub proposer_id: BlockProposerId,
}
```

- **parent_hash**: Hash of the parent block's header (chain linkage)
- **state_root**: Merkle root of the post-execution state trie
- **tx_root**: Merkle root over `hash(tx)` for each transaction
- **receipts_root**: Merkle root over `hash(receipt)` for each receipt
- **number**: Block height in the chain
- **timestamp**: Block timestamp from consensus (seconds since Unix epoch)
- **proposer_id**: ID of the validator that proposed this block

### QbindBlockBody

```rust
pub struct QbindBlockBody {
    pub transactions: Vec<QbindTx>,
}
```

Contains the list of EVM transactions to execute.

### QbindBlock

```rust
pub struct QbindBlock {
    pub header: QbindBlockHeader,
    pub body: QbindBlockBody,
}
```

Complete block structure combining header metadata and transaction body.

## Root Calculation

### Transaction Root

Computed as a simple Merkle tree over transaction hashes:

```rust
tx_root = merkle_root([hash_qbind_tx(tx) for tx in transactions])
```

Transaction serialization is stable and documented in `block.rs`.

### Receipts Root

Computed as a simple Merkle tree over receipt hashes:

```rust
receipts_root = merkle_root([hash_receipt(r) for r in receipts])
```

Receipt serialization is stable and documented in `block.rs`.

### State Root

**Temporary Implementation**: For T151, the state root is computed by hashing
a canonical serialization of the entire in-memory state map. The serialization
is deterministic (accounts sorted by address, storage slots sorted by key).

**Performance Note**: This approach has O(n log n) complexity due to sorting,
where n is the number of accounts plus total storage slots. This is acceptable
for T151 testing but will become a bottleneck as state grows. For production,
a proper incremental trie structure is required.

**Future Work**: A proper Merkle Patricia Trie or Verkle tree will be
introduced in a later task to enable:
- O(log n) state updates
- Efficient state proofs for light clients
- Compatibility with standard Ethereum tooling

## Merkle Tree Implementation

The `merkle_root()` function implements a simple binary Merkle tree:
- Empty list → zero hash
- Single element → element itself
- Multiple elements → binary tree with odd-length duplication

**Note**: This is a simplified implementation that differs from Ethereum's
RLP-encoded Merkle Patricia Trie. The differences are:
1. Simple binary tree vs. Patricia trie
2. SHA3-256 vs. Keccak-256
3. No path-based key encoding

This is intentional for T151 to avoid the complexity of a full MPT
implementation. Future work will introduce a proper trie for full
Ethereum compatibility where needed.

## Block Apply Pipeline

The `apply_qbind_block()` function executes the block application:

```
apply_qbind_block(engine, ledger, block):
    1. Take snapshot of ledger for potential rollback
    2. Build QbindBlockEnv from header (number, timestamp, etc.)
    3. Wrap ledger in LedgerStateView
    4. Call engine.execute_block(&block_env, &state_view, &txs)
    5. Compute:
       - tx_root = merkle_root([hash(tx) for tx in txs])
       - receipts_root = merkle_root([hash(r) for r in receipts])
       - state_root = ledger.compute_state_root()
    6. If header has non-zero roots:
       - Verify tx_root matches computed value
       - Verify receipts_root matches computed value
       - Verify state_root matches computed value
       - On mismatch: rollback and return RootMismatch error
    7. Return BlockApplyResult with receipts and computed roots
```

### Root Verification

If any header root is non-zero, it must match the computed value. This allows:

- **Proposers**: Build blocks with zero roots, execute to compute values,
  then fill in the header
- **Validators**: Verify that the proposer's claimed roots match execution

Zero roots are treated as "don't verify" for flexibility.

## Node Integration

### EvmExecutionBridge

The `EvmExecutionBridge` component integrates execution with consensus:

```rust
pub struct EvmExecutionBridge {
    ledger: EvmLedger,
    engine: RevmExecutionEngine,
    current_height: u64,
    committed_roots: HashMap<u64, EvmCommitResult>,
}
```

### Commit Flow

1. `NodeHotstuffHarness` produces a `NodeCommittedBlock` after HotStuff finality
2. Application code calls `bridge.apply_committed_block(block, evm_txs)`
3. The bridge builds a `QbindBlock` from the consensus data
4. It executes via `apply_qbind_block()`
5. On success: state is updated, result is stored
6. On failure: **panic** (fatal invariant violation in T151)

### Error Handling

For T151, execution failure on a committed block is treated as fatal:

- Committed blocks must be executable (consensus ensures validity)
- If execution fails, it indicates a bug in the node or consensus
- The node panics to prevent further state corruption

Future tasks may implement more sophisticated error recovery.

## Invariants Checked at Commit

1. **Execution Success**: All transactions in a committed block must execute
   (individual tx failures in receipts are OK; engine errors are not)

2. **Root Consistency**: If the block header specifies roots, they must match
   the computed values from execution

3. **Determinism**: Same block + same pre-state → same post-state, receipts,
   and roots across all validators

4. **Sequential Nonces**: Transaction nonces must match sender account state

## State Adapter: LedgerStateView

The `LedgerStateView` adapts `EvmLedger` to the `StateView` trait:

```rust
impl StateView for LedgerStateView {
    fn get_account(&self, addr: &Address) -> Option<EvmAccountState>;
    fn put_account(&mut self, addr: &Address, account: EvmAccountState);
    fn get_storage(&self, addr: &Address, key: &U256) -> U256;
    fn set_storage(&mut self, addr: &Address, key: U256, value: U256);
    fn get_code(&self, addr: &Address) -> Vec<u8>;
    fn account_exists(&self, addr: &Address) -> bool;
}
```

All state access during execution goes through this adapter, ensuring
deterministic and trackable state mutations.

## Test Coverage

### Ledger-Level Tests (`t151_block_apply_tests.rs`)

- Empty block application
- Simple transfer block
- Multiple transfers in a block
- Root mismatch detection (tx_root, state_root, receipts_root)
- Rollback on mismatch
- Deterministic execution verification
- Sequential block determinism
- Contract deployment
- Out-of-gas handling
- Correct root verification

### Node-Level Tests (`t151_commit_execution_integration_tests.rs`)

- Bridge creation and initialization
- Empty block commit
- Transfer block commit with state verification
- Sequential block commits with nonce tracking
- Commit result tracking
- Deterministic state roots across independent executions
- State root evolution across blocks
- Multiple transactions per block

## Non-Goals for T151

- **Mempool integration**: Blocks are constructed externally
- **Gas market**: Fixed gas price (1 Gwei)
- **EIP-1559 base fee updates**: To be added in T156+
- **State proofs**: Placeholder state root implementation
- **Cross-shard execution**: Single shard only

## Relationship to T150

T150 introduced the execution engine abstractions:

- `ExecutionEngine` trait
- `StateView` trait
- `QbindTx`, `QbindBlockEnv`, `TxReceipt`
- `RevmExecutionEngine` implementation

T151 builds on this by:

- Adding canonical block types (`QbindBlock`, `QbindBlockHeader`)
- Adding root computation utilities (`merkle_root`, `hash_qbind_tx`)
- Adding `EvmLedger` for persistent state storage
- Adding `apply_qbind_block()` for end-to-end execution
- Adding `EvmExecutionBridge` for node integration

## Security Considerations

1. **No consensus changes**: Execution is isolated from consensus rules
2. **Deterministic execution**: Same inputs produce same outputs across nodes
3. **Snapshot rollback**: Failed validation doesn't corrupt state
4. **Gas limits enforced**: Prevents unbounded computation
5. **Nonce validation**: Prevents replay attacks

## Future Work

- **T156+**: EIP-1559 base fee updates, mempool integration
- **State Trie**: Replace placeholder with proper Merkle Patricia Trie
- **State Proofs**: Enable light client verification
- **Gas Market**: Priority fee handling and transaction ordering