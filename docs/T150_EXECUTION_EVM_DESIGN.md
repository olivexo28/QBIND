# T150 – QBIND EVM Execution Engine Design

## Overview

This document describes the QBIND execution engine skeleton introduced in T150,
which integrates the [Revm](https://github.com/bluealloy/revm) crate as the
EVM backend.

## Motivation

QBIND requires a deterministic execution engine for:

1. Processing EVM transactions in a consensus-safe manner
2. Gas metering to prevent DoS attacks
3. Future integration with mempool and gas markets (T156+)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    QBIND Consensus                           │
│    (validates signatures, orders transactions)               │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              RevmExecutionEngine                             │
│    (implements ExecutionEngine trait)                        │
├─────────────────────────────────────────────────────────────┤
│  QbindTx → Revm TxEnv                                       │
│  QbindBlockEnv → Revm BlockEnv + CfgEnv                     │
│  StateView ← StateViewDb → Revm Database                    │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Revm EVM                                │
│    (executes bytecode, applies state changes)                │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### ExecutionEngine Trait

The `ExecutionEngine` trait is the main abstraction for block execution:

```rust
pub trait ExecutionEngine {
    type Tx;
    type BlockEnv;
    type Receipt;
    type ExecutionError;

    fn execute_block(
        &self,
        block_env: &Self::BlockEnv,
        state: &mut dyn StateView,
        txs: &[Self::Tx],
    ) -> Result<Vec<Self::Receipt>, Self::ExecutionError>;
}
```

**Design Goals:**
- Generic over transaction and block environment types
- Clean separation from consensus layer
- Deterministic execution guarantees

### StateView Trait

The `StateView` trait abstracts state storage:

```rust
pub trait StateView {
    fn get_account(&self, addr: &Address) -> Option<EvmAccountState>;
    fn put_account(&mut self, addr: &Address, account: EvmAccountState);
    fn get_storage(&self, addr: &Address, key: &U256) -> U256;
    fn set_storage(&mut self, addr: &Address, key: U256, value: U256);
}
```

This allows the execution engine to work with different storage backends
(in-memory, persistent, etc.) without modification.

## QBIND Transaction Type

```rust
pub struct QbindTx {
    pub from: Address,
    pub to: Option<Address>,  // None = contract creation
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub value: U256,
    pub data: Vec<u8>,
}
```

**Key Points:**
- EIP-1559 compatible gas fields
- `to: None` indicates contract creation
- Signature validation is handled by consensus, not execution

## Why Revm?

We chose Revm as the EVM implementation because:

1. **Rust-native**: No FFI overhead or memory management issues
2. **Well-tested**: Used by multiple production systems
3. **Modular**: Clean separation between interpreter, precompiles, and state
4. **Active maintenance**: Regular updates for new EIPs
5. **Deterministic**: Designed for blockchain use cases

### Isolation Layer

The `RevmExecutionEngine` provides a clean adapter between QBIND types and
Revm's internal types:

- `QbindTx` → `TxEnv`
- `QbindBlockEnv` → `BlockEnv` + `CfgEnv`
- `StateView` → Revm `Database` trait

This isolation ensures:
- QBIND code doesn't depend directly on Revm internals
- Future EVM upgrades can be handled in one place
- Testing can use mock implementations

## Determinism Guarantees

The execution engine ensures deterministic execution by:

1. **No wall clock time**: Block timestamp comes from `QbindBlockEnv`
2. **Fixed randomness**: `prev_randao` is protocol-provided
3. **Consistent gas metering**: Uses Revm's built-in gas schedule
4. **No external dependencies**: Execution depends only on inputs

### Verification

The T150 test suite includes a determinism scaffold that:
1. Executes the same block twice from identical initial states
2. Verifies identical receipts (status, gas, logs)
3. Verifies identical final states

## Gas Metering

Gas metering is active from T150, using Revm's standard Ethereum gas
schedule (Cancun spec). Key points:

- Intrinsic gas for transfers: 21,000
- Contract creation base: 53,000 + data costs
- SSTORE: 20,000 (cold) / 2,900 (warm)
- Out-of-gas properly reverts state changes

## Block Execution Flow

```
execute_block(block_env, state, txs):
    state_db = StateViewDb::new(state)
    receipts = []
    cumulative_gas = 0
    
    for tx in txs:
        validate_tx(state_db, tx)
        
        # Build Revm context
        ctx = Context::new(state_db, spec)
        ctx.block = build_block_env(block_env)
        ctx.tx = build_tx_env(tx)
        
        # Execute
        evm = ctx.build_mainnet()
        result = evm.transact_commit(tx)
        
        # Process result
        receipt = process_result(result)
        cumulative_gas += receipt.gas_used
        receipts.push(receipt)
    
    state_db.apply_changes()
    return receipts
```

## Future Work

### T151–T155: Deeper Gas Model

- More sophisticated gas pricing
- State pruning considerations
- EIP-4844 blob support

### T156–T160: Mempool + Gas Market

- Priority fee handling
- EIP-1559 base fee updates
- Transaction ordering policies

### T161+: DAG Mempool

- Parallel transaction execution
- Conflict detection
- Advanced scheduling

## Test Coverage

T150 includes tests for:

1. **Simple transfer**: Basic ETH transfer between accounts
2. **Contract deployment**: Deploying bytecode with SSTORE
3. **Gas metering**: Out-of-gas behavior and proper revert
4. **Determinism**: Same inputs produce same outputs

All tests pass and verify:
- Receipt correctness (status, gas, logs)
- State changes (balances, nonces, storage)
- Error handling (invalid nonce, insufficient balance)

## Security Considerations

1. **No consensus changes**: Execution is isolated from consensus
2. **Gas limits enforced**: Prevents unbounded computation
3. **State isolation**: Changes only committed on success
4. **Input validation**: Nonce and balance checks before execution

## Non-Goals for T150

- Live consensus integration (manual execution only)
- Full EIP-1559 base fee updates
- Mempool or gas market logic
- State pruning