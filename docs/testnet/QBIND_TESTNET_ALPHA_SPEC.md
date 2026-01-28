# QBIND TestNet Alpha Specification

**Task**: T163 (Minimal VM v0), T164 (State Persistence)  
**Status**: Ready  
**Date**: 2026-01-28

---

## 1. Scope

TestNet Alpha is the first public test network for QBIND. It extends the DevNet v0 architecture with:

- **Network Environment**: `NetworkEnvironment::Testnet` (`QBIND_TESTNET_CHAIN_ID`)
- **Execution Profile**: `ExecutionProfile::VmV0` (sequential VM execution with account balances)
- **State Persistence**: RocksDB-backed persistent account state (T164)
- **Consensus**: Same as DevNet (HotStuff BFT, 3-chain commit rule)
- **Networking**: Same as DevNet (static KEMTLS mesh)
- **Mempool**: Same as DevNet (FIFO mempool, DAG v0 opt-in)

### What Changes from DevNet

| Component | DevNet v0 | TestNet Alpha |
| :--- | :--- | :--- |
| **Execution Profile** | `NonceOnly` | `VmV0` |
| **Account State** | Nonce only | Nonce + Balance |
| **Transaction Semantics** | Nonce validation only | Balance transfers |
| **Parallelism** | Stage A (sender-partitioned) | Sequential (for now) |
| **State Persistence** | In-memory only | RocksDB-backed disk persistence |

### What Remains the Same

- Consensus rules (HotStuff, timeouts, view-change)
- Cryptography (ML-DSA-44, ML-KEM-768, KEMTLS)
- Domain-separated signing preimages
- Static mesh networking
- Keystore and signer abstractions

---

## 2. VM v0 Semantics

### 2.1 Account State Model

Each account has:

```rust
pub struct AccountState {
    pub nonce: u64,    // Transaction replay protection
    pub balance: u128, // Account balance
}
```

- **Default**: Absent accounts have `nonce = 0`, `balance = 0`.
- **Persistence**: RocksDB-backed disk storage (T164). See §4.4 for details.

### 2.2 Transfer Transaction Format

VM v0 supports a single transaction type: **transfer**.

The transaction payload encodes:

```rust
pub struct TransferPayload {
    pub recipient: AccountId, // [u8; 32]
    pub amount: u128,         // big-endian
}
```

**Wire Format** (48 bytes):
```
Bytes 0..32:  recipient (AccountId)
Bytes 32..48: amount (u128, big-endian)
```

### 2.3 Transaction Execution Semantics

For each `QbindTransaction` in block order:

1. **Decode Payload**
   - Parse payload as `TransferPayload`.
   - If malformed → `MalformedPayload` error, no state change.

2. **Fetch Sender State**
   - Retrieve `AccountState` for `tx.sender`.
   - Default: `nonce = 0`, `balance = 0` if absent.

3. **Check Nonce**
   - Require `tx.nonce == sender_state.nonce`.
   - If mismatch → `NonceMismatch { expected, got }` error, no state change.

4. **Check Balance**
   - Require `sender_state.balance >= transfer.amount`.
   - If insufficient → `InsufficientBalance { balance, needed }` error, no state change.

5. **Apply State Transition** (if all checks pass)
   - `sender.balance -= amount`
   - `sender.nonce += 1`
   - `recipient.balance += amount` (create recipient if absent, `nonce = 0`)

### 2.4 Error Types

```rust
pub enum VmV0Error {
    NonceMismatch { expected: u64, got: u64 },
    InsufficientBalance { balance: u128, needed: u128 },
    MalformedPayload,
}
```

### 2.5 Determinism

- Transactions are executed **sequentially** in block order.
- All state transitions are deterministic.
- All validators executing the same block produce the same final state.

---

## 3. Execution Profile Abstraction

### 3.1 ExecutionProfile Enum

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExecutionProfile {
    #[default]
    NonceOnly,  // DevNet default
    VmV0,       // TestNet Alpha
}
```

### 3.2 Profile Selection

| Environment | Recommended Profile | Behavior |
| :--- | :--- | :--- |
| DevNet | `NonceOnly` | Stage A parallel nonce execution |
| TestNet Alpha | `VmV0` | Sequential VM v0 execution |

### 3.3 CLI Arguments

```bash
# DevNet (implicit default)
qbind-node --env devnet

# TestNet Alpha with VM v0
qbind-node --env testnet --execution-profile vm-v0
```

---

## 4. Implementation Notes

### 4.1 SingleThreadExecutionService

The `SingleThreadExecutionService` selects behavior based on `ExecutionProfile`:

- **NonceOnly**: Uses `SenderPartitionedNonceExecutor` (Stage A parallelism).
- **VmV0**: Uses `VmV0ExecutionEngine` (sequential execution).

### 4.2 State Backends

VM v0 state can use either backend:

- `InMemoryAccountState`: In-memory only (for testing or when no `data_dir` is configured)
- `RocksDbAccountState`: Persistent disk storage (T164)

Production nodes should use persistent storage via the `CachedPersistentAccountState` wrapper, which provides:

- In-memory caching for fast reads during execution
- Write-through to RocksDB for durability
- Flush-at-block-boundary for crash safety

### 4.3 Parallelism

VM v0 execution is **sequential** for simplicity and safety.

Stage B parallelism (conflict-graph-based) is future work, requiring:
- Read/write set tracking per transaction
- Conflict detection and scheduling
- Deterministic parallel execution

### 4.4 State Persistence (T164)

TestNet Alpha uses RocksDB-backed persistent storage for VM v0 state.

#### Storage Layout

```
<data_dir>/
└── state_vm_v0/        # RocksDB database directory
    ├── 000001.sst     # SST files
    ├── CURRENT
    ├── MANIFEST-*
    └── ...
```

#### Key Format

Account states are stored with keys of the form:

```
"acct:" || account_id (32 bytes)
```

#### Value Format

Account states use a fixed 24-byte binary encoding:

```
nonce:   u64  (8 bytes, big-endian)
balance: u128 (16 bytes, big-endian)
```

#### Durability Guarantees

- State is flushed to disk after each committed block
- Node restart loads persisted state automatically
- All validators converge to the same state after replaying committed blocks

#### Configuration

```rust
// Configure persistent storage via NodeConfig
let config = NodeConfig::testnet_vm_v0()
    .with_data_dir("/data/qbind");

// The VM v0 state directory is: /data/qbind/state_vm_v0
let state_dir = config.vm_v0_state_dir();
```

#### Limitations

- No pruning or compaction yet (state grows monotonically)
- No snapshotting or checkpointing
- Single-node restart only; no cross-node state sync in this version

---

## 5. Testing

### 5.1 Unit Tests

Located in `qbind-ledger/tests/t163_vm_v0_tests.rs`:

- `test_happy_path_simple_transfer`
- `test_nonce_mismatch_rejected`
- `test_insufficient_balance_rejected`
- `test_recipient_creation`
- `test_malformed_payload_error`
- Additional tests for edge cases

### 5.2 Integration Tests

Located in `qbind-node/tests/t163_vm_v0_integration_tests.rs`:

- `test_service_vm_v0_profile`
- `test_service_vm_v0_multiple_blocks`
- `test_service_nonce_only_profile` (DevNet regression)

### 5.3 Persistence Tests (T164)

Located in `qbind-ledger/tests/t164_vm_persistence_tests.rs`:

- `basic_put_get_roundtrip`
- `default_state_for_missing_account`
- `persist_across_reopen`
- `account_state_serialization_roundtrip`
- `cached_state_basic`
- `cached_state_write_through`

Located in `qbind-node/tests/t164_vm_v0_persistence_integration_tests.rs`:

- `test_vm_v0_engine_with_persistent_state`
- `test_vm_v0_state_survives_restart`
- `test_vm_v0_execute_block_persistent`
- `test_vm_v0_multiple_blocks_persistent`

---

## 6. Future Work

| Work Item | Description | Target | Status |
| :--- | :--- | :--- | :--- |
| **State Persistence** | Disk-backed account state (RocksDB) | TestNet Alpha | ✅ Done (T164) |
| **Stage B Parallelism** | Conflict-graph-based VM parallelism | TestNet Beta | Planned |
| **Gas Accounting** | Transaction fees and gas limits | TestNet Beta | Planned |
| **Smart Contracts** | Full EVM or custom VM support | MainNet | Planned |

---

## Appendix A: Related Documents

- [QBIND DevNet v0 Freeze](../devnet/QBIND_DEVNET_V0_FREEZE.md) — DevNet v0 specification and freeze
- [QBIND Parallel Execution Design](../devnet/QBIND_PARALLEL_EXECUTION_DESIGN.md) — Stage A/B parallelism
- [QBIND Chain ID and Domains](../devnet/QBIND_CHAIN_ID_AND_DOMAINS.md) — Domain separation

---

*End of Document*