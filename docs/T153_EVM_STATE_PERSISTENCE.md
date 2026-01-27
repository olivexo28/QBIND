# T153 – EVM State Persistence

This document describes the persistent EVM state management system introduced in T153 for the QBIND post-quantum blockchain.

## Overview

QBIND uses a separate EVM ledger (`EvmLedger`) for storing Ethereum-compatible account states. Prior to T153, this ledger existed only in memory, meaning node restarts would lose all state.

T153 introduces:
- **Snapshot-based persistence**: After each committed block, a full snapshot of the EVM ledger is persisted to disk.
- **Crash-safe restart**: On node startup, the latest snapshot is loaded and validated.
- **Retention-based pruning**: Old snapshots are automatically deleted to bound storage usage.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               EvmExecutionBridge                            │
│    (executes blocks, maintains EVM state)                   │
├─────────────────────────────────────────────────────────────┤
│  - Holds EvmLedger (in-memory state)                        │
│  - Executes blocks via RevmExecutionEngine                  │
│  - On startup: loads latest snapshot                        │
│  - On commit: persists snapshot + prunes old ones           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               EvmStateStorage (trait)                       │
│    (pluggable storage backend)                              │
├─────────────────────────────────────────────────────────────┤
│  - load_latest() → Option<(height, snapshot)>               │
│  - load_by_height(h) → Option<snapshot>                     │
│  - store_snapshot(h, snapshot)                              │
│  - prune_below(min_height)                                  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               FileEvmStateStorage                           │
│    (default file-based implementation)                      │
├─────────────────────────────────────────────────────────────┤
│  - Stores snapshots as evm_state_<height>.bin              │
│  - Atomic writes via temp file + rename                     │
│  - Directory scan on startup to find latest                 │
└─────────────────────────────────────────────────────────────┘
```

## Storage Abstraction

### EvmStateStorage Trait

The `EvmStateStorage` trait defines the interface for persistent storage backends:

```rust
pub trait EvmStateStorage: Send + Sync {
    /// Load the latest committed state snapshot.
    fn load_latest(&self) -> Result<Option<(u64, EvmStateSnapshot)>, EvmStateStorageError>;

    /// Load a specific snapshot by block height.
    fn load_by_height(&self, height: u64) -> Result<Option<EvmStateSnapshot>, EvmStateStorageError>;

    /// Persist a new snapshot for the given block height.
    fn store_snapshot(
        &self,
        height: u64,
        snapshot: &EvmStateSnapshot,
    ) -> Result<(), EvmStateStorageError>;

    /// Prune snapshots below a certain height.
    fn prune_below(&self, min_height: u64) -> Result<(), EvmStateStorageError>;
}
```

### EvmStateSnapshot

A snapshot is a deterministic representation of the EVM ledger state:

```rust
pub struct EvmStateSnapshot {
    /// Account states, sorted by address for determinism.
    pub accounts: Vec<(Address, SerializableAccountState)>,
    
    /// State root at the time of snapshot.
    pub state_root: H256,
}
```

Key properties:
- **Deterministic**: Accounts are always sorted by address before serialization.
- **Self-verifying**: Contains the state root, which can be recomputed to verify integrity.

### FileEvmStateStorage

The default implementation uses individual files per snapshot:

```
storage_dir/
├── evm_state_1.bin
├── evm_state_2.bin
├── evm_state_3.bin
└── ...
```

#### Serialization Format

Snapshots use a simple binary format:
- 8 bytes: account count (u64, big-endian)
- For each account:
  - 20 bytes: address
  - 32 bytes: balance
  - 8 bytes: nonce (u64, big-endian)
  - 4 bytes: code length (u32, big-endian)
  - N bytes: code
  - 8 bytes: storage count (u64, big-endian)
  - For each storage slot (sorted by key):
    - 32 bytes: key
    - 32 bytes: value
- 32 bytes: state root

#### Configuration

```rust
pub struct EvmStateStorageConfig {
    /// Root directory for snapshot storage.
    pub root_dir: PathBuf,
    
    /// Number of snapshots to retain.
    pub retention: u64,
}
```

Default retention: 256 blocks.

## Ledger ↔ Snapshot Conversion

The `EvmLedger` provides methods for snapshot conversion:

```rust
impl EvmLedger {
    /// Create a persistent snapshot from the current ledger state.
    pub fn to_snapshot(&self, state_root: H256) -> EvmStateSnapshot;

    /// Restore ledger state from a snapshot.
    pub fn from_snapshot(snapshot: &EvmStateSnapshot) -> Self;
}
```

Invariant: `ledger.to_snapshot(root)` followed by `EvmLedger::from_snapshot(&snap)` produces a ledger that computes the same state root.

## EvmExecutionBridge Integration

### Startup Behavior

When `EvmExecutionBridge::with_storage()` is called:

1. Calls `storage.load_latest()`.
2. If a snapshot exists:
   - Restores ledger state via `EvmLedger::from_snapshot()`.
   - Recomputes the state root and verifies it matches the snapshot's `state_root`.
   - Sets `current_height` to the snapshot's height.
3. If no snapshot exists:
   - Starts with an empty ledger.
   - Sets `current_height` to 0.

### Commit Behavior

When `apply_committed_block()` succeeds:

1. Updates the in-memory ledger state (as before).
2. Creates a snapshot: `ledger.to_snapshot(new_state_root)`.
3. Persists the snapshot: `storage.store_snapshot(height, &snapshot)`.
4. Prunes old snapshots:
   ```rust
   if height > retention {
       let prune_below = height - retention;
       storage.prune_below(prune_below)?;
   }
   ```

### Error Handling

For T153, storage errors are treated as fatal:
- If `store_snapshot()` fails, the commit returns an error.
- If `load_latest()` fails on startup, construction returns an error.

Future versions may add retry logic or graceful degradation.

## Testing

The test suite (`t153_evm_state_persistence_tests.rs`) covers:

1. **Single-block restart**: Commit a block, drop the bridge, create a new one, verify state.
2. **Multi-block + pruning**: Commit multiple blocks, verify old snapshots are pruned.
3. **Empty startup**: Start with no existing snapshots, verify empty ledger.
4. **State root consistency**: Verify snapshot round-trips preserve the state root.
5. **Backwards compatibility**: Verify bridges without storage still work.

## Limitations and Future Work

### Current Limitations

1. **No incremental updates**: Each commit saves a full snapshot of all accounts. This scales poorly with state size.
2. **No authenticated data structure**: The state root is computed by hashing the entire state. No Merkle proofs are available.
3. **Simple pruning**: Only retention-based pruning. No archival mode or historical queries beyond the retention window.
4. **No export/import**: Snapshots are internal to the node; no light client support.

### Future Work (Not in T153)

- **T154+**: Replace flat snapshots with Merkle Patricia Trie for incremental updates and state proofs.
- **Archival nodes**: Full historical state retention with separate indices.
- **State sync**: Download state snapshots from peers for fast sync.
- **Verkle trees**: Post-quantum friendly state commitment scheme.

## Usage Example

```rust
use qbind_node::{EvmExecutionBridge, FileEvmStateStorage};
use qbind_runtime::EvmStateStorageConfig;
use std::sync::Arc;

// Configure storage
let config = EvmStateStorageConfig {
    root_dir: "/path/to/evm_state".into(),
    retention: 256, // Keep 256 snapshots
};

// Create storage backend
let storage = Arc::new(FileEvmStateStorage::new(config)?);

// Create bridge with persistence
let mut bridge = EvmExecutionBridge::with_storage(
    1337,      // chain_id
    storage,
    256,       // retention
)?;

// The bridge will:
// - Load latest snapshot on creation (if any)
// - Persist snapshots on each commit
// - Prune old snapshots automatically
```

## Backwards Compatibility

The existing `EvmExecutionBridge::new()` and `with_ledger()` constructors continue to work without persistence. This allows:
- Unit tests to run without disk I/O.
- Gradual migration of existing code.
- Development without storage setup.