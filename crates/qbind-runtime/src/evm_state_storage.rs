//! EVM state storage abstraction for persistent snapshots (T153).
//!
//! This module provides:
//! - `EvmStateSnapshot`: A deterministic, serializable snapshot of EVM state.
//! - `EvmStateStorage`: A trait for persistent storage backends.
//! - `EvmStateStorageError`: Errors that can occur during storage operations.
//!
//! ## Design
//!
//! The storage model is snapshot-based: after each committed block, a full
//! snapshot of the EVM ledger is persisted. On node restart, the latest
//! snapshot is loaded to restore state.
//!
//! This is a v0 persistence model. Future tasks will replace this with:
//! - Incremental state updates (instead of full snapshots)
//! - Merkle Patricia Trie / Verkle tree for authenticated storage
//! - State proofs for light clients

use std::fmt;

use crate::block::ZERO_H256;
use crate::evm_types::{Address, EvmAccountState, U256};
use crate::H256;

// ============================================================================
// EvmStateSnapshot: Deterministic snapshot representation
// ============================================================================

/// A deterministic snapshot of EVM ledger state.
///
/// The snapshot contains:
/// - A sorted list of (Address, EvmAccountState) pairs
/// - The state root computed over the ledger at snapshot time
///
/// ## Determinism
///
/// Snapshots are deterministic: accounts are always sorted by address (lex order)
/// before serialization. This ensures identical snapshots produce identical
/// serialized bytes.
#[derive(Clone, Debug)]
pub struct EvmStateSnapshot {
    /// Account states, sorted by address in lex order.
    pub accounts: Vec<(Address, SerializableAccountState)>,

    /// State root at the time of snapshot.
    pub state_root: H256,
}

impl EvmStateSnapshot {
    /// Create a new snapshot from account data and state root.
    ///
    /// The accounts should already be sorted by address.
    pub fn new(accounts: Vec<(Address, SerializableAccountState)>, state_root: H256) -> Self {
        EvmStateSnapshot {
            accounts,
            state_root,
        }
    }

    /// Create an empty snapshot.
    pub fn empty() -> Self {
        EvmStateSnapshot {
            accounts: Vec::new(),
            state_root: ZERO_H256,
        }
    }

    /// Get the number of accounts in the snapshot.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

// ============================================================================
// SerializableAccountState: Account state for serialization
// ============================================================================

/// A serializable representation of account state.
///
/// This structure is designed for deterministic serialization:
/// - Storage is represented as a sorted vec instead of a HashMap
/// - All fields use fixed-size or length-prefixed representations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializableAccountState {
    /// Account balance (32 bytes, big-endian).
    pub balance: [u8; 32],

    /// Transaction nonce.
    pub nonce: u64,

    /// EVM bytecode (length-prefixed).
    pub code: Vec<u8>,

    /// Storage slots, sorted by key for determinism.
    pub storage: Vec<([u8; 32], [u8; 32])>,
}

impl SerializableAccountState {
    /// Convert from EvmAccountState.
    pub fn from_account_state(account: &EvmAccountState) -> Self {
        // Convert storage to sorted vec
        let mut storage: Vec<_> = account
            .storage
            .iter()
            .map(|(k, v)| (*k.as_bytes(), *v.as_bytes()))
            .collect();
        storage.sort_by_key(|(k, _)| *k);

        SerializableAccountState {
            balance: *account.balance.as_bytes(),
            nonce: account.nonce,
            code: account.code.clone(),
            storage,
        }
    }

    /// Convert to EvmAccountState.
    pub fn to_account_state(&self) -> EvmAccountState {
        let mut storage = std::collections::HashMap::new();
        for (k, v) in &self.storage {
            storage.insert(U256::from_bytes(*k), U256::from_bytes(*v));
        }

        EvmAccountState {
            balance: U256::from_bytes(self.balance),
            nonce: self.nonce,
            code: self.code.clone(),
            storage,
        }
    }
}

// ============================================================================
// EvmStateStorageError: Storage operation errors
// ============================================================================

/// Errors that can occur during EVM state storage operations.
#[derive(Debug)]
pub enum EvmStateStorageError {
    /// I/O error during file operations.
    IoError(std::io::Error),

    /// Error decoding snapshot data.
    DecodeError(String),

    /// Error encoding snapshot data.
    EncodeError(String),

    /// Snapshot not found at requested height.
    NotFound(u64),

    /// Storage corruption detected.
    Corruption(String),
}

impl fmt::Display for EvmStateStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmStateStorageError::IoError(e) => write!(f, "io error: {}", e),
            EvmStateStorageError::DecodeError(msg) => write!(f, "decode error: {}", msg),
            EvmStateStorageError::EncodeError(msg) => write!(f, "encode error: {}", msg),
            EvmStateStorageError::NotFound(h) => write!(f, "snapshot not found at height {}", h),
            EvmStateStorageError::Corruption(msg) => write!(f, "storage corruption: {}", msg),
        }
    }
}

impl std::error::Error for EvmStateStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EvmStateStorageError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EvmStateStorageError {
    fn from(e: std::io::Error) -> Self {
        EvmStateStorageError::IoError(e)
    }
}

// ============================================================================
// EvmStateStorage trait
// ============================================================================

/// Trait for persistent EVM state storage backends.
///
/// Implementations of this trait provide snapshot-based persistence for
/// the EVM ledger. The storage is keyed by block height, allowing:
/// - Loading the latest committed state on startup
/// - Loading specific historical states (within retention window)
/// - Pruning old snapshots to bound storage usage
///
/// ## Thread Safety
///
/// Implementations must be `Send + Sync` to allow sharing across threads.
pub trait EvmStateStorage: Send + Sync {
    /// Load the latest committed state snapshot.
    ///
    /// Returns `Ok(None)` if no snapshots have been stored yet.
    fn load_latest(&self) -> Result<Option<(u64, EvmStateSnapshot)>, EvmStateStorageError>;

    /// Load a specific snapshot by block height.
    ///
    /// Returns `Ok(None)` if the snapshot at that height has been pruned
    /// or was never stored.
    fn load_by_height(&self, height: u64)
        -> Result<Option<EvmStateSnapshot>, EvmStateStorageError>;

    /// Persist a new snapshot for the given block height.
    ///
    /// This should be called after each successful block commit.
    fn store_snapshot(
        &self,
        height: u64,
        snapshot: &EvmStateSnapshot,
    ) -> Result<(), EvmStateStorageError>;

    /// Prune snapshots below a certain height (exclusive).
    ///
    /// All snapshots with height < `min_height` will be deleted.
    /// The snapshot at `min_height` (if it exists) is kept.
    fn prune_below(&self, min_height: u64) -> Result<(), EvmStateStorageError>;
}

// ============================================================================
// EvmStateStorageConfig: Configuration for storage backends
// ============================================================================

/// Configuration for EVM state storage.
#[derive(Clone, Debug)]
pub struct EvmStateStorageConfig {
    /// Root directory for snapshot storage.
    pub root_dir: std::path::PathBuf,

    /// Number of snapshots to retain. Older snapshots will be pruned.
    pub retention: u64,
}

impl EvmStateStorageConfig {
    /// Create a new storage configuration.
    pub fn new(root_dir: std::path::PathBuf, retention: u64) -> Self {
        EvmStateStorageConfig {
            root_dir,
            retention,
        }
    }

    /// Default retention (256 blocks).
    pub const DEFAULT_RETENTION: u64 = 256;
}

impl Default for EvmStateStorageConfig {
    fn default() -> Self {
        EvmStateStorageConfig {
            root_dir: std::path::PathBuf::from("./evm_state"),
            retention: Self::DEFAULT_RETENTION,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_serializable_account_state_roundtrip() {
        let mut storage = HashMap::new();
        storage.insert(U256::from_u64(1), U256::from_u64(100));
        storage.insert(U256::from_u64(2), U256::from_u64(200));

        let account = EvmAccountState {
            balance: U256::from_u64(1_000_000),
            nonce: 42,
            code: vec![0x60, 0x80, 0x60, 0x40], // PUSH1 0x80 PUSH1 0x40
            storage,
        };

        let serializable = SerializableAccountState::from_account_state(&account);
        let restored = serializable.to_account_state();

        assert_eq!(account.balance, restored.balance);
        assert_eq!(account.nonce, restored.nonce);
        assert_eq!(account.code, restored.code);
        assert_eq!(account.storage.len(), restored.storage.len());
        for (k, v) in &account.storage {
            assert_eq!(restored.storage.get(k), Some(v));
        }
    }

    #[test]
    fn test_serializable_account_storage_sorted() {
        let mut storage = HashMap::new();
        // Insert in random order
        storage.insert(U256::from_u64(5), U256::from_u64(50));
        storage.insert(U256::from_u64(1), U256::from_u64(10));
        storage.insert(U256::from_u64(3), U256::from_u64(30));

        let account = EvmAccountState {
            balance: U256::zero(),
            nonce: 0,
            code: Vec::new(),
            storage,
        };

        let serializable = SerializableAccountState::from_account_state(&account);

        // Verify storage is sorted
        let keys: Vec<u64> = serializable
            .storage
            .iter()
            .map(|(k, _)| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&k[24..32]);
                u64::from_be_bytes(bytes)
            })
            .collect();

        assert_eq!(keys, vec![1, 3, 5]);
    }

    #[test]
    fn test_snapshot_creation() {
        let addr = make_test_addr(1);
        let account = EvmAccountState::with_balance(U256::from_u64(1000));
        let serializable = SerializableAccountState::from_account_state(&account);

        let state_root = [0xAB; 32];
        let snapshot = EvmStateSnapshot::new(vec![(addr, serializable)], state_root);

        assert_eq!(snapshot.account_count(), 1);
        assert_eq!(snapshot.state_root, state_root);
    }

    #[test]
    fn test_empty_snapshot() {
        let snapshot = EvmStateSnapshot::empty();
        assert_eq!(snapshot.account_count(), 0);
        assert_eq!(snapshot.state_root, [0u8; 32]);
    }
}
