//! File-based EVM state storage backend (T153).
//!
//! This module provides `FileEvmStateStorage`, a simple file-based implementation
//! of the `EvmStateStorage` trait. Snapshots are stored as individual files
//! named by block height.
//!
//! ## File Layout
//!
//! ```text
//! root_dir/
//! ├── evm_state_1.bin
//! ├── evm_state_2.bin
//! ├── evm_state_3.bin
//! └── ...
//! ```
//!
//! ## Serialization Format
//!
//! Snapshots are serialized using a simple binary format:
//! - 8 bytes: account count (u64, big-endian)
//! - For each account:
//!   - 20 bytes: address
//!   - 32 bytes: balance
//!   - 8 bytes: nonce (u64, big-endian)
//!   - 4 bytes: code length (u32, big-endian)
//!   - N bytes: code
//!   - 8 bytes: storage count (u64, big-endian)
//!   - For each storage slot:
//!     - 32 bytes: key
//!     - 32 bytes: value
//! - 32 bytes: state root
//!
//! ## Thread Safety
//!
//! File operations use file locks to ensure safe concurrent access.
//! Write operations are atomic (write to temp file, then rename).

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use qbind_runtime::{
    Address, EvmStateSnapshot, EvmStateStorage, EvmStateStorageConfig, EvmStateStorageError,
    SerializableAccountState,
};

// ============================================================================
// FileEvmStateStorage
// ============================================================================

/// File-based EVM state storage implementation.
///
/// Each snapshot is stored in a separate file named `evm_state_<height>.bin`.
/// The latest height is determined by scanning the directory at startup.
pub struct FileEvmStateStorage {
    /// Root directory for snapshot files.
    root_dir: PathBuf,

    /// Number of snapshots to retain.
    retention: u64,

    /// Inner state protected by a single mutex to avoid deadlocks.
    inner: Mutex<FileEvmStateStorageInner>,
}

/// Inner state for FileEvmStateStorage.
struct FileEvmStateStorageInner {
    /// Cached latest height (updated on store, loaded on startup).
    latest_height: Option<u64>,
}

impl FileEvmStateStorage {
    /// Create a new file-based storage.
    ///
    /// Creates the root directory if it doesn't exist.
    pub fn new(config: EvmStateStorageConfig) -> Result<Self, EvmStateStorageError> {
        fs::create_dir_all(&config.root_dir)?;

        let storage = FileEvmStateStorage {
            root_dir: config.root_dir,
            retention: config.retention,
            inner: Mutex::new(FileEvmStateStorageInner {
                latest_height: None,
            }),
        };

        // Scan for latest height on startup
        storage.refresh_latest_height()?;

        Ok(storage)
    }

    /// Create storage with a specific root directory and retention.
    pub fn with_dir_and_retention(
        root_dir: impl AsRef<Path>,
        retention: u64,
    ) -> Result<Self, EvmStateStorageError> {
        Self::new(EvmStateStorageConfig {
            root_dir: root_dir.as_ref().to_path_buf(),
            retention,
        })
    }

    /// Get the configured retention window.
    pub fn retention(&self) -> u64 {
        self.retention
    }

    /// Get the path for a snapshot file.
    fn snapshot_path(&self, height: u64) -> PathBuf {
        self.root_dir.join(format!("evm_state_{}.bin", height))
    }

    /// Get the path for a temporary file during writes.
    fn temp_path(&self, height: u64) -> PathBuf {
        self.root_dir.join(format!("evm_state_{}.tmp", height))
    }

    /// Scan the directory and find the latest snapshot height.
    fn refresh_latest_height(&self) -> Result<(), EvmStateStorageError> {
        let mut inner = self.inner.lock().unwrap();

        let mut latest: Option<u64> = None;

        for entry in fs::read_dir(&self.root_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(height) = Self::parse_snapshot_filename(&path) {
                latest = Some(latest.map_or(height, |l| l.max(height)));
            }
        }

        inner.latest_height = latest;
        Ok(())
    }

    /// Parse a snapshot filename to extract the height.
    fn parse_snapshot_filename(path: &Path) -> Option<u64> {
        let filename = path.file_name()?.to_str()?;

        if filename.starts_with("evm_state_") && filename.ends_with(".bin") {
            let height_str = &filename[10..filename.len() - 4];
            height_str.parse().ok()
        } else {
            None
        }
    }

    /// Serialize a snapshot to bytes.
    fn serialize_snapshot(snapshot: &EvmStateSnapshot) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4096);

        // Account count
        buf.extend_from_slice(&(snapshot.accounts.len() as u64).to_be_bytes());

        // Accounts (already sorted)
        for (addr, account) in &snapshot.accounts {
            // Address (20 bytes)
            buf.extend_from_slice(addr.as_bytes());

            // Balance (32 bytes)
            buf.extend_from_slice(&account.balance);

            // Nonce (8 bytes)
            buf.extend_from_slice(&account.nonce.to_be_bytes());

            // Code length + code
            buf.extend_from_slice(&(account.code.len() as u32).to_be_bytes());
            buf.extend_from_slice(&account.code);

            // Storage count
            buf.extend_from_slice(&(account.storage.len() as u64).to_be_bytes());

            // Storage slots (already sorted)
            for (key, value) in &account.storage {
                buf.extend_from_slice(key);
                buf.extend_from_slice(value);
            }
        }

        // State root
        buf.extend_from_slice(&snapshot.state_root);

        buf
    }

    /// Deserialize a snapshot from bytes.
    fn deserialize_snapshot(data: &[u8]) -> Result<EvmStateSnapshot, EvmStateStorageError> {
        let mut cursor = 0;

        // Helper function to read bytes
        let read_bytes = |cursor: &mut usize, len: usize| -> Result<&[u8], EvmStateStorageError> {
            if *cursor + len > data.len() {
                return Err(EvmStateStorageError::DecodeError(format!(
                    "unexpected end of data at offset {}",
                    *cursor
                )));
            }
            let slice = &data[*cursor..*cursor + len];
            *cursor += len;
            Ok(slice)
        };

        // Reasonable upper limits to prevent memory exhaustion
        // Max 10 million accounts (for a large chain)
        const MAX_ACCOUNT_COUNT: usize = 10_000_000;
        // Max 24KB code per account (EIP-170 limit)
        const MAX_CODE_SIZE: usize = 24_576;
        // Max 10 million storage slots per account
        const MAX_STORAGE_COUNT: usize = 10_000_000;

        // Account count
        let account_count = {
            let bytes = read_bytes(&mut cursor, 8)?;
            let count = u64::from_be_bytes(bytes.try_into().unwrap()) as usize;
            if count > MAX_ACCOUNT_COUNT {
                return Err(EvmStateStorageError::DecodeError(format!(
                    "account count {} exceeds maximum {}",
                    count, MAX_ACCOUNT_COUNT
                )));
            }
            count
        };

        let mut accounts = Vec::with_capacity(account_count);

        for _ in 0..account_count {
            // Address
            let addr_bytes: [u8; 20] = read_bytes(&mut cursor, 20)?
                .try_into()
                .map_err(|_| EvmStateStorageError::DecodeError("invalid address".to_string()))?;
            let addr = Address::from_bytes(addr_bytes);

            // Balance
            let balance: [u8; 32] = read_bytes(&mut cursor, 32)?
                .try_into()
                .map_err(|_| EvmStateStorageError::DecodeError("invalid balance".to_string()))?;

            // Nonce
            let nonce = {
                let bytes = read_bytes(&mut cursor, 8)?;
                u64::from_be_bytes(bytes.try_into().unwrap())
            };

            // Code
            let code_len = {
                let bytes = read_bytes(&mut cursor, 4)?;
                let len = u32::from_be_bytes(bytes.try_into().unwrap()) as usize;
                if len > MAX_CODE_SIZE {
                    return Err(EvmStateStorageError::DecodeError(format!(
                        "code length {} exceeds maximum {}",
                        len, MAX_CODE_SIZE
                    )));
                }
                len
            };
            let code = read_bytes(&mut cursor, code_len)?.to_vec();

            // Storage count
            let storage_count = {
                let bytes = read_bytes(&mut cursor, 8)?;
                let count = u64::from_be_bytes(bytes.try_into().unwrap()) as usize;
                if count > MAX_STORAGE_COUNT {
                    return Err(EvmStateStorageError::DecodeError(format!(
                        "storage count {} exceeds maximum {}",
                        count, MAX_STORAGE_COUNT
                    )));
                }
                count
            };

            // Storage
            let mut storage = Vec::with_capacity(storage_count);
            for _ in 0..storage_count {
                let key: [u8; 32] = read_bytes(&mut cursor, 32)?.try_into().map_err(|_| {
                    EvmStateStorageError::DecodeError("invalid storage key".to_string())
                })?;
                let value: [u8; 32] = read_bytes(&mut cursor, 32)?.try_into().map_err(|_| {
                    EvmStateStorageError::DecodeError("invalid storage value".to_string())
                })?;
                storage.push((key, value));
            }

            let account = SerializableAccountState {
                balance,
                nonce,
                code,
                storage,
            };

            accounts.push((addr, account));
        }

        // State root
        let state_root: [u8; 32] = read_bytes(&mut cursor, 32)?
            .try_into()
            .map_err(|_| EvmStateStorageError::DecodeError("invalid state root".to_string()))?;

        // Verify we consumed all data
        if cursor != data.len() {
            return Err(EvmStateStorageError::DecodeError(format!(
                "extra {} bytes after snapshot data",
                data.len() - cursor
            )));
        }

        Ok(EvmStateSnapshot::new(accounts, state_root))
    }

    /// List all snapshot heights in the directory.
    fn list_heights(&self) -> Result<Vec<u64>, EvmStateStorageError> {
        let mut heights = Vec::new();

        for entry in fs::read_dir(&self.root_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(height) = Self::parse_snapshot_filename(&path) {
                heights.push(height);
            }
        }

        heights.sort();
        Ok(heights)
    }
}

impl EvmStateStorage for FileEvmStateStorage {
    fn load_latest(&self) -> Result<Option<(u64, EvmStateSnapshot)>, EvmStateStorageError> {
        let inner = self.inner.lock().unwrap();
        let latest = inner.latest_height;
        drop(inner); // Release lock before calling load_by_height

        match latest {
            Some(height) => {
                let snapshot = self
                    .load_by_height(height)?
                    .ok_or(EvmStateStorageError::NotFound(height))?;
                Ok(Some((height, snapshot)))
            }
            None => Ok(None),
        }
    }

    fn load_by_height(
        &self,
        height: u64,
    ) -> Result<Option<EvmStateSnapshot>, EvmStateStorageError> {
        let path = self.snapshot_path(height);

        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        let snapshot = Self::deserialize_snapshot(&data)?;
        Ok(Some(snapshot))
    }

    fn store_snapshot(
        &self,
        height: u64,
        snapshot: &EvmStateSnapshot,
    ) -> Result<(), EvmStateStorageError> {
        let mut inner = self.inner.lock().unwrap();

        let temp_path = self.temp_path(height);
        let final_path = self.snapshot_path(height);

        // Serialize snapshot
        let data = Self::serialize_snapshot(snapshot);

        // Write to temp file
        {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&data)?;
            writer.flush()?;
        }

        // Atomic rename
        fs::rename(&temp_path, &final_path)?;

        // Update latest height
        inner.latest_height = Some(inner.latest_height.map_or(height, |l| l.max(height)));

        Ok(())
    }

    fn prune_below(&self, min_height: u64) -> Result<(), EvmStateStorageError> {
        let _inner = self.inner.lock().unwrap();

        let heights = self.list_heights()?;

        for height in heights {
            if height < min_height {
                let path = self.snapshot_path(height);
                if path.exists() {
                    fs::remove_file(&path)?;
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_runtime::U256;
    use tempfile::tempdir;

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    fn make_test_snapshot(height: u64) -> EvmStateSnapshot {
        let addr = make_test_addr(height as u8);
        let account = SerializableAccountState {
            balance: *U256::from_u64(1000 * height).as_bytes(),
            nonce: height,
            code: vec![0x60, 0x80],
            storage: vec![(
                *U256::from_u64(1).as_bytes(),
                *U256::from_u64(100).as_bytes(),
            )],
        };
        let state_root = [(height as u8).wrapping_add(0xAB); 32];
        EvmStateSnapshot::new(vec![(addr, account)], state_root)
    }

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        assert!(storage.load_latest().unwrap().is_none());
    }

    #[test]
    fn test_store_and_load() {
        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        let snapshot = make_test_snapshot(1);
        storage.store_snapshot(1, &snapshot).unwrap();

        let loaded = storage.load_by_height(1).unwrap().unwrap();
        assert_eq!(loaded.state_root, snapshot.state_root);
        assert_eq!(loaded.accounts.len(), snapshot.accounts.len());
    }

    #[test]
    fn test_load_latest() {
        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        // Store in non-sequential order
        storage.store_snapshot(3, &make_test_snapshot(3)).unwrap();
        storage.store_snapshot(1, &make_test_snapshot(1)).unwrap();
        storage.store_snapshot(5, &make_test_snapshot(5)).unwrap();

        let (height, _snapshot) = storage.load_latest().unwrap().unwrap();
        assert_eq!(height, 5);
    }

    #[test]
    fn test_prune_below() {
        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        // Store snapshots for heights 1-5
        for h in 1..=5 {
            storage.store_snapshot(h, &make_test_snapshot(h)).unwrap();
        }

        // Prune below height 3
        storage.prune_below(3).unwrap();

        // Heights 1 and 2 should be gone
        assert!(storage.load_by_height(1).unwrap().is_none());
        assert!(storage.load_by_height(2).unwrap().is_none());

        // Heights 3, 4, 5 should remain
        assert!(storage.load_by_height(3).unwrap().is_some());
        assert!(storage.load_by_height(4).unwrap().is_some());
        assert!(storage.load_by_height(5).unwrap().is_some());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let snapshot = make_test_snapshot(42);

        let serialized = FileEvmStateStorage::serialize_snapshot(&snapshot);
        let deserialized = FileEvmStateStorage::deserialize_snapshot(&serialized).unwrap();

        assert_eq!(snapshot.state_root, deserialized.state_root);
        assert_eq!(snapshot.accounts.len(), deserialized.accounts.len());

        for i in 0..snapshot.accounts.len() {
            let (addr1, acc1) = &snapshot.accounts[i];
            let (addr2, acc2) = &deserialized.accounts[i];
            assert_eq!(addr1, addr2);
            assert_eq!(acc1.balance, acc2.balance);
            assert_eq!(acc1.nonce, acc2.nonce);
            assert_eq!(acc1.code, acc2.code);
            assert_eq!(acc1.storage, acc2.storage);
        }
    }

    #[test]
    fn test_complex_snapshot_roundtrip() {
        let addr1 = make_test_addr(1);
        let addr2 = make_test_addr(2);

        let acc1 = SerializableAccountState {
            balance: *U256::from_u128(1_000_000_000_000_000_000).as_bytes(),
            nonce: 42,
            code: vec![0x60, 0x80, 0x60, 0x40, 0x52],
            storage: vec![
                (
                    *U256::from_u64(1).as_bytes(),
                    *U256::from_u64(100).as_bytes(),
                ),
                (
                    *U256::from_u64(2).as_bytes(),
                    *U256::from_u64(200).as_bytes(),
                ),
            ],
        };

        let acc2 = SerializableAccountState {
            balance: *U256::from_u64(500).as_bytes(),
            nonce: 1,
            code: Vec::new(),
            storage: Vec::new(),
        };

        let state_root = [0xDE; 32];
        let snapshot = EvmStateSnapshot::new(vec![(addr1, acc1), (addr2, acc2)], state_root);

        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        storage.store_snapshot(100, &snapshot).unwrap();
        let loaded = storage.load_by_height(100).unwrap().unwrap();

        assert_eq!(loaded.state_root, snapshot.state_root);
        assert_eq!(loaded.accounts.len(), 2);
    }

    #[test]
    fn test_load_nonexistent_height() {
        let dir = tempdir().unwrap();
        let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();

        assert!(storage.load_by_height(999).unwrap().is_none());
    }

    #[test]
    fn test_persistence_across_instances() {
        let dir = tempdir().unwrap();

        // First instance
        {
            let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();
            storage.store_snapshot(1, &make_test_snapshot(1)).unwrap();
            storage.store_snapshot(2, &make_test_snapshot(2)).unwrap();
        }

        // Second instance (simulating restart)
        {
            let storage = FileEvmStateStorage::with_dir_and_retention(dir.path(), 10).unwrap();
            let (height, _) = storage.load_latest().unwrap().unwrap();
            assert_eq!(height, 2);

            assert!(storage.load_by_height(1).unwrap().is_some());
            assert!(storage.load_by_height(2).unwrap().is_some());
        }
    }
}