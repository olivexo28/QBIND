//! RocksDB-backed persistence layer for consensus/ledger state.
//!
//! This module provides a minimal storage abstraction and RocksDB implementation
//! for persisting committed blocks, quorum certificates, and basic consensus state.
//!
//! # Design Notes
//!
//! The storage layer is intentionally minimal and consensus-focused:
//! - Stores committed blocks (including suite_id via wire encoding)
//! - Stores associated QCs (including suite_id)
//! - Tracks last committed block for node restart
//!
//! ## Key Layout
//!
//! - Blocks: `b:<block_id_bytes>` → serialized BlockProposal
//! - QCs: `q:<block_id_bytes>` → serialized QuorumCertificate  
//! - Last committed: `meta:last_committed` → block_id_bytes
//! - Current epoch: `meta:current_epoch` → u64 (big-endian, 8 bytes)
//! - Schema version: `meta:schema_version` → u32 (big-endian, 4 bytes)
//!
//! ## Schema Versioning
//!
//! The storage layer includes a schema version mechanism (T104) to detect
//! incompatible on-disk layouts:
//!
//! - **Version 1**: Current layout including blocks, QCs, `meta:last_committed`,
//!   and `meta:current_epoch`.
//! - **Version 0 (implicit)**: Legacy databases without a schema version key.
//!   Treated as compatible with version 1.
//!
//! On startup, [`ensure_compatible_schema`] checks the stored version:
//! - Missing or version ≤ current: accepted as compatible.
//! - Version > current: fails with [`StorageError::IncompatibleSchema`].
//!
//! ## Serialization
//!
//! Uses existing wire encoding from qbind-wire, which ensures suite_id
//! is correctly included and roundtrips.
//!
//! # Limitations
//!
//! - Single column family for simplicity
//! - Minimal RocksDB tuning (sane defaults only)

use std::fmt;
use std::path::Path;

use qbind_wire::consensus::{BlockProposal, QuorumCertificate};
use qbind_wire::io::{WireDecode, WireEncode};

// ============================================================================
// StorageError
// ============================================================================

/// Error type for storage operations.
///
/// This is a non-leaky error type that abstracts away RocksDB-specific details.
#[derive(Debug)]
pub enum StorageError {
    /// I/O or database error.
    Io(String),
    /// Serialization/deserialization error.
    Codec(String),
    /// Incompatible schema version detected (T104).
    ///
    /// This error indicates that the on-disk schema version is newer than
    /// what this binary supports. The node cannot safely operate with data
    /// written by a newer version.
    IncompatibleSchema {
        /// The schema version found in storage.
        stored_version: u32,
        /// The maximum schema version this binary supports.
        current_version: u32,
    },
    /// Data corruption detected (T119).
    ///
    /// This error indicates that a checksum mismatch was detected when reading
    /// data from storage, suggesting bit-rot, disk corruption, or tampering.
    /// The node should not continue with corrupted data.
    Corruption(String),
    /// Other error with a descriptive message.
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(msg) => write!(f, "storage I/O error: {}", msg),
            StorageError::Codec(msg) => write!(f, "storage codec error: {}", msg),
            StorageError::IncompatibleSchema {
                stored_version,
                current_version,
            } => {
                write!(
                    f,
                    "incompatible schema version: storage has version {}, but this binary only supports up to version {}. \
                     The database was created by a newer version of the software and cannot be opened.",
                    stored_version, current_version
                )
            }
            StorageError::Corruption(msg) => write!(f, "storage corruption detected: {}", msg),
            StorageError::Other(msg) => write!(f, "storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

// ============================================================================
// ConsensusStorage trait
// ============================================================================

/// Minimal storage trait for consensus/ledger persistence.
///
/// This trait abstracts what consensus/ledger components need from persistence:
/// - Store and retrieve blocks by ID
/// - Store and retrieve QCs by block ID
/// - Track the last committed block ID
/// - Track the current epoch (T103)
///
/// All stored types include suite_id via their wire encoding.
pub trait ConsensusStorage: Send + Sync {
    /// Store a block proposal by its block ID.
    ///
    /// The block is serialized using wire encoding, which includes all fields
    /// including suite_id in the header.
    fn put_block(&self, block_id: &[u8; 32], block: &BlockProposal) -> Result<(), StorageError>;

    /// Retrieve a block proposal by its block ID.
    ///
    /// Returns `Ok(None)` if the block is not found.
    fn get_block(&self, block_id: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError>;

    /// Store a quorum certificate by the block ID it attests to.
    ///
    /// The QC is serialized using wire encoding, which includes suite_id.
    fn put_qc(&self, block_id: &[u8; 32], qc: &QuorumCertificate) -> Result<(), StorageError>;

    /// Retrieve a quorum certificate by the block ID it attests to.
    ///
    /// Returns `Ok(None)` if the QC is not found.
    fn get_qc(&self, block_id: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError>;

    /// Store the last committed block ID.
    ///
    /// This is updated after each successful commit and is used on startup
    /// to resume from the last known committed state.
    fn put_last_committed(&self, block_id: &[u8; 32]) -> Result<(), StorageError>;

    /// Retrieve the last committed block ID.
    ///
    /// Returns `Ok(None)` if no blocks have been committed yet (fresh node).
    fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError>;

    /// Store the current epoch.
    ///
    /// This is updated when the node transitions to a new epoch (typically
    /// after committing a reconfiguration block). The epoch is stored as
    /// a u64 in big-endian format.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch ID to store.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the write fails.
    fn put_current_epoch(&self, epoch: u64) -> Result<(), StorageError>;

    /// Retrieve the current epoch.
    ///
    /// Returns `Ok(None)` if no epoch has been stored yet (fresh DB).
    /// For backward compatibility with existing databases, a missing
    /// epoch key should be treated as epoch 0.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the read fails, or `StorageError::Codec`
    /// if the stored epoch data is malformed.
    fn get_current_epoch(&self) -> Result<Option<u64>, StorageError>;

    /// Store the schema version (T104).
    ///
    /// The schema version is stored as a u32 in big-endian format (4 bytes)
    /// under the key `meta:schema_version`.
    ///
    /// # Arguments
    ///
    /// * `version` - The schema version to store.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the write fails.
    fn put_schema_version(&self, version: u32) -> Result<(), StorageError>;

    /// Retrieve the schema version (T104).
    ///
    /// Returns `Ok(None)` if no schema version key exists (legacy v0 database).
    /// Returns `Ok(Some(version))` if a schema version is stored.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the read fails, or `StorageError::Codec`
    /// if the stored schema version data is malformed.
    fn get_schema_version(&self) -> Result<Option<u32>, StorageError>;
}

// ============================================================================
// Schema versioning constants (T104)
// ============================================================================

/// Current schema version for consensus storage.
///
/// **Version 1** represents the current key layout:
/// - Blocks: `b:<block_id_bytes>` → serialized BlockProposal
/// - QCs: `q:<block_id_bytes>` → serialized QuorumCertificate
/// - Last committed: `meta:last_committed` → block_id_bytes
/// - Current epoch: `meta:current_epoch` → u64 (big-endian, 8 bytes)
/// - Schema version: `meta:schema_version` → u32 (big-endian, 4 bytes)
///
/// Databases without a schema version key are treated as version 0 (legacy)
/// and are compatible with version 1.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Key prefixes
// ============================================================================

/// Key prefix for block storage.
const BLOCK_PREFIX: &[u8] = b"b:";

/// Key prefix for QC storage.
const QC_PREFIX: &[u8] = b"q:";

/// Key for last committed block ID.
const LAST_COMMITTED_KEY: &[u8] = b"meta:last_committed";

/// Key for current epoch (T103).
///
/// The epoch is stored as a u64 in big-endian format (8 bytes).
/// For backward compatibility, if this key is missing from an existing
/// database, it should be treated as epoch 0.
const CURRENT_EPOCH_KEY: &[u8] = b"meta:current_epoch";

/// Key for schema version (T104).
///
/// The schema version is stored as a u32 in big-endian format (4 bytes).
/// For backward compatibility, if this key is missing from an existing
/// database, it should be treated as schema version 0 (legacy).
const SCHEMA_VERSION_KEY: &[u8] = b"meta:schema_version";

// ============================================================================
// CRC32 Checksum Helpers (T119)
// ============================================================================

/// CRC-32 (IEEE 802.3) lookup table for fast checksum computation.
///
/// This is a precomputed table for the standard CRC-32 polynomial 0xEDB88320
/// (reflected form of 0x04C11DB7).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Compute CRC-32 checksum over data (IEEE 802.3 polynomial).
///
/// This is a fast, standard CRC-32 implementation used for integrity checking
/// of stored values. It's not cryptographically secure, but sufficient for
/// detecting bit-rot and accidental corruption.
fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF_u32;
    for &byte in data {
        let idx = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

/// Wrap a payload in a checksummed envelope.
///
/// The envelope format is:
/// - 4 bytes: CRC32 checksum (big-endian)
/// - N bytes: payload
///
/// This ensures that any bit-flip in the stored data will be detected on read.
fn wrap_checksummed(payload: &[u8]) -> Vec<u8> {
    let checksum = compute_crc32(payload);
    let mut result = Vec::with_capacity(4 + payload.len());
    result.extend_from_slice(&checksum.to_be_bytes());
    result.extend_from_slice(payload);
    result
}

/// Unwrap a checksummed envelope and verify integrity.
///
/// Returns the original payload if checksum matches.
/// Returns `StorageError::Corruption` if:
/// - Data is too short (< 4 bytes)
/// - Checksum mismatch (data corrupted)
fn unwrap_checksummed(data: &[u8], key_description: &str) -> Result<Vec<u8>, StorageError> {
    if data.len() < 4 {
        return Err(StorageError::Corruption(format!(
            "{}: data too short for checksum envelope (len={})",
            key_description,
            data.len()
        )));
    }

    let stored_checksum = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload = &data[4..];
    let computed_checksum = compute_crc32(payload);

    if stored_checksum != computed_checksum {
        return Err(StorageError::Corruption(format!(
            "{}: checksum mismatch (stored={:#010x}, computed={:#010x})",
            key_description, stored_checksum, computed_checksum
        )));
    }

    Ok(payload.to_vec())
}

/// Try to unwrap a checksummed envelope, falling back to raw data for backward compatibility.
///
/// This function handles both checksummed (new) and raw (legacy) data:
/// - If data starts with a valid checksum, unwrap and verify.
/// - If checksum doesn't match, assume it's legacy data without checksum.
///
/// The heuristic is: if the first 4 bytes, interpreted as a CRC32, don't match
/// the remaining data, then this is likely legacy data stored without checksums.
///
/// # Legacy Compatibility
///
/// Old databases created before T119 don't have checksums. To avoid breaking
/// existing deployments, we allow reading legacy data:
/// - If checksum matches: return payload (checksummed format)
/// - If checksum doesn't match and data is valid legacy format: return all data
/// - If neither works: return Corruption error (data is truly corrupted)
fn unwrap_checksummed_or_legacy(
    data: &[u8],
    key_description: &str,
) -> Result<Vec<u8>, StorageError> {
    if data.len() < 4 {
        // Too short for checksum envelope - this is either legacy data or corruption.
        // For critical keys like blocks/QCs, this is likely corruption since they're
        // always longer than 4 bytes. Return the raw data and let the decoder handle it.
        return Ok(data.to_vec());
    }

    let stored_checksum = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload = &data[4..];
    let computed_checksum = compute_crc32(payload);

    if stored_checksum == computed_checksum {
        // Valid checksum - this is checksummed data
        Ok(payload.to_vec())
    } else {
        // Checksum doesn't match - this might be legacy data without checksums.
        // Return the full data and let the caller's decoder handle it.
        // If the decoder fails, it will return a Codec error.
        eprintln!(
            "[T119] {}: checksum mismatch, treating as legacy data (stored={:#010x}, computed={:#010x})",
            key_description, stored_checksum, computed_checksum
        );
        Ok(data.to_vec())
    }
}

/// Try to unwrap checksummed meta value, with strict mode for critical metadata.
///
/// For critical metadata keys (last_committed, current_epoch), we use a strict
/// approach: if the data has the expected checksummed format (4-byte checksum +
/// known-length payload), verify the checksum. If it doesn't match, return Corruption.
///
/// For backward compatibility with legacy DBs:
/// - If the total length matches the legacy (non-checksummed) format, accept it.
/// - If the length matches checksummed format but checksum fails, return Corruption.
fn unwrap_checksummed_meta(
    data: &[u8],
    key_description: &str,
    expected_payload_len: usize,
) -> Result<Vec<u8>, StorageError> {
    // Legacy format: exactly expected_payload_len bytes (no checksum)
    if data.len() == expected_payload_len {
        eprintln!(
            "[T119] {}: found legacy format (len={}, no checksum)",
            key_description,
            data.len()
        );
        return Ok(data.to_vec());
    }

    // Checksummed format: 4-byte checksum + expected_payload_len bytes
    let checksummed_len = 4 + expected_payload_len;
    if data.len() == checksummed_len {
        // This should be checksummed - verify strictly
        return unwrap_checksummed(data, key_description);
    }

    // Unexpected length - could be corruption or future format
    Err(StorageError::Corruption(format!(
        "{}: unexpected data length {} (expected {} or {})",
        key_description,
        data.len(),
        expected_payload_len,
        checksummed_len
    )))
}

// ============================================================================
// RocksDbConsensusStorage
// ============================================================================

use std::sync::Arc;

/// RocksDB-backed implementation of `ConsensusStorage`.
///
/// This struct provides persistent storage for consensus state using RocksDB.
/// It stores blocks and QCs with their full wire encoding (including suite_id).
///
/// # Usage
///
/// ```ignore
/// use qbind_node::storage::RocksDbConsensusStorage;
/// use std::path::PathBuf;
///
/// let storage = RocksDbConsensusStorage::open(PathBuf::from("/path/to/db"))?;
///
/// // Store a block
/// storage.put_block(&block_id, &block)?;
///
/// // Retrieve it later
/// let block = storage.get_block(&block_id)?;
/// ```
///
/// # Metrics (T107)
///
/// When metrics are attached via `with_metrics()`, the storage records
/// latency for all put/get operations.
///
/// ```ignore
/// use qbind_node::metrics::NodeMetrics;
/// use std::sync::Arc;
///
/// let metrics = Arc::new(NodeMetrics::new());
/// let storage = RocksDbConsensusStorage::open("/path/to/db")?
///     .with_metrics(metrics);
/// ```
pub struct RocksDbConsensusStorage {
    db: rocksdb::DB,
    /// Optional metrics for tracking operation latency (T107).
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,
}

impl fmt::Debug for RocksDbConsensusStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksDbConsensusStorage")
            .field("path", &self.db.path())
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl RocksDbConsensusStorage {
    /// Open or create a RocksDB database at the given path.
    ///
    /// Uses sane defaults for RocksDB configuration:
    /// - Creates the database if it doesn't exist
    /// - Single default column family
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the database cannot be opened.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        let db = rocksdb::DB::open(&opts, path).map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(RocksDbConsensusStorage { db, metrics: None })
    }

    /// Attach metrics to this storage instance (T107).
    ///
    /// When metrics are attached, all put/get operations will record their
    /// latency to the `StorageMetrics` component of the provided `NodeMetrics`.
    ///
    /// # Arguments
    ///
    /// * `metrics` - An Arc to a `NodeMetrics` instance.
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::storage::RocksDbConsensusStorage;
    /// use qbind_node::metrics::NodeMetrics;
    /// use std::sync::Arc;
    ///
    /// let metrics = Arc::new(NodeMetrics::new());
    /// let storage = RocksDbConsensusStorage::open("/path/to/db")?
    ///     .with_metrics(metrics);
    /// ```
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::NodeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Build the key for a block entry.
    fn block_key(block_id: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_PREFIX.len() + 32);
        key.extend_from_slice(BLOCK_PREFIX);
        key.extend_from_slice(block_id);
        key
    }

    /// Build the key for a QC entry.
    fn qc_key(block_id: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(QC_PREFIX.len() + 32);
        key.extend_from_slice(QC_PREFIX);
        key.extend_from_slice(block_id);
        key
    }
}

impl ConsensusStorage for RocksDbConsensusStorage {
    fn put_block(&self, block_id: &[u8; 32], block: &BlockProposal) -> Result<(), StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let key = Self::block_key(block_id);

        // Serialize using wire encoding (includes suite_id)
        let mut payload = Vec::new();
        block.encode(&mut payload);

        // T119: Wrap in checksummed envelope
        let value = wrap_checksummed(&payload);

        let result = self
            .db
            .put(&key, &value)
            .map_err(|e| StorageError::Io(e.to_string()));

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::PutBlock, start.elapsed());
        }

        result
    }

    fn get_block(&self, block_id: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let key = Self::block_key(block_id);

        let result = match self.db.get(&key) {
            Ok(Some(value)) => {
                // T119: Unwrap checksummed envelope (with legacy fallback)
                let payload = unwrap_checksummed_or_legacy(&value, "block")?;
                let mut slice: &[u8] = &payload;
                let block = BlockProposal::decode(&mut slice)
                    .map_err(|e| StorageError::Codec(format!("failed to decode block: {:?}", e)))?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        };

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::GetBlock, start.elapsed());
        }

        result
    }

    fn put_qc(&self, block_id: &[u8; 32], qc: &QuorumCertificate) -> Result<(), StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let key = Self::qc_key(block_id);

        // Serialize using wire encoding (includes suite_id)
        let mut payload = Vec::new();
        qc.encode(&mut payload);

        // T119: Wrap in checksummed envelope
        let value = wrap_checksummed(&payload);

        let result = self
            .db
            .put(&key, &value)
            .map_err(|e| StorageError::Io(e.to_string()));

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics.storage().record(StorageOp::PutQc, start.elapsed());
        }

        result
    }

    fn get_qc(&self, block_id: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let key = Self::qc_key(block_id);

        let result = match self.db.get(&key) {
            Ok(Some(value)) => {
                // T119: Unwrap checksummed envelope (with legacy fallback)
                let payload = unwrap_checksummed_or_legacy(&value, "QC")?;
                let mut slice: &[u8] = &payload;
                let qc = QuorumCertificate::decode(&mut slice)
                    .map_err(|e| StorageError::Codec(format!("failed to decode QC: {:?}", e)))?;
                Ok(Some(qc))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        };

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics.storage().record(StorageOp::GetQc, start.elapsed());
        }

        result
    }

    fn put_last_committed(&self, block_id: &[u8; 32]) -> Result<(), StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        // T119: Wrap block_id in checksummed envelope
        let value = wrap_checksummed(block_id);
        let result = self
            .db
            .put(LAST_COMMITTED_KEY, &value)
            .map_err(|e| StorageError::Io(e.to_string()));

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::PutLastCommitted, start.elapsed());
        }

        result
    }

    fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let result = match self.db.get(LAST_COMMITTED_KEY) {
            Ok(Some(value)) => {
                // T119: Unwrap checksummed envelope with strict mode for metadata
                let payload = unwrap_checksummed_meta(&value, "meta:last_committed", 32)?;
                if payload.len() != 32 {
                    return Err(StorageError::Codec(format!(
                        "invalid block_id length: expected 32, got {}",
                        payload.len()
                    )));
                }
                let mut block_id = [0u8; 32];
                block_id.copy_from_slice(&payload);
                Ok(Some(block_id))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        };

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::GetLastCommitted, start.elapsed());
        }

        result
    }

    fn put_current_epoch(&self, epoch: u64) -> Result<(), StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        // Store epoch as big-endian u64 (8 bytes), wrapped in checksum envelope
        let epoch_bytes = epoch.to_be_bytes();
        // T119: Wrap in checksummed envelope
        let value = wrap_checksummed(&epoch_bytes);
        let result = self
            .db
            .put(CURRENT_EPOCH_KEY, &value)
            .map_err(|e| StorageError::Io(e.to_string()));

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::PutCurrentEpoch, start.elapsed());
        }

        result
    }

    fn get_current_epoch(&self) -> Result<Option<u64>, StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        let result = match self.db.get(CURRENT_EPOCH_KEY) {
            Ok(Some(value)) => {
                // T119: Unwrap checksummed envelope with strict mode for metadata
                let payload = unwrap_checksummed_meta(&value, "meta:current_epoch", 8)?;
                if payload.len() != 8 {
                    return Err(StorageError::Codec(format!(
                        "invalid epoch length: expected 8 bytes, got {}",
                        payload.len()
                    )));
                }
                let mut epoch_bytes = [0u8; 8];
                epoch_bytes.copy_from_slice(&payload);
                let epoch = u64::from_be_bytes(epoch_bytes);
                Ok(Some(epoch))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        };

        // Record latency if metrics are attached
        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::GetCurrentEpoch, start.elapsed());
        }

        result
    }

    fn put_schema_version(&self, version: u32) -> Result<(), StorageError> {
        // Store schema version as big-endian u32 (4 bytes)
        let version_bytes = version.to_be_bytes();
        self.db
            .put(SCHEMA_VERSION_KEY, version_bytes)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn get_schema_version(&self) -> Result<Option<u32>, StorageError> {
        match self.db.get(SCHEMA_VERSION_KEY) {
            Ok(Some(value)) => {
                if value.len() != 4 {
                    return Err(StorageError::Codec(format!(
                        "invalid schema version length: expected 4 bytes, got {}",
                        value.len()
                    )));
                }
                let mut version_bytes = [0u8; 4];
                version_bytes.copy_from_slice(&value);
                let version = u32::from_be_bytes(version_bytes);
                Ok(Some(version))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }
}

// ============================================================================
// InMemoryConsensusStorage (for testing)
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory implementation of `ConsensusStorage` for testing.
///
/// This implementation stores everything in memory and is useful for unit tests
/// that don't need actual disk persistence.
#[derive(Debug, Default)]
pub struct InMemoryConsensusStorage {
    blocks: RwLock<HashMap<[u8; 32], Vec<u8>>>,
    qcs: RwLock<HashMap<[u8; 32], Vec<u8>>>,
    last_committed: RwLock<Option<[u8; 32]>>,
    current_epoch: RwLock<Option<u64>>,
    schema_version: RwLock<Option<u32>>,
}

impl InMemoryConsensusStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConsensusStorage for InMemoryConsensusStorage {
    fn put_block(&self, block_id: &[u8; 32], block: &BlockProposal) -> Result<(), StorageError> {
        let mut value = Vec::new();
        block.encode(&mut value);

        self.blocks
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?
            .insert(*block_id, value);
        Ok(())
    }

    fn get_block(&self, block_id: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;

        match blocks.get(block_id) {
            Some(value) => {
                let mut slice: &[u8] = value;
                let block = BlockProposal::decode(&mut slice)
                    .map_err(|e| StorageError::Codec(format!("failed to decode block: {:?}", e)))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn put_qc(&self, block_id: &[u8; 32], qc: &QuorumCertificate) -> Result<(), StorageError> {
        let mut value = Vec::new();
        qc.encode(&mut value);

        self.qcs
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?
            .insert(*block_id, value);
        Ok(())
    }

    fn get_qc(&self, block_id: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError> {
        let qcs = self
            .qcs
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;

        match qcs.get(block_id) {
            Some(value) => {
                let mut slice: &[u8] = value;
                let qc = QuorumCertificate::decode(&mut slice)
                    .map_err(|e| StorageError::Codec(format!("failed to decode QC: {:?}", e)))?;
                Ok(Some(qc))
            }
            None => Ok(None),
        }
    }

    fn put_last_committed(&self, block_id: &[u8; 32]) -> Result<(), StorageError> {
        let mut last = self
            .last_committed
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        *last = Some(*block_id);
        Ok(())
    }

    fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let last = self
            .last_committed
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        Ok(*last)
    }

    fn put_current_epoch(&self, epoch: u64) -> Result<(), StorageError> {
        let mut current = self
            .current_epoch
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        *current = Some(epoch);
        Ok(())
    }

    fn get_current_epoch(&self) -> Result<Option<u64>, StorageError> {
        let current = self
            .current_epoch
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        Ok(*current)
    }

    fn put_schema_version(&self, version: u32) -> Result<(), StorageError> {
        let mut current = self
            .schema_version
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        *current = Some(version);
        Ok(())
    }

    fn get_schema_version(&self) -> Result<Option<u32>, StorageError> {
        let current = self
            .schema_version
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        Ok(*current)
    }
}

// ============================================================================
// Schema compatibility check (T104)
// ============================================================================

/// Check that the storage schema version is compatible with this binary.
///
/// This function performs a fail-safe schema version check on startup:
///
/// - If no schema version key exists (legacy v0 database): treated as compatible.
/// - If stored version ≤ [`CURRENT_SCHEMA_VERSION`]: accepted as compatible.
/// - If stored version > [`CURRENT_SCHEMA_VERSION`]: returns [`StorageError::IncompatibleSchema`].
///
/// This ensures that a node will not silently operate on a database created by
/// a newer version of the software with potentially incompatible data layout.
///
/// # Arguments
///
/// * `storage` - The consensus storage to check.
///
/// # Errors
///
/// Returns `StorageError::IncompatibleSchema` if the stored schema version is
/// greater than the current binary's schema version.
///
/// # Example
///
/// ```ignore
/// use qbind_node::storage::{ensure_compatible_schema, RocksDbConsensusStorage};
///
/// let storage = RocksDbConsensusStorage::open("/path/to/db")?;
/// ensure_compatible_schema(&storage)?; // Fails if schema is incompatible
/// ```
pub fn ensure_compatible_schema<S: ConsensusStorage + ?Sized>(
    storage: &S,
) -> Result<(), StorageError> {
    let stored_version = storage.get_schema_version()?;

    match stored_version {
        None => {
            // Legacy database without schema version key.
            // Treat as version 0, which is compatible with CURRENT_SCHEMA_VERSION (1).
            eprintln!(
                "[T104] No schema version found in storage - treating as legacy v0 (compatible)"
            );
            Ok(())
        }
        Some(v) if v <= CURRENT_SCHEMA_VERSION => {
            // Stored version is compatible (same or older).
            eprintln!(
                "[T104] Schema version {} is compatible with current version {}",
                v, CURRENT_SCHEMA_VERSION
            );
            Ok(())
        }
        Some(v) => {
            // Stored version is newer than what this binary supports.
            eprintln!(
                "[T104] ERROR: Incompatible schema version {} (this binary supports up to {})",
                v, CURRENT_SCHEMA_VERSION
            );
            Err(StorageError::IncompatibleSchema {
                stored_version: v,
                current_version: CURRENT_SCHEMA_VERSION,
            })
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_wire::consensus::BlockHeader;

    fn make_test_proposal(height: u64, suite_id: u16) -> BlockProposal {
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height,
                round: height,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id,
                tx_count: 0,
                timestamp: 1234567890,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![1, 2, 3, 4],
        }
    }

    fn make_test_qc(height: u64, suite_id: u16) -> QuorumCertificate {
        QuorumCertificate {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            step: 0,
            block_id: [42u8; 32],
            suite_id,
            signer_bitmap: vec![0b00000111],
            signatures: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
        }
    }

    #[test]
    fn in_memory_storage_put_get_block_roundtrip() {
        let storage = InMemoryConsensusStorage::new();
        let block_id = [1u8; 32];
        let block = make_test_proposal(10, 42);

        storage.put_block(&block_id, &block).unwrap();
        let retrieved = storage.get_block(&block_id).unwrap();

        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.header.height, 10);
        assert_eq!(retrieved.header.suite_id, 42);
    }

    #[test]
    fn in_memory_storage_put_get_qc_roundtrip() {
        let storage = InMemoryConsensusStorage::new();
        let block_id = [2u8; 32];
        let qc = make_test_qc(20, 123);

        storage.put_qc(&block_id, &qc).unwrap();
        let retrieved = storage.get_qc(&block_id).unwrap();

        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.height, 20);
        assert_eq!(retrieved.suite_id, 123);
    }

    #[test]
    fn in_memory_storage_last_committed_roundtrip() {
        let storage = InMemoryConsensusStorage::new();

        // Initially None
        assert!(storage.get_last_committed().unwrap().is_none());

        let block_id = [3u8; 32];
        storage.put_last_committed(&block_id).unwrap();

        let retrieved = storage.get_last_committed().unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), block_id);
    }

    #[test]
    fn in_memory_storage_get_nonexistent_returns_none() {
        let storage = InMemoryConsensusStorage::new();
        let block_id = [99u8; 32];

        assert!(storage.get_block(&block_id).unwrap().is_none());
        assert!(storage.get_qc(&block_id).unwrap().is_none());
    }

    #[test]
    fn in_memory_storage_current_epoch_roundtrip() {
        let storage = InMemoryConsensusStorage::new();

        // Initially None
        assert!(storage.get_current_epoch().unwrap().is_none());

        // Store epoch 0
        storage.put_current_epoch(0).unwrap();
        let retrieved = storage.get_current_epoch().unwrap();
        assert_eq!(retrieved, Some(0));

        // Update to epoch 1
        storage.put_current_epoch(1).unwrap();
        let retrieved = storage.get_current_epoch().unwrap();
        assert_eq!(retrieved, Some(1));

        // Update to a large epoch value
        storage.put_current_epoch(12345).unwrap();
        let retrieved = storage.get_current_epoch().unwrap();
        assert_eq!(retrieved, Some(12345));
    }
}