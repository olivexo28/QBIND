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
    /// Incomplete epoch transition detected on startup (M16).
    ///
    /// This error indicates that a crash occurred mid-epoch-transition, leaving
    /// the storage in an inconsistent state. The node must not continue with
    /// partially committed epoch boundary state.
    IncompleteEpochTransition {
        /// The epoch ID at which the incomplete transition was detected.
        epoch: u64,
        /// Additional context about what was inconsistent.
        details: String,
    },
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
            StorageError::IncompleteEpochTransition { epoch, details } => {
                write!(
                    f,
                    "FATAL: incomplete epoch transition detected at epoch {}: {}. \
                     The node must not continue with partially committed epoch boundary state. \
                     Manual investigation required.",
                    epoch, details
                )
            }
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

    /// **Run 422 D7-D8.** Store the current epoch under an explicit durability
    /// barrier (synced write).
    ///
    /// Unlike [`Self::put_current_epoch`], which persists the epoch through the
    /// storage's default (asynchronous, un-`fsync`'d) write path, this method
    /// MUST NOT return `Ok(())` until the epoch value has been synchronized to
    /// stable storage under the `crates/qbind-node/src/restore_completion.rs`
    /// durability profile. The restore-completion boundary requires this synced
    /// effect to complete BEFORE it publishes a durable `COMPLETE`
    /// restore-transaction record — a value written by the default
    /// `put_current_epoch` cannot be claimed power-loss durable.
    ///
    /// There is deliberately **no** default implementation: a default that
    /// forwarded to the asynchronous `put_current_epoch` would silently and
    /// falsely report durability for backends (e.g. RocksDB) whose default
    /// write does not `fsync`. Each backend states its true durability
    /// behavior — the RocksDB backend performs a real synced write, and the
    /// in-memory backend documents itself as a non-durable test/model.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the synced write fails.
    fn put_current_epoch_synced(&self, epoch: u64) -> Result<(), StorageError>;

    /// **Run 422 D7-D8.** Force any already-written epoch value to stable
    /// storage (an explicit durability barrier over the epoch surface).
    ///
    /// Used by the restore-completion boundary for the "already consistent"
    /// epoch outcome, where the snapshot epoch already matches the live
    /// committed epoch and no value change is performed: a successful *read*
    /// does not prove the value was ever `fsync`'d, so an explicit barrier is
    /// still required before a durable `COMPLETE` may be published.
    ///
    /// There is deliberately **no** default implementation (see
    /// [`Self::put_current_epoch_synced`]). The RocksDB backend flushes its
    /// write-ahead log; the in-memory backend is a non-durable test/model.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the flush fails.
    fn flush_epoch_durable(&self) -> Result<(), StorageError>;

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

    // ========================================================================
    // Atomic Epoch Transition Methods (M16)
    // ========================================================================

    /// Apply an epoch transition atomically (M16).
    ///
    /// This method commits all epoch-boundary writes in a single atomic batch:
    /// 1. The reconfig block (if provided in batch)
    /// 2. The reconfig block's QC (if provided in batch)
    /// 3. The last committed block ID (if update_last_committed is set)
    /// 4. The new epoch number
    ///
    /// # Crash Safety
    ///
    /// After any crash/restart, the node will load a self-consistent epoch state:
    /// either fully old epoch or fully new epoch, never a hybrid.
    ///
    /// # Arguments
    ///
    /// * `batch` - The epoch transition batch containing all writes.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the write batch fails to commit.
    fn apply_epoch_transition_atomic(
        &self,
        batch: EpochTransitionBatch,
    ) -> Result<(), StorageError>;

    /// Write an epoch transition marker before starting the transition (M16).
    ///
    /// This marker indicates that an epoch transition is in progress. If present
    /// on startup, the transition was incomplete (crash mid-transition).
    ///
    /// # Arguments
    ///
    /// * `marker` - The epoch transition marker to write.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the write fails.
    fn write_epoch_transition_marker(
        &self,
        marker: &EpochTransitionMarker,
    ) -> Result<(), StorageError>;

    /// Check for incomplete epoch transition on startup (M16).
    ///
    /// Returns `Ok(None)` if no incomplete transition is detected.
    /// Returns `Ok(Some(marker))` if an incomplete transition is detected.
    fn check_for_incomplete_epoch_transition(
        &self,
    ) -> Result<Option<EpochTransitionMarker>, StorageError>;

    /// Verify epoch consistency on startup (M16).
    ///
    /// Checks that the stored epoch state is consistent. If any inconsistency
    /// is detected, returns `StorageError::IncompleteEpochTransition`.
    fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError>;
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

/// Key for epoch transition marker (M16).
///
/// This marker is used to detect incomplete epoch transitions on startup.
/// The marker is written atomically with the epoch transition batch and cleared
/// on successful completion. If present on startup, the transition was incomplete.
///
/// Format: `meta:epoch_transition_marker` → `EpochTransitionMarker` (JSON)
const EPOCH_TRANSITION_MARKER_KEY: &[u8] = b"meta:epoch_transition_marker";

/// Run 422 D7-D10 — key prefix for signing-decision journal records. This is a
/// distinct namespace from the block (`b:`) / QC (`q:`) / epoch (`meta:`) keys;
/// their layout and semantics are unchanged. The full key is
/// `sig:` + the journal's position-key bytes.
const SIGNING_RECORD_STORAGE_PREFIX: &[u8] = b"sig:";

/// Run 422 D7-D10 Correction E — full storage key for the signing journal's
/// bounded, versioned **initialization metadata**. It lives inside the signing
/// namespace (`sig:` prefix) but is deliberately NOT a decision-record key: it
/// does not begin with the record key prefix `sig:sj:v1:`, so it is never
/// yielded by the record iterator, and `meta:` sorts before `sj:` so it lies
/// outside the record iteration range. This introduces no new global schema
/// namespace and cannot alias any decision key.
const SIGNING_METADATA_STORAGE_KEY: &[u8] = b"sig:meta:v1";

// ============================================================================
// Epoch Transition Batch (M16)
// ============================================================================

/// Marker indicating epoch transition state (M16).
///
/// This marker is written at the START of an epoch transition batch and cleared
/// at the END of the batch. If present on startup, the node crashed mid-transition.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochTransitionMarker {
    /// The epoch being transitioned TO.
    pub target_epoch: u64,
    /// The previous epoch being transitioned FROM.
    pub previous_epoch: u64,
    /// Timestamp when the transition started (Unix millis).
    pub started_at_ms: u64,
    /// The reconfig block ID that triggered this transition.
    pub reconfig_block_id: [u8; 32],
}

/// Batch of operations for an atomic epoch transition (M16).
///
/// This struct collects all the writes that must happen atomically at an epoch
/// boundary. The writes are committed together in a single RocksDB WriteBatch
/// to ensure that either all succeed or none succeed.
///
/// # Atomic Writes
///
/// At epoch boundary, the following MUST be written atomically:
/// 1. The reconfig block that triggered the transition
/// 2. The reconfig block's QC (if present)
/// 3. The last committed block ID (updated to the reconfig block)
/// 4. The new epoch number
/// 5. The epoch transition marker (cleared on success)
///
/// If a crash occurs mid-transition:
/// - Marker present on startup → incomplete transition → fail-closed
/// - No marker → either fully old or fully new epoch → consistent state
///
/// # Example
///
/// ```rust,ignore
/// let mut batch = EpochTransitionBatch::new(target_epoch, previous_epoch, block_id);
/// batch.set_block(block_id, block);
/// batch.set_qc(block_id, qc);
/// batch.set_last_committed(block_id);
///
/// storage.apply_epoch_transition_atomic(batch)?;
/// ```
#[derive(Debug)]
pub struct EpochTransitionBatch {
    /// The epoch being transitioned TO.
    pub target_epoch: u64,
    /// The epoch being transitioned FROM.
    pub previous_epoch: u64,
    /// The reconfig block ID that triggered this transition.
    pub reconfig_block_id: [u8; 32],
    /// The reconfig block to persist.
    pub block: Option<(BlockProposal, [u8; 32])>,
    /// The QC for the reconfig block (if present).
    pub qc: Option<(QuorumCertificate, [u8; 32])>,
    /// Whether to update last_committed to the reconfig block.
    pub update_last_committed: bool,
}

impl EpochTransitionBatch {
    /// Create a new epoch transition batch.
    ///
    /// # Arguments
    ///
    /// * `target_epoch` - The epoch being transitioned TO.
    /// * `previous_epoch` - The epoch being transitioned FROM.
    /// * `reconfig_block_id` - The block ID that triggered this transition.
    pub fn new(target_epoch: u64, previous_epoch: u64, reconfig_block_id: [u8; 32]) -> Self {
        Self {
            target_epoch,
            previous_epoch,
            reconfig_block_id,
            block: None,
            qc: None,
            update_last_committed: false,
        }
    }

    /// Set the reconfig block to persist.
    pub fn set_block(&mut self, block_id: [u8; 32], block: BlockProposal) {
        self.block = Some((block, block_id));
    }

    /// Set the QC for the reconfig block.
    pub fn set_qc(&mut self, block_id: [u8; 32], qc: QuorumCertificate) {
        self.qc = Some((qc, block_id));
    }

    /// Set whether to update last_committed to the reconfig block.
    pub fn set_update_last_committed(&mut self, update: bool) {
        self.update_last_committed = update;
    }
}

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

/// Run 422 D7-D10 — expose the existing CRC-32 (IEEE 802.3) facility to the
/// signing-reservation journal so its record integrity check reuses the same
/// corruption detector as the block/QC/epoch records rather than introducing a
/// parallel checksum. This is a corruption detector only — not authentication
/// and not rollback protection.
pub(crate) fn signing_journal_crc32(data: &[u8]) -> u32 {
    compute_crc32(data)
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
    /// Run 422 D7-D10 Correction B — the single signing-journal ownership domain
    /// for THIS backend instance, created lazily and shared by every attached
    /// handle so the reservation/publication serialization boundary is enforced,
    /// not advisory.
    signing_domain: std::sync::OnceLock<Arc<crate::signing_reservation_journal::SigningOwnershipDomain>>,
    /// Test-only: When true, forces apply_epoch_transition_atomic() to simulate
    /// a WriteBatch commit failure (M16 atomicity testing).
    #[cfg(any(test, feature = "test-utils"))]
    inject_write_failure: bool,
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

        Ok(RocksDbConsensusStorage {
            db,
            metrics: None,
            signing_domain: std::sync::OnceLock::new(),
            #[cfg(any(test, feature = "test-utils"))]
            inject_write_failure: false,
        })
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

    fn put_current_epoch_synced(&self, epoch: u64) -> Result<(), StorageError> {
        use crate::metrics::StorageOp;
        use std::time::Instant;

        let start = Instant::now();
        // Store epoch as big-endian u64 (8 bytes), wrapped in the same
        // checksum envelope as `put_current_epoch`, but under a SYNCED write
        // (`WriteOptions::set_sync(true)`) so the value is `fsync`'d to stable
        // storage before this call returns. Run 422 D7-D8: the
        // restore-completion boundary requires this before publishing a
        // durable `COMPLETE`.
        let epoch_bytes = epoch.to_be_bytes();
        let value = wrap_checksummed(&epoch_bytes);
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        let result = self
            .db
            .put_opt(CURRENT_EPOCH_KEY, &value, &write_opts)
            .map_err(|e| StorageError::Io(e.to_string()));

        if let Some(ref metrics) = self.metrics {
            metrics
                .storage()
                .record(StorageOp::PutCurrentEpoch, start.elapsed());
        }

        result
    }

    fn flush_epoch_durable(&self) -> Result<(), StorageError> {
        // Run 422 D7-D8: an explicit durability barrier over the epoch
        // surface. Flushing the write-ahead log with `sync=true` forces any
        // previously written (possibly un-`fsync`'d) `meta:current_epoch`
        // value to stable storage. Used for the "already consistent" epoch
        // outcome, where no value change is performed but a durability barrier
        // is still required before a durable `COMPLETE` may be published.
        self.db
            .flush_wal(true)
            .map_err(|e| StorageError::Io(e.to_string()))
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

    fn apply_epoch_transition_atomic(
        &self,
        batch: EpochTransitionBatch,
    ) -> Result<(), StorageError> {
        use std::time::Instant;
        let start = Instant::now();

        // Create RocksDB WriteBatch for atomic commit
        let mut write_batch = rocksdb::WriteBatch::default();

        // 1. Add block to batch (if provided)
        if let Some((block, block_id)) = &batch.block {
            let key = Self::block_key(block_id);
            let mut payload = Vec::new();
            block.encode(&mut payload);
            let value = wrap_checksummed(&payload);
            write_batch.put(&key, &value);
        }

        // 2. Add QC to batch (if provided)
        if let Some((qc, block_id)) = &batch.qc {
            let key = Self::qc_key(block_id);
            let mut payload = Vec::new();
            qc.encode(&mut payload);
            let value = wrap_checksummed(&payload);
            write_batch.put(&key, &value);
        }

        // 3. Add last_committed update to batch (if requested)
        if batch.update_last_committed {
            let value = wrap_checksummed(&batch.reconfig_block_id);
            write_batch.put(LAST_COMMITTED_KEY, &value);
        }

        // 4. Add new epoch to batch
        let epoch_bytes = batch.target_epoch.to_be_bytes();
        let epoch_value = wrap_checksummed(&epoch_bytes);
        write_batch.put(CURRENT_EPOCH_KEY, &epoch_value);

        // 5. Delete the epoch transition marker (if it exists) as part of the atomic batch
        //    This ensures the marker is cleared atomically with the transition
        write_batch.delete(EPOCH_TRANSITION_MARKER_KEY);

        // Test-only: Inject write failure if enabled (M16 atomicity testing)
        #[cfg(any(test, feature = "test-utils"))]
        if self.inject_write_failure {
            return Err(StorageError::Io(
                "injected write failure for atomicity test (M16)".to_string(),
            ));
        }

        // Commit the entire batch atomically
        self.db
            .write(write_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;

        // Log the atomic transition for debugging
        eprintln!(
            "[M16] Atomic epoch transition: {} -> {} (block_id={:?}, elapsed={:?})",
            batch.previous_epoch,
            batch.target_epoch,
            &batch.reconfig_block_id[..8],
            start.elapsed()
        );

        Ok(())
    }

    fn write_epoch_transition_marker(
        &self,
        marker: &EpochTransitionMarker,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_vec(marker).map_err(|e| {
            StorageError::Codec(format!("failed to serialize epoch transition marker: {}", e))
        })?;
        let value = wrap_checksummed(&json);
        self.db
            .put(EPOCH_TRANSITION_MARKER_KEY, &value)
            .map_err(|e| StorageError::Io(e.to_string()))?;

        eprintln!(
            "[M16] Wrote epoch transition marker: {} -> {} (block_id={:?})",
            marker.previous_epoch,
            marker.target_epoch,
            &marker.reconfig_block_id[..8]
        );

        Ok(())
    }

    fn check_for_incomplete_epoch_transition(
        &self,
    ) -> Result<Option<EpochTransitionMarker>, StorageError> {
        match self.db.get(EPOCH_TRANSITION_MARKER_KEY) {
            Ok(Some(value)) => {
                // Unwrap checksummed envelope
                let payload = unwrap_checksummed_or_legacy(&value, "epoch_transition_marker")?;
                let marker: EpochTransitionMarker = serde_json::from_slice(&payload).map_err(
                    |e| {
                        StorageError::Corruption(format!(
                            "failed to deserialize epoch transition marker: {}",
                            e
                        ))
                    },
                )?;

                eprintln!(
                    "[M16] WARNING: Found incomplete epoch transition marker: {} -> {} (block_id={:?})",
                    marker.previous_epoch,
                    marker.target_epoch,
                    &marker.reconfig_block_id[..8]
                );

                Ok(Some(marker))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError> {
        // Check for incomplete epoch transition marker
        if let Some(marker) = self.check_for_incomplete_epoch_transition()? {
            return Err(StorageError::IncompleteEpochTransition {
                epoch: marker.target_epoch,
                details: format!(
                    "epoch transition marker found on startup (previous={}, target={}, block_id={:?}). \
                     This indicates a crash occurred during epoch transition. \
                     The node cannot safely continue.",
                    marker.previous_epoch,
                    marker.target_epoch,
                    &marker.reconfig_block_id[..8]
                ),
            });
        }

        // Get current epoch (if present)
        let current_epoch = self.get_current_epoch()?;

        eprintln!(
            "[M16] Epoch consistency check passed: current_epoch={:?}",
            current_epoch
        );

        Ok(())
    }
}

// ============================================================================
// Atomic Epoch Transition Test-Only Methods (M16)
// ============================================================================

impl RocksDbConsensusStorage {
    /// Test-only: Enable or disable write failure injection for atomicity testing (M16).
    ///
    /// When enabled, `apply_epoch_transition_atomic()` will fail before committing
    /// the RocksDB WriteBatch, allowing tests to verify that no partial state
    /// is left behind on failures.
    ///
    /// # Warning
    ///
    /// This method is for testing purposes only and should not be used in production.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_inject_write_failure(&mut self, inject: bool) {
        self.inject_write_failure = inject;
    }

    /// Test-only: Clear the epoch transition marker directly (M16).
    ///
    /// This is used by tests to simulate recovery from an incomplete transition.
    ///
    /// # Warning
    ///
    /// This method is for testing purposes only and should not be used in production.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn clear_epoch_transition_marker(&self) -> Result<(), StorageError> {
        self.db
            .delete(EPOCH_TRANSITION_MARKER_KEY)
            .map_err(|e| StorageError::Io(e.to_string()))
    }
}

impl RocksDbConsensusStorage {
    /// Build the full storage key for a signing-decision journal record from the
    /// journal's position-key bytes (Run 422 D7-D10).
    fn signing_record_key(position_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(SIGNING_RECORD_STORAGE_PREFIX.len() + position_key.len());
        key.extend_from_slice(SIGNING_RECORD_STORAGE_PREFIX);
        key.extend_from_slice(position_key);
        key
    }

    /// Test-only seam (Run 422 D7-D10 Correction E): write ARBITRARY RAW bytes at
    /// a signing-namespace key, bypassing the checksum envelope. This exists only
    /// so direct-read bound tests can observe the size/truncation boundary of
    /// `get_signing_record`/`get_signing_metadata` against the real backend (for
    /// example a sub-envelope-length value, or an oversized stored value). It is
    /// NOT a production path and performs no validation.
    ///
    /// Passing `None` targets the exact backend-owned metadata key; `Some(key)`
    /// targets the record key derived from the journal position-key bytes.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn put_signing_namespace_raw_for_test(
        &self,
        position_key: Option<&[u8]>,
        raw_bytes: &[u8],
    ) -> Result<(), StorageError> {
        let full = match position_key {
            Some(k) => Self::signing_record_key(k),
            None => SIGNING_METADATA_STORAGE_KEY.to_vec(),
        };
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(&full, raw_bytes, &write_opts)
            .map_err(|e| StorageError::Io(e.to_string()))
    }
}

/// Run 422 D7-D10 — durable, synced backing store for the signing-reservation
/// journal. Writes go through `WriteOptions::set_sync(true)` (`fsync`) exactly
/// like `put_current_epoch_synced`, and the durable acknowledgement corresponds
/// to the signing-record write itself (not an unrelated epoch operation). This
/// implements a durability MECHANISM under the stated storage assumptions
/// (`fsync` semantics of the underlying filesystem/device); the executed tests
/// do NOT establish empirical power-loss behavior, so it is not claimed as
/// demonstrated power-loss durability. Records are wrapped in the same CRC-32
/// checksum envelope used for blocks/QCs/epoch values (corruption detection
/// only — not authentication, not rollback protection).
///
/// Run 422 — build the fixed backend-prefixed signing key `sig:<journal_key>`
/// into a stack `[u8; BACKEND_KEY_LEN]` WITHOUT the allocating legacy
/// `signing_record_key` builder. The journal-key length is validated BEFORE any
/// copy; a key of unexpected length is refused with a bounded error rather than
/// panicking or truncating.
fn signing_backend_key_fixed(
    journal_key: &[u8],
) -> Result<
    [u8; crate::signing_journal_admission::BACKEND_KEY_LEN],
    crate::signing_reservation_journal::BoundedStorageError,
> {
    use crate::signing_journal_admission::{BACKEND_KEY_LEN, JOURNAL_KEY_LEN};
    if journal_key.len() != JOURNAL_KEY_LEN {
        return Err(
            crate::signing_reservation_journal::BoundedStorageError::CapacityExceeded {
                stored_len: journal_key.len(),
                capacity: JOURNAL_KEY_LEN,
            },
        );
    }
    let mut k = [0u8; BACKEND_KEY_LEN];
    let plen = SIGNING_RECORD_STORAGE_PREFIX.len();
    k[..plen].copy_from_slice(SIGNING_RECORD_STORAGE_PREFIX);
    k[plen..].copy_from_slice(journal_key);
    Ok(k)
}

/// Run 422 §7.2 — maximum outer-framed signing-record envelope accepted by the
/// combined atomic write: the FORMAT record limit (`MAX_RECORD_LEN`) plus the
/// 4-byte outer CRC. This is the broad journal FORMAT limit and is deliberately
/// NOT narrowed to any particular read workspace (e.g. the retained-retrieval
/// 2,520-byte buffer). A valid stored record larger than a given read workspace
/// remains a bounded capacity refusal at read time; it is NOT relabeled
/// malformed, nor is the stored format limit changed here.
pub(crate) const MAX_RECORD_ENVELOPE_LEN: usize =
    crate::signing_journal_admission::OUTER_CRC_LEN
        + crate::signing_reservation_journal::MAX_RECORD_LEN;

/// Run 422 §7.2 — maximum outer-framed metadata envelope: the fixed
/// `METADATA_ENCODED_LEN` plus the 4-byte outer CRC (= 30 bytes). The metadata
/// encoding is fixed-length, so this is also the exact expected size.
pub(crate) const MAX_META_ENVELOPE_LEN: usize =
    crate::signing_journal_admission::OUTER_CRC_LEN
        + crate::signing_reservation_journal::METADATA_ENCODED_LEN;

/// Run 422 §7.2 — structural length preflight for the already-outer-framed
/// envelope pair accepted by `put_signing_envelope_and_metadata_synced`, applied
/// BEFORE any repository-owned staging allocation or batch construction.
///
/// This checks ONLY the fixed framing bounds the storage primitive owns; it does
/// NOT decode, verify the inner record/metadata payloads, or perform any
/// semantic journal validation (position, suite, accounting, continuation) —
/// those remain the journal caller's responsibility. A record envelope shorter
/// than `MIN_ENVELOPE_LEN` or a metadata envelope shorter than the bare outer
/// CRC is malformed framing (`Corruption(EnvelopeInvalid)`); an envelope longer
/// than its FORMAT limit is refused with `CapacityExceeded` before any write.
pub(crate) fn preflight_framed_envelope_pair(
    record_envelope: &[u8],
    metadata_envelope: &[u8],
) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
    use crate::signing_journal_admission::{MIN_ENVELOPE_LEN, OUTER_CRC_LEN};
    use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
    if record_envelope.len() < MIN_ENVELOPE_LEN {
        return Err(BoundedStorageError::Corruption(BoundedDiag::EnvelopeInvalid));
    }
    if record_envelope.len() > MAX_RECORD_ENVELOPE_LEN {
        return Err(BoundedStorageError::CapacityExceeded {
            stored_len: record_envelope.len(),
            capacity: MAX_RECORD_ENVELOPE_LEN,
        });
    }
    if metadata_envelope.len() < OUTER_CRC_LEN {
        return Err(BoundedStorageError::Corruption(BoundedDiag::EnvelopeInvalid));
    }
    if metadata_envelope.len() > MAX_META_ENVELOPE_LEN {
        return Err(BoundedStorageError::CapacityExceeded {
            stored_len: metadata_envelope.len(),
            capacity: MAX_META_ENVELOPE_LEN,
        });
    }
    Ok(())
}

/// Run 422 — structural length preflight for the single already-outer-framed
/// RECORD envelope accepted by `put_signing_record_envelope_synced`, applied
/// BEFORE any key build, repository-owned staging allocation, or storage write.
///
/// This checks ONLY the fixed record framing bounds the storage primitive owns;
/// it does NOT decode the inner record, verify a signature, or perform any
/// semantic journal validation (position, suite, accounting, continuation,
/// invoked/acknowledged state) — those remain the journal caller's
/// responsibility. A record envelope shorter than `MIN_ENVELOPE_LEN` is
/// malformed framing (`Corruption(EnvelopeInvalid)`); one longer than the broad
/// FORMAT limit `4 + MAX_RECORD_LEN` (NOT any narrower read workspace) is refused
/// with `CapacityExceeded`. Storage framing admission stays distinct from
/// journal semantic validation.
pub(crate) fn preflight_framed_record_envelope(
    record_envelope: &[u8],
) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
    use crate::signing_journal_admission::MIN_ENVELOPE_LEN;
    use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
    if record_envelope.len() < MIN_ENVELOPE_LEN {
        return Err(BoundedStorageError::Corruption(BoundedDiag::EnvelopeInvalid));
    }
    if record_envelope.len() > MAX_RECORD_ENVELOPE_LEN {
        return Err(BoundedStorageError::CapacityExceeded {
            stored_len: record_envelope.len(),
            capacity: MAX_RECORD_ENVELOPE_LEN,
        });
    }
    Ok(())
}

impl crate::signing_reservation_journal::SigningJournalStorage for RocksDbConsensusStorage {
    fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // Bounded direct read: a decision record is at most `MAX_RECORD_LEN`;
        // with the 4-byte CRC envelope the stored value is at most
        // `4 + MAX_RECORD_LEN`. Apply that length bound to the RAW backend-owned
        // bytes BEFORE copying the payload or unwrapping the envelope. The
        // RocksDB `get` itself still allocates the backend-owned value; this
        // bound only limits subsequent application-owned copying/decoding (it
        // does NOT make the underlying RocksDB API allocation-free).
        const MAX_STORED_ENVELOPE_LEN: usize =
            4 + crate::signing_reservation_journal::MAX_RECORD_LEN;
        let full = Self::signing_record_key(key);
        match self.db.get(&full) {
            // Genuine absence stays `None`.
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                if raw.len() > MAX_STORED_ENVELOPE_LEN {
                    return Err(StorageError::Corruption(format!(
                        "signing_record: stored value exceeds bound (len={} max={})",
                        raw.len(),
                        MAX_STORED_ENVELOPE_LEN
                    )));
                }
                let payload = unwrap_checksummed(&raw, "signing_record")?;
                Ok(Some(payload))
            }
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let full = Self::signing_record_key(key);
        let wrapped = wrap_checksummed(value);
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(&full, &wrapped, &write_opts)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
        // Bounded direct read: the initialization metadata is a FIXED-length
        // encoding (`METADATA_ENCODED_LEN`); with the 4-byte CRC envelope the
        // stored value is at most `4 + METADATA_ENCODED_LEN`. Apply that bound to
        // the RAW backend-owned bytes BEFORE copying/unwrapping. Version and
        // semantic validation remain in the metadata decoder.
        const MAX_STORED_METADATA_LEN: usize =
            4 + crate::signing_reservation_journal::METADATA_ENCODED_LEN;
        match self.db.get(SIGNING_METADATA_STORAGE_KEY) {
            // Genuine absence stays `None`.
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                if raw.len() > MAX_STORED_METADATA_LEN {
                    return Err(StorageError::Corruption(format!(
                        "signing_metadata: stored value exceeds bound (len={} max={})",
                        raw.len(),
                        MAX_STORED_METADATA_LEN
                    )));
                }
                let payload = unwrap_checksummed(&raw, "signing_metadata")?;
                Ok(Some(payload))
            }
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
        let wrapped = wrap_checksummed(value);
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(SIGNING_METADATA_STORAGE_KEY, &wrapped, &write_opts)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn put_signing_record_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_value: &[u8],
        metadata_value: &[u8],
    ) -> Result<(), StorageError> {
        // A single RocksDB WriteBatch committed with sync=true makes the record
        // and the advanced accounting metadata durable together, atomically.
        let full = Self::signing_record_key(record_key);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&full, &wrap_checksummed(record_value));
        batch.put(SIGNING_METADATA_STORAGE_KEY, &wrap_checksummed(metadata_value));
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn for_each_signing_namespace_entry(
        &self,
        visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        // Bounded streaming over the ENTIRE signing namespace (`sig:`), EXCLUDING
        // only the exact backend-owned metadata key `sig:meta:v1`. Iterate forward
        // from the `sig:` prefix and stop at the first key outside it. Unexpected /
        // foreign keys within the namespace ARE yielded so the caller can classify
        // and refuse. Unrelated block/QC/epoch namespaces are never visited.
        //
        // The maximum decision record is `MAX_RECORD_LEN`; with the 4-byte CRC
        // envelope the stored value is at most `4 + MAX_RECORD_LEN`. That value
        // length bound is applied to the RAW stored bytes BEFORE the envelope is
        // unwrapped (which copies the payload).
        const MAX_STORED_ENVELOPE_LEN: usize =
            4 + crate::signing_reservation_journal::MAX_RECORD_LEN;
        let prefix = SIGNING_RECORD_STORAGE_PREFIX;
        let iter = self
            .db
            .iterator(rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward));
        for item in iter {
            let (raw_key, raw_val) = item.map_err(|e| StorageError::Io(e.to_string()))?;
            if !raw_key.starts_with(prefix) {
                break; // left the signing namespace
            }
            // The exact metadata key is classified separately (get_signing_metadata).
            if raw_key.as_ref() == SIGNING_METADATA_STORAGE_KEY {
                continue;
            }
            // Length check BEFORE copying/unwrapping the payload.
            if raw_val.len() > MAX_STORED_ENVELOPE_LEN {
                return Err(StorageError::Corruption(format!(
                    "signing-namespace value exceeds bound (len={} max={})",
                    raw_val.len(),
                    MAX_STORED_ENVELOPE_LEN
                )));
            }
            // Strip the backend storage prefix so the visitor sees the
            // journal-level key (same space as `get_signing_record`).
            let journal_key = &raw_key[SIGNING_RECORD_STORAGE_PREFIX.len()..];
            let payload = unwrap_checksummed(&raw_val, "signing_namespace_entry")?;
            visitor(journal_key, &payload)?;
        }
        Ok(())
    }

    fn read_signing_envelope_into(
        &self,
        journal_key: &[u8],
        dst: &mut [u8],
    ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Build the fixed backend-prefixed key on the stack (no allocating legacy
        // key builder). Length is validated before any copy.
        let bkey = signing_backend_key_fixed(journal_key)?;
        // Pinned read: borrow the backend-internal value without an application
        // copy, apply the length bound, then copy ONE complete envelope into the
        // admitted workspace. The pinned slice is a RocksDB-internal buffer; this
        // method makes no application-owned heap allocation. (RocksDB's own
        // library-internal buffering is explicitly OUTSIDE this component's
        // accounting claim; a pinned API is not by itself a zero-allocation
        // guarantee for the backend library.)
        match self.db.get_pinned(&bkey[..]) {
            Ok(None) => Ok(None),
            Ok(Some(pinned)) => {
                let raw = pinned.as_ref();
                // Length check BEFORE copying into `dst`. A stored value larger
                // than the admitted workspace is a bounded refusal, never grown
                // and never silently truncated.
                if raw.len() > dst.len() {
                    return Err(BoundedStorageError::CapacityExceeded {
                        stored_len: raw.len(),
                        capacity: dst.len(),
                    });
                }
                dst[..raw.len()].copy_from_slice(raw);
                Ok(Some(raw.len()))
            }
            Err(_) => Err(BoundedStorageError::Io(BoundedDiag::ReadIo)),
        }
    }

    fn reissue_signing_envelope_synced(
        &self,
        journal_key: &[u8],
        envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Reissue the EXACT already-validated envelope bytes (outer CRC + record)
        // under the required synced barrier. The stored format is identical to the
        // legacy `wrap_checksummed` layout, so no re-wrap, re-encode, or second
        // application envelope is produced.
        let bkey = signing_backend_key_fixed(journal_key)?;
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .put_opt(&bkey[..], envelope, &write_opts)
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::WriteIo))
    }

    fn put_signing_envelope_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_envelope: &[u8],
        metadata_envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Preflight the fixed framing bounds BEFORE building the stack key or the
        // batch, so an oversized/under-min input is refused without any
        // repository-owned staging work.
        preflight_framed_envelope_pair(record_envelope, metadata_envelope)?;
        // Build the fixed backend-prefixed key on the stack (no allocating legacy
        // key builder); the journal-key length is validated here too.
        let bkey = signing_backend_key_fixed(record_key)?;
        // A single RocksDB WriteBatch committed with sync=true makes the already-
        // outer-framed record envelope and metadata envelope durable TOGETHER,
        // atomically. The borrowed envelopes are written VERBATIM — no
        // `wrap_checksummed` staging Vec and no dynamically assembled backend-key
        // Vec on this route. RocksDB copies the bytes into its own internal batch
        // buffer; that library-internal copying is OUTSIDE this component's
        // allocation accounting and is not an application-owned heap allocation.
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(&bkey[..], record_envelope);
        batch.put(SIGNING_METADATA_STORAGE_KEY, metadata_envelope);
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        // Acknowledged success means both values were written under the synced
        // contract. An error does NOT prove neither was written; the atomic batch
        // only guarantees the two keys are never left as a partially updated pair.
        self.db
            .write_opt(batch, &write_opts)
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::WriteIo))
    }

    fn put_signing_record_envelope_synced(
        &self,
        record_key: &[u8],
        record_envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Preflight the fixed RECORD framing bounds BEFORE building the stack key,
        // so an oversized/under-min input is refused without any key copy or write.
        preflight_framed_record_envelope(record_envelope)?;
        // Build the fixed backend-prefixed key on the stack (no allocating legacy
        // key builder); the journal-key length is validated here too.
        let bkey = signing_backend_key_fixed(record_key)?;
        // One record-key put committed with sync=true stores the already-outer-
        // framed record envelope VERBATIM. The borrowed envelope is written as-is —
        // no `wrap_checksummed` staging Vec, no dynamically assembled backend-key
        // Vec, and no allocating legacy fallback on this route. RocksDB copies the
        // borrowed bytes into its own internal buffer; that library-internal copy is
        // OUTSIDE this component's application-owned allocation accounting. The
        // metadata key is left untouched (reserved-position accounting unchanged).
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        // Acknowledged success means the record was written under the synced
        // contract; an error does NOT prove nothing was written.
        self.db
            .put_opt(&bkey[..], record_envelope, &write_opts)
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::WriteIo))
    }

    fn signing_ownership_domain(
        &self,
    ) -> Arc<crate::signing_reservation_journal::SigningOwnershipDomain> {
        // One domain per backend instance, shared by every attached handle.
        self.signing_domain
            .get_or_init(crate::signing_reservation_journal::SigningOwnershipDomain::new)
            .clone()
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
    /// Epoch transition marker (M16).
    epoch_transition_marker: RwLock<Option<EpochTransitionMarker>>,
    /// Run 422 D7-D10 — signing-decision journal records (MODEL only; no
    /// durability). Present so the journal's read/write model can be exercised
    /// in unit tests; it must NOT be read as durability evidence.
    signing_records: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// Run 422 D7-D10 Correction B — per-instance signing-journal ownership
    /// domain (MODEL only, in-process). `OnceLock` is `Default`, so the derived
    /// `Default`/`new` still hold.
    signing_domain: std::sync::OnceLock<Arc<crate::signing_reservation_journal::SigningOwnershipDomain>>,
}

/// Run 422 D7-D10 Correction E — reserved key under which
/// `InMemoryConsensusStorage` stores the signing initialization metadata inside
/// the SAME map as the records, so the atomic record+metadata write is applied
/// under a single lock acquisition (an honest model of atomicity — NOT durable
/// or crash-atomic). It does not begin with the record key prefix `sj:v1:`, so
/// it is excluded from record iteration.
const INMEM_SIGNING_METADATA_KEY: &[u8] = b"__signing_metadata_v1__";

/// Run 422 D7-D10 — MODEL signing-journal backing store for
/// `InMemoryConsensusStorage`. It provides NO power-loss durability; the synced
/// write simply updates the in-memory map. It exists only for unit/model tests
/// and must never masquerade as a durable production backend.
impl crate::signing_reservation_journal::SigningJournalStorage for InMemoryConsensusStorage {
    fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // Bounded direct read: the MODEL stores the raw record (no envelope), so
        // the applicable bound is the bounded decision-record size
        // `MAX_RECORD_LEN`. Check the stored value's length BEFORE cloning it out
        // of the map (subsequent application-owned copy).
        const MAX_STORED_LEN: usize = crate::signing_reservation_journal::MAX_RECORD_LEN;
        let map = self
            .signing_records
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        match map.get(key) {
            None => Ok(None),
            Some(v) => {
                if v.len() > MAX_STORED_LEN {
                    return Err(StorageError::Corruption(format!(
                        "signing_record: stored value exceeds bound (len={} max={})",
                        v.len(),
                        MAX_STORED_LEN
                    )));
                }
                Ok(Some(v.clone()))
            }
        }
    }

    fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut map = self
            .signing_records
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
        // Bounded direct read: the MODEL stores the raw fixed-length metadata (no
        // envelope), so the applicable bound is `METADATA_ENCODED_LEN`. Check the
        // stored value's length BEFORE cloning.
        const MAX_STORED_METADATA_LEN: usize =
            crate::signing_reservation_journal::METADATA_ENCODED_LEN;
        let map = self
            .signing_records
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        match map.get(INMEM_SIGNING_METADATA_KEY) {
            None => Ok(None),
            Some(v) => {
                if v.len() > MAX_STORED_METADATA_LEN {
                    return Err(StorageError::Corruption(format!(
                        "signing_metadata: stored value exceeds bound (len={} max={})",
                        v.len(),
                        MAX_STORED_METADATA_LEN
                    )));
                }
                Ok(Some(v.clone()))
            }
        }
    }

    fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
        let mut map = self
            .signing_records
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        map.insert(INMEM_SIGNING_METADATA_KEY.to_vec(), value.to_vec());
        Ok(())
    }

    fn put_signing_record_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_value: &[u8],
        metadata_value: &[u8],
    ) -> Result<(), StorageError> {
        // Single lock acquisition covers BOTH inserts: an honest in-process model
        // of an atomic update (NOT durable, NOT crash-atomic).
        let mut map = self
            .signing_records
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        map.insert(record_key.to_vec(), record_value.to_vec());
        map.insert(INMEM_SIGNING_METADATA_KEY.to_vec(), metadata_value.to_vec());
        Ok(())
    }

    fn for_each_signing_namespace_entry(
        &self,
        visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let map = self
            .signing_records
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        // Whole-namespace streaming: visit EVERY entry except the backend-owned
        // metadata key. Stream directly over the map's entries; never collect the
        // namespace into a temporary vector. The stored value is the raw record
        // (no envelope), bounded by `MAX_RECORD_LEN`; that per-entry length bound is
        // applied before the caller decodes.
        const MAX_STORED_LEN: usize = crate::signing_reservation_journal::MAX_RECORD_LEN;
        for (k, v) in map.iter() {
            if k.as_slice() == INMEM_SIGNING_METADATA_KEY {
                continue;
            }
            if v.len() > MAX_STORED_LEN {
                return Err(StorageError::Corruption(format!(
                    "signing-namespace value exceeds bound (len={} max={})",
                    v.len(),
                    MAX_STORED_LEN
                )));
            }
            visitor(k, v)?;
        }
        Ok(())
    }

    fn read_signing_envelope_into(
        &self,
        journal_key: &[u8],
        dst: &mut [u8],
    ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // MODEL backend: records are stored record-ONLY (no outer envelope) and
        // keyed directly by the journal key. The model SYNTHESIZES the outer
        // storage checksum on read so the caller validates the same two checksum
        // layers it would for the durable backend. This is model behavior for
        // exercising the read/validate/reissue path, NOT crash durability.
        let map = self
            .signing_records
            .read()
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::LockRefused))?;
        match map.get(journal_key) {
            None => Ok(None),
            Some(record) => {
                let total = OUTER_CRC_LEN + record.len();
                // Length check BEFORE copying into the admitted workspace.
                if total > dst.len() {
                    return Err(BoundedStorageError::CapacityExceeded {
                        stored_len: total,
                        capacity: dst.len(),
                    });
                }
                let crc = signing_journal_crc32(record);
                dst[..OUTER_CRC_LEN].copy_from_slice(&crc.to_be_bytes());
                dst[OUTER_CRC_LEN..total].copy_from_slice(record);
                Ok(Some(total))
            }
        }
    }

    fn reissue_signing_envelope_synced(
        &self,
        journal_key: &[u8],
        envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // MODEL backend: STRIP the synthesized outer checksum on reissue so the
        // record-only storage format is preserved. The map insert is the model's
        // internal storage, not a bounded production allocation, and provides no
        // power-loss durability.
        if envelope.len() < OUTER_CRC_LEN {
            return Err(BoundedStorageError::Corruption(BoundedDiag::EnvelopeInvalid));
        }
        let record = &envelope[OUTER_CRC_LEN..];
        let mut map = self
            .signing_records
            .write()
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::LockRefused))?;
        map.insert(journal_key.to_vec(), record.to_vec());
        Ok(())
    }

    fn put_signing_envelope_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_envelope: &[u8],
        metadata_envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Same fixed-framing preflight as the durable backend, applied BEFORE any
        // model-owned copy or map mutation.
        preflight_framed_envelope_pair(record_envelope, metadata_envelope)?;
        // The durable backend validates the journal-key length while building its
        // fixed backend key; the model has no such key, so enforce the same length
        // invariant explicitly to keep the primitive's contract uniform.
        if record_key.len() != crate::signing_journal_admission::JOURNAL_KEY_LEN {
            return Err(BoundedStorageError::CapacityExceeded {
                stored_len: record_key.len(),
                capacity: crate::signing_journal_admission::JOURNAL_KEY_LEN,
            });
        }
        // MODEL backend: the model stores the record body record-ONLY (no outer
        // envelope) and the metadata body raw, SYNTHESIZING the outer checksum on
        // read, so STRIP the already-present outer CRC from each framed input to
        // preserve the record-only/raw-metadata storage format shared with the
        // other model readers. The two `.to_vec()` values are MODEL-OWNED heap
        // copies that represent the stored values; this model operation is NOT
        // allocation-free and provides NO power-loss durability.
        let record_body = &record_envelope[OUTER_CRC_LEN..];
        let metadata_body = &metadata_envelope[OUTER_CRC_LEN..];
        // Single lock acquisition covers BOTH inserts: an honest in-process model
        // of an atomic update (NOT durable, NOT crash-atomic). Either both inserts
        // land or, on a lock failure, neither does.
        let mut map = self
            .signing_records
            .write()
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::LockRefused))?;
        map.insert(record_key.to_vec(), record_body.to_vec());
        map.insert(INMEM_SIGNING_METADATA_KEY.to_vec(), metadata_body.to_vec());
        Ok(())
    }

    fn put_signing_record_envelope_synced(
        &self,
        record_key: &[u8],
        record_envelope: &[u8],
    ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
        // Same fixed RECORD framing preflight as the durable backend, applied
        // BEFORE any model-owned copy or map mutation.
        preflight_framed_record_envelope(record_envelope)?;
        // The durable backend validates the journal-key length while building its
        // fixed backend key; the model has no such key, so enforce the same length
        // invariant explicitly to keep the primitive's contract uniform.
        if record_key.len() != crate::signing_journal_admission::JOURNAL_KEY_LEN {
            return Err(BoundedStorageError::CapacityExceeded {
                stored_len: record_key.len(),
                capacity: crate::signing_journal_admission::JOURNAL_KEY_LEN,
            });
        }
        // MODEL backend: the model stores the record body record-ONLY (no outer
        // envelope), SYNTHESIZING the outer checksum on read, so STRIP the already-
        // present outer CRC to preserve the record-only storage format shared with
        // the other model readers. The key `.to_vec()` and the value `.to_vec()`
        // are MODEL-OWNED heap copies that persist for the life of the map entry;
        // this model operation is NOT allocation-free, is backend-owned (not
        // covered by any caller workspace reservation), and provides NO power-loss
        // durability. Only the record map is updated — metadata is left untouched.
        let record_body = &record_envelope[OUTER_CRC_LEN..];
        self.signing_records
            .write()
            .map_err(|_| BoundedStorageError::Io(BoundedDiag::LockRefused))?
            .insert(record_key.to_vec(), record_body.to_vec());
        Ok(())
    }

    fn signing_ownership_domain(
        &self,
    ) -> Arc<crate::signing_reservation_journal::SigningOwnershipDomain> {
        self.signing_domain
            .get_or_init(crate::signing_reservation_journal::SigningOwnershipDomain::new)
            .clone()
    }
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

    fn put_current_epoch_synced(&self, epoch: u64) -> Result<(), StorageError> {
        // Run 422 D7-D8: MODEL behavior only. An in-memory map has no stable
        // storage and provides NO power-loss durability; this simply updates
        // the in-memory value exactly like `put_current_epoch`. It exists so
        // the restore-completion boundary can be exercised in unit/model tests
        // and must NOT be read as durability evidence.
        self.put_current_epoch(epoch)
    }

    fn flush_epoch_durable(&self) -> Result<(), StorageError> {
        // Run 422 D7-D8: MODEL behavior only — nothing to flush for an
        // in-memory backend. Not durability evidence.
        Ok(())
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

    fn apply_epoch_transition_atomic(
        &self,
        batch: EpochTransitionBatch,
    ) -> Result<(), StorageError> {
        // In-memory implementation: apply all writes "atomically" (single-threaded)
        if let Some((block, block_id)) = batch.block {
            self.put_block(&block_id, &block)?;
        }
        if let Some((qc, block_id)) = batch.qc {
            self.put_qc(&block_id, &qc)?;
        }
        if batch.update_last_committed {
            self.put_last_committed(&batch.reconfig_block_id)?;
        }
        self.put_current_epoch(batch.target_epoch)?;

        // Clear the marker
        let mut marker = self
            .epoch_transition_marker
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        *marker = None;

        Ok(())
    }

    fn write_epoch_transition_marker(
        &self,
        marker: &EpochTransitionMarker,
    ) -> Result<(), StorageError> {
        let mut current = self
            .epoch_transition_marker
            .write()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        *current = Some(marker.clone());
        Ok(())
    }

    fn check_for_incomplete_epoch_transition(
        &self,
    ) -> Result<Option<EpochTransitionMarker>, StorageError> {
        let marker = self
            .epoch_transition_marker
            .read()
            .map_err(|e| StorageError::Other(format!("lock poisoned: {}", e)))?;
        Ok(marker.clone())
    }

    fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError> {
        if let Some(marker) = self.check_for_incomplete_epoch_transition()? {
            return Err(StorageError::IncompleteEpochTransition {
                epoch: marker.target_epoch,
                details: format!(
                    "epoch transition marker found on startup (previous={}, target={}, block_id={:?})",
                    marker.previous_epoch,
                    marker.target_epoch,
                    &marker.reconfig_block_id[..8]
                ),
            });
        }
        Ok(())
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

    // Run 422 D7-D10 Correction E (Section 3): direct-read size bounds on the
    // InMemory (MODEL) signing getters. Stored values are raw (no envelope), so
    // the record bound is `MAX_RECORD_LEN` and the metadata bound is
    // `METADATA_ENCODED_LEN`; both are checked BEFORE the value is cloned.
    #[test]
    fn inmemory_signing_record_direct_read_bounds() {
        use crate::signing_reservation_journal::{SigningJournalStorage, MAX_RECORD_LEN};
        let store = InMemoryConsensusStorage::new();
        let key = b"sj:v1:some-position";

        // Genuine absence stays None.
        assert!(store.get_signing_record(key).expect("read").is_none());

        // At-limit value round-trips.
        store
            .put_signing_record_synced(key, &vec![0u8; MAX_RECORD_LEN])
            .expect("store at-limit");
        assert_eq!(
            store
                .get_signing_record(key)
                .expect("read")
                .expect("present")
                .len(),
            MAX_RECORD_LEN
        );

        // Oversized value is refused BEFORE cloning.
        store
            .put_signing_record_synced(key, &vec![0u8; MAX_RECORD_LEN + 1])
            .expect("store oversized");
        assert!(matches!(
            store.get_signing_record(key),
            Err(StorageError::Corruption(_))
        ));
    }

    #[test]
    fn inmemory_signing_metadata_direct_read_bounds() {
        use crate::signing_reservation_journal::{SigningJournalStorage, METADATA_ENCODED_LEN};
        let store = InMemoryConsensusStorage::new();

        // Genuine absence stays None.
        assert!(store.get_signing_metadata().expect("read").is_none());

        // At-limit value round-trips.
        store
            .put_signing_metadata_synced(&vec![0u8; METADATA_ENCODED_LEN])
            .expect("store at-limit");
        assert_eq!(
            store
                .get_signing_metadata()
                .expect("read")
                .expect("present")
                .len(),
            METADATA_ENCODED_LEN
        );

        // Oversized value is refused BEFORE cloning.
        store
            .put_signing_metadata_synced(&vec![0u8; METADATA_ENCODED_LEN + 1])
            .expect("store oversized");
        assert!(matches!(
            store.get_signing_metadata(),
            Err(StorageError::Corruption(_))
        ));
    }

    // =======================================================================
    // Run 422 §7.2 — bounded atomic combined write
    // `put_signing_envelope_and_metadata_synced`. Inputs are ALREADY-outer-
    // framed byte slices; the primitive persists the record envelope and the
    // metadata envelope together under one atomic synced operation and
    // establishes a STORAGE acknowledgement only (no semantic journal
    // validation, continuation, accounting, signer, or delivery).
    // =======================================================================

    /// A 55-byte journal key (`JOURNAL_KEY_LEN`), the length accepted by the
    /// fixed backend-key builder. Content is irrelevant to the storage layer.
    fn framed_test_key() -> [u8; crate::signing_journal_admission::JOURNAL_KEY_LEN] {
        let mut k = [b'k'; crate::signing_journal_admission::JOURNAL_KEY_LEN];
        k[..6].copy_from_slice(b"sj:v1:");
        k
    }

    /// Build a MINIMAL but validly-framed `(record_envelope, metadata_envelope)`
    /// pair using the SAME outer checksum envelope the durable backend reads.
    /// The record body length is arbitrary within the format bounds; here it is
    /// the minimum reserved-record size so framing math is exercised exactly.
    fn framed_test_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        use crate::signing_journal_admission::MIN_ENVELOPE_LEN;
        use crate::signing_reservation_journal::METADATA_ENCODED_LEN;
        let record_body = vec![0xABu8; MIN_ENVELOPE_LEN - 4];
        let metadata_body = vec![0xCDu8; METADATA_ENCODED_LEN];
        let record_env = wrap_checksummed(&record_body);
        let metadata_env = wrap_checksummed(&metadata_body);
        (record_body, metadata_body, record_env, metadata_env)
    }

    /// Item 1: exact record + metadata read-back through the DURABLE backend,
    /// correct framing, and compatibility with the existing readers
    /// (`get_signing_record`, `get_signing_metadata`, `read_signing_envelope_into`).
    #[test]
    fn put_envelope_and_metadata_synced_rocksdb_roundtrip_reader_compat() {
        use crate::signing_reservation_journal::SigningJournalStorage;
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbConsensusStorage::open(dir.path()).unwrap();
        let key = framed_test_key();
        let (record_body, metadata_body, record_env, metadata_env) = framed_test_pair();

        store
            .put_signing_envelope_and_metadata_synced(&key, &record_env, &metadata_env)
            .expect("combined synced write");

        // Existing readers unwrap the outer envelope and return the bodies.
        assert_eq!(
            store.get_signing_record(&key).expect("read").expect("present"),
            record_body
        );
        assert_eq!(
            store.get_signing_metadata().expect("read").expect("present"),
            metadata_body
        );
        // The bounded pinned reader returns the EXACT stored envelope bytes.
        let mut dst = [0u8; 4096];
        let n = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &record_env[..]);
    }

    /// Item 6: RocksDB success then graceful reopen and read-back through the new
    /// method. (Graceful reopen of the same directory — NOT power-loss or
    /// process-death evidence.)
    #[test]
    fn put_envelope_and_metadata_synced_rocksdb_reopen_readback() {
        use crate::signing_reservation_journal::SigningJournalStorage;
        let dir = tempfile::tempdir().unwrap();
        let key = framed_test_key();
        let (record_body, metadata_body, record_env, metadata_env) = framed_test_pair();
        {
            let store = RocksDbConsensusStorage::open(dir.path()).unwrap();
            store
                .put_signing_envelope_and_metadata_synced(&key, &record_env, &metadata_env)
                .expect("combined synced write");
        }
        // Graceful reopen of the same on-disk directory.
        let reopened = RocksDbConsensusStorage::open(dir.path()).unwrap();
        assert_eq!(
            reopened.get_signing_record(&key).expect("read").expect("present"),
            record_body
        );
        assert_eq!(
            reopened.get_signing_metadata().expect("read").expect("present"),
            metadata_body
        );
    }

    /// Item 1 (model): the in-memory MODEL backend stores record-only/raw-metadata
    /// and synthesizes the outer checksum on read, so the same framed inputs round
    /// trip through every model reader. Labelled as a MODEL (no durability).
    #[test]
    fn put_envelope_and_metadata_synced_inmemory_model_roundtrip() {
        use crate::signing_reservation_journal::SigningJournalStorage;
        let store = InMemoryConsensusStorage::new();
        let key = framed_test_key();
        let (record_body, metadata_body, record_env, metadata_env) = framed_test_pair();
        store
            .put_signing_envelope_and_metadata_synced(&key, &record_env, &metadata_env)
            .expect("model combined write");
        assert_eq!(
            store.get_signing_record(&key).expect("read").expect("present"),
            record_body
        );
        assert_eq!(
            store.get_signing_metadata().expect("read").expect("present"),
            metadata_body
        );
        // The model synthesizes the outer CRC, reproducing the exact framed bytes.
        let mut dst = [0u8; 4096];
        let n = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &record_env[..]);
    }

    /// Item 3: key and input-length preflight refusals happen BEFORE any write
    /// attempt — no value is persisted on a refused call.
    #[test]
    fn put_envelope_and_metadata_synced_preflight_refusals_before_write() {
        use crate::signing_journal_admission::{JOURNAL_KEY_LEN, MIN_ENVELOPE_LEN};
        use crate::signing_reservation_journal::{BoundedStorageError, SigningJournalStorage};
        let store = InMemoryConsensusStorage::new();
        let key = framed_test_key();
        let (_rb, _mb, record_env, metadata_env) = framed_test_pair();

        // Record envelope shorter than the minimum framed length → malformed.
        let under = vec![0u8; MIN_ENVELOPE_LEN - 1];
        assert!(matches!(
            store.put_signing_envelope_and_metadata_synced(&key, &under, &metadata_env),
            Err(BoundedStorageError::Corruption(_))
        ));
        // Record envelope larger than the FORMAT limit → capacity refusal (NOT
        // relabeled malformed, and the format limit is the broad 8324, not any
        // narrower read workspace).
        let over = vec![0u8; MAX_RECORD_ENVELOPE_LEN + 1];
        assert!(matches!(
            store.put_signing_envelope_and_metadata_synced(&key, &over, &metadata_env),
            Err(BoundedStorageError::CapacityExceeded { .. })
        ));
        // Metadata envelope larger than its fixed framed size → capacity refusal.
        let meta_over = vec![0u8; MAX_META_ENVELOPE_LEN + 1];
        assert!(matches!(
            store.put_signing_envelope_and_metadata_synced(&key, &record_env, &meta_over),
            Err(BoundedStorageError::CapacityExceeded { .. })
        ));
        // Wrong-length key (valid envelopes) → key refused by the fixed builder.
        let short_key = [b'x'; JOURNAL_KEY_LEN - 1];
        assert!(matches!(
            store.put_signing_envelope_and_metadata_synced(&short_key, &record_env, &metadata_env),
            Err(BoundedStorageError::CapacityExceeded { .. })
        ));
        // None of the refused calls wrote anything.
        assert!(store.get_signing_record(&key).expect("read").is_none());
        assert!(store.get_signing_metadata().expect("read").is_none());
    }

    /// Item 2: a backend that does NOT override the new method inherits the trait
    /// default, which refuses with `Unsupported` and performs no write.
    #[derive(Default)]
    struct DefaultOnlyStore {
        domain:
            std::sync::OnceLock<Arc<crate::signing_reservation_journal::SigningOwnershipDomain>>,
    }
    impl crate::signing_reservation_journal::SigningJournalStorage for DefaultOnlyStore {
        fn get_signing_record(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }
        fn put_signing_record_synced(&self, _k: &[u8], _v: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }
        fn put_signing_metadata_synced(&self, _v: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            _rk: &[u8],
            _rv: &[u8],
            _mv: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn for_each_signing_namespace_entry(
            &self,
            _visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn signing_ownership_domain(
            &self,
        ) -> Arc<crate::signing_reservation_journal::SigningOwnershipDomain> {
            self.domain
                .get_or_init(crate::signing_reservation_journal::SigningOwnershipDomain::new)
                .clone()
        }
    }

    #[test]
    fn put_envelope_and_metadata_synced_default_is_unsupported() {
        use crate::signing_reservation_journal::{BoundedStorageError, SigningJournalStorage};
        let store = DefaultOnlyStore::default();
        let key = framed_test_key();
        let (_rb, _mb, record_env, metadata_env) = framed_test_pair();
        assert!(matches!(
            store.put_signing_envelope_and_metadata_synced(&key, &record_env, &metadata_env),
            Err(BoundedStorageError::Unsupported)
        ));
        // The default performs no write: the stub store still reports absence.
        assert!(store.get_signing_record(&key).expect("read").is_none());
        assert!(store.get_signing_metadata().expect("read").is_none());
    }

    // =======================================================================
    // Run 422 — record-ONLY synced primitive `put_signing_record_envelope_synced`.
    // Input is a single ALREADY-outer-framed record envelope; the primitive
    // persists ONLY that record key under one synced barrier, performs NO
    // metadata write, and establishes a STORAGE acknowledgement only (no signing
    // permission, signature verification, journal acknowledgement, continuation,
    // accounting, or delivery). Framing admission stays distinct from journal
    // semantic validation.
    // =======================================================================

    /// A validly-framed record envelope whose body is `body_len` bytes.
    fn framed_record_of_body(body_len: usize, fill: u8) -> Vec<u8> {
        wrap_checksummed(&vec![fill; body_len])
    }

    /// Item 1: a backend that does NOT override the new method inherits the trait
    /// default, which refuses with `Unsupported` and performs no write.
    #[test]
    fn put_record_envelope_synced_default_is_unsupported() {
        use crate::signing_reservation_journal::{BoundedStorageError, SigningJournalStorage};
        let store = DefaultOnlyStore::default();
        let key = framed_test_key();
        let (_rb, _mb, record_env, _me) = framed_test_pair();
        assert!(matches!(
            store.put_signing_record_envelope_synced(&key, &record_env),
            Err(BoundedStorageError::Unsupported)
        ));
        // The default performs no write: the stub store still reports absence.
        assert!(store.get_signing_record(&key).expect("read").is_none());
    }

    /// Item 2: wrong key length, below-minimum envelope, and above-FORMAT-maximum
    /// envelope are all refused with their FIXED errors BEFORE any write — no
    /// record or metadata value is persisted on a refused call.
    #[test]
    fn put_record_envelope_synced_preflight_refusals_before_write() {
        use crate::signing_journal_admission::{JOURNAL_KEY_LEN, MIN_ENVELOPE_LEN};
        use crate::signing_reservation_journal::{BoundedStorageError, SigningJournalStorage};
        let store = InMemoryConsensusStorage::new();
        let key = framed_test_key();

        // Below-minimum record envelope → malformed framing.
        let under = vec![0u8; MIN_ENVELOPE_LEN - 1];
        assert!(matches!(
            store.put_signing_record_envelope_synced(&key, &under),
            Err(BoundedStorageError::Corruption(_))
        ));
        // Larger than the broad FORMAT limit (8324) → capacity refusal, NOT
        // relabeled malformed and NOT narrowed to any read workspace.
        let over = vec![0u8; MAX_RECORD_ENVELOPE_LEN + 1];
        assert!(matches!(
            store.put_signing_record_envelope_synced(&key, &over),
            Err(BoundedStorageError::CapacityExceeded { .. })
        ));
        // Wrong-length key with a valid envelope → key refused by the length gate.
        let short_key = [b'x'; JOURNAL_KEY_LEN - 1];
        let valid = framed_record_of_body(MIN_ENVELOPE_LEN, 0x5A);
        assert!(matches!(
            store.put_signing_record_envelope_synced(&short_key, &valid),
            Err(BoundedStorageError::CapacityExceeded { .. })
        ));
        // None of the refused calls wrote anything (record or metadata).
        assert!(store.get_signing_record(&key).expect("read").is_none());
        assert!(store.get_signing_metadata().expect("read").is_none());
    }

    /// Item 3/5 (durable): a Reserved then a Signed record envelope are each
    /// stored through the new primitive and read back EXACTLY (RocksDB preserves
    /// the verbatim framed bytes), replacing the record in place.
    #[test]
    fn put_record_envelope_synced_rocksdb_reserved_then_signed_exact_bytes() {
        use crate::signing_journal_admission::MIN_ENVELOPE_LEN;
        use crate::signing_reservation_journal::SigningJournalStorage;
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbConsensusStorage::open(dir.path()).unwrap();
        let key = framed_test_key();

        // Reserved-shaped envelope (opaque to storage; distinct body pattern).
        let reserved = framed_record_of_body(MIN_ENVELOPE_LEN, 0x11);
        store
            .put_signing_record_envelope_synced(&key, &reserved)
            .expect("reserved record write");
        let mut dst = [0u8; 4096];
        let n = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &reserved[..], "verbatim reserved framed bytes");

        // Signed-shaped envelope (changed, longer body) overwrites in place; the
        // record-only primitive accepts the CHANGED bytes (unlike exact reissue).
        let signed = framed_record_of_body(MIN_ENVELOPE_LEN + 64, 0x22);
        store
            .put_signing_record_envelope_synced(&key, &signed)
            .expect("signed record write");
        let n2 = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n2], &signed[..], "verbatim signed framed bytes");
        // No metadata was ever written by this record-only route.
        assert!(store.get_signing_metadata().expect("read").is_none());
    }

    /// Item 3/5 (model): the in-memory MODEL backend stores record-ONLY and
    /// synthesizes the outer CRC on read, so the same framed input round-trips
    /// through every model reader. Labelled MODEL (no durability).
    #[test]
    fn put_record_envelope_synced_inmemory_model_roundtrip() {
        use crate::signing_journal_admission::{MIN_ENVELOPE_LEN, OUTER_CRC_LEN};
        use crate::signing_reservation_journal::SigningJournalStorage;
        let store = InMemoryConsensusStorage::new();
        let key = framed_test_key();
        let env = framed_record_of_body(MIN_ENVELOPE_LEN, 0x33);
        store
            .put_signing_record_envelope_synced(&key, &env)
            .expect("model record write");
        // The direct reader returns the record-only body (outer CRC stripped).
        assert_eq!(
            store.get_signing_record(&key).expect("read").expect("present"),
            &env[OUTER_CRC_LEN..]
        );
        // The bounded reader re-synthesizes the outer CRC, reproducing exact bytes.
        let mut dst = [0u8; 4096];
        let n = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &env[..]);
    }

    /// Item 4: the broad FORMAT boundary (`4 + MAX_RECORD_LEN` = 8324) is ACCEPTED
    /// by this primitive; it is NOT narrowed to the smaller retained-retrieval
    /// workspace. (A record larger than a given read workspace remains a separate
    /// bounded-READ limitation, exercised elsewhere.)
    #[test]
    fn put_record_envelope_synced_accepts_broad_format_boundary() {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        use crate::signing_reservation_journal::{SigningJournalStorage, MAX_RECORD_LEN};
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbConsensusStorage::open(dir.path()).unwrap();
        let key = framed_test_key();
        // Body exactly MAX_RECORD_LEN → envelope exactly MAX_RECORD_ENVELOPE_LEN.
        let at_limit = framed_record_of_body(MAX_RECORD_LEN, 0x44);
        assert_eq!(at_limit.len(), OUTER_CRC_LEN + MAX_RECORD_LEN);
        assert_eq!(at_limit.len(), MAX_RECORD_ENVELOPE_LEN);
        store
            .put_signing_record_envelope_synced(&key, &at_limit)
            .expect("at-format-limit write accepted");
        // Read back the verbatim bytes with a workspace large enough to hold them.
        let mut dst = vec![0u8; MAX_RECORD_ENVELOPE_LEN];
        let n = store
            .read_signing_envelope_into(&key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &at_limit[..]);
    }

    /// Item 6: replacing a record leaves the complete metadata bytes AND an
    /// unrelated record key byte-for-byte unchanged.
    #[test]
    fn put_record_envelope_synced_replacement_preserves_metadata_and_other_records() {
        use crate::signing_journal_admission::MIN_ENVELOPE_LEN;
        use crate::signing_reservation_journal::SigningJournalStorage;
        let store = InMemoryConsensusStorage::new();
        let (_rb, metadata_body, record_env, metadata_env) = framed_test_pair();
        let key = framed_test_key();
        // Seed metadata and a second unrelated record via existing primitives.
        store
            .put_signing_envelope_and_metadata_synced(&key, &record_env, &metadata_env)
            .expect("seed record + metadata");
        let mut other_key = framed_test_key();
        other_key[6..12].copy_from_slice(b"OTHERR");
        let other_env = framed_record_of_body(MIN_ENVELOPE_LEN, 0x77);
        store
            .put_signing_record_envelope_synced(&other_key, &other_env)
            .expect("seed unrelated record");

        // Replace the primary record only.
        let replacement = framed_record_of_body(MIN_ENVELOPE_LEN + 8, 0x66);
        store
            .put_signing_record_envelope_synced(&key, &replacement)
            .expect("replace primary record");

        // Metadata is byte-for-byte unchanged.
        assert_eq!(
            store.get_signing_metadata().expect("read").expect("present"),
            metadata_body
        );
        // The unrelated record is byte-for-byte unchanged (verbatim via bounded read).
        let mut dst = [0u8; 4096];
        let n = store
            .read_signing_envelope_into(&other_key, &mut dst)
            .expect("bounded read")
            .expect("present");
        assert_eq!(&dst[..n], &other_env[..]);
    }

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