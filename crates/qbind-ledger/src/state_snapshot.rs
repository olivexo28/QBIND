//! T215: State snapshots for fast sync and recovery.
//!
//! This module provides a state snapshot trait and supporting types for taking
//! point-in-time account-state snapshots from the canonical RocksDB state.
//! Snapshots are deterministic and local-only (no new consensus rules).
//!
//! # Design
//!
//! State snapshots capture the complete account state at a specific block height,
//! enabling:
//! - Fast node synchronization (boot from snapshot instead of genesis)
//! - Recovery from data corruption
//! - Archival node workflows
//!
//! # Snapshot Directory Layout
//!
//! ```text
//! snapshot_dir/
//! ├── meta.json           # Snapshot metadata (height, hash, chain_id, timestamp)
//! └── state/              # RocksDB checkpoint (SST files)
//! ```
//!
//! # Thread Safety
//!
//! Implementations should be thread-safe. Snapshot creation may run in a
//! background task while reads/writes continue on the main execution path.
//!
//! # Example
//!
//! ```rust,ignore
//! use qbind_ledger::{RocksDbAccountState, StateSnapshotter, StateSnapshotMeta};
//! use std::path::Path;
//!
//! let storage = RocksDbAccountState::open(Path::new("/data/state"))?;
//!
//! let meta = StateSnapshotMeta {
//!     height: 100_000,
//!     block_hash: [0xAA; 32],
//!     created_at_unix_ms: 1700000000000,
//!     chain_id: 0x51424E444D41494E,
//! };
//!
//! storage.create_snapshot(&meta, Path::new("/data/snapshots/100000"))?;
//! println!("Snapshot created at height {}", meta.height);
//! ```

use std::fmt;
use std::path::Path;
use std::time::Duration;

// ============================================================================
// Snapshot Metadata
// ============================================================================

/// Metadata describing a state snapshot (T215).
///
/// This struct captures all information needed to validate and restore
/// a snapshot:
/// - `height`: The block height at which the snapshot was taken
/// - `block_hash`: The hash of the block at this height
/// - `created_at_unix_ms`: Unix timestamp in milliseconds when snapshot was created
/// - `chain_id`: The chain ID to verify snapshot is from correct network
///
/// # Serialization
///
/// Metadata is stored as JSON in `meta.json` within the snapshot directory
/// for human readability and easy validation.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::StateSnapshotMeta;
///
/// let meta = StateSnapshotMeta {
///     height: 100_000,
///     block_hash: [0xAA; 32],
///     created_at_unix_ms: 1700000000000,
///     chain_id: 0x51424E444D41494E, // MainNet chain ID
/// };
///
/// assert_eq!(meta.height, 100_000);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshotMeta {
    /// Block height at which the snapshot was taken.
    ///
    /// The snapshot contains the complete account state after applying
    /// all transactions in this block.
    pub height: u64,

    /// Hash of the block at this height (32 bytes).
    ///
    /// Used to verify the snapshot corresponds to the expected chain state.
    /// During restore, nodes can verify this matches the block at `height`
    /// in their chain.
    pub block_hash: [u8; 32],

    /// Unix timestamp (milliseconds) when the snapshot was created.
    ///
    /// This is the wall-clock time when `create_snapshot()` was called,
    /// not the block timestamp. Useful for monitoring and diagnostics.
    pub created_at_unix_ms: u64,

    /// Chain ID identifying the network (MainNet, TestNet, DevNet).
    ///
    /// Prevents accidentally restoring a snapshot from a different network.
    /// Should match the node's configured chain ID.
    pub chain_id: u64,
}

impl StateSnapshotMeta {
    /// Create a new snapshot metadata instance.
    pub fn new(height: u64, block_hash: [u8; 32], created_at_unix_ms: u64, chain_id: u64) -> Self {
        Self {
            height,
            block_hash,
            created_at_unix_ms,
            chain_id,
        }
    }

    /// Get the current Unix timestamp in milliseconds.
    pub fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Encode metadata to JSON bytes.
    ///
    /// Format:
    /// ```json
    /// {
    ///   "height": 100000,
    ///   "block_hash": "aaaa...aaaa",
    ///   "created_at_unix_ms": 1700000000000,
    ///   "chain_id": 5854693887968574798
    /// }
    /// ```
    pub fn to_json(&self) -> Vec<u8> {
        let block_hash_hex: String = self.block_hash.iter().map(|b| format!("{:02x}", b)).collect();
        format!(
            "{{\n  \"height\": {},\n  \"block_hash\": \"{}\",\n  \"created_at_unix_ms\": {},\n  \"chain_id\": {}\n}}",
            self.height, block_hash_hex, self.created_at_unix_ms, self.chain_id
        )
        .into_bytes()
    }

    /// Parse metadata from JSON bytes.
    ///
    /// Returns `None` if parsing fails or required fields are missing.
    pub fn from_json(data: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(data).ok()?;

        // Simple JSON parsing without external dependencies
        let height = Self::extract_u64(s, "height")?;
        let block_hash_hex = Self::extract_string(s, "block_hash")?;
        let created_at_unix_ms = Self::extract_u64(s, "created_at_unix_ms")?;
        let chain_id = Self::extract_u64(s, "chain_id")?;

        // Parse block hash from hex
        if block_hash_hex.len() != 64 {
            return None;
        }
        let mut block_hash = [0u8; 32];
        for (i, chunk) in block_hash_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).ok()?;
            block_hash[i] = u8::from_str_radix(hex_str, 16).ok()?;
        }

        Some(Self {
            height,
            block_hash,
            created_at_unix_ms,
            chain_id,
        })
    }

    /// Extract a u64 value from JSON-like text.
    fn extract_u64(s: &str, key: &str) -> Option<u64> {
        let key_pattern = format!("\"{}\":", key);
        let start = s.find(&key_pattern)?;
        let value_start = start + key_pattern.len();
        let rest = &s[value_start..];
        let rest = rest.trim_start();

        // Find the end of the number (comma, newline, or closing brace)
        let end = rest
            .find([',', '\n', '}'])
            .unwrap_or(rest.len());
        let num_str = rest[..end].trim();
        num_str.parse().ok()
    }

    /// Extract a string value from JSON-like text.
    fn extract_string(s: &str, key: &str) -> Option<String> {
        let key_pattern = format!("\"{}\":", key);
        let start = s.find(&key_pattern)?;
        let value_start = start + key_pattern.len();
        let rest = &s[value_start..];
        let rest = rest.trim_start();

        // Expect a quoted string
        if !rest.starts_with('"') {
            return None;
        }
        let rest = &rest[1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }
}

impl fmt::Display for StateSnapshotMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Snapshot(height={}, chain_id={:#x}, created={}ms)",
            self.height, self.chain_id, self.created_at_unix_ms
        )
    }
}

// ============================================================================
// Snapshot Errors
// ============================================================================

/// Error type for state snapshot operations (T215).
///
/// Categorizes errors into:
/// - Configuration/path errors
/// - IO errors
/// - Backend-specific errors (RocksDB)
/// - Validation errors
///
/// # Example
///
/// ```rust
/// use qbind_ledger::StateSnapshotError;
///
/// let err = StateSnapshotError::Io("permission denied".to_string());
/// assert!(err.to_string().contains("permission denied"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateSnapshotError {
    /// Configuration error (bad path, missing directory, permissions).
    ///
    /// This typically indicates operator error in specifying snapshot paths.
    Config(String),

    /// IO error during snapshot creation or restore.
    ///
    /// Examples: disk full, file not found, permission denied.
    Io(String),

    /// Backend-specific error (RocksDB checkpoint failure).
    ///
    /// This indicates an error in the underlying storage engine.
    Backend(String),

    /// Snapshot validation error.
    ///
    /// Examples: mismatched chain ID, corrupted metadata, missing files.
    Validation(String),

    /// Snapshot already exists at the target path.
    ///
    /// Prevents accidental overwriting of existing snapshots.
    AlreadyExists(String),
}

impl fmt::Display for StateSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateSnapshotError::Config(msg) => write!(f, "snapshot config error: {}", msg),
            StateSnapshotError::Io(msg) => write!(f, "snapshot IO error: {}", msg),
            StateSnapshotError::Backend(msg) => write!(f, "snapshot backend error: {}", msg),
            StateSnapshotError::Validation(msg) => write!(f, "snapshot validation error: {}", msg),
            StateSnapshotError::AlreadyExists(path) => {
                write!(f, "snapshot already exists at: {}", path)
            }
        }
    }
}

impl std::error::Error for StateSnapshotError {}

// ============================================================================
// Snapshot Statistics
// ============================================================================

/// Statistics from a state snapshot operation (T215).
///
/// Captures telemetry data from a snapshot creation or restore,
/// useful for monitoring and performance tuning.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::SnapshotStats;
/// use std::time::Duration;
///
/// let stats = SnapshotStats::new(
///     100_000,               // height
///     1024 * 1024 * 512,     // 512 MB size
///     Duration::from_secs(5) // 5 seconds
/// );
///
/// println!("Snapshot at height {} took {}ms", stats.height, stats.duration_ms);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotStats {
    /// Block height of the snapshot.
    pub height: u64,

    /// Approximate size of the snapshot in bytes.
    pub size_bytes: u64,

    /// Duration of the snapshot operation in milliseconds.
    pub duration_ms: u64,
}

impl SnapshotStats {
    /// Create new snapshot statistics.
    pub fn new(height: u64, size_bytes: u64, duration: Duration) -> Self {
        Self {
            height,
            size_bytes,
            duration_ms: duration.as_millis() as u64,
        }
    }

    /// Create snapshot statistics with duration in milliseconds.
    pub fn from_ms(height: u64, size_bytes: u64, duration_ms: u64) -> Self {
        Self {
            height,
            size_bytes,
            duration_ms,
        }
    }
}

impl fmt::Display for SnapshotStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size_mb = self.size_bytes as f64 / (1024.0 * 1024.0);
        write!(
            f,
            "height={}, size={:.2}MB, duration={}ms",
            self.height, size_mb, self.duration_ms
        )
    }
}

// ============================================================================
// State Snapshotter Trait
// ============================================================================

/// Trait for state backends that support point-in-time snapshots (T215).
///
/// Implementations create logically consistent snapshots of account state
/// at a given block boundary. Snapshots are local-only and do not affect
/// consensus.
///
/// # Requirements
///
/// - Snapshot must be taken after a committed block (not mid-execution)
/// - All in-flight writes (memtable, WAL) must be flushed before snapshot
/// - Snapshot directory must not already exist
/// - Snapshot must be restorable to recreate the exact state
///
/// # Thread Safety
///
/// Implementations should be safe to call while reads/writes continue.
/// RocksDB checkpoints provide this guarantee by default.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{RocksDbAccountState, StateSnapshotter, StateSnapshotMeta};
/// use std::path::Path;
///
/// let storage = RocksDbAccountState::open(Path::new("/data/state"))?;
///
/// // Create metadata for height 100_000
/// let meta = StateSnapshotMeta {
///     height: 100_000,
///     block_hash: [0xAA; 32],
///     created_at_unix_ms: StateSnapshotMeta::now_unix_ms(),
///     chain_id: 0x51424E444D41494E,
/// };
///
/// // Create snapshot
/// let stats = storage.create_snapshot(&meta, Path::new("/data/snapshots/100000"))?;
/// println!("Snapshot created: {}", stats);
/// ```
pub trait StateSnapshotter {
    /// Create a point-in-time snapshot of the account state.
    ///
    /// # Arguments
    ///
    /// * `meta` - Snapshot metadata (height, block hash, chain ID)
    /// * `target_dir` - Directory to write snapshot files (must not exist)
    ///
    /// # Returns
    ///
    /// `Ok(SnapshotStats)` on success with statistics about the snapshot.
    /// `Err(StateSnapshotError)` on failure.
    ///
    /// # Errors
    ///
    /// - `Config`: Invalid target directory path
    /// - `AlreadyExists`: Target directory already exists
    /// - `Io`: File system errors
    /// - `Backend`: RocksDB checkpoint errors
    ///
    /// # Notes
    ///
    /// - Caller must ensure no block execution is in progress
    /// - WAL and memtable are flushed before checkpoint
    /// - Snapshot is atomic: either fully created or not at all
    fn create_snapshot(
        &self,
        meta: &StateSnapshotMeta,
        target_dir: &Path,
    ) -> Result<SnapshotStats, StateSnapshotError>;

    /// Estimate the current state size in bytes.
    ///
    /// Returns an approximate size of the state that would be captured
    /// in a snapshot. Useful for monitoring and capacity planning.
    ///
    /// # Returns
    ///
    /// `Some(size)` with estimated size in bytes.
    /// `None` if size cannot be determined.
    fn estimate_snapshot_size_bytes(&self) -> Option<u64>;
}

// ============================================================================
// Snapshot Validation
// ============================================================================

/// Result of validating a snapshot directory (T215).
///
/// Used by fast-sync to verify a snapshot before attempting restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotValidationResult {
    /// Snapshot is valid and can be restored.
    Valid(StateSnapshotMeta),

    /// Snapshot metadata is missing or corrupted.
    MissingMetadata(String),

    /// Snapshot state directory is missing or empty.
    MissingStateDir(String),

    /// Chain ID mismatch (snapshot from different network).
    ChainIdMismatch { expected: u64, actual: u64 },

    /// Snapshot height is invalid (e.g., zero or too old).
    InvalidHeight(u64),
}

impl fmt::Display for SnapshotValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotValidationResult::Valid(meta) => write!(f, "valid: {}", meta),
            SnapshotValidationResult::MissingMetadata(msg) => {
                write!(f, "missing metadata: {}", msg)
            }
            SnapshotValidationResult::MissingStateDir(msg) => {
                write!(f, "missing state dir: {}", msg)
            }
            SnapshotValidationResult::ChainIdMismatch { expected, actual } => {
                write!(
                    f,
                    "chain ID mismatch: expected {:#x}, got {:#x}",
                    expected, actual
                )
            }
            SnapshotValidationResult::InvalidHeight(h) => write!(f, "invalid height: {}", h),
        }
    }
}

/// Validate a snapshot directory for fast-sync restore (T215).
///
/// Checks that:
/// 1. `meta.json` exists and is parseable
/// 2. `state/` directory exists and is not empty
/// 3. Chain ID matches expected value
/// 4. Height is reasonable (> 0)
///
/// # Arguments
///
/// * `snapshot_dir` - Path to the snapshot directory
/// * `expected_chain_id` - The chain ID the node is configured for
///
/// # Returns
///
/// `SnapshotValidationResult` indicating validity or specific error.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::validate_snapshot_dir;
///
/// let result = validate_snapshot_dir(
///     Path::new("/data/snapshots/100000"),
///     0x51424E444D41494E  // MainNet chain ID
/// );
///
/// match result {
///     SnapshotValidationResult::Valid(meta) => {
///         println!("Snapshot valid at height {}", meta.height);
///     }
///     other => {
///         eprintln!("Snapshot invalid: {}", other);
///     }
/// }
/// ```
pub fn validate_snapshot_dir(
    snapshot_dir: &Path,
    expected_chain_id: u64,
) -> SnapshotValidationResult {
    // Check meta.json exists
    let meta_path = snapshot_dir.join("meta.json");
    let meta_data = match std::fs::read(&meta_path) {
        Ok(data) => data,
        Err(e) => {
            return SnapshotValidationResult::MissingMetadata(format!(
                "cannot read meta.json: {}",
                e
            ));
        }
    };

    // Parse metadata
    let meta = match StateSnapshotMeta::from_json(&meta_data) {
        Some(m) => m,
        None => {
            return SnapshotValidationResult::MissingMetadata(
                "cannot parse meta.json".to_string(),
            );
        }
    };

    // Check chain ID
    if meta.chain_id != expected_chain_id {
        return SnapshotValidationResult::ChainIdMismatch {
            expected: expected_chain_id,
            actual: meta.chain_id,
        };
    }

    // Check height is reasonable
    if meta.height == 0 {
        return SnapshotValidationResult::InvalidHeight(meta.height);
    }

    // Check state directory exists
    let state_dir = snapshot_dir.join("state");
    if !state_dir.exists() {
        return SnapshotValidationResult::MissingStateDir(
            "state/ directory does not exist".to_string(),
        );
    }

    // Check state directory is not empty
    match std::fs::read_dir(&state_dir) {
        Ok(mut entries) => {
            if entries.next().is_none() {
                return SnapshotValidationResult::MissingStateDir(
                    "state/ directory is empty".to_string(),
                );
            }
        }
        Err(e) => {
            return SnapshotValidationResult::MissingStateDir(format!(
                "cannot read state/ directory: {}",
                e
            ));
        }
    }

    SnapshotValidationResult::Valid(meta)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_meta_new() {
        let meta = StateSnapshotMeta::new(100, [0xAA; 32], 1700000000000, 0x1234);
        assert_eq!(meta.height, 100);
        assert_eq!(meta.block_hash, [0xAA; 32]);
        assert_eq!(meta.created_at_unix_ms, 1700000000000);
        assert_eq!(meta.chain_id, 0x1234);
    }

    #[test]
    fn test_snapshot_meta_json_roundtrip() {
        let meta = StateSnapshotMeta {
            height: 100_000,
            block_hash: [0xAB; 32],
            created_at_unix_ms: 1700000000000,
            chain_id: 0x51424E444D41494E,
        };

        let json = meta.to_json();
        let parsed = StateSnapshotMeta::from_json(&json).expect("should parse");

        assert_eq!(parsed.height, meta.height);
        assert_eq!(parsed.block_hash, meta.block_hash);
        assert_eq!(parsed.created_at_unix_ms, meta.created_at_unix_ms);
        assert_eq!(parsed.chain_id, meta.chain_id);
    }

    #[test]
    fn test_snapshot_meta_from_json_invalid() {
        assert!(StateSnapshotMeta::from_json(b"not json").is_none());
        assert!(StateSnapshotMeta::from_json(b"{}").is_none());
        assert!(StateSnapshotMeta::from_json(b"{\"height\": 100}").is_none());
    }

    #[test]
    fn test_snapshot_meta_display() {
        let meta = StateSnapshotMeta::new(100, [0; 32], 1700000000000, 0x1234);
        let s = format!("{}", meta);
        assert!(s.contains("height=100"));
        assert!(s.contains("chain_id=0x1234"));
    }

    #[test]
    fn test_snapshot_error_display() {
        let err = StateSnapshotError::Config("bad path".to_string());
        assert!(err.to_string().contains("config error"));
        assert!(err.to_string().contains("bad path"));

        let err = StateSnapshotError::Io("disk full".to_string());
        assert!(err.to_string().contains("IO error"));

        let err = StateSnapshotError::Backend("checkpoint failed".to_string());
        assert!(err.to_string().contains("backend error"));

        let err = StateSnapshotError::Validation("corrupted".to_string());
        assert!(err.to_string().contains("validation error"));

        let err = StateSnapshotError::AlreadyExists("/data/snap".to_string());
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_snapshot_stats_new() {
        let stats = SnapshotStats::new(100, 1024 * 1024, std::time::Duration::from_millis(500));
        assert_eq!(stats.height, 100);
        assert_eq!(stats.size_bytes, 1024 * 1024);
        assert_eq!(stats.duration_ms, 500);
    }

    #[test]
    fn test_snapshot_stats_from_ms() {
        let stats = SnapshotStats::from_ms(200, 2048, 100);
        assert_eq!(stats.height, 200);
        assert_eq!(stats.size_bytes, 2048);
        assert_eq!(stats.duration_ms, 100);
    }

    #[test]
    fn test_snapshot_stats_display() {
        let stats = SnapshotStats::new(100, 1024 * 1024, std::time::Duration::from_millis(500));
        let s = format!("{}", stats);
        assert!(s.contains("height=100"));
        assert!(s.contains("duration=500ms"));
    }

    #[test]
    fn test_validation_result_display() {
        let meta = StateSnapshotMeta::new(100, [0; 32], 1700000000000, 0x1234);
        let r = SnapshotValidationResult::Valid(meta);
        assert!(format!("{}", r).contains("valid"));

        let r = SnapshotValidationResult::MissingMetadata("test".to_string());
        assert!(format!("{}", r).contains("missing metadata"));

        let r = SnapshotValidationResult::ChainIdMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(format!("{}", r).contains("chain ID mismatch"));
    }

    #[test]
    fn test_now_unix_ms() {
        let ts = StateSnapshotMeta::now_unix_ms();
        // Should be a reasonable recent timestamp (after year 2020)
        assert!(ts > 1577836800000); // 2020-01-01 00:00:00 UTC
    }
}