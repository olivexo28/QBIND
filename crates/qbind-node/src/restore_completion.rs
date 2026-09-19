//! **Run 422 D7-D8.** Restore-completion boundary primitives.
//!
//! This module implements the bounded restore-transaction record (RTR), the
//! destination advisory lock, the durable-publication sequence, and the
//! ordinary-startup restore-completion guard defined by
//! `docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md`. It contains
//! the reusable, self-contained pieces; the ordering that wires these into the
//! actual restore/materialization flow lives in
//! [`crate::snapshot_restore`], and the entrypoint coverage (lock acquisition,
//! startup inspection) lives in the `qbind-node` binary (`main.rs`).
//!
//! # What this module is (and is NOT)
//!
//! The RTR is this node's own **local bookkeeping** of its own restore
//! attempts at one destination, under the destination lock (§5.5) and the
//! fail-closed / non-adversarial assumptions of §5.1–§5.4. It is **not** an
//! external authority, **not** authentication of checkpoint contents, and
//! **not** an anti-rollback or freshness witness. Its checksum detects
//! accidental corruption/truncation; it is **not** a MAC and provides no
//! protection against an adversary who can rewrite the destination (§5.4, out
//! of scope).
//!
//! # Durability profile (§5.6, supported platform)
//!
//! The supported profile is a POSIX filesystem where `fsync(file)` +
//! `fsync(parent dir)` orders and persists a create/rename, and where the
//! advisory `flock(LOCK_EX | LOCK_NB)` is kernel-managed and auto-released on
//! process death. On non-Unix targets the lock and directory-`fsync`
//! operations are **not** silently succeeded — they fail closed.
//!
//! These are *specified* durability assumptions, not validated guarantees:
//! process-kill tests exercise the interruption ordering but do not establish
//! host power-loss durability (§9).

use std::fmt;
use std::path::{Path, PathBuf};

use qbind_ledger::StateSnapshotMeta;
use sha3::{Digest, Sha3_256};

/// Filename of the authoritative final restore-transaction record, written at
/// the destination `data_dir`.
pub const RTR_FILENAME: &str = "RESTORE_TRANSACTION.rtr";

/// Filename of the staging temp file used for atomic publication. A temp
/// artifact is **never** promoted into completion evidence (§5.9).
pub const RTR_TEMP_FILENAME: &str = "RESTORE_TRANSACTION.rtr.tmp";

/// Filename of the advisory destination lock object (§5.5). Created with the
/// destination and **never** unlinked as a signalling / stale-lock act.
pub const RESTORE_LOCK_FILENAME: &str = "restore.lock";

/// Supported RTR schema version. An unknown/unsupported version is an invalid
/// record and is refused (never auto-upgraded).
pub const RTR_VERSION: u32 = 1;

/// 8-byte magic prefix identifying an RTR file.
const RTR_MAGIC: &[u8; 8] = b"QBNDRTR\x01";

/// Maximum accepted encoded record size (small, bounded). Over-size ⇒ refuse.
pub const RTR_MAX_RECORD_SIZE: usize = 8 * 1024;

/// Maximum accepted `destination_id` byte length. Bounds the untrusted
/// length field before any allocation.
pub const RTR_MAX_DEST_LEN: usize = 4096;

/// Fixed-size header preceding the variable-length destination bytes:
/// magic(8) + version(4) + state(1) + epoch_present(1) + reserved(2) +
/// epoch(8) + digest(32) + nonce(16) + dest_len(4) = 76 bytes.
const RTR_FIXED_HEADER_LEN: usize = 8 + 4 + 1 + 1 + 2 + 8 + 32 + 16 + 4;

/// Trailing checksum length (SHA3-256 over all preceding bytes).
const RTR_CHECKSUM_LEN: usize = 32;

// ============================================================================
// RTR state
// ============================================================================

/// The two persistent RTR states (§4.2). There is no other terminal success
/// state; an `INTENT` never upgraded to `COMPLETE` denotes an interrupted
/// restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtrState {
    /// A restore attempt is in progress; the destination may be partially
    /// mutated. Durably written before any account-state copy.
    Intent,
    /// Every required restore effect satisfied its durability barrier for this
    /// attempt and destination. Durably written only after all effects.
    Complete,
}

impl RtrState {
    fn to_byte(self) -> u8 {
        match self {
            RtrState::Intent => 1,
            RtrState::Complete => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(RtrState::Intent),
            2 => Some(RtrState::Complete),
            _ => None,
        }
    }

    /// Stable lowercase tag for logging.
    pub fn tag(self) -> &'static str {
        match self {
            RtrState::Intent => "INTENT",
            RtrState::Complete => "COMPLETE",
        }
    }
}

// ============================================================================
// Snapshot-meta digest
// ============================================================================

/// Compute the whole-metadata identity digest bound into the RTR (§4.1, §4.8.1).
///
/// The digest is `SHA3-256` over the canonical, deterministic, byte-stable
/// serialization already produced by [`StateSnapshotMeta::to_json`] — which
/// encodes every field in a fixed order, with explicit `Option` handling
/// (omitting absent keys, distinguishing `None` from `Some(0)`) and including
/// both authority fields (`authority_state`, `authority_state_v2`). This reuses
/// the existing canonical encoder and the vendored `sha3` facility; it does
/// **not** hash `Debug` output and does **not** introduce a second metadata
/// parser.
///
/// Equal digests assert equal validated metadata identity only — not
/// authentication, freshness, or authorization.
pub fn snapshot_meta_digest(meta: &StateSnapshotMeta) -> [u8; 32] {
    let canonical = meta.to_json();
    let mut hasher = Sha3_256::new();
    hasher.update(&canonical);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

// ============================================================================
// Destination identity
// ============================================================================

/// Canonical destination identity: the canonicalized absolute `data_dir` path
/// as a UTF-8 string. The `state_vm_v0` subpath is derived from it, so storing
/// the canonical `data_dir` is sufficient to bind a completion to a single
/// destination (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationId(String);

impl DestinationId {
    /// Canonicalize `data_dir` into a stable destination identity. The path
    /// must already exist (the restore/startup path creates `data_dir` before
    /// this is called).
    pub fn canonicalize(data_dir: &Path) -> Result<Self, RtrError> {
        let canonical = std::fs::canonicalize(data_dir).map_err(|e| {
            RtrError::Io(format!(
                "cannot canonicalize destination data_dir {}: {}",
                data_dir.display(),
                e
            ))
        })?;
        let s = canonical.to_str().ok_or_else(|| {
            RtrError::Malformed(format!(
                "destination path is not valid UTF-8: {}",
                canonical.display()
            ))
        })?;
        Ok(DestinationId(s.to_string()))
    }

    /// The canonical destination string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DestinationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// The record
// ============================================================================

/// The bounded restore-transaction record. One authoritative final record per
/// destination, in state `INTENT` or `COMPLETE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTransactionRecord {
    /// Schema version. Always [`RTR_VERSION`] for records this build writes.
    pub version: u32,
    /// Persistent state.
    pub state: RtrState,
    /// Canonical destination identity (§4.1).
    pub destination_id: String,
    /// Whole validated-metadata identity digest (§4.1).
    pub snapshot_meta_digest: [u8; 32],
    /// Per-attempt unique nonce (§4.1). Held in `INTENT`, copied verbatim into
    /// `COMPLETE`.
    pub attempt_nonce: [u8; 16],
    /// The snapshot `meta.epoch`, preserving `None` vs `Some(0)` (§4.1).
    pub expected_epoch: Option<u64>,
}

impl RestoreTransactionRecord {
    /// Construct a fresh `INTENT` record for an attempt.
    pub fn new_intent(
        destination_id: &DestinationId,
        snapshot_meta_digest: [u8; 32],
        attempt_nonce: [u8; 16],
        expected_epoch: Option<u64>,
    ) -> Self {
        RestoreTransactionRecord {
            version: RTR_VERSION,
            state: RtrState::Intent,
            destination_id: destination_id.as_str().to_string(),
            snapshot_meta_digest,
            attempt_nonce,
            expected_epoch,
        }
    }

    /// Produce the `COMPLETE` record for the same attempt (same nonce,
    /// destination, digest, and epoch).
    pub fn into_complete(mut self) -> Self {
        self.state = RtrState::Complete;
        self
    }

    /// Deterministically encode this record (§4.8.1). Layout is fixed-width,
    /// big-endian, with an explicit `Option` tag for the epoch and a trailing
    /// SHA3-256 checksum over all preceding bytes for corruption detection.
    pub fn encode(&self) -> Vec<u8> {
        let dest_bytes = self.destination_id.as_bytes();
        let mut buf = Vec::with_capacity(
            RTR_FIXED_HEADER_LEN + dest_bytes.len() + RTR_CHECKSUM_LEN,
        );
        buf.extend_from_slice(RTR_MAGIC);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.state.to_byte());
        let (epoch_present, epoch_val) = match self.expected_epoch {
            Some(e) => (1u8, e),
            None => (0u8, 0u64),
        };
        buf.push(epoch_present);
        buf.extend_from_slice(&[0u8, 0u8]); // reserved
        buf.extend_from_slice(&epoch_val.to_be_bytes());
        buf.extend_from_slice(&self.snapshot_meta_digest);
        buf.extend_from_slice(&self.attempt_nonce);
        buf.extend_from_slice(&(dest_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(dest_bytes);
        let mut hasher = Sha3_256::new();
        hasher.update(&buf);
        let checksum = hasher.finalize();
        buf.extend_from_slice(&checksum);
        buf
    }

    /// Strictly decode a record from raw bytes (§4.8.1). Rejects unsupported
    /// versions, truncation, trailing data, over-size records, invalid fields,
    /// and checksum-detected corruption. The untrusted `dest_len` is bounded
    /// **before** any allocation.
    pub fn decode(buf: &[u8]) -> Result<Self, RtrDecodeError> {
        if buf.len() > RTR_MAX_RECORD_SIZE {
            return Err(RtrDecodeError::Oversized(buf.len()));
        }
        if buf.len() < RTR_FIXED_HEADER_LEN + RTR_CHECKSUM_LEN {
            return Err(RtrDecodeError::Truncated);
        }
        if &buf[0..8] != RTR_MAGIC {
            return Err(RtrDecodeError::Malformed("bad magic".to_string()));
        }
        let version = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if version != RTR_VERSION {
            return Err(RtrDecodeError::UnsupportedVersion(version));
        }
        let state = RtrState::from_byte(buf[12])
            .ok_or_else(|| RtrDecodeError::Malformed(format!("bad state byte {}", buf[12])))?;
        let epoch_present = buf[13];
        if epoch_present > 1 {
            return Err(RtrDecodeError::Malformed(format!(
                "bad epoch_present byte {}",
                epoch_present
            )));
        }
        // buf[14], buf[15] reserved (ignored on read; not required to be zero
        // for forward tolerance within the same version — but they must fit
        // the fixed layout, which the length check above guarantees).
        let epoch_val = u64::from_be_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        let expected_epoch = if epoch_present == 1 {
            Some(epoch_val)
        } else {
            None
        };
        let mut snapshot_meta_digest = [0u8; 32];
        snapshot_meta_digest.copy_from_slice(&buf[24..56]);
        let mut attempt_nonce = [0u8; 16];
        attempt_nonce.copy_from_slice(&buf[56..72]);
        let dest_len =
            u32::from_be_bytes([buf[72], buf[73], buf[74], buf[75]]) as usize;
        // Bound the untrusted length BEFORE computing the expected total /
        // slicing.
        if dest_len > RTR_MAX_DEST_LEN {
            return Err(RtrDecodeError::Malformed(format!(
                "destination length {} exceeds bound {}",
                dest_len, RTR_MAX_DEST_LEN
            )));
        }
        let expected_total = RTR_FIXED_HEADER_LEN + dest_len + RTR_CHECKSUM_LEN;
        if buf.len() < expected_total {
            return Err(RtrDecodeError::Truncated);
        }
        if buf.len() > expected_total {
            return Err(RtrDecodeError::TrailingData);
        }
        let dest_bytes = &buf[RTR_FIXED_HEADER_LEN..RTR_FIXED_HEADER_LEN + dest_len];
        let destination_id = std::str::from_utf8(dest_bytes)
            .map_err(|_| RtrDecodeError::Malformed("destination not UTF-8".to_string()))?
            .to_string();
        // Verify the trailing checksum over all preceding bytes.
        let body = &buf[..expected_total - RTR_CHECKSUM_LEN];
        let stored = &buf[expected_total - RTR_CHECKSUM_LEN..expected_total];
        let mut hasher = Sha3_256::new();
        hasher.update(body);
        let computed = hasher.finalize();
        if computed.as_slice() != stored {
            return Err(RtrDecodeError::Corrupt);
        }
        Ok(RestoreTransactionRecord {
            version,
            state,
            destination_id,
            snapshot_meta_digest,
            attempt_nonce,
            expected_epoch,
        })
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Strict-decode failure reasons (§4.8.1). Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtrDecodeError {
    /// The buffer is shorter than the record it claims to be.
    Truncated,
    /// Extra bytes trail a complete record.
    TrailingData,
    /// The encoded record exceeds [`RTR_MAX_RECORD_SIZE`].
    Oversized(usize),
    /// A field failed structural validation.
    Malformed(String),
    /// The schema version is unknown/unsupported (never auto-upgraded).
    UnsupportedVersion(u32),
    /// The trailing checksum did not match (accidental corruption).
    Corrupt,
}

impl fmt::Display for RtrDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtrDecodeError::Truncated => write!(f, "RTR record is truncated"),
            RtrDecodeError::TrailingData => write!(f, "RTR record has trailing data"),
            RtrDecodeError::Oversized(n) => {
                write!(f, "RTR record is oversized ({} bytes)", n)
            }
            RtrDecodeError::Malformed(m) => write!(f, "RTR record is malformed: {}", m),
            RtrDecodeError::UnsupportedVersion(v) => {
                write!(f, "RTR record has unsupported version {}", v)
            }
            RtrDecodeError::Corrupt => {
                write!(f, "RTR record failed its integrity checksum")
            }
        }
    }
}

/// General RTR errors surfaced to callers (IO, decode, or field validation).
#[derive(Debug, Clone)]
pub enum RtrError {
    /// An IO / filesystem error (read, write, sync, canonicalize, lock).
    Io(String),
    /// A field failed validation while constructing a record.
    Malformed(String),
    /// A stored record failed strict decoding.
    Decode(RtrDecodeError),
}

impl fmt::Display for RtrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtrError::Io(m) => write!(f, "restore-transaction IO error: {}", m),
            RtrError::Malformed(m) => write!(f, "restore-transaction record invalid: {}", m),
            RtrError::Decode(d) => write!(f, "restore-transaction record undecodable: {}", d),
        }
    }
}

impl std::error::Error for RtrError {}

// ============================================================================
// Reading and classification
// ============================================================================

/// The observed final RTR at a destination.
#[derive(Debug, Clone)]
pub enum RtrReadResult {
    /// No RTR present (untracked destination / ordinary lifecycle).
    Absent,
    /// A structurally valid record present.
    Present(RestoreTransactionRecord),
    /// A present record failed strict decoding (fail-closed).
    Invalid(RtrDecodeError),
}

/// Path to the authoritative RTR file at `data_dir`.
pub fn rtr_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RTR_FILENAME)
}

/// Read and classify the final RTR at `data_dir`.
///
/// A missing file is [`RtrReadResult::Absent`]. A present-but-unreadable file
/// is an IO error (fail-closed). A present-but-undecodable file is
/// [`RtrReadResult::Invalid`]. Only a strictly valid record yields
/// [`RtrReadResult::Present`]. The read is bounded: a file larger than
/// [`RTR_MAX_RECORD_SIZE`] is refused without allocating from its length.
pub fn read_rtr(data_dir: &Path) -> Result<RtrReadResult, RtrError> {
    let path = rtr_path(data_dir);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RtrReadResult::Absent)
        }
        Err(e) => {
            return Err(RtrError::Io(format!(
                "cannot stat RTR {}: {}",
                path.display(),
                e
            )))
        }
    };
    if meta.len() > RTR_MAX_RECORD_SIZE as u64 {
        // Do not allocate from an untrusted oversized length.
        return Ok(RtrReadResult::Invalid(RtrDecodeError::Oversized(
            meta.len() as usize,
        )));
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return Err(RtrError::Io(format!(
                "cannot read RTR {}: {}",
                path.display(),
                e
            )))
        }
    };
    match RestoreTransactionRecord::decode(&bytes) {
        Ok(rec) => Ok(RtrReadResult::Present(rec)),
        Err(d) => Ok(RtrReadResult::Invalid(d)),
    }
}

// ============================================================================
// Publication (atomic, durable)
// ============================================================================

/// Publish a record durably at `data_dir` using the selected temp-file →
/// `fsync` file → atomic `rename` → `fsync` parent-dir sequence (§5.9). A
/// temp artifact is never promoted into completion evidence.
pub fn publish_record(
    data_dir: &Path,
    record: &RestoreTransactionRecord,
) -> Result<(), RtrError> {
    use std::io::Write;

    let final_path = rtr_path(data_dir);
    let temp_path = data_dir.join(RTR_TEMP_FILENAME);
    let bytes = record.encode();

    // Write temp, fsync temp.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|e| {
                RtrError::Io(format!(
                    "cannot open temp RTR {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
        f.write_all(&bytes).map_err(|e| {
            RtrError::Io(format!(
                "cannot write temp RTR {}: {}",
                temp_path.display(),
                e
            ))
        })?;
        f.sync_all().map_err(|e| {
            RtrError::Io(format!(
                "cannot fsync temp RTR {}: {}",
                temp_path.display(),
                e
            ))
        })?;
    }

    // Atomic rename temp -> final.
    std::fs::rename(&temp_path, &final_path).map_err(|e| {
        RtrError::Io(format!(
            "cannot atomically publish RTR {} -> {}: {}",
            temp_path.display(),
            final_path.display(),
            e
        ))
    })?;

    // fsync the parent directory so the rename is durable.
    fsync_dir(data_dir)?;
    Ok(())
}

// ============================================================================
// Directory / file synchronization helpers
// ============================================================================

/// `fsync` a directory so a create/rename within it is durable. On non-Unix
/// targets this fails closed rather than silently succeeding.
pub fn fsync_dir(dir: &Path) -> Result<(), RtrError> {
    #[cfg(unix)]
    {
        let f = std::fs::File::open(dir).map_err(|e| {
            RtrError::Io(format!("cannot open dir for fsync {}: {}", dir.display(), e))
        })?;
        f.sync_all().map_err(|e| {
            RtrError::Io(format!("cannot fsync dir {}: {}", dir.display(), e))
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(RtrError::Io(
            "directory fsync is unsupported on this non-Unix platform \
             (restore-completion durability profile requires POSIX fsync)"
                .to_string(),
        ))
    }
}

/// `fsync` a single file at `path`.
pub fn fsync_file(path: &Path) -> Result<(), RtrError> {
    let f = std::fs::File::open(path).map_err(|e| {
        RtrError::Io(format!("cannot open file for fsync {}: {}", path.display(), e))
    })?;
    f.sync_all()
        .map_err(|e| RtrError::Io(format!("cannot fsync file {}: {}", path.display(), e)))
}

/// Recursively `fsync` every regular file under `dir`, then `fsync` `dir`
/// itself and each nested subdirectory. Used to persist a freshly copied
/// account-state tree and its directory entries (§5.9 step 4).
pub fn fsync_tree(dir: &Path) -> Result<(), RtrError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        RtrError::Io(format!("cannot read dir for fsync {}: {}", dir.display(), e))
    })?;
    for entry in entries {
        let entry = entry
            .map_err(|e| RtrError::Io(format!("cannot read dir entry: {}", e)))?;
        let ft = entry
            .file_type()
            .map_err(|e| RtrError::Io(format!("cannot stat dir entry: {}", e)))?;
        let path = entry.path();
        if ft.is_dir() {
            fsync_tree(&path)?;
        } else if ft.is_file() {
            fsync_file(&path)?;
        }
        // Other file types are not produced by the checkpoint copy; ignore.
    }
    fsync_dir(dir)
}

// ============================================================================
// OS RNG nonce
// ============================================================================

/// Draw a fresh per-attempt nonce from the OS RNG (§4.8.1). Reads 16 bytes from
/// `/dev/urandom`; fails closed on error (never a predictable fallback).
pub fn fresh_attempt_nonce() -> Result<[u8; 16], RtrError> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| {
        RtrError::Io(format!("cannot open /dev/urandom for attempt nonce: {}", e))
    })?;
    let mut nonce = [0u8; 16];
    f.read_exact(&mut nonce).map_err(|e| {
        RtrError::Io(format!("cannot read attempt nonce from /dev/urandom: {}", e))
    })?;
    Ok(nonce)
}

// ============================================================================
// Destination lock (§5.5)
// ============================================================================

/// A held advisory exclusive destination lock.
///
/// The lock is `flock(LOCK_EX | LOCK_NB)` on an open descriptor of
/// `<data_dir>/restore.lock`. It is the kernel lock on that open descriptor —
/// not the mere presence of the file. Ownership is expressed by holding this
/// value: dropping it (or the process dying) closes the descriptor and the
/// kernel auto-releases the lock. The lock file is **never** unlinked as a
/// signalling / stale-lock act. Passing this value through the startup path
/// (rather than re-acquiring) avoids nested independent acquisitions.
#[derive(Debug)]
pub struct DestinationLock {
    /// The open lock-file descriptor whose closure releases the lock. Held for
    /// process lifetime by the owner of this value.
    _file: std::fs::File,
    /// The lock path, for diagnostics only.
    path: PathBuf,
}

impl DestinationLock {
    /// The lock file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The outcome of a non-blocking destination-lock acquisition.
#[derive(Debug)]
pub enum LockAcquireError {
    /// Another participating process already holds the lock (`EWOULDBLOCK`).
    /// The contender must refuse (fail-closed).
    Contended(PathBuf),
    /// An explicit acquisition error (open / flock / unsupported platform).
    Io(String),
}

impl fmt::Display for LockAcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockAcquireError::Contended(p) => write!(
                f,
                "destination lock {} is already held by another participating process",
                p.display()
            ),
            LockAcquireError::Io(m) => write!(f, "destination lock error: {}", m),
        }
    }
}

impl std::error::Error for LockAcquireError {}

/// Acquire the advisory exclusive destination lock at `<data_dir>/restore.lock`
/// with `flock(LOCK_EX | LOCK_NB)` (§5.5).
///
/// `data_dir` must already exist. On contention returns
/// [`LockAcquireError::Contended`]; on any other failure (including non-Unix
/// platforms, where the operation is **not** silently succeeded) returns
/// [`LockAcquireError::Io`]. The returned [`DestinationLock`] must be held for
/// the process lifetime.
pub fn acquire_destination_lock(data_dir: &Path) -> Result<DestinationLock, LockAcquireError> {
    let path = data_dir.join(RESTORE_LOCK_FILENAME);
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // Open (create if missing) the stable lock object. The file is never
        // truncated or unlinked; only the kernel lock on this fd matters.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                LockAcquireError::Io(format!(
                    "cannot open destination lock {}: {}",
                    path.display(),
                    e
                ))
            })?;
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is a valid open descriptor owned by `file` for the
        // duration of this call; `flock` does not take ownership of it.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(DestinationLock { _file: file, path });
        }
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error();
        if raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN) {
            return Err(LockAcquireError::Contended(path));
        }
        Err(LockAcquireError::Io(format!(
            "flock(LOCK_EX|LOCK_NB) on {} failed: {}",
            path.display(),
            err
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = &path;
        Err(LockAcquireError::Io(
            "advisory destination locking is unsupported on this non-Unix platform \
             (restore-completion requires POSIX flock); refusing to proceed without \
             destination ownership"
                .to_string(),
        ))
    }
}

// ============================================================================
// Startup / restore-precondition decisions
// ============================================================================

/// The decision for an ordinary (no-flag) startup, from the observable final
/// RTR plus the actual destination (§4.5, §4.8).
#[derive(Debug, Clone)]
pub enum OrdinaryStartupDecision {
    /// No RTR (untracked / ordinary lifecycle) — proceed.
    ProceedAbsent,
    /// Valid `COMPLETE` for this destination with `state_vm_v0` present —
    /// proceed and admit the restored state (no re-copy, no epoch re-write).
    ProceedComplete,
    /// A tracked interrupted restore (`INTENT`) — refuse, fail-closed.
    RefuseIntent,
    /// A corrupt / unsupported / malformed / unreadable record — refuse.
    RefuseInvalid(String),
    /// A `COMPLETE` whose recorded destination does not match — refuse.
    RefuseForeign { recorded: String, actual: String },
    /// A `COMPLETE` whose required installed state is missing/empty/unreadable
    /// — refuse; do not recreate.
    RefuseMissingState(String),
}

impl OrdinaryStartupDecision {
    /// Whether this decision permits ordinary startup to proceed.
    pub fn permits_startup(&self) -> bool {
        matches!(
            self,
            OrdinaryStartupDecision::ProceedAbsent | OrdinaryStartupDecision::ProceedComplete
        )
    }
}

/// Whether `state_vm_v0` under `data_dir` is present and non-empty. A
/// missing/empty/unreadable required state behind a `COMPLETE` is refused.
fn state_vm_v0_present(data_dir: &Path) -> Result<bool, RtrError> {
    let dir = data_dir.join(crate::snapshot_restore::VM_V0_STATE_SUBDIR);
    match std::fs::read_dir(&dir) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(RtrError::Io(format!(
            "cannot read installed state {}: {}",
            dir.display(),
            e
        ))),
    }
}

/// Evaluate the ordinary (no-flag) startup RTR guard (§4.5, §7).
///
/// `data_dir` must already exist and be canonicalizable. This performs no
/// mutation. A historical `COMPLETE` is admitted only after validating the
/// record, that the recorded `destination_id` matches the actual destination,
/// and that `state_vm_v0` is present; it never re-copies state or rewrites the
/// epoch. `INTENT`, corrupt, foreign, or missing-state cases refuse.
pub fn evaluate_ordinary_startup(data_dir: &Path) -> OrdinaryStartupDecision {
    let read = match read_rtr(data_dir) {
        Ok(r) => r,
        // A present-but-unreadable RTR is fail-closed.
        Err(e) => return OrdinaryStartupDecision::RefuseInvalid(e.to_string()),
    };
    match read {
        RtrReadResult::Absent => OrdinaryStartupDecision::ProceedAbsent,
        RtrReadResult::Invalid(d) => OrdinaryStartupDecision::RefuseInvalid(d.to_string()),
        RtrReadResult::Present(rec) => match rec.state {
            RtrState::Intent => OrdinaryStartupDecision::RefuseIntent,
            RtrState::Complete => {
                let actual = match DestinationId::canonicalize(data_dir) {
                    Ok(d) => d,
                    Err(e) => {
                        return OrdinaryStartupDecision::RefuseInvalid(e.to_string())
                    }
                };
                if rec.destination_id != actual.as_str() {
                    return OrdinaryStartupDecision::RefuseForeign {
                        recorded: rec.destination_id,
                        actual: actual.as_str().to_string(),
                    };
                }
                match state_vm_v0_present(data_dir) {
                    Ok(true) => OrdinaryStartupDecision::ProceedComplete,
                    Ok(false) => OrdinaryStartupDecision::RefuseMissingState(
                        "state_vm_v0 is missing or empty behind a COMPLETE record".to_string(),
                    ),
                    Err(e) => OrdinaryStartupDecision::RefuseMissingState(e.to_string()),
                }
            }
        },
    }
}

/// The precondition decision for a requested restore (with-flag), inspecting
/// the existing RTR before validation/mutation (§5.9 step 1(b)).
#[derive(Debug, Clone)]
pub enum RequestedRestorePrecondition {
    /// No existing RTR — the restore attempt may proceed to validation.
    ProceedNoExistingRtr,
    /// An existing `INTENT` or `COMPLETE` occupies the destination — refuse
    /// (no idempotent-success route; operator clears/replaces before retry).
    RefuseOccupied(RtrState),
    /// A corrupt / unsupported / unreadable existing record — refuse.
    RefuseInvalid(String),
}

/// Inspect the existing RTR to decide whether a requested restore may proceed
/// to validation (§5.9 step 1(b), §4.5). A new attempt never overwrites or
/// replaces an existing RTR; any existing record (valid `INTENT`/`COMPLETE` or
/// corrupt) refuses.
pub fn evaluate_requested_restore_precondition(
    data_dir: &Path,
) -> RequestedRestorePrecondition {
    match read_rtr(data_dir) {
        Ok(RtrReadResult::Absent) => RequestedRestorePrecondition::ProceedNoExistingRtr,
        Ok(RtrReadResult::Present(rec)) => {
            RequestedRestorePrecondition::RefuseOccupied(rec.state)
        }
        Ok(RtrReadResult::Invalid(d)) => {
            RequestedRestorePrecondition::RefuseInvalid(d.to_string())
        }
        Err(e) => RequestedRestorePrecondition::RefuseInvalid(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(state: RtrState) -> RestoreTransactionRecord {
        RestoreTransactionRecord {
            version: RTR_VERSION,
            state,
            destination_id: "/data/qbind".to_string(),
            snapshot_meta_digest: [7u8; 32],
            attempt_nonce: [9u8; 16],
            expected_epoch: Some(7),
        }
    }

    #[test]
    fn encode_decode_roundtrip_intent() {
        let rec = sample_record(RtrState::Intent);
        let bytes = rec.encode();
        let decoded = RestoreTransactionRecord::decode(&bytes).expect("decode");
        assert_eq!(decoded, rec);
    }

    #[test]
    fn encode_decode_roundtrip_complete_none_epoch() {
        let mut rec = sample_record(RtrState::Complete);
        rec.expected_epoch = None;
        let bytes = rec.encode();
        let decoded = RestoreTransactionRecord::decode(&bytes).expect("decode");
        assert_eq!(decoded, rec);
        assert_eq!(decoded.expected_epoch, None);
    }

    #[test]
    fn epoch_none_distinct_from_zero() {
        let mut a = sample_record(RtrState::Complete);
        a.expected_epoch = None;
        let mut b = sample_record(RtrState::Complete);
        b.expected_epoch = Some(0);
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn truncated_is_refused() {
        let rec = sample_record(RtrState::Intent);
        let bytes = rec.encode();
        let err = RestoreTransactionRecord::decode(&bytes[..bytes.len() - 1])
            .expect_err("truncation must fail");
        // Dropping the last byte breaks the checksum length → Truncated
        // (short of expected_total) is the classification here.
        assert!(matches!(
            err,
            RtrDecodeError::Truncated | RtrDecodeError::Corrupt
        ));
    }

    #[test]
    fn trailing_data_is_refused() {
        let rec = sample_record(RtrState::Intent);
        let mut bytes = rec.encode();
        bytes.push(0xAB);
        let err = RestoreTransactionRecord::decode(&bytes).expect_err("trailing must fail");
        assert_eq!(err, RtrDecodeError::TrailingData);
    }

    #[test]
    fn oversized_is_refused() {
        let big = vec![0u8; RTR_MAX_RECORD_SIZE + 1];
        let err = RestoreTransactionRecord::decode(&big).expect_err("oversize must fail");
        assert!(matches!(err, RtrDecodeError::Oversized(_)));
    }

    #[test]
    fn unsupported_version_is_refused() {
        let rec = sample_record(RtrState::Intent);
        let mut bytes = rec.encode();
        // Corrupt the version field (bytes 8..12) to 999 and re-checksum so the
        // ONLY failure is the version check.
        bytes[8..12].copy_from_slice(&999u32.to_be_bytes());
        let body_len = bytes.len() - RTR_CHECKSUM_LEN;
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes[..body_len]);
        let cs = hasher.finalize();
        bytes[body_len..].copy_from_slice(&cs);
        let err = RestoreTransactionRecord::decode(&bytes).expect_err("bad version");
        assert_eq!(err, RtrDecodeError::UnsupportedVersion(999));
    }

    #[test]
    fn corruption_is_detected() {
        let rec = sample_record(RtrState::Intent);
        let mut bytes = rec.encode();
        // Flip a byte in the digest region without fixing the checksum.
        bytes[30] ^= 0xFF;
        let err = RestoreTransactionRecord::decode(&bytes).expect_err("corruption");
        assert_eq!(err, RtrDecodeError::Corrupt);
    }

    #[test]
    fn oversized_dest_len_refused_before_alloc() {
        let rec = sample_record(RtrState::Intent);
        let mut bytes = rec.encode();
        // Set dest_len (bytes 72..76) to a huge value.
        bytes[72..76].copy_from_slice(&(u32::MAX).to_be_bytes());
        let err = RestoreTransactionRecord::decode(&bytes).expect_err("huge dest_len");
        assert!(matches!(err, RtrDecodeError::Malformed(_)));
    }

    #[test]
    fn digest_binds_authority_fields() {
        // Two metas differing only in authority_state must produce different
        // digests (binding covers the whole validated metadata).
        use qbind_ledger::state_snapshot::AuthorityStateSnapshotMeta;
        let base = StateSnapshotMeta::new(10, [1u8; 32], 123, 0x42);
        let with_auth = base.clone().with_authority_state(Some(AuthorityStateSnapshotMeta {
            chain_id_hex: "0000000000000042".to_string(),
            environment: "devnet".to_string(),
            genesis_hash_hex: "ab".repeat(32),
            authority_policy_version: 1,
            authority_sequence: 3,
            authority_epoch: Some(2),
            authority_root_fingerprint: "cd".repeat(16),
            ratified_bundle_signing_key_fingerprint: "ef".repeat(16),
            ratification_object_hash: "12".repeat(32),
        }));
        assert_ne!(
            snapshot_meta_digest(&base),
            snapshot_meta_digest(&with_auth)
        );
    }

    #[test]
    fn publish_then_read_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rec = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &rec).expect("publish");
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Present(got) => assert_eq!(got, rec),
            other => panic!("expected present, got {other:?}"),
        }
        // The temp artifact must not remain.
        assert!(!tmp.path().join(RTR_TEMP_FILENAME).exists());
    }

    #[test]
    fn read_absent_when_no_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Absent
        ));
    }

    #[cfg(unix)]
    #[test]
    fn second_lock_acquisition_is_contended() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = acquire_destination_lock(tmp.path()).expect("first lock");
        match acquire_destination_lock(tmp.path()) {
            Err(LockAcquireError::Contended(_)) => {}
            other => panic!("expected contention, got {other:?}"),
        }
        drop(first);
        // After release the lock is re-acquirable.
        let _second = acquire_destination_lock(tmp.path()).expect("re-acquire after release");
    }

    #[test]
    fn ordinary_startup_absent_proceeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::ProceedAbsent
        ));
    }

    #[test]
    fn ordinary_startup_intent_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = DestinationId::canonicalize(tmp.path()).expect("canon");
        let rec =
            RestoreTransactionRecord::new_intent(&dest, [1u8; 32], [2u8; 16], Some(3));
        publish_record(tmp.path(), &rec).expect("publish");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::RefuseIntent
        ));
    }

    #[test]
    fn ordinary_startup_complete_missing_state_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = DestinationId::canonicalize(tmp.path()).expect("canon");
        let rec = RestoreTransactionRecord::new_intent(&dest, [1u8; 32], [2u8; 16], Some(3))
            .into_complete();
        publish_record(tmp.path(), &rec).expect("publish");
        // No state_vm_v0 present.
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::RefuseMissingState(_)
        ));
    }

    #[test]
    fn ordinary_startup_complete_with_state_proceeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = DestinationId::canonicalize(tmp.path()).expect("canon");
        let rec = RestoreTransactionRecord::new_intent(&dest, [1u8; 32], [2u8; 16], Some(3))
            .into_complete();
        publish_record(tmp.path(), &rec).expect("publish");
        let state = tmp.path().join(crate::snapshot_restore::VM_V0_STATE_SUBDIR);
        std::fs::create_dir_all(&state).expect("mk state");
        std::fs::write(state.join("CURRENT"), b"x").expect("write state file");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::ProceedComplete
        ));
    }

    #[test]
    fn ordinary_startup_foreign_complete_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Record a COMPLETE with a bogus (foreign) destination id.
        let mut rec = sample_record(RtrState::Complete);
        rec.destination_id = "/some/other/dest".to_string();
        publish_record(tmp.path(), &rec).expect("publish");
        let state = tmp.path().join(crate::snapshot_restore::VM_V0_STATE_SUBDIR);
        std::fs::create_dir_all(&state).expect("mk state");
        std::fs::write(state.join("CURRENT"), b"x").expect("write state file");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::RefuseForeign { .. }
        ));
    }

    #[test]
    fn requested_restore_precondition_occupied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = DestinationId::canonicalize(tmp.path()).expect("canon");
        let rec =
            RestoreTransactionRecord::new_intent(&dest, [1u8; 32], [2u8; 16], Some(3));
        publish_record(tmp.path(), &rec).expect("publish");
        assert!(matches!(
            evaluate_requested_restore_precondition(tmp.path()),
            RequestedRestorePrecondition::RefuseOccupied(RtrState::Intent)
        ));
    }

    #[test]
    fn requested_restore_precondition_absent_proceeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            evaluate_requested_restore_precondition(tmp.path()),
            RequestedRestorePrecondition::ProceedNoExistingRtr
        ));
    }
}
