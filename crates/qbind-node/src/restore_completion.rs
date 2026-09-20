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

/// The outcome of a bounded read of the authoritative final record's bytes
/// (Correction B). Distinguishes an over-limit object from an in-limit one,
/// without ever trusting file metadata or an encoded length field to size an
/// allocation. Absence is handled separately at open time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedRecordBytes {
    /// The opened object supplied strictly more than the configured maximum;
    /// the single detection byte beyond the limit was observed. Over-limit
    /// input is rejected before decoding.
    Oversized,
    /// The opened object supplied at most the configured maximum bytes.
    Bytes(Vec<u8>),
}

/// Bounded read of an already-opened final-record reader (Correction B).
///
/// Reads at most `max + 1` bytes using checked arithmetic: the `+ 1` is a
/// single detection byte that lets an over-limit object be distinguished from a
/// maximum-size one WITHOUT trusting any advertised/metadata length. The
/// allocation is bounded by `max + 1` regardless of how many bytes the reader
/// actually supplies, so a source that yields more bytes than its initial
/// advertised size can never force an unbounded buffer. An I/O failure
/// (including one after a partial read) is propagated as a refusal, never
/// absence or success.
pub(crate) fn read_bounded_final_record_bytes<R: std::io::Read>(
    mut reader: R,
    max: usize,
    what: &str,
) -> Result<BoundedRecordBytes, RtrError> {
    let cap = max
        .checked_add(1)
        .ok_or_else(|| RtrError::Io(format!("bounded read limit overflow for {}", what)))?;
    let mut buf = Vec::with_capacity(cap);
    // `take(cap)` caps the total bytes `read_to_end` will consume/allocate at
    // `cap`, independent of any advertised length; failures propagate as Io.
    use std::io::Read as _;
    let read = std::io::Read::take(&mut reader, cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| RtrError::Io(format!("cannot read {}: {}", what, e)))?;
    debug_assert_eq!(read, buf.len());
    if buf.len() > max {
        // At least one byte beyond the limit was present ⇒ over-limit; reject
        // before decoding and without reading/allocating the whole object.
        return Ok(BoundedRecordBytes::Oversized);
    }
    Ok(BoundedRecordBytes::Bytes(buf))
}

/// Open the authoritative final record at `path`, refusing a non-regular file
/// and failing closed on any open/stat error (Correction B).
///
/// Returns `Ok(None)` ONLY for a genuinely absent record (open ⇒ NotFound).
/// The open validates the OPENED object: the authoritative final component is
/// opened WITHOUT following a symlink (Correction A) — a final-component symlink
/// is refused whether its target exists or is dangling, closing the prior hole
/// where a dangling symlink was mis-mapped to `NotFound`/absence even though a
/// directory entry existed. The opened object MUST be a regular file; a FIFO,
/// device, socket, directory, symlink, or other special file is refused. On the
/// supported Unix profile the open combines `O_NOFOLLOW` (atomic no-follow of
/// the final component; a separate stat-then-open would be a check-then-follow
/// race) with `O_NONBLOCK` so a FIFO (or other special file) cannot block
/// startup during the open itself — the object is classified and refused
/// without blocking. Neither flag has an adverse effect on a regular file.
///
/// A genuinely absent final record (no directory entry) still opens to
/// `NotFound` and is treated as absence; a final-component symlink instead
/// fails the no-follow open (`ELOOP`) and is refused, never absence.
fn open_regular_final_record(path: &Path) -> Result<Option<std::fs::File>, RtrError> {
    let open_result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(path)
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new().read(true).open(path)
        }
    };
    let file = match open_result {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(RtrError::Io(format!(
                "cannot open RTR {}: {}",
                path.display(),
                e
            )))
        }
    };
    let meta = file.metadata().map_err(|e| {
        RtrError::Io(format!(
            "cannot stat opened RTR {}: {}",
            path.display(),
            e
        ))
    })?;
    if !meta.file_type().is_file() {
        return Err(RtrError::Io(format!(
            "RTR {} is not a regular file ({:?}); refusing (fail-closed)",
            path.display(),
            meta.file_type()
        )));
    }
    Ok(Some(file))
}

/// Read and classify the final RTR at `data_dir`.
///
/// A missing file is [`RtrReadResult::Absent`]. A present-but-unreadable file
/// is an IO error (fail-closed). A present-but-undecodable file is
/// [`RtrReadResult::Invalid`]. Only a strictly valid record yields
/// [`RtrReadResult::Present`].
///
/// Correction B: the read is bounded during the read itself. The authoritative
/// final record is opened ONCE; the opened object is validated as a regular
/// file (special files are refused without a blocking open); at most
/// [`RTR_MAX_RECORD_SIZE`] plus one detection byte are read using checked
/// arithmetic; an over-limit object is rejected before decoding. No buffer is
/// ever allocated from file metadata or an encoded length, so a file that grows
/// (or advertises a smaller size than it supplies) between operations cannot
/// force an unbounded read. Absent semantics are preserved ONLY for a genuinely
/// absent final record; every I/O failure — including one after a partial read
/// — is a refusal, never absence or success.
pub fn read_rtr(data_dir: &Path) -> Result<RtrReadResult, RtrError> {
    let path = rtr_path(data_dir);
    let file = match open_regular_final_record(&path)? {
        Some(f) => f,
        None => return Ok(RtrReadResult::Absent),
    };
    let what = format!("RTR {}", path.display());
    match read_bounded_final_record_bytes(file, RTR_MAX_RECORD_SIZE, &what)? {
        BoundedRecordBytes::Oversized => {
            // Report the smallest known over-limit length; the reader never
            // consumed (or trusted) the object's full advertised size.
            Ok(RtrReadResult::Invalid(RtrDecodeError::Oversized(
                RTR_MAX_RECORD_SIZE + 1,
            )))
        }
        BoundedRecordBytes::Bytes(bytes) => match RestoreTransactionRecord::decode(&bytes) {
            Ok(rec) => Ok(RtrReadResult::Present(rec)),
            Err(d) => Ok(RtrReadResult::Invalid(d)),
        },
    }
}

// ============================================================================
// Publication (atomic, durable)
// ============================================================================

/// The stage at which a [`publish_record`] operation failed (§5.9).
///
/// The publication sequence is temp-write → temp-`fsync` → atomic `rename` →
/// parent-directory `fsync`. Reporting the ACTUAL stage is required so a caller
/// never asserts an unobserved final on-disk state: a failure AFTER the rename
/// may have already left the new record at the final pathname, so the prior
/// record can NOT be claimed to be retained.
#[derive(Debug, Clone)]
pub enum PublishError {
    /// The failure occurred BEFORE the atomic replacement (temp open, write,
    /// `fsync`, or the `rename` itself failed). The previously published final
    /// record — if any — remains authoritative and unmodified.
    BeforeReplace(RtrError),
    /// The atomic `rename` succeeded but the subsequent parent-directory
    /// `fsync` failed. The final pathname may ALREADY contain the new record,
    /// but its durability is unacknowledged. A caller MUST NOT assert that the
    /// prior record is retained; it must fail closed and let a later startup
    /// classify the actual final record under the accepted contract.
    AfterReplace(RtrError),
}

impl PublishError {
    /// The underlying IO error, regardless of stage.
    pub fn io(&self) -> &RtrError {
        match self {
            PublishError::BeforeReplace(e) | PublishError::AfterReplace(e) => e,
        }
    }

    /// Whether the atomic replacement had ALREADY occurred when the failure was
    /// observed (so the prior record can NOT be claimed retained).
    pub fn replaced(&self) -> bool {
        matches!(self, PublishError::AfterReplace(_))
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishError::BeforeReplace(e) => write!(
                f,
                "restore-transaction publication failed before atomic replacement \
                 (prior final record retained): {e}"
            ),
            PublishError::AfterReplace(e) => write!(
                f,
                "restore-transaction publication failed AFTER atomic replacement but \
                 before its directory-sync was acknowledged (the final record may \
                 already be the new record; the prior record is NOT retained): {e}"
            ),
        }
    }
}

impl std::error::Error for PublishError {}

/// Publish a record durably at `data_dir` using the temp-file → `fsync` file →
/// atomic `rename` → `fsync` parent-dir sequence (§5.9). A temp artifact is
/// never promoted into completion evidence.
///
/// On failure the returned [`PublishError`] distinguishes a failure BEFORE the
/// atomic replacement (prior record retained) from a failure AFTER it (the new
/// record may already be final; the prior record is NOT retained).
pub fn publish_record(
    data_dir: &Path,
    record: &RestoreTransactionRecord,
) -> Result<(), PublishError> {
    publish_record_inner(data_dir, record, &|dir| fsync_dir(dir))
}

/// Internal publication with an injectable post-rename directory-sync step so
/// tests can deterministically exercise the AFTER-replacement failure boundary
/// without any production fault-injection flag or environment switch. Production
/// callers use [`publish_record`], which always passes the real [`fsync_dir`].
fn publish_record_inner(
    data_dir: &Path,
    record: &RestoreTransactionRecord,
    dir_sync: &dyn Fn(&Path) -> Result<(), RtrError>,
) -> Result<(), PublishError> {
    use std::io::Write;

    let final_path = rtr_path(data_dir);
    let temp_path = data_dir.join(RTR_TEMP_FILENAME);
    let bytes = record.encode();

    // Write temp, fsync temp. Any failure here is BEFORE replacement.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|e| {
                PublishError::BeforeReplace(RtrError::Io(format!(
                    "cannot open temp RTR {}: {}",
                    temp_path.display(),
                    e
                )))
            })?;
        f.write_all(&bytes).map_err(|e| {
            PublishError::BeforeReplace(RtrError::Io(format!(
                "cannot write temp RTR {}: {}",
                temp_path.display(),
                e
            )))
        })?;
        f.sync_all().map_err(|e| {
            PublishError::BeforeReplace(RtrError::Io(format!(
                "cannot fsync temp RTR {}: {}",
                temp_path.display(),
                e
            )))
        })?;
    }

    // Atomic rename temp -> final. A failure here leaves the prior final record
    // in place (BEFORE replacement).
    std::fs::rename(&temp_path, &final_path).map_err(|e| {
        PublishError::BeforeReplace(RtrError::Io(format!(
            "cannot atomically publish RTR {} -> {}: {}",
            temp_path.display(),
            final_path.display(),
            e
        )))
    })?;

    // fsync the parent directory so the rename is durable. The rename has
    // ALREADY replaced the final pathname; a failure here is AFTER replacement
    // and must never be reported as "prior record retained".
    dir_sync(data_dir).map_err(PublishError::AfterReplace)?;
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

/// Whether `state_vm_v0` under `data_dir` is present and non-empty, failing
/// closed on any directory-read error.
///
/// This is a cheap STRUCTURAL pre-filter only: it refuses an absent or empty
/// state directory, and a directory-entry read error is treated as a failure
/// (NOT as presence). It deliberately does NOT attempt to distinguish an
/// unrelated file from a real account database — a non-empty directory is not,
/// by itself, an existing database. The authoritative existing-database check
/// is performed by opening the account state with create-if-missing DISABLED
/// (`RocksDbAccountState::open_existing`, wired through
/// `VmV0RuntimeState::open_existing_from_config`) on the COMPLETE admission
/// path, which fails closed for a directory that does not contain an openable
/// database and never initializes a replacement. See
/// `docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md` §7.
fn state_vm_v0_present(data_dir: &Path) -> Result<bool, RtrError> {
    let dir = data_dir.join(crate::snapshot_restore::VM_V0_STATE_SUBDIR);
    let mut entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(RtrError::Io(format!(
                "cannot read installed state {}: {}",
                dir.display(),
                e
            )))
        }
    };
    match entries.next() {
        // A successfully-read first entry proves the directory is non-empty.
        Some(Ok(_)) => Ok(true),
        // A directory-entry read error is a failure, NOT presence (fail-closed).
        Some(Err(e)) => Err(RtrError::Io(format!(
            "cannot read installed state entry under {}: {}",
            dir.display(),
            e
        ))),
        None => Ok(false),
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

// ============================================================================
// Active-attempt finalization (INTENT -> COMPLETE transition)
// ============================================================================

/// Why an on-disk final record failed to match the expected published INTENT
/// during finalization (§5.9 step 9, active-attempt binding). Every variant
/// suppresses `COMPLETE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentMismatch {
    /// The on-disk record is not in `INTENT` state (e.g. already `COMPLETE`).
    WrongState { found: RtrState },
    /// The on-disk record binds a different destination.
    WrongDestination { expected: String, found: String },
    /// The on-disk record binds a different per-attempt nonce.
    WrongNonce,
    /// The on-disk record binds a different whole-metadata digest.
    WrongDigest,
    /// The on-disk record binds a different expected epoch (preserving the
    /// `None` vs `Some(0)` distinction).
    WrongEpoch {
        expected: Option<u64>,
        found: Option<u64>,
    },
    /// The on-disk record has a different schema version.
    WrongVersion { found: u32 },
}

impl fmt::Display for IntentMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntentMismatch::WrongState { found } => {
                write!(f, "on-disk record is {} (expected INTENT)", found.tag())
            }
            IntentMismatch::WrongDestination { expected, found } => write!(
                f,
                "on-disk record binds a different destination (expected={expected}, found={found})"
            ),
            IntentMismatch::WrongNonce => {
                write!(f, "on-disk record binds a different per-attempt nonce")
            }
            IntentMismatch::WrongDigest => {
                write!(f, "on-disk record binds a different whole-metadata digest")
            }
            IntentMismatch::WrongEpoch { expected, found } => write!(
                f,
                "on-disk record binds a different expected epoch (expected={expected:?}, found={found:?})"
            ),
            IntentMismatch::WrongVersion { found } => {
                write!(f, "on-disk record has a different schema version {found}")
            }
        }
    }
}

/// A finalization failure (§5.9 step 9). `COMPLETE` is suppressed and the
/// inconsistent on-disk evidence is NOT overwritten.
#[derive(Debug)]
pub enum FinalizeError {
    /// The authoritative final record is absent, undecodable, or unreadable.
    ExpectedIntentUnavailable(String),
    /// The authoritative final record does not match the expected published
    /// INTENT identity for this active attempt.
    Mismatch(IntentMismatch),
    /// The expected INTENT identity supplied by the caller is itself not a
    /// well-formed `INTENT` (programming error; fail closed).
    ExpectedNotIntent,
    /// Publishing the `COMPLETE` record failed (stage-classified).
    Publish(PublishError),
}

impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FinalizeError::ExpectedIntentUnavailable(m) => write!(
                f,
                "cannot finalize COMPLETE: authoritative INTENT record unavailable: {m}"
            ),
            FinalizeError::Mismatch(m) => write!(
                f,
                "cannot finalize COMPLETE: active-attempt binding mismatch: {m}"
            ),
            FinalizeError::ExpectedNotIntent => write!(
                f,
                "cannot finalize COMPLETE: the supplied expected record is not an INTENT"
            ),
            FinalizeError::Publish(e) => {
                write!(f, "cannot finalize COMPLETE: publication failed: {e}")
            }
        }
    }
}

impl std::error::Error for FinalizeError {}

/// Validate and perform the INTENT→COMPLETE transition for the active attempt
/// while destination ownership is held (§5.9 step 9, active-attempt binding).
///
/// `expected_intent` is the identity of the `INTENT` this process successfully
/// published for the current attempt. The authoritative final record on disk is
/// re-read and must match it exactly (state `INTENT`, same destination, nonce,
/// whole-metadata digest, expected epoch preserving `None` vs `Some(0)`, and
/// version). Only then is the RETAINED INTENT identity promoted to `COMPLETE`
/// and published. Any mismatch suppresses `COMPLETE` and leaves the
/// inconsistent evidence untouched — the transition never overwrites an
/// inconsistent active attempt with a freshly reconstructed success record.
pub fn finalize_complete_from_intent(
    data_dir: &Path,
    expected_intent: &RestoreTransactionRecord,
) -> Result<(), FinalizeError> {
    if expected_intent.state != RtrState::Intent {
        return Err(FinalizeError::ExpectedNotIntent);
    }
    let found = match read_rtr(data_dir) {
        Ok(RtrReadResult::Present(rec)) => rec,
        Ok(RtrReadResult::Absent) => {
            return Err(FinalizeError::ExpectedIntentUnavailable(
                "no restore-transaction record present at finalization".to_string(),
            ))
        }
        Ok(RtrReadResult::Invalid(d)) => {
            return Err(FinalizeError::ExpectedIntentUnavailable(d.to_string()))
        }
        Err(e) => return Err(FinalizeError::ExpectedIntentUnavailable(e.to_string())),
    };
    check_intent_matches(expected_intent, &found).map_err(FinalizeError::Mismatch)?;
    // Promote the RETAINED intent identity (not a fresh reconstruction of
    // unknown provenance) to COMPLETE and publish it durably.
    let complete = expected_intent.clone().into_complete();
    publish_record(data_dir, &complete).map_err(FinalizeError::Publish)
}

/// Compare the authoritative on-disk record against the expected published
/// INTENT identity. `found` must be an `INTENT` with identical version,
/// destination, nonce, digest, and epoch.
fn check_intent_matches(
    expected: &RestoreTransactionRecord,
    found: &RestoreTransactionRecord,
) -> Result<(), IntentMismatch> {
    if found.state != RtrState::Intent {
        return Err(IntentMismatch::WrongState { found: found.state });
    }
    if found.version != expected.version {
        return Err(IntentMismatch::WrongVersion {
            found: found.version,
        });
    }
    if found.destination_id != expected.destination_id {
        return Err(IntentMismatch::WrongDestination {
            expected: expected.destination_id.clone(),
            found: found.destination_id.clone(),
        });
    }
    if found.attempt_nonce != expected.attempt_nonce {
        return Err(IntentMismatch::WrongNonce);
    }
    if found.snapshot_meta_digest != expected.snapshot_meta_digest {
        return Err(IntentMismatch::WrongDigest);
    }
    if found.expected_epoch != expected.expected_epoch {
        return Err(IntentMismatch::WrongEpoch {
            expected: expected.expected_epoch,
            found: found.expected_epoch,
        });
    }
    Ok(())
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
    fn digest_binds_authority_state_v2_field() {
        // Independently of the v1 authority_state, a change to authority_state_v2
        // alone must change the whole-metadata digest (§4.1 binding covers the
        // full validated metadata, including the v2 marker carrier).
        use qbind_ledger::state_snapshot::AuthorityStateSnapshotMetaV2;
        let base = StateSnapshotMeta::new(10, [1u8; 32], 123, 0x42);
        let with_v2 = base.clone().with_authority_state_v2(Some(AuthorityStateSnapshotMetaV2 {
            chain_id_hex: "0000000000000042".to_string(),
            environment: "devnet".to_string(),
            genesis_hash_hex: "ab".repeat(32),
            authority_root_fingerprint: "cd".repeat(16),
            authority_root_suite_id: 1,
            active_bundle_signing_key_fingerprint: "ef".repeat(16),
            active_bundle_signing_key_suite_id: 1,
            latest_authority_domain_sequence: 3,
            latest_lifecycle_action_byte: 0,
            previous_bundle_signing_key_fingerprint: None,
            latest_ratification_v2_digest: "12".repeat(32),
            revoked_key_metadata: None,
        }));
        assert_ne!(
            snapshot_meta_digest(&base),
            snapshot_meta_digest(&with_v2)
        );
        // Changing a single v2 field again produces a distinct digest.
        let mut mutated = with_v2.clone();
        if let Some(v2) = mutated.authority_state_v2.as_mut() {
            v2.latest_authority_domain_sequence = 4;
        }
        assert_ne!(
            snapshot_meta_digest(&with_v2),
            snapshot_meta_digest(&mutated)
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

    // ------------------------------------------------------------------
    // Correction C — publication failures reported by their actual stage.
    // ------------------------------------------------------------------

    #[test]
    fn publish_before_replace_retains_prior_final_record() {
        // A prior valid INTENT is authoritative.
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");

        // Force a BEFORE-rename failure deterministically: make the temp path a
        // directory so opening it as a file fails before any rename.
        let temp_path = tmp.path().join(RTR_TEMP_FILENAME);
        std::fs::create_dir(&temp_path).expect("mk temp dir");

        let complete = intent.clone().into_complete();
        let err = publish_record(tmp.path(), &complete).expect_err("must fail before replace");
        assert!(matches!(err, PublishError::BeforeReplace(_)));
        assert!(!err.replaced());

        // The prior final record is retained: still the original INTENT.
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Present(rec) => {
                assert_eq!(rec.state, RtrState::Intent);
                assert_eq!(rec, intent);
            }
            other => panic!("expected present INTENT, got {other:?}"),
        }
    }

    #[test]
    fn publish_after_replace_reports_failure_final_may_be_new() {
        // Failure AFTER rename but before directory-sync: the operation reports
        // failure, but the final record may ALREADY be the new record. No false
        // "prior retained" assertion is made.
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");

        let complete = intent.clone().into_complete();
        let failing_dir_sync =
            |_dir: &Path| -> Result<(), RtrError> { Err(RtrError::Io("injected dir-sync failure".to_string())) };
        let err = publish_record_inner(tmp.path(), &complete, &failing_dir_sync)
            .expect_err("must fail after replace");
        assert!(matches!(err, PublishError::AfterReplace(_)));
        assert!(err.replaced());

        // The rename already happened: the final record is the NEW COMPLETE.
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Present(rec) => {
                assert_eq!(rec.state, RtrState::Complete);
                assert_eq!(rec, complete);
            }
            other => panic!("expected present COMPLETE, got {other:?}"),
        }
    }

    #[test]
    fn temp_artifact_never_authorizes_startup() {
        // A lone temp artifact (no final record) is NOT a completion record:
        // the destination reads as Absent.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(RTR_TEMP_FILENAME), b"partial-junk").expect("write temp");
        assert!(matches!(read_rtr(tmp.path()).expect("read"), RtrReadResult::Absent));
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::ProceedAbsent
        ));

        // A temp artifact alongside a valid final INTENT does not upgrade it:
        // the final INTENT still refuses ordinary startup.
        let dest = DestinationId::canonicalize(tmp.path()).expect("canon");
        let intent = RestoreTransactionRecord::new_intent(&dest, [1u8; 32], [2u8; 16], Some(3));
        publish_record(tmp.path(), &intent).expect("publish intent");
        std::fs::write(tmp.path().join(RTR_TEMP_FILENAME), b"partial-junk").expect("write temp");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::RefuseIntent
        ));
    }

    // ------------------------------------------------------------------
    // state_vm_v0_present — non-empty directory is not silently "present".
    // ------------------------------------------------------------------

    #[test]
    fn state_present_absent_and_empty_are_false() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Absent state dir.
        assert!(!state_vm_v0_present(tmp.path()).expect("absent ok"));
        // Empty state dir.
        std::fs::create_dir_all(tmp.path().join(crate::snapshot_restore::VM_V0_STATE_SUBDIR))
            .expect("mk empty state");
        assert!(!state_vm_v0_present(tmp.path()).expect("empty ok"));
    }

    #[test]
    fn state_present_nonempty_is_true_prefilter_only() {
        // A non-empty directory passes the cheap structural pre-filter; the
        // authoritative existing-database check happens at open time.
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = tmp.path().join(crate::snapshot_restore::VM_V0_STATE_SUBDIR);
        std::fs::create_dir_all(&state).expect("mk state");
        std::fs::write(state.join("UNRELATED_SENTINEL"), b"x").expect("write sentinel");
        assert!(state_vm_v0_present(tmp.path()).expect("nonempty ok"));
    }

    // ------------------------------------------------------------------
    // Active-attempt binding — INTENT->COMPLETE transition validation.
    // ------------------------------------------------------------------

    #[test]
    fn finalize_success_publishes_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");
        finalize_complete_from_intent(tmp.path(), &intent).expect("finalize");
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Present(rec) => {
                assert_eq!(rec.state, RtrState::Complete);
                assert_eq!(rec.attempt_nonce, intent.attempt_nonce);
                assert_eq!(rec.snapshot_meta_digest, intent.snapshot_meta_digest);
                assert_eq!(rec.destination_id, intent.destination_id);
                assert_eq!(rec.expected_epoch, intent.expected_epoch);
            }
            other => panic!("expected COMPLETE, got {other:?}"),
        }
    }

    /// Assert the on-disk record is still the original untouched INTENT.
    fn assert_still_intent(dir: &Path, expected: &RestoreTransactionRecord) {
        match read_rtr(dir).expect("read") {
            RtrReadResult::Present(rec) => {
                assert_eq!(rec.state, RtrState::Intent);
                assert_eq!(&rec, expected);
            }
            other => panic!("expected untouched INTENT, got {other:?}"),
        }
    }

    #[test]
    fn finalize_wrong_nonce_suppresses_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");
        let mut expected = intent.clone();
        expected.attempt_nonce = [0xAA; 16];
        let err = finalize_complete_from_intent(tmp.path(), &expected).expect_err("mismatch");
        assert!(matches!(err, FinalizeError::Mismatch(IntentMismatch::WrongNonce)));
        assert_still_intent(tmp.path(), &intent);
    }

    #[test]
    fn finalize_wrong_digest_suppresses_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");
        let mut expected = intent.clone();
        expected.snapshot_meta_digest = [0xBB; 32];
        let err = finalize_complete_from_intent(tmp.path(), &expected).expect_err("mismatch");
        assert!(matches!(err, FinalizeError::Mismatch(IntentMismatch::WrongDigest)));
        assert_still_intent(tmp.path(), &intent);
    }

    #[test]
    fn finalize_wrong_destination_suppresses_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        publish_record(tmp.path(), &intent).expect("publish intent");
        let mut expected = intent.clone();
        expected.destination_id = "/some/other/dest".to_string();
        let err = finalize_complete_from_intent(tmp.path(), &expected).expect_err("mismatch");
        assert!(matches!(
            err,
            FinalizeError::Mismatch(IntentMismatch::WrongDestination { .. })
        ));
        assert_still_intent(tmp.path(), &intent);
    }

    #[test]
    fn finalize_wrong_epoch_none_vs_zero_suppresses_complete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut intent = sample_record(RtrState::Intent);
        intent.expected_epoch = None;
        publish_record(tmp.path(), &intent).expect("publish intent");
        let mut expected = intent.clone();
        expected.expected_epoch = Some(0);
        let err = finalize_complete_from_intent(tmp.path(), &expected).expect_err("mismatch");
        assert!(matches!(
            err,
            FinalizeError::Mismatch(IntentMismatch::WrongEpoch {
                expected: Some(0),
                found: None
            })
        ));
        assert_still_intent(tmp.path(), &intent);
    }

    #[test]
    fn finalize_wrong_state_already_complete_suppresses() {
        // The on-disk record is already COMPLETE: the transition refuses rather
        // than overwrite it with a reconstructed success record.
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        let complete = intent.clone().into_complete();
        publish_record(tmp.path(), &complete).expect("publish complete");
        let err = finalize_complete_from_intent(tmp.path(), &intent).expect_err("mismatch");
        assert!(matches!(
            err,
            FinalizeError::Mismatch(IntentMismatch::WrongState {
                found: RtrState::Complete
            })
        ));
        // Unchanged COMPLETE.
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Present(rec) => assert_eq!(rec, complete),
            other => panic!("expected COMPLETE unchanged, got {other:?}"),
        }
    }

    #[test]
    fn finalize_absent_record_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let intent = sample_record(RtrState::Intent);
        let err = finalize_complete_from_intent(tmp.path(), &intent).expect_err("absent");
        assert!(matches!(err, FinalizeError::ExpectedIntentUnavailable(_)));
    }

    #[test]
    fn finalize_invalid_record_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Write a corrupt final record.
        std::fs::write(rtr_path(tmp.path()), b"not-a-valid-rtr-record").expect("write junk");
        let intent = sample_record(RtrState::Intent);
        let err = finalize_complete_from_intent(tmp.path(), &intent).expect_err("invalid");
        assert!(matches!(err, FinalizeError::ExpectedIntentUnavailable(_)));
    }

    #[test]
    fn finalize_rejects_expected_not_intent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let complete = sample_record(RtrState::Complete);
        publish_record(tmp.path(), &complete).expect("publish");
        let err = finalize_complete_from_intent(tmp.path(), &complete).expect_err("not intent");
        assert!(matches!(err, FinalizeError::ExpectedNotIntent));
    }

    // ------------------------------------------------------------------
    // Correction B — bounded final-record reader.
    // ------------------------------------------------------------------

    #[test]
    fn bounded_reader_valid_record_reads_all_bytes() {
        let rec = sample_record(RtrState::Complete);
        let bytes = rec.encode();
        let out = read_bounded_final_record_bytes(&bytes[..], RTR_MAX_RECORD_SIZE, "test")
            .expect("read");
        assert_eq!(out, BoundedRecordBytes::Bytes(bytes));
    }

    #[test]
    fn bounded_reader_maximum_size_boundary_is_accepted() {
        // Exactly `max` bytes is in-limit; `max + 1` is over-limit.
        let at_max = vec![0u8; RTR_MAX_RECORD_SIZE];
        let out = read_bounded_final_record_bytes(&at_max[..], RTR_MAX_RECORD_SIZE, "test")
            .expect("read");
        assert!(matches!(out, BoundedRecordBytes::Bytes(b) if b.len() == RTR_MAX_RECORD_SIZE));

        let over = vec![0u8; RTR_MAX_RECORD_SIZE + 1];
        let out = read_bounded_final_record_bytes(&over[..], RTR_MAX_RECORD_SIZE, "test")
            .expect("read");
        assert_eq!(out, BoundedRecordBytes::Oversized);
    }

    /// A reader that advertises a small size but yields far more bytes than
    /// advertised — the bounded reader must NOT trust the advertised size and
    /// must still cap the bytes it consumes/allocates at `max + 1`.
    struct LyingReader {
        remaining: usize,
    }
    impl std::io::Read for LyingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let n = buf.len().min(self.remaining);
            for b in &mut buf[..n] {
                *b = 0xAB;
            }
            self.remaining -= n;
            Ok(n)
        }
    }

    #[test]
    fn bounded_reader_ignores_advertised_size_and_caps_allocation() {
        // The source will supply 4 MiB but the bounded reader must stop at
        // max + 1 and classify it Oversized without allocating the whole thing.
        let reader = LyingReader {
            remaining: 4 * 1024 * 1024,
        };
        let out =
            read_bounded_final_record_bytes(reader, RTR_MAX_RECORD_SIZE, "lying").expect("read");
        assert_eq!(out, BoundedRecordBytes::Oversized);
    }

    /// A reader that returns some bytes then a hard I/O error — a read error
    /// after partial input must propagate as refusal, never absence/success.
    struct PartialThenError {
        yielded: bool,
    }
    impl std::io::Read for PartialThenError {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.yielded {
                self.yielded = true;
                let n = buf.len().min(16);
                for b in &mut buf[..n] {
                    *b = 1;
                }
                return Ok(n);
            }
            Err(std::io::Error::other("injected read error"))
        }
    }

    #[test]
    fn bounded_reader_read_error_after_partial_is_refusal() {
        let reader = PartialThenError { yielded: false };
        let err = read_bounded_final_record_bytes(reader, RTR_MAX_RECORD_SIZE, "partial")
            .expect_err("must refuse");
        assert!(matches!(err, RtrError::Io(_)));
    }

    #[test]
    fn read_rtr_truncated_record_is_invalid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rec = sample_record(RtrState::Complete);
        let bytes = rec.encode();
        std::fs::write(rtr_path(tmp.path()), &bytes[..bytes.len() - 1]).expect("write truncated");
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Invalid(_)
        ));
    }

    #[test]
    fn read_rtr_trailing_bytes_is_invalid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rec = sample_record(RtrState::Complete);
        let mut bytes = rec.encode();
        bytes.push(0x00);
        std::fs::write(rtr_path(tmp.path()), &bytes).expect("write trailing");
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Invalid(RtrDecodeError::TrailingData)
        ));
    }

    #[test]
    fn read_rtr_oversized_on_disk_is_invalid_without_trusting_metadata() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Write far more than the maximum. The bounded reader rejects it before
        // decoding, without allocating from metadata.
        let big = vec![0xCDu8; RTR_MAX_RECORD_SIZE + 4096];
        std::fs::write(rtr_path(tmp.path()), &big).expect("write oversized");
        match read_rtr(tmp.path()).expect("read") {
            RtrReadResult::Invalid(RtrDecodeError::Oversized(n)) => {
                assert_eq!(n, RTR_MAX_RECORD_SIZE + 1)
            }
            other => panic!("expected Oversized, got {other:?}"),
        }
    }

    #[test]
    fn read_rtr_maximum_valid_size_boundary_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rec = sample_record(RtrState::Complete);
        let bytes = rec.encode();
        assert!(bytes.len() <= RTR_MAX_RECORD_SIZE);
        std::fs::write(rtr_path(tmp.path()), &bytes).expect("write");
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Present(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_rtr_fifo_is_refused_without_blocking_open() {
        use std::ffi::CString;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = rtr_path(tmp.path());
        let c = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        // Create a FIFO at the authoritative record path (no writer attached).
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
        // read_rtr must refuse (not block) — the open uses O_NONBLOCK and the
        // non-regular file type is rejected.
        let err = read_rtr(tmp.path()).expect_err("fifo must be refused");
        assert!(matches!(err, RtrError::Io(_)));
    }

    #[cfg(unix)]
    #[test]
    fn read_rtr_directory_at_record_path_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(rtr_path(tmp.path())).expect("mk dir at rtr path");
        let err = read_rtr(tmp.path()).expect_err("directory must be refused");
        assert!(matches!(err, RtrError::Io(_)));
    }

    /// Correction A: a final-component symlink whose target is a valid regular
    /// RTR must be refused (no-follow open), NOT read as `Present`, and neither
    /// the link nor its target may be deleted/replaced/repaired by the reader.
    #[cfg(unix)]
    #[test]
    fn read_rtr_symlink_to_valid_regular_is_refused_and_preserved() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // A valid regular RTR stored under a side name (not the authoritative
        // path), then a symlink at the authoritative path pointing to it.
        let target = tmp.path().join("real_rtr_target");
        let rec = sample_record(RtrState::Complete);
        std::fs::write(&target, rec.encode()).expect("write target");
        let link = rtr_path(tmp.path());
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = read_rtr(tmp.path()).expect_err("symlink to valid RTR must be refused");
        assert!(matches!(err, RtrError::Io(_)));

        // The link itself must still be a symlink (not followed/replaced/removed),
        // proven via symlink_metadata (Path::exists follows the link).
        let link_meta = std::fs::symlink_metadata(&link).expect("link must still exist");
        assert!(
            link_meta.file_type().is_symlink(),
            "authoritative path must remain a symlink; reader must not rewrite it"
        );
        // The target must be untouched and still decode to the same record.
        let target_bytes = std::fs::read(&target).expect("target must remain");
        match RestoreTransactionRecord::decode(&target_bytes) {
            Ok(got) => assert_eq!(got, rec, "target record must be unchanged"),
            Err(d) => panic!("target must remain a valid record, got {d:?}"),
        }
    }

    /// Correction A: a dangling final-component symlink (target missing) must be
    /// refused, NOT mis-mapped to absence, and the dangling link must be
    /// preserved. `Path::exists()` alone cannot distinguish a dangling link from
    /// a genuinely absent record; `symlink_metadata` proves the link entry.
    #[cfg(unix)]
    #[test]
    fn read_rtr_dangling_symlink_is_refused_and_preserved() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing_target = tmp.path().join("does_not_exist_target");
        let link = rtr_path(tmp.path());
        std::os::unix::fs::symlink(&missing_target, &link).expect("symlink");
        // Sanity: the link is dangling — following it would report absence.
        assert!(!link.exists(), "target is intentionally missing (dangling)");

        let err = read_rtr(tmp.path()).expect_err("dangling symlink must be refused, not absent");
        assert!(matches!(err, RtrError::Io(_)));

        // The dangling link entry must still exist (a directory entry is present,
        // so this is NOT ordinary absence) and must remain a symlink.
        let link_meta =
            std::fs::symlink_metadata(&link).expect("dangling link entry must still exist");
        assert!(
            link_meta.file_type().is_symlink(),
            "dangling link must be preserved as a symlink; reader must not delete/repair it"
        );
        // The reader must not have created the missing target.
        assert!(
            std::fs::symlink_metadata(&missing_target).is_err(),
            "reader must not create/repair the dangling target"
        );
    }

    /// Correction A control: genuine absence (no directory entry at all) retains
    /// ordinary-lifecycle `Absent` behavior and is distinct from a dangling link.
    #[cfg(unix)]
    #[test]
    fn read_rtr_genuine_absence_is_absent_not_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // No entry of any kind at the authoritative path.
        assert!(
            std::fs::symlink_metadata(rtr_path(tmp.path())).is_err(),
            "there must be no directory entry (genuine absence)"
        );
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Absent
        ));
    }

    /// Correction A: exercise the symlink refusal through the ordinary-startup
    /// precondition — a final-component symlink refuses (fail-closed) before any
    /// protected state is admitted, rather than proceeding as absent.
    #[cfg(unix)]
    #[test]
    fn ordinary_startup_refuses_final_component_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("real_rtr_target");
        std::fs::write(&target, sample_record(RtrState::Complete).encode()).expect("write");
        std::os::unix::fs::symlink(&target, rtr_path(tmp.path())).expect("symlink");
        assert!(matches!(
            evaluate_ordinary_startup(tmp.path()),
            OrdinaryStartupDecision::RefuseInvalid(_)
        ));
    }

    /// Correction A: exercise the symlink refusal through the requested-restore
    /// precondition — a dangling final-component symlink refuses before any
    /// validation/mutation, rather than being treated as an empty destination.
    #[cfg(unix)]
    #[test]
    fn requested_restore_precondition_refuses_dangling_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(
            tmp.path().join("missing_target"),
            rtr_path(tmp.path()),
        )
        .expect("symlink");
        assert!(matches!(
            evaluate_requested_restore_precondition(tmp.path()),
            RequestedRestorePrecondition::RefuseInvalid(_)
        ));
    }

    #[test]
    fn read_rtr_temp_artifact_never_replaces_authoritative_record() {
        // A temp artifact is never the authoritative final record; with only a
        // temp artifact present the destination reads Absent.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(RTR_TEMP_FILENAME), b"junk").expect("write temp");
        assert!(matches!(
            read_rtr(tmp.path()).expect("read"),
            RtrReadResult::Absent
        ));
    }
}