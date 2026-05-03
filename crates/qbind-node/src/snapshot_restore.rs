//! B3: Restore-from-snapshot startup path for `qbind-node`.
//!
//! This module owns the smallest honest restore-from-snapshot startup path
//! for the QBIND node binary. It is invoked from `main.rs` before consensus
//! starts whenever the operator passes `--restore-from-snapshot <PATH>` (or
//! sets `FastSyncConfig::from_snapshot(...)` on the `NodeConfig`).
//!
//! # Canonical basis
//!
//! - `docs/whitepaper/contradiction.md` C4 (B3 sub-item)
//! - `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` §6.1, §10
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_002.md` §11
//! - `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`
//!
//! # Snapshot format
//!
//! The existing `StateSnapshotter` (T215) already defines the on-disk format
//! we reuse here. A snapshot directory has:
//!
//! ```text
//! <snapshot_dir>/
//! ├── meta.json   # StateSnapshotMeta (height, block_hash, chain_id, ts)
//! └── state/      # RocksDB checkpoint files (SST + MANIFEST + ...)
//! ```
//!
//! No new snapshot format is invented. The B3 restore path validates this
//! exact layout and materializes the `state/` checkpoint into the node's
//! VM-v0 state directory at `<data_dir>/state_vm_v0`.
//!
//! # What B3 supports today
//!
//! - VM-v0 RocksDB account state (the format `RocksDbAccountState` produces).
//! - Single-validator and multi-validator restores at the *state-store* level
//!   (the snapshot is local; multi-validator P2P interconnect is **not**
//!   solved by this change and is explicitly out of scope).
//!
//! # What B3 does NOT do
//!
//! - It does not invent a new snapshot or checkpoint format.
//! - It does not migrate snapshots across chain IDs (a chain-id mismatch is
//!   treated as a hard error — the snapshot is from a different network).
//! - It does not silently overwrite an existing populated state directory
//!   (operator-honest: refuse rather than corrupt local state).
//! - It does not currently restore non–VM-v0 substate (e.g. the consensus
//!   storage RocksDB at `<data_dir>/consensus`). Those are not produced by
//!   `StateSnapshotter` and are left to a future extension; this is logged
//!   loudly at restore time.
//!
//! # Failure model (operator-honest)
//!
//! All error variants are surfaced with a precise reason and propagate to a
//! non-zero process exit from `main.rs`. The restore path never silently
//! degrades to "no restore".

use std::fmt;
use std::path::{Path, PathBuf};

use qbind_ledger::{validate_snapshot_dir, SnapshotValidationResult, StateSnapshotMeta};

use crate::node_config::NodeConfig;

/// Subdirectory within `data_dir` where the VM-v0 RocksDB state lives.
///
/// This matches `NodeConfig::vm_v0_state_dir()`. Centralized here so the
/// restore path and the runtime open path agree.
pub const VM_V0_STATE_SUBDIR: &str = "state_vm_v0";

/// Filename for the audit marker written next to the restored state.
///
/// The marker captures the snapshot metadata at the moment of restore and
/// is appended to (not overwritten) on subsequent restores. It is the
/// auditable receipt of "this node booted from a snapshot".
pub const RESTORE_MARKER_FILENAME: &str = "RESTORED_FROM_SNAPSHOT.json";

/// Errors returned by [`apply_snapshot_restore_if_requested`].
///
/// All variants are surfaced with a clear, operator-readable message and
/// cause the binary to exit non-zero.
#[derive(Debug)]
pub enum RestoreError {
    /// The configured `data_dir` is missing — restore requires a persistent
    /// state directory to materialize the snapshot into.
    MissingDataDir,

    /// The snapshot directory does not exist on disk.
    SnapshotPathMissing(PathBuf),

    /// The snapshot directory failed `validate_snapshot_dir` — the variant
    /// carries the underlying reason for clarity.
    SnapshotInvalid(SnapshotValidationResult),

    /// The target VM-v0 state directory already exists and is non-empty.
    /// We refuse to overwrite (operator-honest) — the operator must remove
    /// or move the existing state before restoring.
    TargetStateNotEmpty(PathBuf),

    /// IO error during snapshot materialization (copy / mkdir / write).
    Io(String),
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreError::MissingDataDir => write!(
                f,
                "restore-from-snapshot requires --data-dir (no persistent data directory configured)"
            ),
            RestoreError::SnapshotPathMissing(p) => write!(
                f,
                "restore-from-snapshot path does not exist: {}",
                p.display()
            ),
            RestoreError::SnapshotInvalid(v) => {
                write!(f, "restore-from-snapshot snapshot is invalid: {}", v)
            }
            RestoreError::TargetStateNotEmpty(p) => write!(
                f,
                "restore-from-snapshot target state directory is not empty: {} \
                 (refusing to overwrite; remove or move it before restoring)",
                p.display()
            ),
            RestoreError::Io(msg) => write!(f, "restore-from-snapshot IO error: {}", msg),
        }
    }
}

impl std::error::Error for RestoreError {}

/// Outcome of a successful restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Snapshot metadata as read from `meta.json`.
    pub meta: StateSnapshotMeta,

    /// Where the snapshot was read from.
    pub snapshot_dir: PathBuf,

    /// Where the VM-v0 state was materialized to.
    pub target_state_dir: PathBuf,

    /// Path to the audit marker JSON written by the restore.
    pub marker_path: PathBuf,

    /// Total bytes copied from `snapshot/state/` into the target state dir.
    pub bytes_copied: u64,
}

/// Apply a restore-from-snapshot if `config.fast_sync_config` requests one.
///
/// This is the single entry point used by the binary (`main.rs`).
///
/// # Behavior
///
/// - If `config.fast_sync_config.is_enabled() == false`: returns `Ok(None)`
///   (normal startup; nothing changes).
/// - If enabled: validates and materializes the snapshot, returning
///   `Ok(Some(RestoreOutcome))`. On any error, returns `Err(RestoreError)`
///   with a precise reason.
///
/// # Side effects on success
///
/// 1. The snapshot's `state/` directory is recursively copied into
///    `<data_dir>/state_vm_v0`. The target directory is created if
///    missing; if it already exists *and is non-empty* the call fails
///    rather than silently overwriting.
/// 2. An audit marker file `<data_dir>/RESTORED_FROM_SNAPSHOT.json` is
///    written (or appended to as a JSON-lines stream if it already
///    exists — each restore is recorded).
/// 3. Progress is logged to stderr with `[restore]` prefix.
pub fn apply_snapshot_restore_if_requested(
    config: &NodeConfig,
) -> Result<Option<RestoreOutcome>, RestoreError> {
    if !config.fast_sync_config.is_enabled() {
        return Ok(None);
    }

    let snapshot_dir = config
        .fast_sync_config
        .fast_sync_snapshot_dir
        .as_ref()
        .expect("is_enabled() guarantees Some")
        .clone();

    let data_dir = config
        .data_dir
        .as_ref()
        .ok_or(RestoreError::MissingDataDir)?
        .clone();

    let expected_chain_id = config.chain_id().as_u64();

    eprintln!(
        "[restore] requested: snapshot_dir={} data_dir={} expected_chain_id=0x{:016x}",
        snapshot_dir.display(),
        data_dir.display(),
        expected_chain_id,
    );

    let outcome = restore_from_snapshot(&snapshot_dir, &data_dir, expected_chain_id)?;

    eprintln!(
        "[restore] complete: height={} chain_id=0x{:016x} bytes_copied={} target={}",
        outcome.meta.height,
        outcome.meta.chain_id,
        outcome.bytes_copied,
        outcome.target_state_dir.display(),
    );
    eprintln!(
        "[restore] audit marker written to {}",
        outcome.marker_path.display()
    );

    Ok(Some(outcome))
}

/// Lower-level restore primitive that does not depend on `NodeConfig`.
///
/// Exposed `pub` so integration tests can drive the exact same code path
/// the binary uses without standing up a full `NodeConfig`.
pub fn restore_from_snapshot(
    snapshot_dir: &Path,
    data_dir: &Path,
    expected_chain_id: u64,
) -> Result<RestoreOutcome, RestoreError> {
    // 1. Snapshot path must exist on disk.
    if !snapshot_dir.exists() {
        return Err(RestoreError::SnapshotPathMissing(snapshot_dir.to_path_buf()));
    }

    // 2. Validate via the existing T215 validator (chain-id, layout, height).
    let meta = match validate_snapshot_dir(snapshot_dir, expected_chain_id) {
        SnapshotValidationResult::Valid(m) => m,
        other => return Err(RestoreError::SnapshotInvalid(other)),
    };

    // 3. Ensure data_dir exists.
    std::fs::create_dir_all(data_dir).map_err(|e| {
        RestoreError::Io(format!(
            "cannot create data_dir {}: {}",
            data_dir.display(),
            e
        ))
    })?;

    // 4. Compute target state dir and refuse to overwrite if non-empty.
    let target_state_dir = data_dir.join(VM_V0_STATE_SUBDIR);
    if target_state_dir.exists() {
        let mut entries = std::fs::read_dir(&target_state_dir).map_err(|e| {
            RestoreError::Io(format!(
                "cannot read target state dir {}: {}",
                target_state_dir.display(),
                e
            ))
        })?;
        if entries.next().is_some() {
            return Err(RestoreError::TargetStateNotEmpty(target_state_dir));
        }
    } else {
        std::fs::create_dir_all(&target_state_dir).map_err(|e| {
            RestoreError::Io(format!(
                "cannot create target state dir {}: {}",
                target_state_dir.display(),
                e
            ))
        })?;
    }

    // 5. Recursively copy snapshot/state/* into <data_dir>/state_vm_v0/.
    let source_state_dir = snapshot_dir.join("state");
    let bytes_copied = copy_dir_recursive(&source_state_dir, &target_state_dir)?;

    // 6. Write audit marker (append a JSON line per restore for full history).
    let marker_path = data_dir.join(RESTORE_MARKER_FILENAME);
    write_restore_marker(&marker_path, &meta, snapshot_dir, &target_state_dir, bytes_copied)?;

    Ok(RestoreOutcome {
        meta,
        snapshot_dir: snapshot_dir.to_path_buf(),
        target_state_dir,
        marker_path,
        bytes_copied,
    })
}

/// Recursively copy `src` directory contents into `dst`. Returns total bytes
/// copied. `dst` must already exist and (for our use case) be empty.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<u64, RestoreError> {
    let mut total: u64 = 0;
    let entries = std::fs::read_dir(src).map_err(|e| {
        RestoreError::Io(format!("cannot read source dir {}: {}", src.display(), e))
    })?;
    for entry in entries {
        let entry = entry
            .map_err(|e| RestoreError::Io(format!("cannot read source entry: {}", e)))?;
        let file_type = entry
            .file_type()
            .map_err(|e| RestoreError::Io(format!("cannot stat source entry: {}", e)))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path).map_err(|e| {
                RestoreError::Io(format!(
                    "cannot create dst dir {}: {}",
                    dst_path.display(),
                    e
                ))
            })?;
            total += copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            let n = std::fs::copy(&src_path, &dst_path).map_err(|e| {
                RestoreError::Io(format!(
                    "cannot copy {} to {}: {}",
                    src_path.display(),
                    dst_path.display(),
                    e
                ))
            })?;
            total += n;
        } else {
            // Symlinks / other special files are not produced by the
            // RocksDB checkpoint API for our config; surface explicitly.
            return Err(RestoreError::Io(format!(
                "unsupported file type in snapshot: {}",
                src_path.display()
            )));
        }
    }
    Ok(total)
}

/// Append a JSON line describing this restore to the audit marker file.
fn write_restore_marker(
    path: &Path,
    meta: &StateSnapshotMeta,
    snapshot_dir: &Path,
    target_state_dir: &Path,
    bytes_copied: u64,
) -> Result<(), RestoreError> {
    use std::io::Write;

    let now_ms = StateSnapshotMeta::now_unix_ms();
    let block_hash_hex: String = meta
        .block_hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    // Hand-rolled to avoid adding a serde derive on StateSnapshotMeta and to
    // keep the marker shape stable and grep-able for ops drills.
    let line = format!(
        "{{\"restored_at_unix_ms\":{},\"snapshot_dir\":\"{}\",\"target_state_dir\":\"{}\",\
         \"bytes_copied\":{},\"snapshot_height\":{},\"snapshot_block_hash\":\"{}\",\
         \"snapshot_chain_id\":{},\"snapshot_created_at_unix_ms\":{}}}\n",
        now_ms,
        escape_json(&snapshot_dir.display().to_string()),
        escape_json(&target_state_dir.display().to_string()),
        bytes_copied,
        meta.height,
        block_hash_hex,
        meta.chain_id,
        meta.created_at_unix_ms,
    );

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            RestoreError::Io(format!("cannot open marker file {}: {}", path.display(), e))
        })?;
    f.write_all(line.as_bytes()).map_err(|e| {
        RestoreError::Io(format!(
            "cannot write marker file {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(())
}

/// Escape a string for inclusion as a JSON string literal value.
/// Sufficient for paths on supported platforms; not a general JSON encoder.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// Unit tests (path-level; full integration tests live under tests/).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_json_basic() {
        assert_eq!(escape_json("plain"), "plain");
        assert_eq!(escape_json("a\"b"), "a\\\"b");
        assert_eq!(escape_json("a\\b"), "a\\\\b");
        assert_eq!(escape_json("a\nb"), "a\\nb");
    }

    #[test]
    fn restore_error_display_reasons_are_precise() {
        let e = RestoreError::MissingDataDir;
        assert!(e.to_string().contains("--data-dir"));

        let e = RestoreError::SnapshotPathMissing(PathBuf::from("/no/such"));
        assert!(e.to_string().contains("/no/such"));

        let e = RestoreError::TargetStateNotEmpty(PathBuf::from("/d/state_vm_v0"));
        assert!(e.to_string().contains("not empty"));

        let e = RestoreError::Io("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn restore_rejects_missing_snapshot_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let snapshot_dir = tmp.path().join("nope");
        let data_dir = tmp.path().join("data");
        let err = restore_from_snapshot(&snapshot_dir, &data_dir, 0x1234)
            .expect_err("missing snapshot must fail");
        assert!(matches!(err, RestoreError::SnapshotPathMissing(_)));
    }
}