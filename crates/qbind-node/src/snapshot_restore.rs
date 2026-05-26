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
use qbind_types::{ChainId, NetworkEnvironment};

use crate::node_config::NodeConfig;
use crate::pqc_authority_state::{
    authority_state_file_path, verify_snapshot_authority_state_for_restore,
    verify_snapshot_authority_state_for_restore_v2, SnapshotRestoreAuthorityCheckInputs,
    SnapshotRestoreAuthorityCheckOutcome, SnapshotRestoreAuthorityCheckV2Inputs,
    SnapshotRestoreAuthorityCheckV2Outcome,
};

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

    /// **Run 124.** The snapshot's authority-state metadata conflicts with
    /// the locally persisted authority marker (rollback, equivocation,
    /// key conflict, policy regression, wrong-domain, etc.), or one side
    /// is present while the other is missing in a way that would silently
    /// downgrade or erase the local marker. The embedded outcome captures
    /// the precise reject reason. Fail-closed: the restore is refused
    /// BEFORE any state materialization or audit-marker write, so on-disk
    /// state under `<data_dir>` is byte-identical to its pre-restore form
    /// (including the local authority marker file, which is never mutated
    /// or deleted by the restore surface).
    AuthorityMarkerConflict(SnapshotRestoreAuthorityCheckOutcome),

    /// **Run 140.** The snapshot's v2 authority-state metadata
    /// (`authority_state_v2`) conflicts with the locally persisted
    /// versioned authority marker (lower v2 sequence, same v2 sequence
    /// with different ratification digest, wrong authority root, wrong
    /// key/action linkage, v1-after-v2, malformed bytes,
    /// wrong-domain, ambiguous snapshot carrying both v1+v2 blocks,
    /// etc.), or one side is present while the other is missing in a
    /// way that would silently downgrade or erase the local v2 marker.
    /// The embedded outcome captures the precise reject reason.
    /// Fail-closed: the restore is refused BEFORE any state
    /// materialization or audit-marker write; on-disk state under
    /// `<data_dir>` is byte-identical to its pre-restore form
    /// (including the local authority marker file, which is never
    /// mutated or deleted by the restore surface).
    AuthorityMarkerConflictV2(SnapshotRestoreAuthorityCheckV2Outcome),

    /// **Run 124.** The restore surface was invoked without the runtime
    /// authority context (`NetworkEnvironment` + canonical genesis hash)
    /// needed to honestly evaluate the snapshot vs. local-marker
    /// comparison. The surface fails closed rather than silently skipping
    /// the check; production callers (the binary in `main.rs`) always
    /// provide the context. Surfaces this only on the legacy
    /// no-context [`apply_snapshot_restore_if_requested`] path when a
    /// local marker file already exists on disk.
    AuthorityContextMissing,
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
            RestoreError::AuthorityMarkerConflict(o) => write!(
                f,
                "restore-from-snapshot refused by authority-marker check: {} (no state mutation, no audit-marker write; local pqc_authority_state.json bytes preserved verbatim)",
                o
            ),
            RestoreError::AuthorityMarkerConflictV2(o) => write!(
                f,
                "restore-from-snapshot refused by Run 140 v2 authority-marker check: {} (no state mutation, no audit-marker write; local pqc_authority_state.json bytes preserved verbatim)",
                o
            ),
            RestoreError::AuthorityContextMissing => write!(
                f,
                "restore-from-snapshot refused: a local pqc_authority_state.json marker exists but no runtime authority context (env, chain_id, genesis_hash) was supplied to the restore surface (fail closed). Use restore_from_snapshot_with_authority_marker_check from a binary surface that has loaded the canonical genesis."
            ),
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
    apply_snapshot_restore_if_requested_inner(config, None)
}

/// **Run 124.** Apply a restore-from-snapshot with the runtime authority
/// context required to enforce the snapshot/restore authority-marker
/// conflict check (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_124.md`).
///
/// This is the production entry point the binary (`main.rs`) calls once the
/// canonical Run 101 genesis hash has been computed and verified (Run 102).
/// It composes the existing B3 validate→materialize pipeline with the pure
/// Run 124 [`verify_snapshot_authority_state_for_restore`] helper, refusing
/// the restore BEFORE any state copy or audit-marker write whenever the
/// snapshot would silently downgrade, conflict with, or erase the locally
/// persisted `<data_dir>/pqc_authority_state.json` marker.
///
/// The legacy [`apply_snapshot_restore_if_requested`] entry point remains
/// available for callers that have no genesis context (no marker
/// enforcement is attempted there; but if a local marker file already
/// exists the legacy path fails closed with
/// [`RestoreError::AuthorityContextMissing`] rather than silently
/// permitting a restore that could shadow the marker).
pub fn apply_snapshot_restore_if_requested_with_authority_context(
    config: &NodeConfig,
    authority_ctx: &RestoreAuthorityContext<'_>,
) -> Result<Option<RestoreOutcome>, RestoreError> {
    apply_snapshot_restore_if_requested_inner(config, Some(authority_ctx))
}

fn apply_snapshot_restore_if_requested_inner(
    config: &NodeConfig,
    authority_ctx: Option<&RestoreAuthorityContext<'_>>,
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

    let outcome = match authority_ctx {
        Some(ctx) => restore_from_snapshot_with_authority_marker_check(
            &snapshot_dir,
            &data_dir,
            expected_chain_id,
            ctx,
        )?,
        None => {
            // Legacy no-context path: still enforce the conservative
            // fail-closed rule that a pre-existing local marker requires
            // a runtime authority context (Run 124 strict non-goal: no
            // silent shadowing of an existing local marker).
            let marker_path = authority_state_file_path(&data_dir);
            if marker_path.exists() {
                return Err(RestoreError::AuthorityContextMissing);
            }
            restore_from_snapshot(&snapshot_dir, &data_dir, expected_chain_id)?
        }
    };

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

/// **Run 124.** Borrowed bundle of runtime authority-trust-domain inputs
/// required to enforce the snapshot/restore authority-marker conflict
/// check. Constructed by the binary surface from the same Run 102/105
/// boot context the rest of the trust-bundle pipeline uses.
#[derive(Debug, Clone, Copy)]
pub struct RestoreAuthorityContext<'a> {
    /// Runtime network environment (Devnet / Testnet / Mainnet).
    pub runtime_env: NetworkEnvironment,
    /// Runtime chain id (Run 069+).
    pub runtime_chain_id: ChainId,
    /// 64 lowercase hex chars of the canonical genesis hash this node booted
    /// against. Equals `compute_canonical_genesis_hash(...)` on the runtime
    /// genesis config rendered without the `0x` prefix.
    pub runtime_genesis_hash_hex: &'a str,
}

/// Lower-level restore primitive that does not depend on `NodeConfig`.
///
/// Exposed `pub` so integration tests can drive the exact same code path
/// the binary uses without standing up a full `NodeConfig`.
///
/// **This entry point does not enforce the Run 124 snapshot/restore
/// authority-marker conflict check.** Production callers should prefer
/// [`restore_from_snapshot_with_authority_marker_check`], which composes
/// the same materialization pipeline with the typed
/// [`verify_snapshot_authority_state_for_restore`] check from
/// `pqc_authority_state`.
pub fn restore_from_snapshot(
    snapshot_dir: &Path,
    data_dir: &Path,
    expected_chain_id: u64,
) -> Result<RestoreOutcome, RestoreError> {
    let meta = validate_snapshot_for_restore(snapshot_dir, expected_chain_id)?;
    materialize_validated_snapshot(snapshot_dir, data_dir, meta)
}

/// **Run 124.** Validate a snapshot AND enforce the snapshot/restore
/// authority-marker conflict check against the locally persisted
/// `<data_dir>/pqc_authority_state.json` marker BEFORE any state
/// materialization or audit-marker write.
///
/// On reject, no bytes are copied, the audit marker is not written, and
/// the local authority-marker file (if any) is byte-identical to its
/// pre-restore state. The typed
/// [`SnapshotRestoreAuthorityCheckOutcome`] is surfaced via
/// [`RestoreError::AuthorityMarkerConflict`] so the operator log line
/// can pinpoint the precise reason.
pub fn restore_from_snapshot_with_authority_marker_check(
    snapshot_dir: &Path,
    data_dir: &Path,
    expected_chain_id: u64,
    authority_ctx: &RestoreAuthorityContext<'_>,
) -> Result<RestoreOutcome, RestoreError> {
    // 1. Validate snapshot layout / chain id / meta parse first, so any
    //    snapshot-layer failure is reported as such (not as an authority
    //    check failure).
    let meta = validate_snapshot_for_restore(snapshot_dir, expected_chain_id)?;

    // 2. Compute the local marker path.
    let marker_path = authority_state_file_path(data_dir);

    // 3. Dispatch on the snapshot meta's authority block(s):
    //    - Run 140: if the snapshot carries a v2 block, route the pure
    //      check through `verify_snapshot_authority_state_for_restore_v2`,
    //      passing `snapshot_also_carries_v1_block` so an ambiguous
    //      snapshot (both v1 + v2 blocks present) is rejected fail-closed
    //      without consulting either block.
    //    - Otherwise: Run 124 v1 path verbatim (no v1 regression).
    if meta.authority_state_v2.is_some() {
        let check_outcome_v2 = verify_snapshot_authority_state_for_restore_v2(
            SnapshotRestoreAuthorityCheckV2Inputs {
                marker_path: &marker_path,
                snapshot_meta_v2: meta.authority_state_v2.as_ref(),
                snapshot_also_carries_v1_block: meta.authority_state.is_some(),
                runtime_env: authority_ctx.runtime_env,
                runtime_chain_id: authority_ctx.runtime_chain_id,
                runtime_genesis_hash_hex: authority_ctx.runtime_genesis_hash_hex,
            },
        );

        if check_outcome_v2.is_reject() {
            eprintln!(
                "[restore] FATAL: refused by Run 140 v2 authority-marker check: {}",
                check_outcome_v2
            );
            return Err(RestoreError::AuthorityMarkerConflictV2(check_outcome_v2));
        }

        eprintln!(
            "[restore] Run 140 v2 authority-marker check: {} (proceeding with materialization)",
            check_outcome_v2
        );
    } else {
        let check_outcome =
            verify_snapshot_authority_state_for_restore(SnapshotRestoreAuthorityCheckInputs {
                marker_path: &marker_path,
                snapshot_meta: meta.authority_state.as_ref(),
                runtime_env: authority_ctx.runtime_env,
                runtime_chain_id: authority_ctx.runtime_chain_id,
                runtime_genesis_hash_hex: authority_ctx.runtime_genesis_hash_hex,
            });

        if check_outcome.is_reject() {
            eprintln!(
                "[restore] FATAL: refused by Run 124 authority-marker check: {}",
                check_outcome
            );
            return Err(RestoreError::AuthorityMarkerConflict(check_outcome));
        }

        eprintln!(
            "[restore] Run 124 authority-marker check: {} (proceeding with materialization)",
            check_outcome
        );
    }

    // 4. Materialize. The marker file under <data_dir> is NEVER written,
    //    rewritten, or deleted by the restore surface — only the audit
    //    marker (RESTORED_FROM_SNAPSHOT.json) plus the state checkpoint.
    materialize_validated_snapshot(snapshot_dir, data_dir, meta)
}

/// Run the existing B3 validation pipeline and return the parsed meta.
/// Factored out so [`restore_from_snapshot`] and
/// [`restore_from_snapshot_with_authority_marker_check`] share identical
/// snapshot-layer semantics.
fn validate_snapshot_for_restore(
    snapshot_dir: &Path,
    expected_chain_id: u64,
) -> Result<StateSnapshotMeta, RestoreError> {
    if !snapshot_dir.exists() {
        return Err(RestoreError::SnapshotPathMissing(snapshot_dir.to_path_buf()));
    }
    match validate_snapshot_dir(snapshot_dir, expected_chain_id) {
        SnapshotValidationResult::Valid(m) => Ok(m),
        other => Err(RestoreError::SnapshotInvalid(other)),
    }
}

/// Copy the snapshot state checkpoint into `<data_dir>/state_vm_v0/` and
/// write the audit marker. Factored out so both restore entry points share
/// identical materialization semantics.
fn materialize_validated_snapshot(
    snapshot_dir: &Path,
    data_dir: &Path,
    meta: StateSnapshotMeta,
) -> Result<RestoreOutcome, RestoreError> {
    // Ensure data_dir exists.
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