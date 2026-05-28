//! Run 093 — minimum production binary-path `ConsensusStorage` lifecycle.
//!
//! This module implements the smallest amount of "open and probe the
//! production consensus storage on the real binary path" needed so that
//! a later run can safely consume `meta:current_epoch` as the canonical
//! pre-consensus epoch source for PQC trust-bundle activation. It does
//! **not** yet consume `current_epoch` for trust-bundle activation —
//! Run 091's fail-closed `CurrentEpochUnavailable` boundary remains
//! unchanged on every `qbind-node` invocation.
//!
//! # What this module does
//!
//! - Defines the canonical on-disk consensus-storage location as
//!   `<data_dir>/consensus` (resolved by
//!   [`crate::node_config::NodeConfig::consensus_storage_dir`]).
//! - Opens [`RocksDbConsensusStorage`] at that location, runs
//!   [`ensure_compatible_schema`] (T104) and
//!   [`ConsensusStorage::verify_epoch_consistency_on_startup`] (M16),
//!   and probes [`ConsensusStorage::get_current_epoch`].
//! - Exposes the three explicit startup-state variants required by
//!   `task/RUN_093_TASK.txt` §"Startup state distinction":
//!     1. [`ConsensusStorageState::NoConsensusStorage`] — no
//!        `data_dir` configured (DevNet-only ad-hoc smoke).
//!     2. [`ConsensusStorageState::PresentNoCommittedEpoch`] — storage
//!        opens cleanly but no `meta:current_epoch` has ever been
//!        written. This is the **expected** state for the production
//!        `qbind-node` binary today because the binary consensus loop
//!        does not yet emit epoch transitions onto
//!        `apply_epoch_transition_atomic`.
//!     3. [`ConsensusStorageState::CommittedEpoch`] — a committed
//!        `meta:current_epoch` was found on disk. This is the state
//!        a later run will surface to PQC trust-bundle activation.
//!
//! # What this module does NOT do
//!
//! - It does **not** invent a synthetic epoch, read epoch from
//!   wall-clock, or derive epoch from block height.
//! - It does **not** treat a missing committed epoch as `0`.
//! - It does **not** consume `current_epoch` for trust-bundle
//!   activation. The activation surface continues to receive
//!   `ActivationContext { current_epoch: None }` and continues to
//!   fail closed with `CurrentEpochUnavailable` on any bundle that
//!   declares `activation_epoch`.
//! - It does **not** modify the snapshot/restore boundary. Snapshot
//!   epoch parity is documented as still-open in
//!   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md`.
//! - It does **not** wire the binary-path consensus loop into
//!   `apply_epoch_transition_atomic`. Until a later run lands real
//!   epoch-transition events on the binary path, the storage opens
//!   and persists no epoch value.
//!
//! # Fail-closed behavior
//!
//! Every error returned by this module is non-recoverable: the
//! production binary must fail-closed on any open / schema /
//! recovery / probe failure rather than silently degrade. See
//! [`ProductionConsensusStorageError`].
//!
//! # See also
//!
//! - `task/RUN_093_TASK.txt`
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md`
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_091.md` (Run 091 fail-closed boundary)
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_092.md` (Run 092 investigation)
//! - `docs/whitepaper/contradiction.md` C4

use std::path::PathBuf;
use std::sync::Arc;

use crate::node_config::NodeConfig;
use crate::storage::{
    ensure_compatible_schema, ConsensusStorage, RocksDbConsensusStorage, StorageError,
};

// ============================================================================
// ConsensusStorageState
// ============================================================================

/// Explicit startup-state distinction for the production binary-path
/// `ConsensusStorage` lifecycle (Run 093).
///
/// These three variants exist so that callers (today: startup logging
/// and tests; tomorrow: PQC trust-bundle activation) can never silently
/// conflate "no storage available" with "storage available but no
/// epoch ever committed" with "epoch committed". In particular, a
/// missing committed epoch must **not** be treated as `current_epoch = 0`
/// for PQC trust-bundle activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStorageState {
    /// No production consensus storage is configured.
    ///
    /// Reached when `NodeConfig.data_dir` is `None`. The production
    /// `qbind-node` invariant is that TestNet / MainNet require
    /// `data_dir`; this state is therefore only reachable on DevNet
    /// ad-hoc smoke invocations that explicitly opt out of
    /// persistence. Trust-bundle activation must **not** treat this
    /// as `current_epoch = 0`.
    NoConsensusStorage,

    /// Storage opened cleanly and passed all startup checks
    /// (`ensure_compatible_schema`, `verify_epoch_consistency_on_startup`),
    /// but no `meta:current_epoch` value has ever been written.
    ///
    /// This is the **expected** state on the production binary today
    /// because the binary consensus loop does not yet emit epoch
    /// transitions onto `apply_epoch_transition_atomic`. Trust-bundle
    /// activation must **not** treat this as `current_epoch = 0`.
    PresentNoCommittedEpoch,

    /// Storage opened cleanly and a committed `meta:current_epoch`
    /// value was found on disk. This is the state a later run will
    /// expose as the canonical pre-consensus epoch source for PQC
    /// trust-bundle activation.
    CommittedEpoch(u64),
}

impl ConsensusStorageState {
    /// Returns `Some(epoch)` only for [`Self::CommittedEpoch`].
    ///
    /// Run 093 callers MUST NOT collapse `NoConsensusStorage` or
    /// `PresentNoCommittedEpoch` into `Some(0)` — see
    /// `task/RUN_093_TASK.txt` §"Startup state distinction".
    pub fn committed_epoch(&self) -> Option<u64> {
        match self {
            ConsensusStorageState::CommittedEpoch(e) => Some(*e),
            ConsensusStorageState::NoConsensusStorage
            | ConsensusStorageState::PresentNoCommittedEpoch => None,
        }
    }

    /// Returns `true` if a `RocksDbConsensusStorage` is actually open
    /// (i.e. not [`Self::NoConsensusStorage`]).
    pub fn has_open_storage(&self) -> bool {
        !matches!(self, ConsensusStorageState::NoConsensusStorage)
    }

    /// Stable, operator-facing log tag (used by [`OpenedProductionConsensusStorage::log_summary`]).
    pub fn tag(&self) -> &'static str {
        match self {
            ConsensusStorageState::NoConsensusStorage => "no-consensus-storage",
            ConsensusStorageState::PresentNoCommittedEpoch => "present-no-committed-epoch",
            ConsensusStorageState::CommittedEpoch(_) => "committed-epoch",
        }
    }
}

// ============================================================================
// Error
// ============================================================================

/// Errors produced by [`open_production_consensus_storage`].
///
/// Every variant is fatal: the production binary must fail-closed on
/// any of them. None of these errors silently degrade to "no storage"
/// — that path is reachable only when `data_dir` is unset (which
/// produces [`ConsensusStorageState::NoConsensusStorage`], not an error).
#[derive(Debug)]
pub enum ProductionConsensusStorageError {
    /// The configured `data_dir` does not exist and cannot be created.
    DataDirUnavailable { path: PathBuf, details: String },
    /// `RocksDbConsensusStorage::open` failed at the canonical path.
    OpenFailed { path: PathBuf, source: StorageError },
    /// `ensure_compatible_schema` (T104) reported an incompatible
    /// on-disk schema version. The binary refuses to run on a
    /// database written by a newer / unknown version.
    SchemaIncompatible { path: PathBuf, source: StorageError },
    /// `verify_epoch_consistency_on_startup` (M16) detected an
    /// incomplete epoch transition. The binary must not continue
    /// with partially committed epoch boundary state.
    IncompleteEpochTransition { path: PathBuf, source: StorageError },
    /// Reading `meta:current_epoch` failed (e.g. checksum mismatch,
    /// I/O error). Failing closed rather than treating as "no epoch"
    /// preserves the Run 091/092 invariant that a missing epoch is
    /// **not** silently `0`.
    EpochProbeFailed { path: PathBuf, source: StorageError },
    /// Run 097: failure to persist a snapshot-supplied canonical
    /// committed epoch (`StateSnapshotMeta::epoch`) into the open
    /// production `ConsensusStorage`. Treated as fatal — the binary
    /// must not continue with a restored on-disk state whose canonical
    /// epoch parity cannot be honestly written to the
    /// `<data_dir>/consensus` surface.
    RestoreEpochWriteFailed {
        path: PathBuf,
        epoch: u64,
        source: StorageError,
    },
    /// Run 097: a restore was requested that would overwrite an
    /// existing CommittedEpoch with a *different* value sourced from
    /// the snapshot's `meta.json`. This is a hard inconsistency —
    /// either the operator is restoring a snapshot from the wrong
    /// node/epoch, or the on-disk consensus storage was advanced
    /// after the snapshot was taken. The binary must fail closed
    /// rather than silently overwrite.
    RestoreEpochInconsistent {
        path: PathBuf,
        existing: u64,
        snapshot: u64,
    },
}

impl std::fmt::Display for ProductionConsensusStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProductionConsensusStorageError::DataDirUnavailable { path, details } => write!(
                f,
                "production consensus storage: data_dir '{}' is unavailable: {}",
                path.display(),
                details
            ),
            ProductionConsensusStorageError::OpenFailed { path, source } => write!(
                f,
                "production consensus storage: RocksDbConsensusStorage::open('{}') failed: {}",
                path.display(),
                source
            ),
            ProductionConsensusStorageError::SchemaIncompatible { path, source } => write!(
                f,
                "production consensus storage: incompatible schema at '{}': {}",
                path.display(),
                source
            ),
            ProductionConsensusStorageError::IncompleteEpochTransition { path, source } => {
                write!(
                    f,
                    "production consensus storage: incomplete epoch transition at '{}': {}. \
                     The node must not continue with partially committed epoch boundary state.",
                    path.display(),
                    source
                )
            }
            ProductionConsensusStorageError::EpochProbeFailed { path, source } => write!(
                f,
                "production consensus storage: meta:current_epoch probe failed at '{}': {}",
                path.display(),
                source
            ),
            ProductionConsensusStorageError::RestoreEpochWriteFailed {
                path,
                epoch,
                source,
            } => write!(
                f,
                "production consensus storage: Run 097 restore failed to persist \
                 snapshot canonical epoch={} into '{}': {}. \
                 The node must not continue without a recorded canonical epoch \
                 matching the restored on-disk state.",
                epoch,
                path.display(),
                source
            ),
            ProductionConsensusStorageError::RestoreEpochInconsistent {
                path,
                existing,
                snapshot,
            } => write!(
                f,
                "production consensus storage: Run 097 restore inconsistency at \
                 '{}': existing meta:current_epoch={} but snapshot meta.json \
                 declares epoch={}. Refusing to silently overwrite. Either \
                 the snapshot is from a different node/epoch, or the on-disk \
                 consensus storage was advanced after the snapshot was taken.",
                path.display(),
                existing,
                snapshot
            ),
        }
    }
}

impl std::error::Error for ProductionConsensusStorageError {}

// ============================================================================
// OpenedProductionConsensusStorage
// ============================================================================

/// Result of [`open_production_consensus_storage`].
///
/// Carries the (optional) live `RocksDbConsensusStorage` handle, the
/// canonical on-disk path that was resolved, and the explicit
/// [`ConsensusStorageState`] observed at startup.
///
/// The `handle` is `None` only in the [`ConsensusStorageState::NoConsensusStorage`]
/// case. When `Some`, callers MUST keep the `Arc` alive for the
/// lifetime of the binary so the RocksDB lock is held continuously
/// (this is the lifecycle the task requires).
#[derive(Debug, Clone)]
pub struct OpenedProductionConsensusStorage {
    /// Canonical resolved path. `None` when `data_dir` is unset.
    pub path: Option<PathBuf>,
    /// Open storage handle. `None` when `data_dir` is unset.
    pub handle: Option<Arc<RocksDbConsensusStorage>>,
    /// Startup state observed.
    pub state: ConsensusStorageState,
}

impl OpenedProductionConsensusStorage {
    /// Build the "no consensus storage" outcome.
    pub fn no_storage() -> Self {
        OpenedProductionConsensusStorage {
            path: None,
            handle: None,
            state: ConsensusStorageState::NoConsensusStorage,
        }
    }

    /// Stable single-line summary used by `main.rs` startup logging.
    ///
    /// Example output:
    /// `[binary] Run 093 consensus storage: state=present-no-committed-epoch path=/data/qbind/consensus`
    /// `[binary] Run 093 consensus storage: state=committed-epoch epoch=7 path=/data/qbind/consensus`
    /// `[binary] Run 093 consensus storage: state=no-consensus-storage path=<none>`
    pub fn log_summary(&self) -> String {
        let path_str = self
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string());
        match self.state {
            ConsensusStorageState::CommittedEpoch(epoch) => format!(
                "[binary] Run 093 consensus storage: state={} epoch={} path={}",
                self.state.tag(),
                epoch,
                path_str
            ),
            _ => format!(
                "[binary] Run 093 consensus storage: state={} path={}",
                self.state.tag(),
                path_str
            ),
        }
    }
}

// ============================================================================
// open_production_consensus_storage
// ============================================================================

/// Open the production binary-path `ConsensusStorage` instance at the
/// canonical location and probe its startup state (Run 093).
///
/// Algorithm:
///
/// 1. If `config.data_dir` is `None`, return
///    [`OpenedProductionConsensusStorage::no_storage`] with state
///    [`ConsensusStorageState::NoConsensusStorage`]. **No fallback path
///    is invented.** This branch is only reachable on DevNet ad-hoc
///    smoke invocations; TestNet/MainNet already require `data_dir`
///    via existing invariant validation.
/// 2. Otherwise, resolve `<data_dir>/consensus` via
///    [`NodeConfig::consensus_storage_dir`]. Ensure the parent
///    `data_dir` exists; create it (and the consensus subdir parent
///    chain) if missing. Any I/O failure surfaces as
///    [`ProductionConsensusStorageError::DataDirUnavailable`].
/// 3. Call [`RocksDbConsensusStorage::open`] at that path. Any
///    error surfaces as
///    [`ProductionConsensusStorageError::OpenFailed`].
/// 4. Call [`ensure_compatible_schema`] (T104). Any error surfaces
///    as [`ProductionConsensusStorageError::SchemaIncompatible`].
/// 5. Call
///    [`ConsensusStorage::verify_epoch_consistency_on_startup`] (M16).
///    Any error surfaces as
///    [`ProductionConsensusStorageError::IncompleteEpochTransition`].
/// 6. Probe [`ConsensusStorage::get_current_epoch`]. `Ok(None)` →
///    [`ConsensusStorageState::PresentNoCommittedEpoch`]. `Ok(Some(e))`
///    → [`ConsensusStorageState::CommittedEpoch(e)`]. `Err(_)` →
///    [`ProductionConsensusStorageError::EpochProbeFailed`].
///
/// The opened handle is wrapped in an `Arc` and returned to the
/// caller, which MUST keep it alive for the lifetime of the binary.
///
/// # Errors
///
/// Returns [`ProductionConsensusStorageError`] on any open / schema
/// recovery / probe failure. The production binary MUST fail-closed
/// (non-zero exit) on any of these.
pub fn open_production_consensus_storage(
    config: &NodeConfig,
) -> Result<OpenedProductionConsensusStorage, ProductionConsensusStorageError> {
    // Step 1: data_dir presence check.
    let canonical_path = match config.consensus_storage_dir() {
        Some(p) => p,
        None => return Ok(OpenedProductionConsensusStorage::no_storage()),
    };

    // Step 2: ensure the parent data_dir exists (create if missing).
    // We do not pre-create the `consensus` subdir itself —
    // RocksDB::open with create_if_missing=true handles that. We only
    // need the parent so RocksDB can create the leaf directory.
    if let Some(parent) = canonical_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err(ProductionConsensusStorageError::DataDirUnavailable {
                    path: parent.to_path_buf(),
                    details: e.to_string(),
                });
            }
        }
    }

    // Step 3: open RocksDB at the canonical path.
    let storage = RocksDbConsensusStorage::open(&canonical_path).map_err(|e| {
        ProductionConsensusStorageError::OpenFailed {
            path: canonical_path.clone(),
            source: e,
        }
    })?;

    // Step 4: schema compatibility check (T104).
    ensure_compatible_schema(&storage).map_err(|e| {
        ProductionConsensusStorageError::SchemaIncompatible {
            path: canonical_path.clone(),
            source: e,
        }
    })?;

    // Step 5: incomplete-epoch-transition recovery / verification (M16).
    storage.verify_epoch_consistency_on_startup().map_err(|e| {
        ProductionConsensusStorageError::IncompleteEpochTransition {
            path: canonical_path.clone(),
            source: e,
        }
    })?;

    // Step 6: probe meta:current_epoch.
    let state = match storage.get_current_epoch() {
        Ok(None) => ConsensusStorageState::PresentNoCommittedEpoch,
        Ok(Some(epoch)) => ConsensusStorageState::CommittedEpoch(epoch),
        Err(e) => {
            return Err(ProductionConsensusStorageError::EpochProbeFailed {
                path: canonical_path,
                source: e,
            })
        }
    };

    Ok(OpenedProductionConsensusStorage {
        path: Some(canonical_path),
        handle: Some(Arc::new(storage)),
        state,
    })
}

// ============================================================================
// Run 097 — restore-time epoch parity
// ============================================================================

/// Run 097: persist a snapshot-supplied canonical committed epoch into the
/// production `<data_dir>/consensus` storage opened by
/// [`open_production_consensus_storage`].
///
/// Called from the binary's startup path **after** the on-disk VM-v0 state
/// has been materialized from the snapshot (B3) and **after** the canonical
/// `ConsensusStorage` has been opened (Run 093). This re-establishes
/// canonical epoch parity between the restored state and the
/// `<data_dir>/consensus` `meta:current_epoch` surface so that Run 094's
/// engine-epoch persistence and PQC trust-bundle activation observe the
/// same canonical epoch the snapshot was taken at.
///
/// # Semantics
///
/// - `snapshot_epoch == None`: legacy or no-epoch snapshot. No write is
///   attempted. The function returns `Ok(false)`. Run 097 MUST NOT coerce
///   absence into `Some(0)`.
/// - `snapshot_epoch == Some(n)`, storage state is
///   [`ConsensusStorageState::NoConsensusStorage`]: no storage handle is
///   open (DevNet ad-hoc smoke without `--data-dir`). Restore itself
///   already required `--data-dir`, so this branch is unreachable when
///   reached through the normal `apply_snapshot_restore_if_requested`
///   path; defensively returns `Ok(false)` if hit.
/// - `snapshot_epoch == Some(n)`, storage state is
///   [`ConsensusStorageState::PresentNoCommittedEpoch`]: writes
///   `meta:current_epoch = n` via `put_current_epoch`. Returns `Ok(true)`.
/// - `snapshot_epoch == Some(n)`, storage state is
///   [`ConsensusStorageState::CommittedEpoch(m)`] with `m == n`:
///   no-op (idempotent restore re-run). Returns `Ok(false)`.
/// - `snapshot_epoch == Some(n)`, storage state is
///   [`ConsensusStorageState::CommittedEpoch(m)`] with `m != n`:
///   returns [`ProductionConsensusStorageError::RestoreEpochInconsistent`]
///   (fail-closed — never silently overwrites).
///
/// # Errors
///
/// - [`ProductionConsensusStorageError::RestoreEpochWriteFailed`] on
///   `put_current_epoch` IO/checksum failure.
/// - [`ProductionConsensusStorageError::RestoreEpochInconsistent`] when
///   the pre-existing CommittedEpoch differs from the snapshot's epoch.
///
/// The production binary MUST fail-closed (non-zero exit) on either error.
pub fn persist_restored_snapshot_epoch(
    opened: &OpenedProductionConsensusStorage,
    snapshot_epoch: Option<u64>,
) -> Result<bool, ProductionConsensusStorageError> {
    let Some(target_epoch) = snapshot_epoch else {
        eprintln!(
            "[restore] Run 097 snapshot meta carries no canonical epoch (epoch=None); \
             leaving <data_dir>/consensus meta:current_epoch unchanged (explicit absence, NOT 0)"
        );
        return Ok(false);
    };

    let (path, storage) = match (&opened.path, &opened.handle) {
        (Some(p), Some(s)) => (p.clone(), s.clone()),
        _ => {
            eprintln!(
                "[restore] Run 097 snapshot canonical epoch={} not persisted: \
                 no production ConsensusStorage handle open (no --data-dir). \
                 This is unreachable on the supported restore path because \
                 restore itself requires --data-dir.",
                target_epoch
            );
            return Ok(false);
        }
    };

    match opened.state {
        ConsensusStorageState::CommittedEpoch(existing) if existing == target_epoch => {
            eprintln!(
                "[restore] Run 097 snapshot canonical epoch={} already matches \
                 pre-existing meta:current_epoch at {}; no-op (idempotent restore)",
                target_epoch,
                path.display()
            );
            Ok(false)
        }
        ConsensusStorageState::CommittedEpoch(existing) => {
            Err(ProductionConsensusStorageError::RestoreEpochInconsistent {
                path,
                existing,
                snapshot: target_epoch,
            })
        }
        ConsensusStorageState::PresentNoCommittedEpoch => {
            eprintln!(
                "[restore] Run 097 persisting snapshot canonical epoch={} into \
                 {} (state was present-no-committed-epoch)",
                target_epoch,
                path.display()
            );
            storage.put_current_epoch(target_epoch).map_err(|e| {
                ProductionConsensusStorageError::RestoreEpochWriteFailed {
                    path: path.clone(),
                    epoch: target_epoch,
                    source: e,
                }
            })?;
            eprintln!(
                "[restore] Run 097 persisted snapshot canonical epoch={} into {}",
                target_epoch,
                path.display()
            );
            Ok(true)
        }
        ConsensusStorageState::NoConsensusStorage => {
            // Defensive: matched the (None, None) branch above; never reached.
            Ok(false)
        }
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::NodeConfig;
    use tempfile::TempDir;

    fn devnet_config_with_data_dir(data_dir: &std::path::Path) -> NodeConfig {
        NodeConfig::devnet().with_data_dir(data_dir)
    }

    #[test]
    fn canonical_path_is_data_dir_slash_consensus() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let resolved = cfg.consensus_storage_dir().expect("data_dir set");
        assert_eq!(resolved, tmp.path().join("consensus"));
    }

    #[test]
    fn no_data_dir_yields_no_consensus_storage() {
        let cfg = NodeConfig::devnet();
        assert!(cfg.consensus_storage_dir().is_none());
        let opened = open_production_consensus_storage(&cfg).expect("ok");
        assert_eq!(opened.state, ConsensusStorageState::NoConsensusStorage);
        assert!(opened.handle.is_none());
        assert!(opened.path.is_none());
        assert!(opened.state.committed_epoch().is_none());
        assert!(!opened.state.has_open_storage());
    }

    #[test]
    fn fresh_open_is_present_no_committed_epoch() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("open ok");
        assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
        assert!(opened.handle.is_some());
        assert_eq!(
            opened.path.as_deref(),
            Some(tmp.path().join("consensus").as_path())
        );
        // Fresh-genesis MUST NOT silently look like current_epoch=0.
        assert!(opened.state.committed_epoch().is_none());
    }

    #[test]
    fn committed_epoch_is_distinguishable_from_present_no_committed_epoch() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        // First open: write a committed epoch directly through the trait surface.
        {
            let opened = open_production_consensus_storage(&cfg).expect("open ok");
            assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
            opened
                .handle
                .as_ref()
                .unwrap()
                .put_current_epoch(7)
                .expect("write epoch");
            // Drop handle to release RocksDB lock before re-open.
        }
        // Second open: should observe CommittedEpoch(7).
        let opened2 = open_production_consensus_storage(&cfg).expect("reopen ok");
        assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(7));
        assert_eq!(opened2.state.committed_epoch(), Some(7));
        assert!(opened2.state.has_open_storage());
    }

    #[test]
    fn committed_epoch_persists_across_restart() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        // Open, write epoch=42, close.
        {
            let opened = open_production_consensus_storage(&cfg).expect("open ok");
            opened
                .handle
                .as_ref()
                .unwrap()
                .put_current_epoch(42)
                .expect("write epoch");
        }
        // Restart simulated by dropping the previous handle and re-opening.
        let opened2 = open_production_consensus_storage(&cfg).expect("reopen ok");
        assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(42));
    }

    #[test]
    fn log_summary_includes_state_tag_and_epoch_when_committed() {
        let no = OpenedProductionConsensusStorage::no_storage();
        let line = no.log_summary();
        assert!(line.contains("state=no-consensus-storage"));
        assert!(line.contains("path=<none>"));

        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("ok");
        let line = opened.log_summary();
        assert!(line.contains("state=present-no-committed-epoch"));
        assert!(line.contains("consensus"));

        opened
            .handle
            .as_ref()
            .unwrap()
            .put_current_epoch(11)
            .unwrap();
        // Re-probe by re-opening to get CommittedEpoch state.
        drop(opened);
        let opened2 = open_production_consensus_storage(&cfg).expect("ok");
        let line = opened2.log_summary();
        assert!(line.contains("state=committed-epoch"));
        assert!(line.contains("epoch=11"));
    }

    #[test]
    fn handle_is_arc_and_can_be_cloned_for_lifetime_holding() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("ok");
        let h1 = opened.handle.as_ref().unwrap().clone();
        let h2 = h1.clone();
        // Both clones must be usable for reads.
        assert!(h1.get_current_epoch().unwrap().is_none());
        assert!(h2.get_current_epoch().unwrap().is_none());
    }

    // ========================================================================
    // Run 097 — persist_restored_snapshot_epoch tests
    // ========================================================================

    #[test]
    fn run097_persist_none_snapshot_epoch_is_noop() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("open");
        // Snapshot meta carrying epoch=None must NOT trigger any write
        // and MUST NOT silently coerce to epoch=0.
        let wrote = persist_restored_snapshot_epoch(&opened, None).expect("ok");
        assert!(!wrote);
        // Confirm storage still has no committed epoch (NOT 0).
        assert_eq!(
            opened.handle.as_ref().unwrap().get_current_epoch().unwrap(),
            None
        );
    }

    #[test]
    fn run097_persist_some_into_present_no_committed_epoch_writes_canonical_epoch() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("open");
        assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);

        let wrote = persist_restored_snapshot_epoch(&opened, Some(13)).expect("write ok");
        assert!(wrote);

        // The same handle now reads back epoch=13.
        let got = opened
            .handle
            .as_ref()
            .unwrap()
            .get_current_epoch()
            .expect("get");
        assert_eq!(got, Some(13));

        // Re-opening the storage observes the restored CommittedEpoch.
        drop(opened);
        let opened2 = open_production_consensus_storage(&cfg).expect("reopen");
        assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(13));
    }

    #[test]
    fn run097_persist_idempotent_when_existing_matches_snapshot() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        // Pre-write epoch=5 then re-open so state observes CommittedEpoch(5).
        {
            let opened = open_production_consensus_storage(&cfg).expect("open");
            opened
                .handle
                .as_ref()
                .unwrap()
                .put_current_epoch(5)
                .unwrap();
        }
        let opened = open_production_consensus_storage(&cfg).expect("reopen");
        assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(5));

        // Restoring a snapshot whose epoch matches the existing value
        // is an idempotent no-op (returns Ok(false)).
        let wrote = persist_restored_snapshot_epoch(&opened, Some(5)).expect("ok");
        assert!(!wrote);
    }

    #[test]
    fn run097_persist_inconsistent_existing_epoch_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        {
            let opened = open_production_consensus_storage(&cfg).expect("open");
            opened
                .handle
                .as_ref()
                .unwrap()
                .put_current_epoch(9)
                .unwrap();
        }
        let opened = open_production_consensus_storage(&cfg).expect("reopen");
        assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(9));

        // Snapshot meta says epoch=7 but on-disk says epoch=9 — must
        // fail closed rather than silently overwriting either side.
        let err = persist_restored_snapshot_epoch(&opened, Some(7)).expect_err("must fail");
        match err {
            ProductionConsensusStorageError::RestoreEpochInconsistent {
                existing,
                snapshot,
                ..
            } => {
                assert_eq!(existing, 9);
                assert_eq!(snapshot, 7);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Confirm storage was NOT overwritten.
        let got = opened.handle.as_ref().unwrap().get_current_epoch().unwrap();
        assert_eq!(got, Some(9));
    }

    #[test]
    fn run097_persist_into_no_storage_is_defensive_noop() {
        let opened = OpenedProductionConsensusStorage::no_storage();
        // No data_dir, no handle. The function returns Ok(false) and
        // does not attempt any write — this branch is unreachable in
        // production because restore itself requires --data-dir.
        let wrote = persist_restored_snapshot_epoch(&opened, Some(3)).expect("ok");
        assert!(!wrote);
    }

    #[test]
    fn run097_persist_epoch_zero_is_canonical_committed_epoch_zero() {
        // Snapshot carrying epoch=Some(0) is the canonical genesis
        // CommittedEpoch — NOT the same as absence. It must be
        // persisted as `meta:current_epoch=0`.
        let tmp = TempDir::new().unwrap();
        let cfg = devnet_config_with_data_dir(tmp.path());
        let opened = open_production_consensus_storage(&cfg).expect("open");
        let wrote = persist_restored_snapshot_epoch(&opened, Some(0)).expect("ok");
        assert!(wrote);
        assert_eq!(
            opened.handle.as_ref().unwrap().get_current_epoch().unwrap(),
            Some(0)
        );

        drop(opened);
        let opened2 = open_production_consensus_storage(&cfg).expect("reopen");
        assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(0));
    }
}
