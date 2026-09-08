//! Run 098 — canonical activation epoch source helper for production
//! trust-bundle activation.
//!
//! This module provides a narrow, safe helper surface that wires the
//! canonical Run 093 production `ConsensusStorage` `meta:current_epoch`
//! value into the `ActivationContext.current_epoch` field used at
//! trust-bundle activation call sites.
//!
//! # Background
//!
//! - **Run 091** established the fail-closed `CurrentEpochUnavailable`
//!   boundary: any trust bundle declaring `activation_epoch` is
//!   rejected when no canonical epoch source is available.
//! - **Run 092** investigated wiring but found that `qbind-node` did
//!   not open RocksDB consensus storage.
//! - **Run 093** landed the canonical production binary-path
//!   `ConsensusStorage` lifecycle (`<data_dir>/consensus`).
//! - **Run 094–096** added binary-path epoch transition persistence.
//! - **Run 097** added snapshot epoch parity so that restored
//!   snapshots can re-establish `meta:current_epoch`.
//!
//! **Run 098** is the first run allowed to consume the canonical
//! committed epoch for trust-bundle activation.
//!
//! # What this module does
//!
//! - Exports [`ActivationEpochSource`] enum with two variants:
//!   `Committed(u64)` (a canonical committed epoch exists) and
//!   `UnavailableNoCommittedEpoch` (no canonical epoch is present).
//! - Exports helper functions to derive `ActivationEpochSource` from:
//!   * An already-opened [`OpenedProductionConsensusStorage`]
//!     (lifecycle path — used at startup).
//!   * A bare `Option<&Arc<RocksDbConsensusStorage>>` handle
//!     (running-node path — used by SIGHUP and live dispatcher).
//! - Exports [`load_activation_current_epoch_for_cli`] for CLI
//!   subcommand paths that exit before the main consensus loop starts.
//!
//! # What this module does NOT do
//!
//! - Does **not** derive epoch from block height, view number,
//!   wall-clock time, timer ticks, snapshot height, filename, or
//!   any other non-canonical source.
//! - Does **not** treat missing epoch as epoch `0`. Missing epoch
//!   returns `UnavailableNoCommittedEpoch` → `as_option()` returns
//!   `None`, which in turn triggers
//!   `TrustBundleActivationError::CurrentEpochUnavailable` at the
//!   activation gate for any bundle that declares `activation_epoch`.
//! - Does **not** silently ignore storage errors. Storage failures
//!   are surfaced as typed errors (fail-closed direction).
//!
//! # See also
//!
//! - `task/RUN_098_TASK.txt`
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md`
//! - `crates/qbind-node/src/production_consensus_storage.rs` (Run 093)
//! - `crates/qbind-node/src/pqc_trust_activation.rs` (Run 057/091)

use std::sync::Arc;

use crate::node_config::NodeConfig;
use crate::production_consensus_storage::{
    OpenedProductionConsensusStorage, ProductionConsensusStorageError,
    open_production_consensus_storage,
};
use crate::storage::{ConsensusStorage, RocksDbConsensusStorage, StorageError};

// ============================================================================
// ActivationEpochSource
// ============================================================================

/// Run 098 — explicit canonical activation epoch source.
///
/// This enum distinguishes between two production states:
///
/// 1. `Committed(u64)` — a canonical `meta:current_epoch` value
///    exists in the production `ConsensusStorage`. Trust-bundle
///    activation can use `Some(n)` for `current_epoch`.
/// 2. `UnavailableNoCommittedEpoch` — no canonical epoch has ever
///    been committed (fresh genesis, old snapshot without epoch,
///    or no `data_dir` configured). Trust-bundle activation MUST
///    use `None` for `current_epoch`, causing any bundle that
///    declares `activation_epoch` to fail closed with
///    `CurrentEpochUnavailable`.
///
/// **Critical invariants:**
///
/// - Missing epoch is **NOT** epoch `0`.
/// - Storage errors are surfaced separately; this enum is for
///   valid no-epoch vs valid committed-epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationEpochSource {
    /// A committed canonical epoch exists.
    Committed(u64),
    /// No committed epoch exists. This is the expected state for
    /// fresh genesis, old snapshots without epoch metadata, or
    /// ad-hoc DevNet invocations without `--data-dir`.
    UnavailableNoCommittedEpoch,
}

impl ActivationEpochSource {
    /// Convert to `Option<u64>` for use in `ActivationContext`.
    ///
    /// - `Committed(n)` → `Some(n)`
    /// - `UnavailableNoCommittedEpoch` → `None`
    ///
    /// When the result is `None`, the activation gate's
    /// `check_bundle_activation` will return
    /// `CurrentEpochUnavailable` for any bundle that declares
    /// `activation_epoch`.
    pub fn as_option(&self) -> Option<u64> {
        match self {
            ActivationEpochSource::Committed(n) => Some(*n),
            ActivationEpochSource::UnavailableNoCommittedEpoch => None,
        }
    }
}

// ============================================================================
// Derivation from OpenedProductionConsensusStorage (lifecycle path)
// ============================================================================

/// Derive [`ActivationEpochSource`] from an already-opened
/// [`OpenedProductionConsensusStorage`] (Run 093 lifecycle result).
///
/// This is the startup path: the canonical consensus storage has
/// already been opened, schema-checked, and epoch-probed by
/// `open_production_consensus_storage`. We simply inspect the
/// resulting [`ConsensusStorageState`].
///
/// # Returns
///
/// - `Committed(n)` if `opened.state` is `CommittedEpoch(n)`.
/// - `UnavailableNoCommittedEpoch` if `opened.state` is
///   `NoConsensusStorage` or `PresentNoCommittedEpoch`.
pub fn activation_epoch_source_from_lifecycle(
    opened: &OpenedProductionConsensusStorage,
) -> ActivationEpochSource {
    match opened.state.committed_epoch() {
        Some(n) => ActivationEpochSource::Committed(n),
        None => ActivationEpochSource::UnavailableNoCommittedEpoch,
    }
}

// ============================================================================
// Derivation from storage handle (running-node path)
// ============================================================================

/// Derive [`ActivationEpochSource`] from an optional storage handle.
///
/// This is the running-node path: the SIGHUP live-reload trigger
/// and the live peer-candidate dispatcher need to read the current
/// canonical epoch per activation without re-opening the database.
///
/// # Arguments
///
/// - `storage` — an already-open `RocksDbConsensusStorage` handle,
///   or `None` if no storage is available (DevNet ad-hoc without
///   `--data-dir`).
///
/// # Returns
///
/// - `Ok(Committed(n))` if `storage.get_current_epoch()` returns
///   `Ok(Some(n))`.
/// - `Ok(UnavailableNoCommittedEpoch)` if `storage` is `None` or
///   `storage.get_current_epoch()` returns `Ok(None)`.
/// - `Err(StorageError)` if `storage.get_current_epoch()` returns
///   an error. The caller MUST handle this fail-closed (e.g. log
///   and treat as unavailable for that activation frame).
pub fn activation_epoch_source_from_storage(
    storage: Option<&Arc<RocksDbConsensusStorage>>,
) -> Result<ActivationEpochSource, StorageError> {
    match storage {
        None => Ok(ActivationEpochSource::UnavailableNoCommittedEpoch),
        Some(s) => match s.get_current_epoch() {
            Ok(Some(n)) => Ok(ActivationEpochSource::Committed(n)),
            Ok(None) => Ok(ActivationEpochSource::UnavailableNoCommittedEpoch),
            Err(e) => Err(e),
        },
    }
}

// ============================================================================
// CLI subcommand helper
// ============================================================================

/// Open the canonical production `ConsensusStorage` and derive the
/// activation epoch source (CLI subcommand path).
///
/// This is for CLI modes that exit via `std::process::exit()` and
/// therefore cannot use an already-opened storage lifecycle (e.g.
/// `--p2p-trust-bundle-reload-check`,
/// `--p2p-trust-bundle-peer-candidate-check`,
/// `--p2p-trust-bundle-reload-apply-path`).
///
/// # Arguments
///
/// - `config` — the `NodeConfig` (carries `data_dir`).
///
/// # Returns
///
/// - `Ok((source, opened))` — the epoch source derived from the
///   opened storage, plus the opened lifecycle handle. The caller
///   MUST keep `opened` alive for the duration of the operation
///   (bind to `_opened` until process exit).
/// - `Err(ProductionConsensusStorageError)` — storage open, schema,
///   recovery, or probe failed. The caller MUST fail-closed (exit 1).
///
/// If `config.data_dir` is `None` (DevNet ad-hoc), returns
/// `Ok((UnavailableNoCommittedEpoch, no_storage()))`.
pub fn load_activation_current_epoch_for_cli(
    config: &NodeConfig,
) -> Result<(ActivationEpochSource, OpenedProductionConsensusStorage), ProductionConsensusStorageError>
{
    let opened = open_production_consensus_storage(config)?;
    let source = activation_epoch_source_from_lifecycle(&opened);
    Ok((source, opened))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_consensus_storage::ConsensusStorageState;
    use tempfile::TempDir;

    // Helper: build an OpenedProductionConsensusStorage with a given state
    fn mock_opened(state: ConsensusStorageState) -> OpenedProductionConsensusStorage {
        OpenedProductionConsensusStorage {
            path: None,
            handle: None,
            state,
        }
    }

    #[test]
    fn committed_epoch_lifecycle_maps_to_source() {
        // Given an OpenedProductionConsensusStorage with CommittedEpoch(7)
        let opened = mock_opened(ConsensusStorageState::CommittedEpoch(7));

        // When we derive the activation epoch source
        let source = activation_epoch_source_from_lifecycle(&opened);

        // Then it should be Committed(7) and as_option should return Some(7)
        assert_eq!(source, ActivationEpochSource::Committed(7));
        assert_eq!(source.as_option(), Some(7));
    }

    #[test]
    fn present_no_committed_epoch_maps_to_unavailable() {
        // Given an OpenedProductionConsensusStorage with PresentNoCommittedEpoch
        let opened = mock_opened(ConsensusStorageState::PresentNoCommittedEpoch);

        // When we derive the activation epoch source
        let source = activation_epoch_source_from_lifecycle(&opened);

        // Then it should be UnavailableNoCommittedEpoch and as_option should return None
        assert_eq!(source, ActivationEpochSource::UnavailableNoCommittedEpoch);
        assert_eq!(source.as_option(), None);
    }

    #[test]
    fn no_consensus_storage_maps_to_unavailable() {
        // Given an OpenedProductionConsensusStorage with NoConsensusStorage
        let opened = mock_opened(ConsensusStorageState::NoConsensusStorage);

        // When we derive the activation epoch source
        let source = activation_epoch_source_from_lifecycle(&opened);

        // Then it should be UnavailableNoCommittedEpoch and as_option should return None
        assert_eq!(source, ActivationEpochSource::UnavailableNoCommittedEpoch);
        assert_eq!(source.as_option(), None);
    }

    #[test]
    fn storage_handle_with_committed_epoch_returns_committed() {
        // Open a real RocksDB in a tempdir, put_current_epoch(11)
        let tmp = TempDir::new().unwrap();
        let storage = RocksDbConsensusStorage::open(tmp.path()).expect("open ok");
        storage.put_current_epoch(11).expect("put epoch ok");
        let arc = Arc::new(storage);

        // Call activation_epoch_source_from_storage(Some(&handle))
        let result = activation_epoch_source_from_storage(Some(&arc));

        // Expect Ok(Committed(11))
        assert!(result.is_ok());
        let source = result.unwrap();
        assert_eq!(source, ActivationEpochSource::Committed(11));
        assert_eq!(source.as_option(), Some(11));
    }

    #[test]
    fn storage_handle_with_no_epoch_returns_unavailable() {
        // Open a real RocksDB in a tempdir, do NOT put_current_epoch
        let tmp = TempDir::new().unwrap();
        let storage = RocksDbConsensusStorage::open(tmp.path()).expect("open ok");
        let arc = Arc::new(storage);

        // Call activation_epoch_source_from_storage(Some(&handle))
        let result = activation_epoch_source_from_storage(Some(&arc));

        // Expect Ok(UnavailableNoCommittedEpoch)
        assert!(result.is_ok());
        let source = result.unwrap();
        assert_eq!(source, ActivationEpochSource::UnavailableNoCommittedEpoch);
        assert_eq!(source.as_option(), None);
    }

    #[test]
    fn no_storage_handle_returns_unavailable() {
        // Call activation_epoch_source_from_storage(None)
        let result = activation_epoch_source_from_storage(None);

        // Expect Ok(UnavailableNoCommittedEpoch)
        assert!(result.is_ok());
        let source = result.unwrap();
        assert_eq!(source, ActivationEpochSource::UnavailableNoCommittedEpoch);
        assert_eq!(source.as_option(), None);
    }
}