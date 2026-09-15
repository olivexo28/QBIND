//! Read-only, non-authorizing observation boundary over consensus storage
//! (Run 422 D7-C1).
//!
//! This module provides a **bounded, read-only** view of what an *already
//! opened* consensus [`ConsensusStorage`] handle reports at the moment it is
//! queried. It exists to distinguish, without mutation, the storage states a
//! caller may legitimately need to reason about:
//!
//! - no storage handle at all,
//! - a database with no committed epoch key,
//! - an explicitly stored epoch (including the distinct value zero),
//! - an incompatible schema,
//! - malformed / corrupt epoch or schema metadata,
//! - an incomplete epoch transition.
//!
//! # What this boundary is NOT
//!
//! A readable persisted epoch is **not** proof of current Proposal/Vote
//! authority. This observation:
//!
//! - does **not** open, create, upgrade, or rewrite storage;
//! - does **not** write, delete, clear, apply a transition, or restore;
//! - does **not** establish an authorization owner, activate genesis
//!   authority, or claim durable anti-rollback;
//! - does **not** convert its result into
//!   [`crate::genesis_consensus_authority::LocalAuthorizationState::Established`],
//!   a `CurrentAuthorizationOwner`, an `AuthorizedProposalVoteSnapshot`, or any
//!   authorization ticket.
//!
//! The observed epoch is returned **only as storage evidence**. Binding that
//! evidence to chain/genesis identity, validator membership, keys, signing
//! domain, activation authorization, or a rollback trust model is explicitly
//! out of scope and must be established separately before any current-
//! authorization lifecycle could depend on it.
//!
//! # Synchronization assumption
//!
//! [`observe_consensus_storage`] performs several ordinary reads (schema
//! version, epoch-transition marker, current epoch) against the supplied
//! handle. These reads are **not** taken as one atomic snapshot. The result is
//! therefore meaningful only for observations made while the relevant writers
//! are serialized or quiescent (e.g. a startup probe, or a caller that holds
//! the storage lock exclusively). This boundary makes no claim of an atomic
//! snapshot, concurrent consistency, or freshness that survives a later
//! consensus write. No concurrency redesign is introduced here.
//!
//! # Read model
//!
//! The reader consults the actual storage on **each** invocation (it never
//! caches a startup summary), so it observes the current persisted value even
//! if some earlier startup-state summary is stale. It reuses the existing
//! storage decoding/checksum behavior (`get_schema_version`,
//! [`ensure_compatible_schema`], `check_for_incomplete_epoch_transition`,
//! `get_current_epoch`) rather than parsing epoch bytes itself, so legacy
//! storage compatibility is preserved unchanged.

use crate::storage::{ensure_compatible_schema, ConsensusStorage, StorageError};

// ============================================================================
// Observation result
// ============================================================================

/// The read-only observation of a consensus storage handle at query time.
///
/// This describes *only* what the supplied local database reports under the
/// read model documented at the module level. It carries no authorization,
/// freshness, or identity binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStorageObservation {
    /// No storage handle was supplied. Nothing was opened or created.
    NoStorageHandle,
    /// A storage handle is present, but it holds no committed epoch key.
    ///
    /// This is **distinct** from [`Self::CommittedEpoch`] with value `0`: a
    /// missing epoch is never coerced to zero.
    PresentNoCommittedEpoch,
    /// A storage handle is present and reports an explicitly committed epoch.
    ///
    /// The inner value — including an explicit `0` — is **storage evidence
    /// only** and never implies authorization or freshness.
    CommittedEpoch(u64),
}

impl ConsensusStorageObservation {
    /// The observed committed epoch, if any.
    ///
    /// Returns `None` for both [`Self::NoStorageHandle`] and
    /// [`Self::PresentNoCommittedEpoch`], preserving the distinction between an
    /// absent epoch and an explicitly stored epoch. This value is storage
    /// evidence only; it is not an authorization capability.
    pub fn committed_epoch(&self) -> Option<u64> {
        match self {
            ConsensusStorageObservation::CommittedEpoch(e) => Some(*e),
            ConsensusStorageObservation::NoStorageHandle
            | ConsensusStorageObservation::PresentNoCommittedEpoch => None,
        }
    }

    /// Whether a storage handle was present at observation time.
    pub fn has_storage_handle(&self) -> bool {
        !matches!(self, ConsensusStorageObservation::NoStorageHandle)
    }
}

// ============================================================================
// Observation error
// ============================================================================

/// Bounded error categories for [`observe_consensus_storage`].
///
/// These categories are deliberately narrow and are **never** collapsed into a
/// "no epoch" observation: a corruption, I/O, schema, or incomplete-transition
/// condition always surfaces as an explicit error rather than as
/// [`ConsensusStorageObservation::PresentNoCommittedEpoch`].
#[derive(Debug)]
pub enum ConsensusStorageObservationError {
    /// The on-disk schema version is newer than this binary supports (T104).
    ///
    /// Surfaced from [`ensure_compatible_schema`]; the existing compatibility
    /// policy is applied unchanged (missing / older versions are compatible).
    IncompatibleSchema {
        /// Schema version found in storage.
        stored_version: u32,
        /// Maximum schema version this binary supports.
        current_version: u32,
    },
    /// An incomplete epoch-transition marker was observed (M16).
    ///
    /// The observation refuses rather than reporting an epoch, even when an
    /// epoch key is independently readable. The marker is **not** cleared and
    /// the stored epoch is **not** changed.
    IncompleteEpochTransition {
        /// Epoch the interrupted transition was moving toward.
        target_epoch: u64,
        /// Epoch the interrupted transition was moving away from.
        previous_epoch: u64,
    },
    /// Stored metadata failed to decode (checksum/codec/corruption).
    ///
    /// Never reported as "no epoch". Preserves the underlying
    /// [`StorageError`] category.
    MalformedMetadata {
        /// Which logical metadata surface failed to decode.
        surface: &'static str,
        /// The underlying storage error (`Codec` / `Corruption`).
        source: StorageError,
    },
    /// An underlying read failed (I/O or other non-decode failure).
    ///
    /// Never reported as "no epoch".
    ReadFailed {
        /// Which logical read failed.
        surface: &'static str,
        /// The underlying storage error (`Io` / `Other`).
        source: StorageError,
    },
}

impl std::fmt::Display for ConsensusStorageObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusStorageObservationError::IncompatibleSchema {
                stored_version,
                current_version,
            } => write!(
                f,
                "consensus storage observation: incompatible schema version {} (this binary \
                 supports up to {})",
                stored_version, current_version
            ),
            ConsensusStorageObservationError::IncompleteEpochTransition {
                target_epoch,
                previous_epoch,
            } => write!(
                f,
                "consensus storage observation: incomplete epoch transition marker present \
                 (previous={}, target={}); refusing to report an epoch",
                previous_epoch, target_epoch
            ),
            ConsensusStorageObservationError::MalformedMetadata { surface, source } => write!(
                f,
                "consensus storage observation: malformed {} metadata: {}",
                surface, source
            ),
            ConsensusStorageObservationError::ReadFailed { surface, source } => write!(
                f,
                "consensus storage observation: read of {} failed: {}",
                surface, source
            ),
        }
    }
}

impl std::error::Error for ConsensusStorageObservationError {}

/// Classify a [`StorageError`] into a bounded observation error category,
/// preserving the underlying category (corruption/codec vs I/O) and never
/// collapsing it into a "no epoch" result.
fn classify_read_error(
    surface: &'static str,
    err: StorageError,
) -> ConsensusStorageObservationError {
    match err {
        StorageError::IncompatibleSchema {
            stored_version,
            current_version,
        } => ConsensusStorageObservationError::IncompatibleSchema {
            stored_version,
            current_version,
        },
        StorageError::IncompleteEpochTransition { epoch, .. } => {
            // The marker path (below) provides the richer previous/target pair;
            // this arm only fires if a helper surfaces the category directly.
            ConsensusStorageObservationError::IncompleteEpochTransition {
                target_epoch: epoch,
                previous_epoch: epoch,
            }
        }
        StorageError::Codec(_) | StorageError::Corruption(_) => {
            ConsensusStorageObservationError::MalformedMetadata { surface, source: err }
        }
        StorageError::Io(_) | StorageError::Other(_) => {
            ConsensusStorageObservationError::ReadFailed { surface, source: err }
        }
    }
}

// ============================================================================
// observe_consensus_storage
// ============================================================================

/// Observe an already-opened consensus storage handle, read-only.
///
/// This is the sole entry point of the D7-C1 observation boundary. It consumes
/// an **optional reference** to an existing [`ConsensusStorage`] handle and
/// never opens, creates, or mutates storage.
///
/// # Behavior
///
/// 1. `None` handle → [`ConsensusStorageObservation::NoStorageHandle`]. Nothing
///    is opened or created.
/// 2. Apply the existing schema-compatibility policy via
///    [`ensure_compatible_schema`]. A newer-than-supported schema surfaces as
///    [`ConsensusStorageObservationError::IncompatibleSchema`]; malformed schema
///    metadata surfaces as
///    [`ConsensusStorageObservationError::MalformedMetadata`]. No silent
///    upgrade or rewrite occurs.
/// 3. Reject an incomplete epoch transition (M16) via
///    `check_for_incomplete_epoch_transition`. If a marker is present the
///    function returns
///    [`ConsensusStorageObservationError::IncompleteEpochTransition`] **without**
///    clearing the marker or reading past it, even if an epoch key is readable.
/// 4. Probe `get_current_epoch`. `Ok(None)` →
///    [`ConsensusStorageObservation::PresentNoCommittedEpoch`]; `Ok(Some(e))` →
///    [`ConsensusStorageObservation::CommittedEpoch(e)`] (including `e == 0`).
///    Any decode/read failure surfaces as an explicit bounded error and is
///    never turned into "no epoch".
///
/// The handle is read on **every** call, so the result reflects the current
/// persisted value rather than any cached startup summary. See the module-level
/// synchronization assumption: the several reads are not atomic and are only
/// meaningful while writers are serialized or quiescent.
///
/// # Non-authorization
///
/// The returned [`ConsensusStorageObservation`] is storage evidence only. It is
/// intentionally not convertible into any authorization state, owner, snapshot,
/// or ticket.
pub fn observe_consensus_storage<S>(
    handle: Option<&S>,
) -> Result<ConsensusStorageObservation, ConsensusStorageObservationError>
where
    S: ConsensusStorage + ?Sized,
{
    // Step 1: explicit "no handle" report — never opens or creates anything.
    let storage = match handle {
        None => return Ok(ConsensusStorageObservation::NoStorageHandle),
        Some(s) => s,
    };

    // Step 2: existing schema-compatibility policy (read-only). Preserves the
    // legacy-compatible / newer-incompatible rules without upgrading storage.
    ensure_compatible_schema(storage).map_err(|e| classify_read_error("schema version", e))?;

    // Step 3: reject an incomplete epoch transition (M16) before reading the
    // epoch. This read does not clear the marker or mutate the epoch.
    match storage.check_for_incomplete_epoch_transition() {
        Ok(Some(marker)) => {
            return Err(ConsensusStorageObservationError::IncompleteEpochTransition {
                target_epoch: marker.target_epoch,
                previous_epoch: marker.previous_epoch,
            });
        }
        Ok(None) => {}
        Err(e) => return Err(classify_read_error("epoch transition marker", e)),
    }

    // Step 4: observe the committed epoch. Preserve None vs Some(0); never turn
    // a decode/read failure into "no epoch".
    match storage.get_current_epoch() {
        Ok(None) => Ok(ConsensusStorageObservation::PresentNoCommittedEpoch),
        Ok(Some(epoch)) => Ok(ConsensusStorageObservation::CommittedEpoch(epoch)),
        Err(e) => Err(classify_read_error("current epoch", e)),
    }
}

// ============================================================================
// Unit tests (logic-level; real-storage/recovery coverage lives in the
// integration target crates/qbind-node/tests/run_422_d7c1_*).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryConsensusStorage;

    #[test]
    fn none_handle_reports_no_storage_handle() {
        let obs = observe_consensus_storage::<InMemoryConsensusStorage>(None).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::NoStorageHandle);
        assert!(!obs.has_storage_handle());
        assert_eq!(obs.committed_epoch(), None);
    }

    #[test]
    fn present_without_committed_epoch_is_not_zero() {
        let storage = InMemoryConsensusStorage::new();
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);
        assert!(obs.has_storage_handle());
        assert_eq!(obs.committed_epoch(), None);
    }

    #[test]
    fn explicit_epoch_zero_is_distinct_from_absence() {
        let storage = InMemoryConsensusStorage::new();
        storage.put_current_epoch(0).unwrap();
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(0));
        assert_eq!(obs.committed_epoch(), Some(0));
    }

    #[test]
    fn later_epoch_is_observed() {
        let storage = InMemoryConsensusStorage::new();
        storage.put_current_epoch(7).unwrap();
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(7));
    }

    #[test]
    fn incomplete_transition_marker_rejected_and_preserved() {
        use crate::storage::EpochTransitionMarker;
        let storage = InMemoryConsensusStorage::new();
        storage.put_current_epoch(3).unwrap();
        let marker = EpochTransitionMarker {
            target_epoch: 4,
            previous_epoch: 3,
            started_at_ms: 1,
            reconfig_block_id: [9u8; 32],
        };
        storage.write_epoch_transition_marker(&marker).unwrap();

        let err = observe_consensus_storage(Some(&storage)).unwrap_err();
        match err {
            ConsensusStorageObservationError::IncompleteEpochTransition {
                target_epoch,
                previous_epoch,
            } => {
                assert_eq!(target_epoch, 4);
                assert_eq!(previous_epoch, 3);
            }
            other => panic!("expected IncompleteEpochTransition, got {:?}", other),
        }

        // The observation neither cleared the marker nor changed the epoch.
        assert!(storage
            .check_for_incomplete_epoch_transition()
            .unwrap()
            .is_some());
        assert_eq!(storage.get_current_epoch().unwrap(), Some(3));
    }
}
