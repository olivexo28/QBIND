//! Vote accumulator for HotStuff-like QC formation.
//!
//! This module provides a `VoteAccumulator` that:
//! - Tracks votes keyed by (view, block_id)
//! - Knows which validators have voted for each (view, block_id) pair
//! - Emits a `QuorumCertificate` when a quorum is reached
//! - Enforces configurable memory limits to prevent unbounded growth
//!
//! # Design Note
//!
//! The accumulator is generic over `BlockIdT` to support different block
//! identifier types. The canonical type in cano-consensus is `[u8; 32]`.
//!
//! No cryptographic verification is performed in this module; that will be
//! added in future tasks.
//!
//! # Memory Limits (T118)
//!
//! The accumulator can be configured with memory limits via `ConsensusLimitsConfig`:
//! - `max_tracked_views`: Maximum number of views to track simultaneously
//! - `max_votes_per_view`: Maximum votes per (view, block_id) pair
//!
//! When limits are exceeded, the accumulator drops excess votes or evicts
//! old view state rather than growing unbounded.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;

/// Configuration for consensus memory limits (T118, T122, T123).
///
/// This struct configures bounds on data structures in the consensus layer
/// to prevent unbounded memory growth under adversarial conditions.
///
/// # Defaults
///
/// The default configuration uses conservative values that should work for
/// most deployments while providing protection against memory exhaustion:
/// - `max_tracked_views`: 128 views
/// - `max_votes_per_view`: 256 votes per (view, block_id) pair
/// - `max_pending_blocks`: 4096 pending blocks
/// - `max_votes_by_view_entries`: 16384 votes-by-view entries
/// - `max_commit_log_entries`: 8192 commit log entries
///
/// # Safety
///
/// These limits affect liveness but never safety:
/// - If views are evicted, votes for those views are lost (may delay QC formation)
/// - If votes are dropped, we may fail to form a QC (but never form an invalid one)
/// - If blocks are evicted, only non-committed blocks that are not part of the
///   current 3-chain/locked QC path are removed
/// - If commit log entries are evicted, only the oldest entries are removed,
///   preserving recent history for observability
/// - The system will never panic due to memory limits being exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusLimitsConfig {
    /// Maximum number of distinct views to track simultaneously.
    ///
    /// When this limit is exceeded, the oldest (lowest-numbered) views are
    /// evicted to make room for newer views. This prevents unbounded growth
    /// when receiving votes for many different views.
    ///
    /// Default: 128
    pub max_tracked_views: usize,

    /// Maximum number of votes to store per (view, block_id) pair.
    ///
    /// When this limit is exceeded for a particular (view, block_id), new
    /// votes are dropped. Since we track unique validators, in practice this
    /// limit is rarely hit unless there are many validators or an attack
    /// attempts to fill storage with conflicting votes.
    ///
    /// Default: 256
    pub max_votes_per_view: usize,

    /// Maximum number of pending blocks to store in the block tree.
    ///
    /// When this limit is exceeded, the engine evicts the oldest non-committed
    /// blocks that are not ancestors of the locked/leaf blocks. Committed
    /// blocks and blocks that are part of the current 3-chain/locked QC path
    /// are never evicted.
    ///
    /// Default: 4096
    pub max_pending_blocks: usize,

    /// Maximum number of entries in the votes_by_view map.
    ///
    /// This map tracks which block each validator voted for in each view,
    /// used for equivocation detection. When this limit is exceeded,
    /// entries for the lowest views are evicted first.
    ///
    /// Default: 16384
    pub max_votes_by_view_entries: usize,

    /// Maximum number of entries in the commit log.
    ///
    /// The commit log records committed blocks for observability and debugging.
    /// When this limit is exceeded, the oldest entries are removed, preserving
    /// the most recent commit history. This does not affect safety as the
    /// committed block and height are tracked separately.
    ///
    /// Default: 8192
    pub max_commit_log_entries: usize,
}

impl Default for ConsensusLimitsConfig {
    fn default() -> Self {
        Self {
            max_tracked_views: 128,
            max_votes_per_view: 256,
            max_pending_blocks: 4096,
            max_votes_by_view_entries: 16384,
            max_commit_log_entries: 8192,
        }
    }
}

impl ConsensusLimitsConfig {
    /// Create a new configuration with the specified limits.
    pub fn new(
        max_tracked_views: usize,
        max_votes_per_view: usize,
        max_pending_blocks: usize,
        max_votes_by_view_entries: usize,
    ) -> Self {
        Self {
            max_tracked_views,
            max_votes_per_view,
            max_pending_blocks,
            max_votes_by_view_entries,
            max_commit_log_entries: Self::default().max_commit_log_entries,
        }
    }

    /// Create a new configuration with only the vote accumulator limits
    /// (for backward compatibility).
    pub fn new_vote_accumulator_limits(
        max_tracked_views: usize,
        max_votes_per_view: usize,
    ) -> Self {
        Self {
            max_tracked_views,
            max_votes_per_view,
            max_pending_blocks: Self::default().max_pending_blocks,
            max_votes_by_view_entries: Self::default().max_votes_by_view_entries,
            max_commit_log_entries: Self::default().max_commit_log_entries,
        }
    }
}

/// Internal key for vote accumulation, representing (view, block_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VoteKey<BlockIdT> {
    view: u64,
    block_id: BlockIdT,
}

/// Accumulates votes for HotStuff-like QC formation.
///
/// This struct tracks votes keyed by (view, block_id) and knows when to
/// emit a `QuorumCertificate` based on the validator set's quorum threshold.
///
/// # Memory Limits (T118)
///
/// The accumulator enforces configurable memory limits:
/// - When `max_tracked_views` is exceeded, the oldest views are evicted
/// - When `max_votes_per_view` is exceeded, new votes are dropped
///
/// These limits affect liveness (may delay or prevent QC formation) but
/// never affect safety (will never form an invalid QC).
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
///
/// # Example
///
/// ```ignore
/// let limits = ConsensusLimitsConfig::default();
/// let mut acc = VoteAccumulator::with_limits(limits);
/// acc.on_vote(&validators, ValidatorId(0), view, &block_id)?;
/// acc.on_vote(&validators, ValidatorId(1), view, &block_id)?;
/// acc.on_vote(&validators, ValidatorId(2), view, &block_id)?;
/// if let Some(qc) = acc.maybe_qc_for(&validators, view, &block_id)? {
///     // QC is formed!
/// }
/// ```
#[derive(Debug)]
pub struct VoteAccumulator<BlockIdT> {
    /// Map from (view, block_id) to set of validators who have voted.
    entries: HashMap<VoteKey<BlockIdT>, HashSet<ValidatorId>>,
    /// Sorted set of all views currently being tracked.
    /// Used for efficient eviction of the oldest views.
    tracked_views: BTreeSet<u64>,
    /// Memory limits configuration.
    limits: ConsensusLimitsConfig,
    /// Counter for dropped votes due to per-view limit.
    dropped_votes: u64,
    /// Counter for evicted views due to max_tracked_views limit.
    evicted_views: u64,
}

impl<BlockIdT> Default for VoteAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<BlockIdT> VoteAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new empty `VoteAccumulator` with default limits.
    pub fn new() -> Self {
        Self::with_limits(ConsensusLimitsConfig::default())
    }

    /// Create a new empty `VoteAccumulator` with custom limits.
    ///
    /// # Arguments
    ///
    /// - `limits`: Configuration for memory limits
    pub fn with_limits(limits: ConsensusLimitsConfig) -> Self {
        VoteAccumulator {
            entries: HashMap::new(),
            tracked_views: BTreeSet::new(),
            limits,
            dropped_votes: 0,
            evicted_views: 0,
        }
    }

    /// Get the current limits configuration.
    pub fn limits(&self) -> &ConsensusLimitsConfig {
        &self.limits
    }

    /// Get the number of votes that were dropped due to per-view limits.
    pub fn dropped_votes(&self) -> u64 {
        self.dropped_votes
    }

    /// Get the number of views that were evicted due to max_tracked_views limit.
    pub fn evicted_views(&self) -> u64 {
        self.evicted_views
    }

    /// Get the number of views currently being tracked.
    pub fn tracked_view_count(&self) -> usize {
        self.tracked_views.len()
    }

    /// Evict the oldest views until we are under the limit.
    ///
    /// This is called when adding a new view would exceed `max_tracked_views`.
    /// We evict the lowest-numbered views first, as they are least likely
    /// to be useful for ongoing consensus.
    fn evict_oldest_views(&mut self) {
        while self.tracked_views.len() >= self.limits.max_tracked_views {
            if let Some(&oldest_view) = self.tracked_views.iter().next() {
                // Remove all entries for this view
                self.entries.retain(|key, _| key.view != oldest_view);
                self.tracked_views.remove(&oldest_view);
                self.evicted_views += 1;
            } else {
                break;
            }
        }
    }

    /// Ingest a single vote.
    ///
    /// Returns `Ok(true)` if this vote is new for this (view, block_id) pair,
    /// `Ok(false)` if it was a duplicate from the same validator or if the
    /// vote was dropped due to memory limits.
    ///
    /// # Memory Limits
    ///
    /// - If the view is new and would exceed `max_tracked_views`, the oldest
    ///   views are evicted first.
    /// - If the (view, block_id) pair already has `max_votes_per_view` votes,
    ///   the new vote is dropped and `Ok(false)` is returned.
    ///
    /// # Errors
    ///
    /// Returns `Err(QcValidationError::NonMemberSigner)` if the voter is not
    /// in the validator set.
    ///
    /// # Arguments
    ///
    /// - `validators`: The validator set to check membership against
    /// - `voter`: The validator who cast the vote
    /// - `view`: The view/round number of the vote
    /// - `block_id`: The block being voted for
    pub fn on_vote(
        &mut self,
        validators: &ConsensusValidatorSet,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<bool, QcValidationError> {
        // Reject non-members early.
        if !validators.contains(voter) {
            return Err(QcValidationError::NonMemberSigner(voter));
        }

        // Handle view tracking and eviction
        if !self.tracked_views.contains(&view) {
            // New view - check if we need to evict old views
            if self.tracked_views.len() >= self.limits.max_tracked_views {
                self.evict_oldest_views();
            }
            self.tracked_views.insert(view);
        }

        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };

        // Check per-view vote limit
        if let Some(existing_votes) = self.entries.get(&key) {
            if existing_votes.len() >= self.limits.max_votes_per_view {
                // Check if this is a duplicate (already present)
                if existing_votes.contains(&voter) {
                    return Ok(false); // Duplicate, not dropped
                }
                // Drop the new vote due to limit
                self.dropped_votes += 1;
                return Ok(false);
            }
        }

        let entry = self.entries.entry(key).or_default();
        // Returns true if the voter was newly inserted, false if already present
        Ok(entry.insert(voter))
    }

    /// Attempts to form a QC for the given (view, block_id) pair.
    ///
    /// Returns `Ok(Some(qc))` if signers reach quorum; otherwise `Ok(None)`.
    ///
    /// This does *not* remove the entry; call `remove_entry` if you want to
    /// clean up after QC formation.
    ///
    /// # Errors
    ///
    /// Returns an error if the QC validation fails (e.g., non-member signers
    /// or duplicate signers, though duplicates should not occur if votes were
    /// ingested correctly).
    pub fn maybe_qc_for(
        &self,
        validators: &ConsensusValidatorSet,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<Option<QuorumCertificate<BlockIdT>>, QcValidationError> {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };

        let signers = match self.entries.get(&key) {
            Some(s) => s,
            None => return Ok(None),
        };

        let ids: Vec<ValidatorId> = signers.iter().copied().collect();
        let qc = QuorumCertificate::new(block_id.clone(), view, ids);

        // Reuse QC's validate() logic, which checks quorum, duplicates, non-members.
        match qc.validate(validators) {
            Ok(()) => Ok(Some(qc)),
            Err(QcValidationError::InsufficientQuorum { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Clear state for a given (view, block_id) once QC is formed.
    ///
    /// This is optional but can help reduce memory usage after a QC has been
    /// successfully formed.
    pub fn remove_entry(&mut self, view: u64, block_id: &BlockIdT) {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };
        self.entries.remove(&key);

        // Check if this was the last entry for this view
        let view_has_entries = self.entries.keys().any(|k| k.view == view);
        if !view_has_entries {
            self.tracked_views.remove(&view);
        }
    }

    /// Returns the number of votes currently accumulated for a given (view, block_id).
    ///
    /// Returns 0 if no votes have been received for this pair.
    pub fn vote_count(&self, view: u64, block_id: &BlockIdT) -> usize {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };
        self.entries.get(&key).map(|s| s.len()).unwrap_or(0)
    }

    /// Returns the number of (view, block_id) entries currently tracked.
    ///
    /// This is useful for testing and diagnostics.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}
