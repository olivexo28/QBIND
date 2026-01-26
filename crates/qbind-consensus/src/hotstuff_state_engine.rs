//! HotStuff state machine with QC-based locking and commit bookkeeping.
//!
//! This module provides a minimal HotStuff state machine that:
//! - Maintains a simple "block tree" keyed by block id
//! - Tracks `locked_qc` (latest QC on a locked block)
//! - Tracks the latest committed block id via the 3-chain commit rule
//! - Integrates `VoteAccumulator` for QC formation
//! - Detects equivocation (double-voting) and tracks metrics
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation that implements:
//! - QC-based locking (locked_qc updated when a higher-view QC is formed)
//! - Basic vote accumulation and QC formation
//! - 3-chain commit rule: when three consecutive QCs are formed (G → P → B),
//!   the grandparent block G is committed
//! - Equivocation detection: detects when a validator votes for different blocks
//!   in the same view
//!
//! It does NOT yet implement:
//! - Timeouts or view-change mechanics

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::block_state::BlockNode;
use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;
use crate::vote_accumulator::{ConsensusLimitsConfig, VoteAccumulator};

/// An entry in the commit log recording a committed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEntry<BlockIdT> {
    /// The block identifier that was committed.
    pub block_id: BlockIdT,
    /// The view at which the block was proposed.
    pub view: u64,
    /// The height of the block in the chain from genesis.
    pub height: u64,
}

/// Outcome of recording a vote in the history tracker.
///
/// This enum is used internally to distinguish between:
/// - First time we see a (view, validator) pair
/// - Duplicate vote for the same block (benign)
/// - Equivocation: different block in the same view
#[derive(Debug, Clone, PartialEq, Eq)]
enum VoteHistoryOutcome<BlockIdT> {
    /// First time we see this (view, validator) pair.
    FirstVote,
    /// Duplicate vote for the same block_id (benign duplicate).
    DuplicateSameBlock,
    /// Equivocation: same (view, validator), different block.
    Equivocation {
        /// The block the validator previously voted for.
        previous_block: BlockIdT,
    },
}

/// HotStuff state machine managing block tree, locking, and commit tracking.
///
/// This struct maintains the consensus state for a HotStuff-like protocol:
/// - Known block nodes keyed by block id
/// - Current locked QC (the "lock" on a block)
/// - Latest committed block id
/// - Vote accumulator for QC formation
/// - Validator set for quorum checks
/// - Equivocation detection and metrics
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in qbind-consensus is `[u8; 32]`.
#[derive(Debug)]
pub struct HotStuffStateEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Known block nodes keyed by block id.
    blocks: HashMap<BlockIdT, BlockNode<BlockIdT>>,

    /// Order of pending blocks for eviction (oldest first).
    /// Contains block IDs of non-committed blocks that are not ancestors of locked/leaf blocks.
    pending_block_order: VecDeque<BlockIdT>,

    /// Current locked QC (HotStuff "lock" on a block).
    locked_qc: Option<QuorumCertificate<BlockIdT>>,

    /// Latest committed block id, if any.
    committed_block: Option<BlockIdT>,

    /// Latest committed height, if any.
    committed_height: Option<u64>,

    /// Simple append-only commit log for tests/inspection.
    commit_log: Vec<CommittedEntry<BlockIdT>>,

    /// Vote accumulator for QC formation.
    votes: VoteAccumulator<BlockIdT>,

    /// Validator set for quorum checks.
    validators: ConsensusValidatorSet,

    /// For each (view, validator), remember which block they voted for.
    /// Used for equivocation detection.
    votes_by_view: HashMap<(u64, ValidatorId), BlockIdT>,

    /// Sorted set of views currently tracked in votes_by_view (for eviction).
    votes_by_view_tracked_views: BTreeSet<u64>,

    /// Count of detected equivocations (double-votes per view).
    equivocations_detected: u64,

    /// Set of validators that ever equivocated (per this engine instance).
    equivocating_validators: HashSet<ValidatorId>,

    /// Counter for blocks evicted due to memory limits.
    evicted_blocks: u64,

    /// Counter for votes_by_view entries evicted due to memory limits.
    evicted_votes_by_view_entries: u64,

    /// Counter for commit log entries evicted due to memory limits.
    evicted_commit_log_entries: u64,
}

impl<BlockIdT> HotStuffStateEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new `HotStuffStateEngine` with the given validator set and default limits.
    ///
    /// The engine starts with:
    /// - No known blocks
    /// - No locked QC
    /// - No committed block
    /// - Empty vote accumulator with default memory limits
    /// - Empty equivocation tracking
    pub fn new(validators: ConsensusValidatorSet) -> Self {
        Self::with_limits(validators, ConsensusLimitsConfig::default())
    }

    /// Create a new `HotStuffStateEngine` with custom memory limits.
    ///
    /// # Arguments
    ///
    /// - `validators`: The validator set for quorum checks
    /// - `limits`: Configuration for memory limits
    pub fn with_limits(validators: ConsensusValidatorSet, limits: ConsensusLimitsConfig) -> Self {
        HotStuffStateEngine {
            blocks: HashMap::new(),
            pending_block_order: VecDeque::new(),
            locked_qc: None,
            committed_block: None,
            committed_height: None,
            commit_log: Vec::new(),
            votes: VoteAccumulator::with_limits(limits),
            validators,
            votes_by_view: HashMap::new(),
            votes_by_view_tracked_views: BTreeSet::new(),
            equivocations_detected: 0,
            equivocating_validators: HashSet::new(),
            evicted_blocks: 0,
            evicted_votes_by_view_entries: 0,
            evicted_commit_log_entries: 0,
        }
    }

    /// Get the current memory limits configuration.
    pub fn limits(&self) -> &ConsensusLimitsConfig {
        self.votes.limits()
    }

    /// Get the number of votes dropped due to memory limits.
    pub fn dropped_votes(&self) -> u64 {
        self.votes.dropped_votes()
    }

    /// Get the number of views evicted due to memory limits.
    pub fn evicted_views(&self) -> u64 {
        self.votes.evicted_views()
    }

    /// Get the current locked QC, if any.
    pub fn locked_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.locked_qc.as_ref()
    }

    /// Get the latest committed block id, if any.
    pub fn committed_block(&self) -> Option<&BlockIdT> {
        self.committed_block.as_ref()
    }

    /// Get the latest committed height, if any.
    pub fn committed_height(&self) -> Option<u64> {
        self.committed_height
    }

    /// Get the commit log (sequence of committed blocks).
    pub fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        &self.commit_log
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        &self.validators
    }

    /// Update the validator set (T102).
    ///
    /// This method replaces the validator set while preserving all other state:
    /// - Block tree is preserved
    /// - Locked QC is preserved
    /// - Committed block and height are preserved
    /// - Commit log is preserved
    /// - Memory limits configuration is preserved
    ///
    /// However, the vote accumulator is cleared because:
    /// - Pending votes may no longer be valid with the new validator set
    /// - Quorum thresholds may have changed
    ///
    /// # Arguments
    ///
    /// * `new_validators` - The new validator set for the next epoch
    pub fn update_validators(&mut self, new_validators: ConsensusValidatorSet) {
        let limits = *self.votes.limits();
        self.validators = new_validators;
        // Clear vote accumulator since quorum thresholds may have changed
        // and pending votes may no longer be valid, but preserve limits
        self.votes = VoteAccumulator::with_limits(limits);
        // Clear vote history for the new epoch
        self.votes_by_view.clear();
    }

    /// Get the count of detected equivocations (double-votes per view).
    pub fn equivocations_detected(&self) -> u64 {
        self.equivocations_detected
    }

    /// Get a reference to the set of validators that have equivocated.
    pub fn equivocating_validators(&self) -> &HashSet<ValidatorId> {
        &self.equivocating_validators
    }

    /// Get a block node by its id, if known.
    pub fn get_block(&self, id: &BlockIdT) -> Option<&BlockNode<BlockIdT>> {
        self.blocks.get(id)
    }

    /// Returns the number of known blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the number of blocks evicted due to memory limits.
    pub fn evicted_blocks(&self) -> u64 {
        self.evicted_blocks
    }

    /// Get the number of votes_by_view entries evicted due to memory limits.
    pub fn evicted_votes_by_view_entries(&self) -> u64 {
        self.evicted_votes_by_view_entries
    }

    /// Get the number of commit log entries evicted due to memory limits.
    pub fn evicted_commit_log_entries(&self) -> u64 {
        self.evicted_commit_log_entries
    }

    /// Check if a block is safe to evict.
    ///
    /// A block is NOT safe to evict if:
    /// 1. It is committed (height <= committed_height)
    /// 2. It is an ancestor of the locked block (if we have a lock)
    /// 3. It is an ancestor of any block with own_qc (part of a 3-chain)
    /// 4. It is the locked block itself
    fn is_block_safe_to_evict(&self, block_id: &BlockIdT) -> bool {
        // 1. Check if block is committed
        if let Some(committed_height) = self.committed_height {
            if let Some(block) = self.blocks.get(block_id) {
                if block.height <= committed_height {
                    return false;
                }
            }
        }

        // 2. Check if block is locked block or its ancestor
        if let Some(locked_qc) = &self.locked_qc {
            let locked_block_id = &locked_qc.block_id;
            if block_id == locked_block_id {
                return false;
            }
            // Walk up from locked block to see if this block is an ancestor
            let mut current_id = locked_block_id;
            while let Some(current) = self.blocks.get(current_id) {
                if let Some(parent_id) = &current.parent_id {
                    if parent_id == block_id {
                        return false;
                    }
                    current_id = parent_id;
                } else {
                    break;
                }
            }
        }

        // 3. Check if block has own_qc (part of a QC chain)
        if let Some(block) = self.blocks.get(block_id) {
            if block.own_qc.is_some() {
                return false;
            }
        }

        // 4. Check if block is an ancestor of any block with own_qc
        for (other_id, other_block) in &self.blocks {
            if other_block.own_qc.is_some() {
                // Walk up from this block to see if block_id is an ancestor
                let mut current_id = other_id;
                while let Some(current) = self.blocks.get(current_id) {
                    if let Some(parent_id) = &current.parent_id {
                        if parent_id == block_id {
                            return false;
                        }
                        current_id = parent_id;
                    } else {
                        break;
                    }
                }
            }
        }

        true
    }

    /// Evict blocks if we're over the limit.
    ///
    /// This method tries to evict blocks from pending_block_order
    /// until we're under the max_pending_blocks limit.
    /// Only evicts blocks that are safe to evict.
    fn evict_blocks_if_needed(&mut self) {
        let max_pending_blocks = self.limits().max_pending_blocks;
        while self.blocks.len() > max_pending_blocks {
            // Try to find a block to evict from pending_block_order
            let mut evicted = false;
            while let Some(block_id) = self.pending_block_order.pop_front() {
                if self.blocks.contains_key(&block_id) && self.is_block_safe_to_evict(&block_id) {
                    self.blocks.remove(&block_id);
                    self.evicted_blocks += 1;
                    evicted = true;
                    break;
                }
            }

            // If we couldn't evict any block, break to avoid infinite loop
            if !evicted {
                break;
            }
        }
    }

    /// Evict votes_by_view entries if we're over the limit.
    ///
    /// This method evicts entries for the lowest views first.
    fn evict_votes_by_view_if_needed(&mut self) {
        let max_entries = self.limits().max_votes_by_view_entries;
        while self.votes_by_view.len() >= max_entries {
            // Find the lowest view to evict
            if let Some(&lowest_view) = self.votes_by_view_tracked_views.iter().next() {
                // Remove all entries for this view
                self.votes_by_view
                    .retain(|(view, _), _| *view != lowest_view);
                self.votes_by_view_tracked_views.remove(&lowest_view);
                self.evicted_votes_by_view_entries += 1;
            } else {
                break;
            }
        }
    }

    /// Evict commit log entries if we're over the limit.
    ///
    /// This method removes the oldest entries from the commit log when
    /// the log exceeds `max_commit_log_entries`. The log behaves as a
    /// sliding window, keeping only the most recent entries.
    fn evict_commit_log_if_needed(&mut self) {
        let max_entries = self.limits().max_commit_log_entries;
        if self.commit_log.len() > max_entries {
            let excess = self.commit_log.len() - max_entries;
            // Remove the oldest `excess` entries from the front
            self.commit_log.drain(0..excess);
            self.evicted_commit_log_entries += excess as u64;
        }
    }

    // ========================================================================
    // Hook 1: Registering proposals into the block tree
    // ========================================================================

    /// Register a block node in the block tree.
    ///
    /// This method adds or updates a block in the internal block tree.
    /// It can be used when processing proposals to track known blocks.
    /// The block's height is computed as parent's height + 1, or 0 if no parent
    /// (genesis) or if the parent is not yet registered.
    ///
    /// # Arguments
    ///
    /// - `id`: The block identifier
    /// - `view`: The view/round at which this block was proposed
    /// - `parent_id`: The parent block id, if any
    /// - `justify_qc`: The QC that justifies this block, if any
    pub fn register_block(
        &mut self,
        id: BlockIdT,
        view: u64,
        parent_id: Option<BlockIdT>,
        justify_qc: Option<QuorumCertificate<BlockIdT>>,
    ) {
        // Compute height: 0 if no parent, otherwise parent.height + 1
        let height = match parent_id.as_ref() {
            None => 0,
            Some(pid) => self.blocks.get(pid).map(|p| p.height + 1).unwrap_or(0),
        };

        let node = BlockNode::new(id.clone(), view, parent_id, justify_qc, height);

        // Check if this is an update to an existing block
        let is_new = !self.blocks.contains_key(&id);

        self.blocks.insert(id.clone(), node);

        // If it's a new block, add to pending block order for eviction
        if is_new {
            self.pending_block_order.push_back(id);
        }

        // Evict blocks if we're over the limit
        self.evict_blocks_if_needed();
    }

    // ========================================================================
    // Hook 2: Vote ingestion → QC → locking/commit
    // ========================================================================

    /// Internal helper to record vote history and detect equivocation.
    ///
    /// This method tracks which block each (view, validator) pair has voted for.
    /// It returns the outcome of this check:
    /// - `FirstVote`: First time we see this (view, validator) pair
    /// - `DuplicateSameBlock`: Same validator voted for the same block in the same view
    /// - `Equivocation`: Same validator voted for a different block in the same view
    fn record_vote_history(
        &mut self,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> VoteHistoryOutcome<BlockIdT> {
        let key = (view, voter);
        match self.votes_by_view.get(&key) {
            None => {
                // First time we see this (view, validator) pair.
                // Track the view for eviction purposes
                self.votes_by_view_tracked_views.insert(view);

                // Evict old entries if we're over the limit
                self.evict_votes_by_view_if_needed();

                self.votes_by_view.insert(key, block_id.clone());
                VoteHistoryOutcome::FirstVote
            }
            Some(prev_block) => {
                if prev_block == block_id {
                    // Same block as before: benign duplicate.
                    VoteHistoryOutcome::DuplicateSameBlock
                } else {
                    // Different block: equivocation.
                    VoteHistoryOutcome::Equivocation {
                        previous_block: prev_block.clone(),
                    }
                }
            }
        }
    }

    /// Ingest a vote and if quorum is reached, form and process a QC.
    ///
    /// This method:
    /// 1. Detects equivocation (same validator voting for different blocks in the same view)
    /// 2. If equivocation is detected, records metrics and ignores the vote
    /// 3. Validates that the voter is a member of the validator set
    /// 4. Records the vote in the accumulator
    /// 5. Attempts to form a QC if quorum is reached
    /// 6. If a QC is formed, applies locking logic
    ///
    /// # Arguments
    ///
    /// - `voter`: The validator who cast the vote
    /// - `view`: The view/round number of the vote
    /// - `block_id`: The block being voted for
    ///
    /// # Returns
    ///
    /// - `Ok(Some(qc))` if a QC was formed and applied
    /// - `Ok(None)` if the vote was recorded but no QC formed yet, or if the vote
    ///   was an equivocation and was ignored
    /// - `Err(QcValidationError)` if the voter is not a member
    pub fn on_vote(
        &mut self,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<Option<QuorumCertificate<BlockIdT>>, QcValidationError> {
        // 1. Equivocation detection.
        match self.record_vote_history(voter, view, block_id) {
            VoteHistoryOutcome::Equivocation { previous_block: _ } => {
                // Record metrics and ignore this vote for QC formation.
                self.equivocations_detected += 1;
                self.equivocating_validators.insert(voter);
                // For now we silently ignore; later we may want to expose this
                // via a separate error or event.
                return Ok(None);
            }
            VoteHistoryOutcome::FirstVote | VoteHistoryOutcome::DuplicateSameBlock => {
                // Proceed to feed vote into accumulator.
            }
        }

        // 2. Ingest vote into accumulator (membership & duplicate checks).
        let _is_new = self
            .votes
            .on_vote(&self.validators, voter, view, block_id)?;

        // 3. Attempt to form QC for this (view, block_id).
        let qc = self.votes.maybe_qc_for(&self.validators, view, block_id)?;

        if let Some(ref qc) = qc {
            // 4. Apply locking logic with the new QC.
            self.on_qc(qc)?;
        }

        Ok(qc)
    }

    /// Handle a newly formed QC.
    ///
    /// This method implements HotStuff-style locking and commit logic:
    /// - Updates `locked_qc` to the QC if its view is higher than the current lock
    /// - Attaches the QC to the corresponding block node as `own_qc`
    /// - Attempts the 3-chain commit rule
    fn on_qc(&mut self, qc: &QuorumCertificate<BlockIdT>) -> Result<(), QcValidationError> {
        // Minimal HotStuff-style locking:
        // - Update locked_qc to the highest-view QC.
        let replace_lock = match &self.locked_qc {
            None => true,
            Some(existing) => qc.view > existing.view,
        };

        if replace_lock {
            self.locked_qc = Some(qc.clone());
        }

        // Record QC on the block node itself.
        if let Some(node) = self.blocks.get_mut(&qc.block_id) {
            node.own_qc = Some(qc.clone());
        }

        // Attempt 3-chain commit logic.
        self.try_commit_with_qc(qc);

        Ok(())
    }

    /// Attempt to commit a block using the 3-chain commit rule.
    ///
    /// Classic HotStuff 3-chain commit rule:
    /// - Let B be the block with `qc.block_id`
    /// - Let P = parent of B
    /// - Let G = parent of P (grandparent of B)
    /// - If B, P, and G each have their `own_qc` and views are strictly increasing,
    ///   we commit G (or advance `committed_block` to G if it's higher).
    ///
    /// This ensures that a block is only committed when there are two subsequent
    /// blocks with QCs in the chain, providing Byzantine fault tolerance.
    fn try_commit_with_qc(&mut self, qc: &QuorumCertificate<BlockIdT>) {
        // 1. Find B (the block this QC is for).
        let b_view = match self.blocks.get(&qc.block_id) {
            Some(node) => {
                // Check B has own_qc
                if node.own_qc.is_none() {
                    return;
                }
                node.view
            }
            None => return, // unknown block; nothing to commit
        };

        // 2. Find P = parent of B.
        let (p_id, p_view) = {
            let b = match self.blocks.get(&qc.block_id) {
                Some(node) => node,
                None => return,
            };
            match &b.parent_id {
                Some(id) => {
                    let p = match self.blocks.get(id) {
                        Some(node) => node,
                        None => return,
                    };
                    // Check P has own_qc
                    if p.own_qc.is_none() {
                        return;
                    }
                    (id.clone(), p.view)
                }
                None => return, // no parent → no 3-chain
            }
        };

        // 3. Find G = parent of P (grandparent of B).
        let (g_id, g_view, g_height) = {
            let p = match self.blocks.get(&p_id) {
                Some(node) => node,
                None => return,
            };
            match &p.parent_id {
                Some(id) => {
                    let g = match self.blocks.get(id) {
                        Some(node) => node,
                        None => return,
                    };
                    // Check G has own_qc
                    if g.own_qc.is_none() {
                        return;
                    }
                    (id.clone(), g.view, g.height)
                }
                None => return, // no grandparent → no 3-chain
            }
        };

        // 4. Ensure views are strictly increasing: G.view < P.view < B.view
        if !(g_view < p_view && p_view < b_view) {
            return;
        }

        // 5. Commit G if it is "ahead" of current committed_block (monotonic).
        // For height-based monotonicity, we compare heights to ensure we don't go backwards.
        let height_ok = match self.committed_height {
            None => true,
            Some(h) => g_height > h,
        };

        let should_commit = match &self.committed_block {
            None => true,
            Some(committed_id) => {
                if committed_id == &g_id {
                    // Already committed this block
                    false
                } else {
                    // Check if G's view is higher than the current committed block's view
                    // to ensure we don't go backwards
                    match self.blocks.get(committed_id) {
                        Some(committed_node) => g_view > committed_node.view,
                        None => {
                            // Current committed block not in our tree (shouldn't happen normally)
                            // Allow commit to move forward
                            true
                        }
                    }
                }
            }
        };

        if should_commit && height_ok {
            self.committed_block = Some(g_id.clone());
            self.committed_height = Some(g_height);

            // Avoid duplicate log entries: only push if last entry is different.
            let push_entry = match self.commit_log.last() {
                None => true,
                Some(last) => last.block_id != g_id,
            };
            if push_entry {
                self.commit_log.push(CommittedEntry {
                    block_id: g_id,
                    view: g_view,
                    height: g_height,
                });
                // Evict old entries if we're over the limit
                self.evict_commit_log_if_needed();
            }
        }
    }

    /// Directly set a locked QC (for testing or initialization).
    ///
    /// This bypasses the normal QC formation process and directly sets
    /// the locked QC. Useful for testing locking behavior.
    pub fn set_locked_qc(&mut self, qc: QuorumCertificate<BlockIdT>) {
        self.locked_qc = Some(qc);
    }

    /// Initialize the engine from persisted restart state.
    ///
    /// This method is called during node restart to restore the engine to a
    /// safe state based on the last committed block.
    ///
    /// # Restart Semantics (T84)
    ///
    /// ## What is Restored
    ///
    /// - `committed_block`: Set to the last committed block ID
    /// - `committed_height`: Set to the height of the last committed block
    /// - `locked_qc`: Set conservatively to a QC for the committed block (if provided)
    ///
    /// ## What is NOT Restored
    ///
    /// - In-flight proposals: Any proposals that were pending are lost
    /// - Pending votes: Votes that hadn't formed a QC are lost
    /// - Vote accumulator state: Starts fresh
    /// - Block tree: Only the committed block is known initially
    ///
    /// ## Safety Guarantee
    ///
    /// This is safe because:
    /// 1. We start from the committed prefix, which by definition has a 3-chain
    ///    QC backing it and cannot be reverted.
    /// 2. By setting locked_qc conservatively to the QC for the committed block,
    ///    we ensure we won't vote for conflicting blocks.
    /// 3. We may lose some liveness (temporarily cannot vote for some valid
    ///    proposals if they don't extend our lock), but we never violate safety.
    ///
    /// ## Liveness Note
    ///
    /// After restart, the node may need to wait for a new proposal with a QC
    /// at or above the locked_qc.view before it can vote. This is a conservative
    /// choice that prioritizes safety over immediate liveness.
    ///
    /// # Arguments
    ///
    /// - `committed_block_id`: The block ID of the last committed block
    /// - `committed_height`: The height of the last committed block
    /// - `locked_qc`: Optional QC to use as the locked QC (typically the QC for
    ///   the committed block or the embedded QC in the committed block)
    pub fn initialize_from_restart(
        &mut self,
        committed_block_id: BlockIdT,
        committed_height: u64,
        locked_qc: Option<QuorumCertificate<BlockIdT>>,
    ) {
        // Set the committed block and height
        self.committed_block = Some(committed_block_id.clone());
        self.committed_height = Some(committed_height);

        // Set the locked QC conservatively
        // This ensures we won't vote for blocks that conflict with our last commit
        if let Some(qc) = locked_qc {
            self.locked_qc = Some(qc);
        }

        // Note: We do NOT populate the block tree or vote accumulator.
        // The block tree will be rebuilt as new proposals arrive.
        // Vote accumulator starts fresh - any in-flight votes are lost,
        // which is safe because we restart from a committed state.
    }

    /// Get the current vote count for a (view, block_id) pair.
    ///
    /// Returns 0 if no votes have been received for this pair.
    pub fn vote_count(&self, view: u64, block_id: &BlockIdT) -> usize {
        self.votes.vote_count(view, block_id)
    }

    /// Returns true if it is safe to vote for the given block.
    ///
    /// This implements the standard HotStuff safe-voting rule. It is safe to
    /// vote for a block B with justify_qc if EITHER:
    /// 1. There is no locked QC yet, OR
    /// 2. B extends the currently locked block (locked block is in B's ancestor chain), OR
    /// 3. B's justify_qc.view >= locked_qc.view
    ///
    /// This rule preserves safety while allowing liveness: a node will not vote
    /// for a block that conflicts with its lock unless the block has a QC from
    /// a view at least as recent as the lock.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The identifier of the block to check
    ///
    /// # Returns
    ///
    /// - `true` if it is safe to vote for this block
    /// - `false` if voting for this block would violate the safety rule
    pub fn is_safe_to_vote_on_block(&self, block_id: &BlockIdT) -> bool {
        // 1. If no locked qc yet, allow.
        let locked = match self.locked_qc.as_ref() {
            None => return true,
            Some(qc) => qc,
        };

        // 2. Find this block's node.
        let block_node = match self.blocks.get(block_id) {
            Some(node) => node,
            None => {
                // If the block is not yet registered, return false for safety
                // since we cannot verify the ancestor chain without the block data.
                // This ensures we never vote for a block whose ancestry we cannot verify.
                return false;
            }
        };

        // 3. Check if justify_qc.view >= locked_qc.view (liveness condition)
        //    This is the standard HotStuff rule that allows progress even when
        //    the block doesn't directly extend the locked block.
        if let Some(ref justify_qc) = block_node.justify_qc {
            if justify_qc.view >= locked.view {
                return true;
            }
        }

        // 4. Walk ancestors until genesis or until we find locked_qc.block_id.
        let locked_block_id = &locked.block_id;
        let mut current = block_node;
        loop {
            if &current.id == locked_block_id {
                return true;
            }
            let parent_id = match &current.parent_id {
                Some(pid) => pid,
                None => break,
            };
            current = match self.blocks.get(parent_id) {
                Some(node) => node,
                None => break,
            };
        }

        // If we walked the chain and didn't find the locked block, and the
        // justify_qc.view was not >= locked_qc.view, this block conflicts
        // with our lock; do not vote.
        false
    }
}
