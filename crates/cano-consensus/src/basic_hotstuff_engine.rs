//! BasicHotStuffEngine: A concrete HotStuff engine with static leader scheduling.
//!
//! This module provides a complete HotStuff-like consensus engine that:
//! - Uses a static leader schedule (round-robin based on view % n)
//! - Generates proposals when acting as leader
//! - Votes on valid proposals from the leader
//! - Integrates with `HotStuffStateEngine` for QC formation and commit tracking
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation for T56. It implements:
//! - Static leader election (view % num_validators)
//! - Basic proposal generation and voting
//! - QC formation via vote accumulation
//! - 3-chain commit rule via `HotStuffStateEngine`
//!
//! It does NOT implement:
//! - Timeouts or view-change mechanics
//! - Equivocation handling
//! - Leader rotation policies beyond simple round-robin

use crate::driver::{ConsensusEngineAction, HasCommitLog};
use crate::hotstuff_state_engine::{CommittedEntry, HotStuffStateEngine};
use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::timeout::{TimeoutAccumulator, TimeoutCertificate, TimeoutMsg, TimeoutValidationError};
use crate::validator_set::ConsensusValidatorSet;

use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// ViewDurationRecorder - Metrics callback trait (T90.5)
// ============================================================================

/// Trait for recording view/round duration metrics.
///
/// This trait allows external metrics systems to receive view duration
/// notifications without introducing a hard dependency from cano-consensus
/// to cano-node.
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ViewDurationRecorder: Send + Sync + std::fmt::Debug {
    /// Record the duration of a completed view.
    ///
    /// This is called whenever the engine transitions from one view to the next.
    /// The duration represents the time from when the previous view was activated
    /// until the new view is activated.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration of the completed view
    /// * `from_view` - The view number that just completed
    /// * `to_view` - The view number being entered
    fn record_view_duration(&self, duration: Duration, from_view: u64, to_view: u64);
}

/// No-op implementation of `ViewDurationRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopViewDurationRecorder;

impl ViewDurationRecorder for NoopViewDurationRecorder {
    fn record_view_duration(&self, _duration: Duration, _from_view: u64, _to_view: u64) {
        // No-op
    }
}

// ============================================================================
// ConsensusProgressRecorder - Metrics callback trait (T127)
// ============================================================================

/// Trait for recording consensus progress metrics.
///
/// This trait allows external metrics systems to receive notifications about
/// consensus progress events without introducing a hard dependency from
/// cano-consensus to cano-node.
///
/// # Events Tracked
///
/// - QC formation: when a quorum certificate is successfully formed
/// - Vote observation: when a valid vote is accepted
/// - View changes: when the engine transitions to a new view
/// - Leader changes: when the leader for a new view differs from previous
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ConsensusProgressRecorder: Send + Sync + std::fmt::Debug {
    /// Record that a QC was formed.
    ///
    /// This is called exactly once per QC that is actually used by the engine
    /// (not for every deserialized QC).
    fn record_qc_formed(&self);

    /// Record that a QC was formed with latency information.
    ///
    /// This is called with the duration from view start to QC formation.
    fn record_qc_formed_with_latency(&self, _latency: Duration) {
        // Default: just record the QC without latency
        self.record_qc_formed();
    }

    /// Record that a vote was observed.
    ///
    /// This is called when a valid, epoch-correct vote is accepted.
    ///
    /// # Arguments
    ///
    /// * `is_for_current_view` - Whether the vote is for the current view
    fn record_vote_observed(&self, is_for_current_view: bool);

    /// Record a view change.
    ///
    /// This is called when the engine advances to a new view.
    ///
    /// # Arguments
    ///
    /// * `from_view` - The view being left
    /// * `to_view` - The view being entered
    fn record_view_change(&self, from_view: u64, to_view: u64);

    /// Record a leader change.
    ///
    /// This is called when the leader for the new view differs from the previous view.
    /// In round-robin leader selection, this equals view changes.
    fn record_leader_change(&self);

    /// Reset the current view vote counter.
    ///
    /// This is called when transitioning to a new view to reset the
    /// approximate gauge of votes in the current view.
    fn reset_current_view_votes(&self);
}

/// No-op implementation of `ConsensusProgressRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopConsensusProgressRecorder;

impl ConsensusProgressRecorder for NoopConsensusProgressRecorder {
    fn record_qc_formed(&self) {
        // No-op
    }

    fn record_vote_observed(&self, _is_for_current_view: bool) {
        // No-op
    }

    fn record_view_change(&self, _from_view: u64, _to_view: u64) {
        // No-op
    }

    fn record_leader_change(&self) {
        // No-op
    }

    fn reset_current_view_votes(&self) {
        // No-op
    }
}

// ============================================================================
// ValidatorVoteRecorder - Per-validator vote metrics callback trait (T128)
// ============================================================================

/// Trait for recording per-validator vote metrics (T128).
///
/// This trait allows external metrics systems to receive notifications about
/// individual validator vote events without introducing a hard dependency from
/// cano-consensus to cano-node.
///
/// # Events Tracked
///
/// - `on_validator_vote`: Called when a valid vote is accepted from a validator
///
/// # Important
///
/// Only call this for valid, epoch-correct votes. Do not call for:
/// - Rejected votes (wrong epoch, wrong suite, invalid signature)
/// - Equivocating votes (already recorded; the first vote was valid)
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ValidatorVoteRecorder: Send + Sync + std::fmt::Debug {
    /// Record a vote from a specific validator.
    ///
    /// This is called when a valid vote is accepted by the engine.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who cast the vote
    /// * `view` - The view number of the vote
    fn on_validator_vote(&self, validator_id: ValidatorId, view: u64);
}

/// No-op implementation of `ValidatorVoteRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopValidatorVoteRecorder;

impl ValidatorVoteRecorder for NoopValidatorVoteRecorder {
    fn on_validator_vote(&self, _validator_id: ValidatorId, _view: u64) {
        // No-op
    }
}

// ============================================================================
// ValidatorEquivocationRecorder - Per-validator equivocation metrics callback (T129)
// ============================================================================

/// Trait for recording per-validator equivocation events (T129).
///
/// This trait allows external metrics systems to receive notifications about
/// equivocation events without introducing a hard dependency from cano-consensus
/// to cano-node.
///
/// # Events Tracked
///
/// - `on_validator_equivocation`: Called when equivocation is detected for a validator
///
/// # Important
///
/// This is called exactly once per equivocation event. A validator can equivocate
/// multiple times in different views, and each event triggers a callback.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` as the callback may be invoked from
/// different threads.
pub trait ValidatorEquivocationRecorder: Send + Sync + std::fmt::Debug {
    /// Record an equivocation event from a specific validator.
    ///
    /// This is called when a validator votes for different blocks in the same view.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who equivocated
    /// * `view` - The view number where equivocation occurred
    fn on_validator_equivocation(&self, validator_id: ValidatorId, view: u64);
}

/// No-op implementation of `ValidatorEquivocationRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopValidatorEquivocationRecorder;

impl ValidatorEquivocationRecorder for NoopValidatorEquivocationRecorder {
    fn on_validator_equivocation(&self, _validator_id: ValidatorId, _view: u64) {
        // No-op
    }
}

// ============================================================================
// BasicHotStuffEngine
// ============================================================================

/// A concrete HotStuff engine with static leader scheduling.
///
/// This struct wraps a `HotStuffStateEngine` and adds:
/// - Local validator identity
/// - View tracking
/// - Static leader schedule
/// - Proposal and vote generation logic
/// - View duration metrics (T90.5)
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
///
/// # View Duration Metrics (T90.5)
///
/// The engine tracks the start time of each view and computes the duration
/// when transitioning to the next view. This duration is reported via an
/// optional `ViewDurationRecorder` callback.
///
/// Definition of "view duration":
/// - Time from when view `v` is activated (via `advance_view()` or `set_view()`)
/// - Until view `v+1` is activated
///
/// Caveats:
/// - The first view duration after restart includes time since `initialize_from_restart()`
/// - View durations use monotonic time (`std::time::Instant`), not wall-clock
pub struct BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Local validator id (identity of this node in the validator set).
    local_id: ValidatorId,

    /// Underlying HotStuff state (block tree, QCs, commits).
    state: HotStuffStateEngine<BlockIdT>,

    /// Simple view counter for this node.
    current_view: u64,

    /// Current epoch number (T101).
    ///
    /// All votes, proposals, and QCs produced by this engine will carry this epoch.
    /// Messages from a different epoch will be rejected.
    ///
    /// For now, this is always EpochId(0) and is static (no epoch transitions).
    /// Future tasks will add epoch transition support.
    current_epoch: u64,

    /// Cached leader ordering for this validator set (static, sorted ascending).
    leaders: Vec<ValidatorId>,

    /// Whether we have already proposed in the current view.
    proposed_in_view: bool,

    /// Whether we have already voted in the current view.
    voted_in_view: bool,

    /// Timestamp when the current view started (T90.5).
    ///
    /// Used to compute view duration when transitioning to the next view.
    /// Set to `Some(Instant::now())` on construction and view transitions.
    last_view_start_instant: Option<Instant>,

    /// Optional metrics recorder for view durations (T90.5).
    ///
    /// If `None`, view durations are computed but not recorded.
    view_duration_recorder: Option<Arc<dyn ViewDurationRecorder>>,

    /// Optional metrics recorder for consensus progress (T127).
    ///
    /// If `None`, consensus progress events are not recorded.
    progress_recorder: Option<Arc<dyn ConsensusProgressRecorder>>,

    /// Optional metrics recorder for per-validator vote tracking (T128).
    ///
    /// If `None`, per-validator vote events are not recorded.
    validator_vote_recorder: Option<Arc<dyn ValidatorVoteRecorder>>,

    /// Optional metrics recorder for per-validator equivocation tracking (T129).
    ///
    /// If `None`, equivocation events are not recorded.
    equivocation_recorder: Option<Arc<dyn ValidatorEquivocationRecorder>>,

    /// Timeout message accumulator for view-change (T146).
    ///
    /// Collects timeout messages from validators and forms TimeoutCertificates
    /// when 2f+1 validators have timed out for the same view.
    timeout_accumulator: TimeoutAccumulator<[u8; 32]>,

    /// Whether we have already emitted a timeout message for the current view (T146).
    timeout_emitted_in_view: bool,
}

// Manual Debug implementation because Arc<dyn ViewDurationRecorder> uses Debug
impl<BlockIdT> std::fmt::Debug for BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicHotStuffEngine")
            .field("local_id", &self.local_id)
            .field("state", &self.state)
            .field("current_view", &self.current_view)
            .field("current_epoch", &self.current_epoch)
            .field("leaders", &self.leaders)
            .field("proposed_in_view", &self.proposed_in_view)
            .field("voted_in_view", &self.voted_in_view)
            .field("last_view_start_instant", &self.last_view_start_instant)
            .field("view_duration_recorder", &self.view_duration_recorder)
            .field("progress_recorder", &self.progress_recorder)
            .field("validator_vote_recorder", &self.validator_vote_recorder)
            .field("equivocation_recorder", &self.equivocation_recorder)
            .field("timeout_accumulator", &self.timeout_accumulator)
            .field("timeout_emitted_in_view", &self.timeout_emitted_in_view)
            .finish()
    }
}

impl<BlockIdT> BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new `BasicHotStuffEngine` with the given local id and validator set.
    ///
    /// The engine starts at view 0, epoch 0 with no blocks, no locked QC, and no commits.
    /// View timing starts from construction time.
    pub fn new(local_id: ValidatorId, validators: ConsensusValidatorSet) -> Self {
        let mut ids: Vec<ValidatorId> = validators.iter().map(|v| v.id).collect();
        ids.sort_by_key(|id| id.0);

        BasicHotStuffEngine {
            local_id,
            state: HotStuffStateEngine::new(validators),
            current_view: 0,
            current_epoch: 0, // Default to epoch 0 (T101)
            leaders: ids,
            proposed_in_view: false,
            voted_in_view: false,
            last_view_start_instant: Some(Instant::now()),
            view_duration_recorder: None,
            progress_recorder: None,
            validator_vote_recorder: None,
            equivocation_recorder: None,
            timeout_accumulator: TimeoutAccumulator::new(),
            timeout_emitted_in_view: false,
        }
    }

    /// Attach a view duration recorder for metrics (T90.5).
    ///
    /// The recorder will be called on each view transition with the
    /// duration of the completed view.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ViewDurationRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_view_duration_recorder(mut self, recorder: Arc<dyn ViewDurationRecorder>) -> Self {
        self.view_duration_recorder = Some(recorder);
        self
    }

    /// Set the view duration recorder after construction (T90.5).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_view_duration_recorder(&mut self, recorder: Arc<dyn ViewDurationRecorder>) {
        self.view_duration_recorder = Some(recorder);
    }

    /// Attach a consensus progress recorder for metrics (T127).
    ///
    /// The recorder will be called on consensus events like QC formation,
    /// vote observation, and view changes.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ConsensusProgressRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_progress_recorder(mut self, recorder: Arc<dyn ConsensusProgressRecorder>) -> Self {
        self.progress_recorder = Some(recorder);
        self
    }

    /// Set the consensus progress recorder after construction (T127).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_progress_recorder(&mut self, recorder: Arc<dyn ConsensusProgressRecorder>) {
        self.progress_recorder = Some(recorder);
    }

    /// Attach a per-validator vote recorder for metrics (T128).
    ///
    /// The recorder will be called for each valid vote accepted by the engine.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ValidatorVoteRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_validator_vote_recorder(
        mut self,
        recorder: Arc<dyn ValidatorVoteRecorder>,
    ) -> Self {
        self.validator_vote_recorder = Some(recorder);
        self
    }

    /// Set the per-validator vote recorder after construction (T128).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_validator_vote_recorder(&mut self, recorder: Arc<dyn ValidatorVoteRecorder>) {
        self.validator_vote_recorder = Some(recorder);
    }

    /// Attach a per-validator equivocation recorder for metrics (T129).
    ///
    /// The recorder will be called for each equivocation event detected by the engine.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ValidatorEquivocationRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_equivocation_recorder(
        mut self,
        recorder: Arc<dyn ValidatorEquivocationRecorder>,
    ) -> Self {
        self.equivocation_recorder = Some(recorder);
        self
    }

    /// Set the per-validator equivocation recorder after construction (T129).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_equivocation_recorder(&mut self, recorder: Arc<dyn ValidatorEquivocationRecorder>) {
        self.equivocation_recorder = Some(recorder);
    }

    /// Get the local validator id.
    pub fn local_id(&self) -> ValidatorId {
        self.local_id
    }

    /// Get the current view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Get the current epoch (T101).
    ///
    /// Returns the epoch number used for all consensus messages produced by this engine.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Set the current epoch (T101).
    ///
    /// This should be called at startup to set the epoch from the configured EpochState.
    /// For now, this is a simple setter. Future tasks will add epoch transition logic.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number to use for all consensus messages.
    pub fn set_current_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Transition to a new epoch (T102).
    ///
    /// This method is called when a reconfiguration block is committed. It:
    /// 1. Validates that the transition is sequential (N → N+1)
    /// 2. Updates `current_epoch` to the new epoch
    /// 3. Updates the validator set and leader cache
    ///
    /// # Arguments
    ///
    /// * `new_epoch` - The new epoch ID to transition to
    /// * `new_validator_set` - The validator set for the new epoch
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transition succeeded
    /// * `Err(EpochTransitionError)` if the transition is invalid
    ///
    /// # Design Note
    ///
    /// For T102, we keep it strict: the new epoch must be exactly current_epoch + 1.
    /// The caller is responsible for validating the EpochState against governance
    /// before calling this method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // On reconfig block commit:
    /// let next_epoch_state = provider.get_epoch_state(next_epoch_id).unwrap();
    /// next_epoch_state.validate_with_governance_strict(...)?;
    /// engine.transition_to_epoch(next_epoch_id, next_epoch_state.validator_set)?;
    /// ```
    pub fn transition_to_epoch(
        &mut self,
        new_epoch: crate::validator_set::EpochId,
        new_validator_set: ConsensusValidatorSet,
    ) -> Result<(), crate::validator_set::EpochTransitionError> {
        let current = crate::validator_set::EpochId::new(self.current_epoch);
        let expected_next = crate::validator_set::EpochId::new(self.current_epoch + 1);

        // Enforce sequential epoch transitions
        if new_epoch != expected_next {
            return Err(
                crate::validator_set::EpochTransitionError::NonSequentialEpoch {
                    current,
                    requested: new_epoch,
                },
            );
        }

        // Update epoch atomically
        self.current_epoch = new_epoch.as_u64();

        // Update leader cache
        let mut ids: Vec<ValidatorId> = new_validator_set.iter().map(|v| v.id).collect();
        ids.sort_by_key(|id| id.0);
        self.leaders = ids;

        // Update the underlying state engine's validator set while preserving
        // committed state (block tree, locked QC, commit log, etc.)
        self.state.update_validators(new_validator_set);

        eprintln!(
            "[T102] Epoch transition complete: {} -> {}",
            current, new_epoch
        );

        Ok(())
    }

    /// Get the leader for a given view (round-robin).
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty. This should never happen since
    /// `ConsensusValidatorSet::new` enforces non-empty validator sets.
    pub fn leader_for_view(&self, view: u64) -> ValidatorId {
        let n = self.leaders.len() as u64;
        assert!(n > 0, "validator set must not be empty");
        let idx = (view % n) as usize;
        self.leaders[idx]
    }

    /// Check if this node is the leader for the current view.
    pub fn is_leader_for_current_view(&self) -> bool {
        self.leader_for_view(self.current_view) == self.local_id
    }

    /// Get the underlying state engine.
    pub fn state(&self) -> &HotStuffStateEngine<BlockIdT> {
        &self.state
    }

    /// Mutably access the underlying state engine.
    pub fn state_mut(&mut self) -> &mut HotStuffStateEngine<BlockIdT> {
        &mut self.state
    }

    /// Get the current locked QC, if any.
    pub fn locked_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.state.locked_qc()
    }

    /// Get the latest committed block id, if any.
    pub fn committed_block(&self) -> Option<&BlockIdT> {
        self.state.committed_block()
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        self.state.validators()
    }

    /// Get the commit log (sequence of committed blocks).
    pub fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }

    /// Advance to the next view.
    ///
    /// This resets the `proposed_in_view`, `voted_in_view`, and `timeout_emitted_in_view` flags.
    ///
    /// # Metrics (T90.5)
    ///
    /// If a view duration recorder is attached, computes the duration since
    /// the view started and reports it to the recorder.
    ///
    /// # Metrics (T127)
    ///
    /// If a progress recorder is attached, records view change and leader
    /// change events.
    pub fn advance_view(&mut self) {
        let from_view = self.current_view;
        let to_view = self.current_view + 1;

        // Compute and record view duration if we have a start timestamp
        self.record_view_duration_internal(from_view, to_view);

        // Record consensus progress metrics (T127)
        self.record_progress_view_change_internal(from_view, to_view);

        self.current_view = to_view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Start timing for the new view
        self.last_view_start_instant = Some(Instant::now());
    }

    /// Internal helper to compute and record view duration (T90.5).
    fn record_view_duration_internal(&self, from_view: u64, to_view: u64) {
        if let (Some(start), Some(recorder)) = (
            self.last_view_start_instant,
            self.view_duration_recorder.as_ref(),
        ) {
            let duration = start.elapsed();
            recorder.record_view_duration(duration, from_view, to_view);
        }
    }

    /// Internal helper to record progress metrics on view change (T127).
    fn record_progress_view_change_internal(&self, from_view: u64, to_view: u64) {
        if let Some(recorder) = self.progress_recorder.as_ref() {
            // Record view change
            recorder.record_view_change(from_view, to_view);

            // Reset current view votes counter
            recorder.reset_current_view_votes();

            // Check for leader change by comparing actual leaders for the views
            // This handles both round-robin and any future leader selection policies
            let from_leader = self.leader_for_view(from_view);
            let to_leader = self.leader_for_view(to_view);
            if from_leader != to_leader {
                recorder.record_leader_change();
            }
        }
    }

    /// Set the current view directly (for restart recovery).
    ///
    /// This is used when restoring state from persistence to set the view
    /// to the height/view of the last committed block + 1.
    ///
    /// # Safety Note
    ///
    /// This should only be called during startup/restart, not during normal
    /// consensus operation. Setting view incorrectly could violate liveness.
    ///
    /// # Metrics (T90.5)
    ///
    /// If transitioning from a different view, records the duration of the
    /// previous view. The new view timing starts from this call.
    pub fn set_view(&mut self, view: u64) {
        let from_view = self.current_view;

        // Record duration of the previous view if we're changing views
        if view != from_view {
            self.record_view_duration_internal(from_view, view);
        }

        self.current_view = view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Start timing for the new view
        self.last_view_start_instant = Some(Instant::now());
    }

    /// Get the committed height, if any.
    ///
    /// Returns the height of the latest committed block, or `None` if no
    /// block has been committed yet.
    pub fn committed_height(&self) -> Option<u64> {
        self.state.committed_height()
    }

    /// Initialize the engine from persisted restart state.
    ///
    /// This method restores the engine to a safe state based on the last
    /// committed block from persistence. Call this during node startup after
    /// loading state from `ConsensusStorage`.
    ///
    /// # Restart Semantics (T84)
    ///
    /// ## What is Restored
    ///
    /// - **Committed block**: The engine recognizes this block as committed
    /// - **Committed height**: Used for monotonicity checks
    /// - **Locked QC**: Set conservatively to prevent voting for conflicting blocks
    /// - **Current view**: Set to `committed_height + 1` to resume from next view
    ///
    /// ## What is NOT Restored
    ///
    /// - **In-flight proposals**: Lost; will be re-proposed by leaders
    /// - **Pending votes**: Lost; safe because we restart from committed state
    /// - **High QC vs Locked QC distinction**: We conservatively treat them as same
    /// - **Vote accumulator**: Starts fresh
    ///
    /// ## Safety Guarantee
    ///
    /// This approach is safe because:
    /// 1. The committed prefix has a 3-chain QC and cannot be reverted
    /// 2. Setting locked_qc prevents voting for conflicting blocks
    /// 3. Setting view to `committed_height + 1` prevents re-committing old blocks
    ///
    /// ## Liveness Trade-off
    ///
    /// The conservative locked_qc may delay voting until a new proposal arrives
    /// with a QC at or above the locked view. This is acceptable for restart
    /// scenarios where safety is paramount.
    ///
    /// # Arguments
    ///
    /// - `committed_block_id`: The block ID of the last committed block
    /// - `committed_height`: The height of the last committed block
    /// - `locked_qc`: Optional QC for locking (typically QC for the committed block)
    ///
    /// # Metrics (T90.5)
    ///
    /// Initializes view timing from this point. The first view duration after
    /// restart will include any time from this call until the first view change.
    /// This is documented and acceptable behavior.
    pub fn initialize_from_restart(
        &mut self,
        committed_block_id: BlockIdT,
        committed_height: u64,
        locked_qc: Option<QuorumCertificate<BlockIdT>>,
    ) {
        // Initialize the underlying state engine
        self.state
            .initialize_from_restart(committed_block_id, committed_height, locked_qc);

        // Set view to committed_height + 1 to resume from the next view
        // This ensures we don't re-propose or re-vote for already committed heights
        self.current_view = committed_height.saturating_add(1);
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Initialize view timing from restart (T90.5)
        // The first view duration will include time since this call
        self.last_view_start_instant = Some(Instant::now());
    }
}

// ============================================================================
// HasCommitLog implementation for BasicHotStuffEngine
// ============================================================================

impl<BlockIdT> HasCommitLog<BlockIdT> for BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }
}

// ============================================================================
// BlockIdT = [u8; 32] specific implementation
// ============================================================================

impl BasicHotStuffEngine<[u8; 32]> {
    /// Generate a deterministic block id based on proposal header fields.
    ///
    /// This creates a consistent block_id that both the proposer and followers
    /// can derive from the same proposal header.
    fn derive_block_id_from_header(
        proposer: ValidatorId,
        view: u64,
        parent_block_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut id = [0u8; 32];
        // Encode proposer id in the first 8 bytes
        let proposer_bytes = proposer.0.to_le_bytes();
        id[..8].copy_from_slice(&proposer_bytes);
        // Encode view in bytes 8-15
        let view_bytes = view.to_le_bytes();
        id[8..16].copy_from_slice(&view_bytes);
        // Copy first 16 bytes of parent_block_id for uniqueness
        id[16..32].copy_from_slice(&parent_block_id[..16]);
        id
    }

    /// Generate a block id for the current view (as leader).
    fn make_block_id(&mut self, parent_block_id: &[u8; 32]) -> [u8; 32] {
        Self::derive_block_id_from_header(self.local_id, self.current_view, parent_block_id)
    }

    /// Called when this node is leader for the current view.
    ///
    /// Returns a list of actions to be performed:
    /// - `BroadcastProposal` for the new block proposal
    /// - `BroadcastVote` for the leader's own vote on the proposal
    ///
    /// Returns an empty Vec if we are not the leader or have already proposed.
    ///
    /// # Two-Node Liveness
    ///
    /// In a 2-node setup with 2/3 quorum requirement, both nodes must vote and
    /// both votes must be seen by someone to form a QC. The leader broadcasts
    /// both its proposal AND its vote so that the follower can collect both
    /// votes and form a QC.
    pub fn on_leader_step(&mut self) -> Vec<ConsensusEngineAction<ValidatorId>> {
        if !self.is_leader_for_current_view() {
            return Vec::new();
        }

        if self.proposed_in_view {
            return Vec::new();
        }

        let view = self.current_view;

        // Parent is the locked block or committed block or none.
        // Note: We use [0xFF; 32] as the sentinel for "no parent" because [0u8; 32]
        // can be a valid block_id. Specifically, the first proposal with proposer=0,
        // view=0, and parent=[0u8;32] produces block_id=[0u8;32], making it unsuitable
        // as a sentinel value.
        let parent_id = self
            .state
            .locked_qc()
            .map(|qc| qc.block_id)
            .or_else(|| self.state.committed_block().cloned());

        let parent_block_id = parent_id.unwrap_or([0xFF; 32]);

        // Build a proposal - use consistent block_id derivation
        let block_id = self.make_block_id(&parent_block_id);

        let justify_qc = self.state.locked_qc().cloned();

        // Register the block in our local state
        self.state
            .register_block(block_id, view, parent_id, justify_qc.clone());

        // Build the wire-format proposal
        use cano_wire::consensus::{BlockHeader, BlockProposal, Vote};

        let epoch = self.current_epoch;

        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch,
                height: view,
                round: view,
                parent_block_id,
                payload_hash: [0u8; 32],
                proposer_index: self.local_id.0 as u16,
                suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: cano_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
            },
            qc: justify_qc.map(|qc| {
                // Convert our logical QC to wire format
                use cano_wire::consensus::QuorumCertificate as WireQc;
                WireQc {
                    version: 1,
                    chain_id: 1,
                    epoch,
                    height: qc.view,
                    round: qc.view,
                    step: 0,
                    block_id: qc.block_id,
                    suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
                    signer_bitmap: vec![],
                    signatures: vec![],
                }
            }),
            txs: vec![],
            signature: vec![],
        };

        self.proposed_in_view = true;

        // Vote for our own proposal
        let result = self.state.on_vote(self.local_id, view, &block_id);
        self.voted_in_view = true;

        // Record self-vote observation (T127)
        if result.is_ok() {
            if let Some(recorder) = self.progress_recorder.as_ref() {
                recorder.record_vote_observed(true); // Self-vote is always for current view
            }
            // Record per-validator self-vote (T128)
            if let Some(recorder) = self.validator_vote_recorder.as_ref() {
                recorder.on_validator_vote(self.local_id, view);
            }
        }

        // Build the leader's vote to broadcast
        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index: self.local_id.0 as u16,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        };

        // If a QC was formed immediately (e.g., single node), record and advance view
        if let Ok(Some(_qc)) = result {
            // Record QC formation with latency (T127)
            if let Some(recorder) = self.progress_recorder.as_ref() {
                if let Some(start) = self.last_view_start_instant {
                    let latency = start.elapsed();
                    recorder.record_qc_formed_with_latency(latency);
                } else {
                    recorder.record_qc_formed();
                }
            }
            self.advance_view();
        }

        // Return both actions: broadcast proposal and broadcast leader's vote
        vec![
            ConsensusEngineAction::BroadcastProposal(proposal),
            ConsensusEngineAction::BroadcastVote(vote),
        ]
    }

    /// Called when we receive a proposal from the network.
    ///
    /// Returns a `BroadcastVote` action if we should vote for the proposal,
    /// or `None` if we should not vote.
    ///
    /// # Epoch Validation (T101)
    ///
    /// If the proposal's header.epoch doesn't match the engine's `current_epoch`,
    /// we reject the proposal (return None). Future work may add explicit error handling.
    pub fn on_proposal_event(
        &mut self,
        from: ValidatorId,
        proposal: &cano_wire::consensus::BlockProposal,
    ) -> Option<ConsensusEngineAction<ValidatorId>> {
        // T101: Epoch validation - reject proposals from wrong epoch
        if proposal.header.epoch != self.current_epoch {
            // Log and reject (future work: return explicit error)
            return None;
        }

        let view = proposal.header.height;

        // If proposal is for a future view, advance directly to it
        if view > self.current_view {
            self.current_view = view;
            self.proposed_in_view = false;
            self.voted_in_view = false;
        }

        // Only process proposals for our current view
        if view != self.current_view {
            return None;
        }

        // Only accept proposals from the leader for this view
        let expected_leader = self.leader_for_view(view);
        if from != expected_leader {
            return None;
        }

        // Don't vote twice in the same view
        if self.voted_in_view {
            return None;
        }

        // Derive the block_id consistently using the same function as the proposer
        let block_id = Self::derive_block_id_from_header(
            from, // proposer's id
            view,
            &proposal.header.parent_block_id,
        );

        // Parse justify QC from proposal
        let justify_qc = proposal
            .qc
            .as_ref()
            .map(|wire_qc| QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![]));

        // Register the block in our state.
        // Note: We use [0xFF; 32] as the sentinel for "no parent" because [0u8; 32]
        // can be a valid block_id. Specifically, the first proposal with proposer=0,
        // view=0, and parent=[0u8;32] produces block_id=[0u8;32], making it unsuitable
        // as a sentinel value.
        let parent_id = if proposal.header.parent_block_id == [0xFF; 32] {
            None
        } else {
            Some(proposal.header.parent_block_id)
        };
        self.state
            .register_block(block_id, view, parent_id, justify_qc);

        // Enforce locked-block safety: only vote if this block is on a chain
        // that includes the locked block as an ancestor (or if there is no lock yet).
        if !self.state.is_safe_to_vote_on_block(&block_id) {
            // Proposal is on a conflicting fork; do not vote.
            return None;
        }

        // Create and ingest our own vote
        // Errors here would indicate a bug in our code (voting for a block we just registered)
        let vote_result = self.state.on_vote(self.local_id, view, &block_id);
        debug_assert!(
            vote_result.is_ok(),
            "self-vote should not fail: {:?}",
            vote_result
        );

        self.voted_in_view = true;

        // Create a vote to broadcast
        use cano_wire::consensus::Vote;

        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch: self.current_epoch,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index: self.local_id.0 as u16,
            suite_id: cano_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        };

        // NOTE: We do NOT advance view here. View advancement happens only when
        // a QC is formed (either locally via on_vote_event, or when the leader
        // processes our vote and forms the QC). This ensures all nodes stay
        // synchronized on the same view until consensus is reached.

        Some(ConsensusEngineAction::BroadcastVote(vote))
    }

    /// Called when we receive a vote from the network.
    ///
    /// This ingests the vote into our state engine. If a QC is formed,
    /// we advance to the next view.
    ///
    /// Returns `None` as we don't emit further network actions on vote receipt.
    ///
    /// # Epoch Validation (T101)
    ///
    /// If the vote's epoch doesn't match the engine's `current_epoch`,
    /// returns `Err(ConsensusVerifyError::WrongEpoch)`.
    ///
    /// # Metrics (T127, T128)
    ///
    /// Records vote observation and QC formation events if a progress recorder
    /// is attached. Records per-validator vote events if a validator vote recorder
    /// is attached.
    pub fn on_vote_event(
        &mut self,
        from: ValidatorId,
        vote: &cano_wire::consensus::Vote,
    ) -> Result<Option<QuorumCertificate<[u8; 32]>>, QcValidationError> {
        // T101: Epoch validation
        if vote.epoch != self.current_epoch {
            return Err(QcValidationError::Verify(
                crate::ConsensusVerifyError::WrongEpoch {
                    expected: self.current_epoch,
                    actual: vote.epoch,
                },
            ));
        }

        let view = vote.height;
        let block_id = vote.block_id;

        // Track equivocation count before vote ingestion for detection (T129)
        let equivocations_before = self.state.equivocations_detected();

        // Ingest the vote
        let result = self.state.on_vote(from, view, &block_id)?;

        // Check for new equivocation (T129)
        // If equivocation count increased, the vote was an equivocating vote
        let equivocations_after = self.state.equivocations_detected();
        if equivocations_after > equivocations_before {
            // Record equivocation event
            if let Some(recorder) = self.equivocation_recorder.as_ref() {
                recorder.on_validator_equivocation(from, view);
            }
            // Note: Equivocating votes are ignored by on_vote() and return Ok(None),
            // so we don't record them as valid votes in the progress/validator metrics
        } else {
            // Record vote observation (T127)
            // Note: We record after successful ingestion to only count valid votes
            if let Some(recorder) = self.progress_recorder.as_ref() {
                let is_for_current_view = view == self.current_view;
                recorder.record_vote_observed(is_for_current_view);
            }

            // Record per-validator vote (T128)
            // Note: We record after successful ingestion to only count valid votes
            if let Some(recorder) = self.validator_vote_recorder.as_ref() {
                recorder.on_validator_vote(from, view);
            }
        }

        // If a QC was formed, record and advance view
        if let Some(_qc) = result.as_ref() {
            // Record QC formation with latency if available (T127)
            if let Some(recorder) = self.progress_recorder.as_ref() {
                if let Some(start) = self.last_view_start_instant {
                    let latency = start.elapsed();
                    recorder.record_qc_formed_with_latency(latency);
                } else {
                    recorder.record_qc_formed();
                }
            }

            // Advance view if the QC is for our current view or later
            if view >= self.current_view {
                self.advance_view();
            }
        }

        Ok(result)
    }

    /// Process a single step of the engine.
    ///
    /// This is called by the driver on each iteration. It:
    /// 1. Checks if we are leader and should propose
    /// 2. Returns any actions that should be broadcast
    ///
    /// The event parameter is the event from the network, if any.
    /// The driver should call `on_proposal_event` or `on_vote_event` before calling this.
    pub fn try_propose(&mut self) -> Vec<ConsensusEngineAction<ValidatorId>> {
        self.on_leader_step()
    }

    /// Verify that a message's epoch matches the current epoch (T101).
    ///
    /// Returns `Ok(())` if epochs match, or `Err(WrongEpoch)` if they don't.
    pub fn verify_epoch(&self, msg_epoch: u64) -> Result<(), crate::ConsensusVerifyError> {
        if msg_epoch != self.current_epoch {
            return Err(crate::ConsensusVerifyError::WrongEpoch {
                expected: self.current_epoch,
                actual: msg_epoch,
            });
        }
        Ok(())
    }

    // ========================================================================
    // Timeout / View-Change Methods (T146)
    // ========================================================================

    /// Check if we have already emitted a timeout for the current view.
    pub fn timeout_emitted_in_view(&self) -> bool {
        self.timeout_emitted_in_view
    }

    /// Mark that we have emitted a timeout for the current view.
    ///
    /// This is called after broadcasting a TimeoutMsg to prevent duplicate emissions.
    pub fn mark_timeout_emitted(&mut self) {
        self.timeout_emitted_in_view = true;
    }

    /// Create a TimeoutMsg for the current view.
    ///
    /// This creates an unsigned timeout message. The caller is responsible for
    /// signing it before broadcasting.
    ///
    /// # Returns
    ///
    /// A `TimeoutMsg` ready to be signed and broadcast.
    pub fn create_timeout_msg(&self) -> TimeoutMsg<[u8; 32]> {
        let high_qc = self.state.locked_qc().cloned();
        TimeoutMsg::new(self.current_view, high_qc, self.local_id)
    }

    /// Process an incoming timeout message from another validator.
    ///
    /// This ingests the timeout message into the accumulator. If a
    /// TimeoutCertificate can be formed (2f+1 timeouts), it is returned.
    ///
    /// # Arguments
    ///
    /// - `from`: The validator who sent the timeout message
    /// - `timeout`: The timeout message
    ///
    /// # Returns
    ///
    /// - `Ok(Some(tc))` if a TimeoutCertificate was formed
    /// - `Ok(None)` if the timeout was accepted but no TC formed yet
    /// - `Err(TimeoutValidationError)` if the timeout was invalid
    ///
    /// # Note
    ///
    /// This method does NOT verify the signature. Signature verification
    /// should be done by the caller before calling this method.
    pub fn on_timeout_msg(
        &mut self,
        from: ValidatorId,
        timeout: TimeoutMsg<[u8; 32]>,
    ) -> Result<Option<TimeoutCertificate<[u8; 32]>>, TimeoutValidationError> {
        // Verify the sender matches the timeout's validator_id
        if from != timeout.validator_id {
            return Err(TimeoutValidationError::InvalidSignature(from));
        }

        // Only accept timeouts for current or future views
        if timeout.view < self.current_view {
            // Stale timeout - silently ignore
            return Ok(None);
        }

        // Ingest into accumulator
        let _is_new = self
            .timeout_accumulator
            .on_timeout(self.state.validators(), timeout)?;

        // Check if we can form a TC for this view
        let view = from; // Use the timeout's view for TC check
        let _ = view; // Unused, we use the timeout's view below

        // Try to form TC for any view where we have enough timeouts
        // Start from current_view and check upward
        for check_view in self.current_view..=self.current_view + 10 {
            if let Some(tc) = self
                .timeout_accumulator
                .maybe_tc_for(self.state.validators(), check_view)
            {
                return Ok(Some(tc));
            }
        }

        Ok(None)
    }

    /// Process a TimeoutCertificate to advance to a new view.
    ///
    /// This method is called when a TC is formed locally or received from
    /// another validator. It:
    /// 1. Validates the TC has sufficient signers
    /// 2. Updates the locked QC if the TC's high_qc is higher
    /// 3. Advances to the TC's target view
    ///
    /// # Arguments
    ///
    /// - `tc`: The timeout certificate
    ///
    /// # Returns
    ///
    /// - `Ok(new_view)` with the new view number if successful
    /// - `Err(TimeoutValidationError)` if the TC is invalid
    ///
    /// # Safety Invariants (T146)
    ///
    /// - The TC's high_qc becomes the justify_qc for the next proposal
    /// - If TC's high_qc.view > locked_qc.view, we update locked_qc
    /// - This maintains HotStuff safety: no conflicting commits
    pub fn on_timeout_certificate(
        &mut self,
        tc: &TimeoutCertificate<[u8; 32]>,
    ) -> Result<u64, TimeoutValidationError> {
        // Validate the TC
        tc.validate(self.state.validators())?;

        // Only process TCs for views > current_view
        if tc.view <= self.current_view {
            // TC is for an old view, ignore
            return Ok(self.current_view);
        }

        // T146 Safety: Update locked_qc if TC's high_qc is higher
        // This ensures we don't vote for blocks that conflict with committed blocks
        if let Some(ref tc_high_qc) = tc.high_qc {
            let should_update = match self.state.locked_qc() {
                None => true,
                Some(locked) => tc_high_qc.view > locked.view,
            };

            if should_update {
                // Update locked_qc through the state engine
                self.state.set_locked_qc(tc_high_qc.clone());
            }
        }

        // Advance to the TC's target view
        let from_view = self.current_view;
        let to_view = tc.view;

        // Record metrics
        self.record_view_duration_internal(from_view, to_view);
        self.record_progress_view_change_internal(from_view, to_view);

        // Update view state
        self.current_view = to_view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false;
        self.last_view_start_instant = Some(Instant::now());

        // Clear old timeout messages
        self.timeout_accumulator.clear_view(tc.timeout_view);

        Ok(to_view)
    }

    /// Get the timeout accumulator (for testing/debugging).
    pub fn timeout_accumulator(&self) -> &TimeoutAccumulator<[u8; 32]> {
        &self.timeout_accumulator
    }

    /// Get the number of timeout messages collected for a view.
    pub fn timeout_count(&self, view: u64) -> usize {
        self.timeout_accumulator.timeout_count(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::ValidatorSetEntry;

    fn make_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    #[test]
    fn basic_engine_leader_for_view_round_robin() {
        let validators = make_validator_set(3);
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Leaders are sorted: [1, 2, 3]
        // view 0 -> 0 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(0), ValidatorId(1));
        // view 1 -> 1 % 3 = 1 -> leader[1] = 2
        assert_eq!(engine.leader_for_view(1), ValidatorId(2));
        // view 2 -> 2 % 3 = 2 -> leader[2] = 3
        assert_eq!(engine.leader_for_view(2), ValidatorId(3));
        // view 3 -> 3 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(3), ValidatorId(1));
    }

    #[test]
    fn basic_engine_is_leader_for_current_view() {
        let validators = make_validator_set(3);

        // Node 1 at view 0: is leader
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators.clone());
        assert!(engine.is_leader_for_current_view());

        // Node 2 at view 0: not leader
        let engine2: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);
        assert!(!engine2.is_leader_for_current_view());
    }

    #[test]
    fn basic_engine_advance_view() {
        let validators = make_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        assert_eq!(engine.current_view(), 0);
        engine.advance_view();
        assert_eq!(engine.current_view(), 1);
        engine.advance_view();
        assert_eq!(engine.current_view(), 2);
    }

    #[test]
    fn basic_engine_on_leader_step_produces_proposal() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Single node is always leader
        let actions = engine.on_leader_step();
        assert!(!actions.is_empty());

        // First action should be BroadcastProposal
        if let ConsensusEngineAction::BroadcastProposal(proposal) = &actions[0] {
            assert_eq!(proposal.header.height, 0);
            assert_eq!(proposal.header.proposer_index, 1);
        } else {
            panic!("Expected BroadcastProposal action");
        }

        // Second action should be BroadcastVote (leader's own vote)
        assert!(actions.len() >= 2);
        assert!(matches!(
            &actions[1],
            ConsensusEngineAction::BroadcastVote(_)
        ));

        // With a single node, QC forms immediately, view advances to 1
        // So the second call produces another proposal (for view 1)
        // This is correct behavior with optimistic view advancement
        let actions2 = engine.on_leader_step();
        assert!(!actions2.is_empty());

        if let ConsensusEngineAction::BroadcastProposal(proposal2) = &actions2[0] {
            assert_eq!(proposal2.header.height, 1);
        } else {
            panic!("Expected BroadcastProposal action for view 1");
        }
    }

    #[test]
    fn basic_engine_non_leader_does_not_propose() {
        let validators = make_validator_set(3);
        // Node 2 is not leader at view 0
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);

        let actions = engine.on_leader_step();
        assert!(actions.is_empty());
    }

    // ========================================================================
    // View duration metrics tests (T90.5)
    // ========================================================================

    use std::sync::atomic::{AtomicU64, Ordering};

    /// A simple test recorder that captures view duration calls.
    #[derive(Debug, Default)]
    struct TestViewDurationRecorder {
        call_count: AtomicU64,
        total_from_view: AtomicU64,
        total_to_view: AtomicU64,
        // Note: We can't easily capture Duration in atomics, so we just count calls
    }

    impl ViewDurationRecorder for TestViewDurationRecorder {
        fn record_view_duration(&self, _duration: Duration, from_view: u64, to_view: u64) {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            self.total_from_view.fetch_add(from_view, Ordering::Relaxed);
            self.total_to_view.fetch_add(to_view, Ordering::Relaxed);
        }
    }

    impl TestViewDurationRecorder {
        fn call_count(&self) -> u64 {
            self.call_count.load(Ordering::Relaxed)
        }

        fn last_from_view(&self) -> u64 {
            self.total_from_view.load(Ordering::Relaxed)
        }

        fn last_to_view(&self) -> u64 {
            self.total_to_view.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn engine_without_recorder_does_not_panic_on_advance_view() {
        let validators = make_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Should not panic even without a recorder
        engine.advance_view();
        engine.advance_view();
        assert_eq!(engine.current_view(), 2);
    }

    #[test]
    fn engine_with_recorder_calls_on_advance_view() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // First advance: from view 0 to view 1
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 0);
        assert_eq!(recorder.last_to_view(), 1);

        // Second advance: from view 1 to view 2 (totals are cumulative)
        engine.advance_view();
        assert_eq!(recorder.call_count(), 2);
        assert_eq!(recorder.last_from_view(), 1); // 0 + 1
        assert_eq!(recorder.last_to_view(), 3); // 1 + 2
    }

    #[test]
    fn engine_set_view_records_duration_when_changing() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // set_view to a different view should record
        engine.set_view(5);
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 0);
        assert_eq!(recorder.last_to_view(), 5);

        // set_view to the same view should NOT record
        engine.set_view(5);
        assert_eq!(recorder.call_count(), 1); // Still 1
    }

    #[test]
    fn engine_set_recorder_after_construction() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // No recorder yet, advance view
        engine.advance_view();
        assert_eq!(recorder.call_count(), 0);

        // Now set the recorder
        engine.set_view_duration_recorder(recorder.clone());

        // Further advances should be recorded
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
    }

    #[test]
    fn noop_recorder_is_debug() {
        let recorder = NoopViewDurationRecorder;
        // Just ensure it implements Debug
        let _ = format!("{:?}", recorder);
    }

    #[test]
    fn engine_initialize_from_restart_sets_timestamp() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // Initialize from restart at height 10
        engine.initialize_from_restart([0u8; 32], 10, None);

        // View should be 11 (10 + 1)
        assert_eq!(engine.current_view(), 11);

        // initialize_from_restart should NOT record (it's setting up, not completing a view)
        // Actually, looking at our implementation, it doesn't record because we don't track
        // the old view. Let's verify:
        assert_eq!(recorder.call_count(), 0);

        // But advancing from this point SHOULD record
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 11);
        assert_eq!(recorder.last_to_view(), 12);
    }
}
