//! Pacemaker abstraction for HotStuff-style consensus.
//!
//! This module provides pacemaker implementations that control when a leader
//! should propose and when validators should timeout waiting for progress.
//!
//! # Design (T146)
//!
//! The module provides two pacemaker implementations:
//!
//! 1. [`BasicTickPacemaker`]: Simple tick-based pacemaker for proposal timing.
//!    This is the original implementation that only decides "should we propose?"
//!
//! 2. [`TimeoutPacemaker`]: Full timeout/view-change pacemaker (T146).
//!    This pacemaker tracks real time and generates timeout events when no
//!    progress is made within the configured timeout period.
//!
//! # View Change Protocol (T146)
//!
//! When using `TimeoutPacemaker`, the flow is:
//!
//! 1. On each tick, call `on_tick(now, engine_view)` which returns a `PacemakerEvent`
//! 2. If `PacemakerEvent::Timeout { view }` is returned, the node should:
//!    - Emit a `TimeoutMsg` for that view
//!    - Broadcast it to all validators
//! 3. When 2f+1 timeout messages are collected, a `TimeoutCertificate` is formed
//! 4. The TC enables view change via `PacemakerEvent::NewView { view }`
//!
//! # Example (Basic)
//!
//! ```
//! use cano_consensus::pacemaker::{Pacemaker, PacemakerConfig, BasicTickPacemaker};
//!
//! let cfg = PacemakerConfig { min_ticks_between_proposals: 1, ..Default::default() };
//! let mut pm = BasicTickPacemaker::new(cfg);
//!
//! // First tick at view 0 allows proposal
//! assert!(pm.on_tick(0));
//!
//! // Second tick at same view does not allow another proposal
//! assert!(!pm.on_tick(0));
//!
//! // Moving to a new view resets
//! assert!(pm.on_tick(1));
//! ```
//!
//! # Example (Timeout)
//!
//! ```
//! use cano_consensus::pacemaker::{TimeoutPacemaker, TimeoutPacemakerConfig, PacemakerEvent};
//! use std::time::{Duration, Instant};
//!
//! let cfg = TimeoutPacemakerConfig {
//!     base_timeout: Duration::from_millis(1000),
//!     timeout_multiplier: 2.0,
//!     max_timeout: Duration::from_secs(30),
//! };
//! let mut pm = TimeoutPacemaker::new(cfg);
//!
//! // Simulate time passing without progress
//! let now = Instant::now();
//! // ... after timeout period with no progress, on_tick returns Timeout event
//! ```

use std::time::{Duration, Instant};

/// Configuration for a simple tick-based pacemaker.
#[derive(Clone, Debug)]
pub struct PacemakerConfig {
    /// Minimum number of ticks between proposals in the same view.
    pub min_ticks_between_proposals: u32,
    /// Base timeout duration for view 0 (only used by TimeoutPacemaker).
    /// Default: 1000ms.
    pub base_timeout_ms: u64,
    /// Timeout multiplier for exponential backoff (only used by TimeoutPacemaker).
    /// Default: 2.0 (doubles timeout each consecutive timeout).
    pub timeout_multiplier: f64,
}

impl Default for PacemakerConfig {
    fn default() -> Self {
        PacemakerConfig {
            min_ticks_between_proposals: 1,
            base_timeout_ms: 1000,
            timeout_multiplier: 2.0,
        }
    }
}

/// Configuration for the timeout-aware pacemaker (T146).
///
/// This config controls the timeout behavior for view changes.
#[derive(Clone, Debug)]
pub struct TimeoutPacemakerConfig {
    /// Base timeout duration for the first timeout attempt.
    /// Subsequent timeouts may use exponential backoff.
    pub base_timeout: Duration,
    /// Multiplier for exponential backoff on consecutive timeouts.
    /// Set to 1.0 for no backoff.
    pub timeout_multiplier: f64,
    /// Maximum timeout duration (caps the backoff).
    pub max_timeout: Duration,
}

impl Default for TimeoutPacemakerConfig {
    fn default() -> Self {
        TimeoutPacemakerConfig {
            base_timeout: Duration::from_millis(1000),
            timeout_multiplier: 2.0,
            max_timeout: Duration::from_secs(30),
        }
    }
}

/// Events that a pacemaker can generate (T146).
///
/// This enum represents the possible outcomes of a pacemaker tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacemakerEvent {
    /// No event - continue normal operation.
    None,
    /// Timeout detected for the given view.
    /// The node should emit a TimeoutMsg and broadcast it.
    Timeout {
        /// The view that timed out (current view with no progress).
        view: u64,
    },
    /// View should advance to the specified view.
    /// This is triggered when a TimeoutCertificate is formed/received.
    NewView {
        /// The new view to transition to.
        view: u64,
    },
    /// Proposal should be attempted (leader only).
    ShouldPropose,
}

/// A minimal pacemaker interface for HotStuff-style consensus.
///
/// This trait is intentionally small; it is driven by "ticks" (logical time)
/// and the consensus engine's current view. It decides whether the local
/// leader should attempt a proposal on this tick.
pub trait Pacemaker {
    /// Called once per logical tick. Returns `true` if the local node should
    /// attempt to propose in the current view (assuming it is the leader).
    ///
    /// `engine_view` is the current view as seen by the consensus engine.
    fn on_tick(&mut self, engine_view: u64) -> bool;

    /// Notify the pacemaker that a QC for `qc_view` was observed.
    ///
    /// This can be used to reset internal state when progress is made.
    fn on_qc(&mut self, qc_view: u64);
}

/// A very simple tick-based pacemaker:
/// - Tracks the last view it saw from the engine.
/// - Counts ticks since the last proposal in that view.
/// - Allows at most one proposal per view per `min_ticks_between_proposals`.
#[derive(Debug)]
pub struct BasicTickPacemaker {
    cfg: PacemakerConfig,
    last_view: u64,
    ticks_in_view: u32,
    proposals_in_view: u32,
}

impl BasicTickPacemaker {
    /// Create a new `BasicTickPacemaker` with the given configuration.
    pub fn new(cfg: PacemakerConfig) -> Self {
        BasicTickPacemaker {
            cfg,
            last_view: 0,
            ticks_in_view: 0,
            proposals_in_view: 0,
        }
    }
}

impl Pacemaker for BasicTickPacemaker {
    fn on_tick(&mut self, engine_view: u64) -> bool {
        if engine_view != self.last_view {
            // We moved to a new view: reset counters.
            self.last_view = engine_view;
            self.ticks_in_view = 0;
            self.proposals_in_view = 0;
        }

        self.ticks_in_view = self.ticks_in_view.saturating_add(1);

        // Allow a proposal if:
        // - we haven't proposed yet in this view, AND
        // - we have waited at least min_ticks_between_proposals ticks.
        if self.proposals_in_view == 0 && self.ticks_in_view >= self.cfg.min_ticks_between_proposals
        {
            self.proposals_in_view = 1;
            true
        } else {
            false
        }
    }

    fn on_qc(&mut self, qc_view: u64) {
        // For now, we only use QC as a hint to reset if we somehow lagged.
        if qc_view > self.last_view {
            self.last_view = qc_view;
            self.ticks_in_view = 0;
            self.proposals_in_view = 0;
        }
    }
}

// ============================================================================
// TimeoutPacemaker - Full timeout/view-change pacemaker (T146)
// ============================================================================

/// A pacemaker with real-time timeout detection for view changes (T146).
///
/// This pacemaker tracks time since last progress and generates timeout events
/// when the configured timeout period elapses without progress.
///
/// # Progress Definition
///
/// "Progress" is defined as:
/// - Receiving a valid proposal for the current view
/// - Forming a QC for the current view
/// - Committing a block
///
/// Call `on_progress()` when any of these occur to reset the timeout timer.
///
/// # Timeout Behavior
///
/// - The timeout duration starts at `base_timeout`
/// - On each consecutive timeout without progress, the duration is multiplied
///   by `timeout_multiplier` (exponential backoff)
/// - The timeout is capped at `max_timeout`
/// - Progress resets the backoff counter
///
/// # View Change Flow
///
/// 1. `on_tick_with_time()` returns `PacemakerEvent::Timeout { view }` when timeout expires
/// 2. Node emits and broadcasts a `TimeoutMsg`
/// 3. When TC is received/formed, call `on_timeout_certificate()`
/// 4. `on_tick_with_time()` returns `PacemakerEvent::NewView { view }` or view is updated
#[derive(Debug)]
pub struct TimeoutPacemaker {
    /// Configuration for timeout behavior.
    cfg: TimeoutPacemakerConfig,
    /// Current view as known by this pacemaker.
    current_view: u64,
    /// Timestamp of last progress (proposal/QC/commit).
    last_progress: Instant,
    /// Whether we have already emitted a timeout for the current view.
    timeout_emitted: bool,
    /// Number of consecutive timeouts without progress (for backoff).
    consecutive_timeouts: u32,
    /// Pending new view from a TC (will be emitted on next tick).
    pending_new_view: Option<u64>,
}

impl TimeoutPacemaker {
    /// Create a new timeout pacemaker with the given configuration.
    pub fn new(cfg: TimeoutPacemakerConfig) -> Self {
        TimeoutPacemaker {
            cfg,
            current_view: 0,
            last_progress: Instant::now(),
            timeout_emitted: false,
            consecutive_timeouts: 0,
            pending_new_view: None,
        }
    }

    /// Create a timeout pacemaker with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TimeoutPacemakerConfig::default())
    }

    /// Get the current view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Get the current timeout duration (with backoff applied).
    pub fn current_timeout(&self) -> Duration {
        let multiplier = self
            .cfg
            .timeout_multiplier
            .powi(self.consecutive_timeouts as i32);
        let timeout_nanos = (self.cfg.base_timeout.as_nanos() as f64 * multiplier) as u128;
        let timeout = Duration::from_nanos(timeout_nanos.min(u64::MAX as u128) as u64);
        timeout.min(self.cfg.max_timeout)
    }

    /// Compute the timeout duration for a given view (for testing/observability).
    ///
    /// This uses the same formula as `current_timeout()` but for an arbitrary
    /// number of consecutive timeouts.
    pub fn timeout_for_consecutive(&self, consecutive: u32) -> Duration {
        let multiplier = self.cfg.timeout_multiplier.powi(consecutive as i32);
        let timeout_nanos = (self.cfg.base_timeout.as_nanos() as f64 * multiplier) as u128;
        let timeout = Duration::from_nanos(timeout_nanos.min(u64::MAX as u128) as u64);
        timeout.min(self.cfg.max_timeout)
    }

    /// Called when progress is made (proposal received, QC formed, block committed).
    ///
    /// This resets the timeout timer and clears the backoff counter.
    /// Call this when:
    /// - A valid proposal is received for the current view
    /// - A QC is formed for the current view
    /// - A block is committed
    pub fn on_progress(&mut self) {
        self.last_progress = Instant::now();
        self.consecutive_timeouts = 0;
        // Don't reset timeout_emitted here - that's handled by view change
    }

    /// Called when a QC is observed.
    ///
    /// If the QC is for a view >= current_view, this advances the view and
    /// resets state (progress timer, timeout flag).
    pub fn on_qc(&mut self, qc_view: u64) {
        if qc_view >= self.current_view {
            self.advance_to_view(qc_view + 1);
        }
    }

    /// Called when a TimeoutCertificate is formed or received.
    ///
    /// This schedules a view change to the TC's target view.
    /// The actual NewView event is returned on the next `on_tick_with_time()` call.
    pub fn on_timeout_certificate(&mut self, tc_view: u64) {
        if tc_view > self.current_view {
            self.pending_new_view = Some(tc_view);
        }
    }

    /// Advance to a new view.
    ///
    /// This resets the timeout timer and timeout flag for the new view.
    fn advance_to_view(&mut self, new_view: u64) {
        if new_view > self.current_view {
            self.current_view = new_view;
            self.last_progress = Instant::now();
            self.timeout_emitted = false;
            // Note: We don't reset consecutive_timeouts here.
            // That's reset by on_progress() (actual progress, not just view change).
        }
    }

    /// Process a pacemaker tick with the current time.
    ///
    /// Returns a `PacemakerEvent` indicating what action should be taken.
    ///
    /// # Arguments
    ///
    /// - `now`: The current time (typically `Instant::now()`)
    /// - `engine_view`: The current view as known by the consensus engine
    ///
    /// # Returns
    ///
    /// - `PacemakerEvent::NewView { view }` if a TC triggered view change
    /// - `PacemakerEvent::Timeout { view }` if timeout expired without progress
    /// - `PacemakerEvent::None` otherwise
    pub fn on_tick_with_time(&mut self, now: Instant, engine_view: u64) -> PacemakerEvent {
        // Sync with engine view if it's ahead
        if engine_view > self.current_view {
            self.advance_to_view(engine_view);
        }

        // Check for pending new view (from TC)
        if let Some(new_view) = self.pending_new_view.take() {
            if new_view > self.current_view {
                self.advance_to_view(new_view);
                return PacemakerEvent::NewView { view: new_view };
            }
        }

        // Check for timeout
        let elapsed = now.saturating_duration_since(self.last_progress);
        let timeout = self.current_timeout();

        if elapsed >= timeout && !self.timeout_emitted {
            self.timeout_emitted = true;
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            return PacemakerEvent::Timeout {
                view: self.current_view,
            };
        }

        PacemakerEvent::None
    }

    /// Check if we should attempt to propose (leader check is done externally).
    ///
    /// This is a simple check that doesn't involve timeout logic - just whether
    /// we haven't already proposed in this view. The actual leader check should
    /// be done by the caller.
    pub fn should_propose(&self) -> bool {
        // TimeoutPacemaker doesn't track proposals itself.
        // The engine tracks proposed_in_view.
        true
    }

    /// Get the number of consecutive timeouts (for metrics/debugging).
    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }

    /// Check if a timeout has been emitted for the current view.
    pub fn timeout_emitted(&self) -> bool {
        self.timeout_emitted
    }

    /// Get the time since last progress.
    pub fn time_since_progress(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_progress)
    }

    /// Reset state for testing.
    #[cfg(test)]
    pub fn reset_for_test(&mut self) {
        self.current_view = 0;
        self.last_progress = Instant::now();
        self.timeout_emitted = false;
        self.consecutive_timeouts = 0;
        self.pending_new_view = None;
    }
}

#[cfg(test)]
mod timeout_pacemaker_tests {
    use super::*;

    #[test]
    fn timeout_pacemaker_new_starts_at_view_zero() {
        let pm = TimeoutPacemaker::with_defaults();
        assert_eq!(pm.current_view(), 0);
        assert!(!pm.timeout_emitted());
        assert_eq!(pm.consecutive_timeouts(), 0);
    }

    #[test]
    fn timeout_pacemaker_on_progress_resets_backoff() {
        let mut pm = TimeoutPacemaker::with_defaults();
        pm.consecutive_timeouts = 5;
        pm.on_progress();
        assert_eq!(pm.consecutive_timeouts(), 0);
    }

    #[test]
    fn timeout_pacemaker_on_qc_advances_view() {
        let mut pm = TimeoutPacemaker::with_defaults();
        assert_eq!(pm.current_view(), 0);

        pm.on_qc(5);
        assert_eq!(pm.current_view(), 6); // QC for view 5 -> advance to view 6
        assert!(!pm.timeout_emitted()); // Reset on view change
    }

    #[test]
    fn timeout_pacemaker_timeout_triggers_after_duration() {
        let cfg = TimeoutPacemakerConfig {
            base_timeout: Duration::from_millis(100),
            timeout_multiplier: 1.0, // No backoff for simplicity
            max_timeout: Duration::from_secs(10),
        };
        let mut pm = TimeoutPacemaker::new(cfg);

        // Immediately after creation, no timeout
        let now = pm.last_progress;
        let event = pm.on_tick_with_time(now, 0);
        assert_eq!(event, PacemakerEvent::None);

        // After timeout period, timeout should trigger
        let later = now + Duration::from_millis(150);
        let event = pm.on_tick_with_time(later, 0);
        assert_eq!(event, PacemakerEvent::Timeout { view: 0 });
        assert!(pm.timeout_emitted());

        // Subsequent ticks should not trigger another timeout for same view
        let even_later = later + Duration::from_millis(100);
        let event = pm.on_tick_with_time(even_later, 0);
        assert_eq!(event, PacemakerEvent::None);
    }

    #[test]
    fn timeout_pacemaker_exponential_backoff() {
        let cfg = TimeoutPacemakerConfig {
            base_timeout: Duration::from_millis(100),
            timeout_multiplier: 2.0,
            max_timeout: Duration::from_secs(10),
        };
        let pm = TimeoutPacemaker::new(cfg);

        // First timeout: 100ms
        assert_eq!(pm.timeout_for_consecutive(0), Duration::from_millis(100));
        // Second timeout: 200ms
        assert_eq!(pm.timeout_for_consecutive(1), Duration::from_millis(200));
        // Third timeout: 400ms
        assert_eq!(pm.timeout_for_consecutive(2), Duration::from_millis(400));
        // Fourth timeout: 800ms
        assert_eq!(pm.timeout_for_consecutive(3), Duration::from_millis(800));
    }

    #[test]
    fn timeout_pacemaker_backoff_capped_at_max() {
        let cfg = TimeoutPacemakerConfig {
            base_timeout: Duration::from_millis(100),
            timeout_multiplier: 2.0,
            max_timeout: Duration::from_millis(500),
        };
        let pm = TimeoutPacemaker::new(cfg);

        // Should be capped at 500ms
        assert_eq!(pm.timeout_for_consecutive(10), Duration::from_millis(500));
    }

    #[test]
    fn timeout_pacemaker_tc_triggers_new_view() {
        let mut pm = TimeoutPacemaker::with_defaults();
        pm.current_view = 5;

        // Receive TC for view 10
        pm.on_timeout_certificate(10);

        // Next tick should return NewView
        let now = Instant::now();
        let event = pm.on_tick_with_time(now, 5);
        assert_eq!(event, PacemakerEvent::NewView { view: 10 });
        assert_eq!(pm.current_view(), 10);
    }

    #[test]
    fn timeout_pacemaker_tc_for_lower_view_ignored() {
        let mut pm = TimeoutPacemaker::with_defaults();
        pm.current_view = 10;

        // TC for lower view should be ignored
        pm.on_timeout_certificate(5);

        let now = Instant::now();
        let event = pm.on_tick_with_time(now, 10);
        assert_eq!(event, PacemakerEvent::None);
        assert_eq!(pm.current_view(), 10);
    }

    #[test]
    fn timeout_pacemaker_syncs_with_engine_view() {
        let mut pm = TimeoutPacemaker::with_defaults();
        assert_eq!(pm.current_view(), 0);

        // Engine is ahead
        let now = Instant::now();
        let _ = pm.on_tick_with_time(now, 5);

        assert_eq!(pm.current_view(), 5);
    }

    #[test]
    fn timeout_pacemaker_consecutive_timeouts_increment() {
        let cfg = TimeoutPacemakerConfig {
            base_timeout: Duration::from_millis(10),
            timeout_multiplier: 1.0,
            max_timeout: Duration::from_secs(10),
        };
        let mut pm = TimeoutPacemaker::new(cfg);

        // First timeout
        let start = pm.last_progress;
        let t1 = start + Duration::from_millis(20);
        let event = pm.on_tick_with_time(t1, 0);
        assert_eq!(event, PacemakerEvent::Timeout { view: 0 });
        assert_eq!(pm.consecutive_timeouts(), 1);

        // Advance view (simulating TC reception)
        pm.on_timeout_certificate(1);
        let t2 = t1 + Duration::from_millis(1);
        let event = pm.on_tick_with_time(t2, 0);
        assert_eq!(event, PacemakerEvent::NewView { view: 1 });

        // Second timeout in new view (consecutive_timeouts not reset by view change)
        let t3 = t2 + Duration::from_millis(20);
        let event = pm.on_tick_with_time(t3, 1);
        assert_eq!(event, PacemakerEvent::Timeout { view: 1 });
        assert_eq!(pm.consecutive_timeouts(), 2);

        // Progress resets consecutive_timeouts
        pm.on_progress();
        assert_eq!(pm.consecutive_timeouts(), 0);
    }
}
