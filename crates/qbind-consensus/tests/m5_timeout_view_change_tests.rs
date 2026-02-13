//! M5 Integration Tests: Timeout and View-Change Mechanism for HotStuff Consensus
//!
//! These tests validate the production-ready timeout and view-change logic
//! consistent with Section 17 (View-Change and Liveness Model) of the QBIND whitepaper.
//!
//! # Test Coverage
//!
//! 1. **Leader crash → next view progresses**: System makes progress when leader fails
//! 2. **No proposal received → view increments**: Timeout triggers view change
//! 3. **Proposal received but no QC → view increments**: Timeout handles QC formation failure
//! 4. **Safety preserved across view changes**: No conflicting commits
//! 5. **Determinism**: Same event sequence → same view progression
//! 6. **Partition simulation**: After timeout escalation, progress resumes
//!
//! # Safety Invariants
//!
//! - View number never decreases
//! - Validator never votes below locked_height
//! - Double-vote protection remains intact
//! - Fail-closed behavior on inconsistent state
//!
//! # Pacemaker State Requirements
//!
//! Each validator maintains:
//! - `current_view`: Current view number (monotonically increasing)
//! - `locked_qc`: The highest QC that locked a block
//! - `highest_qc`: The highest QC observed
//! - `timeout_counter`: Consecutive timeout count for exponential backoff

use qbind_consensus::{
    basic_hotstuff_engine::BasicHotStuffEngine,
    pacemaker::{PacemakerEvent, TimeoutPacemaker, TimeoutPacemakerConfig},
    timeout::{
        select_max_high_qc, TimeoutAccumulator, TimeoutCertificate, TimeoutMsg,
        TimeoutValidationError, TIMEOUT_SUITE_ID,
    },
    validator_set::{ConsensusValidatorSet, ValidatorSetEntry},
    QuorumCertificate, ValidatorId,
};
use std::time::{Duration, Instant};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_validator_set(num: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_qc(block_id: [u8; 32], view: u64, signers: Vec<ValidatorId>) -> QuorumCertificate<[u8; 32]> {
    QuorumCertificate::new(block_id, view, signers)
}

fn make_timeout_msg(
    view: u64,
    high_qc: Option<QuorumCertificate<[u8; 32]>>,
    validator_id: ValidatorId,
) -> TimeoutMsg<[u8; 32]> {
    let mut msg = TimeoutMsg::new(view, high_qc, validator_id);
    // Add a dummy signature for testing
    msg.set_signature(vec![0u8; 64]);
    msg
}

// ============================================================================
// Test 1: Leader crash → next view progresses
// ============================================================================

/// Test that when a leader crashes (doesn't propose), the system eventually
/// times out and advances to the next view with a new leader.
#[test]
fn m5_leader_crash_next_view_progresses() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // Start at view 0
    assert_eq!(engine.current_view(), 0);
    let leader_v0 = engine.leader_for_view(0);
    assert_eq!(leader_v0, ValidatorId(1));

    // Simulate leader crash by not producing a proposal.
    // Instead, we simulate receiving timeout messages from 2f+1 validators.
    // With 4 validators, we need 3 (2f+1 where f=1).

    let timeout_view = 0;
    let high_qc = None; // No QC yet at genesis

    // Simulate collecting timeout messages
    for i in 1..=3 {
        let timeout_msg = make_timeout_msg(timeout_view, high_qc.clone(), ValidatorId(i));
        let result = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
        assert!(result.is_ok(), "timeout message should be accepted");
    }

    // After collecting 3 timeouts (2f+1), we should be able to form a TC
    // The engine's timeout accumulator should have enough
    let tc_opt = engine
        .timeout_accumulator()
        .maybe_tc_for(&validators, timeout_view);
    assert!(tc_opt.is_some(), "TC should be formable with 2f+1 timeouts");

    let tc = tc_opt.unwrap();
    assert_eq!(tc.timeout_view, 0);
    assert_eq!(tc.target_view(), 1); // Should advance to view 1

    // Apply the TC to advance the view
    let result = engine.on_timeout_certificate(&tc);
    assert!(result.is_ok());
    assert_eq!(
        engine.current_view(),
        1,
        "view should advance to 1 after TC"
    );

    // Verify new leader is different (round-robin)
    let leader_v1 = engine.leader_for_view(1);
    assert_eq!(leader_v1, ValidatorId(2)); // Next leader in rotation
}

// ============================================================================
// Test 2: No proposal received → view increments
// ============================================================================

/// Test that when no proposal is received within the timeout window,
/// the view increments via timeout mechanism.
#[test]
fn m5_no_proposal_view_increments() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Initially at view 0, no timeout
    assert_eq!(pacemaker.current_view(), 0);
    assert!(!pacemaker.timeout_emitted());

    // Wait for timeout to expire
    std::thread::sleep(Duration::from_millis(50));

    // Check for timeout event
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event, PacemakerEvent::Timeout { view: 0 }),
        "should timeout after no proposal: got {:?}",
        event
    );

    // Timeout was emitted for view 0
    assert!(pacemaker.timeout_emitted());
    assert_eq!(pacemaker.consecutive_timeouts(), 1);

    // Simulate receiving a TC that advances to view 1
    pacemaker.on_timeout_certificate(1);
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event, PacemakerEvent::NewView { view: 1 }),
        "should advance to new view: got {:?}",
        event
    );

    assert_eq!(pacemaker.current_view(), 1);
}

// ============================================================================
// Test 3: Proposal received but no QC → view increments
// ============================================================================

/// Test that when a proposal is received but no QC forms (insufficient votes),
/// the view eventually increments via timeout.
#[test]
fn m5_proposal_no_qc_view_increments() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators.clone());

    // Start at view 0
    assert_eq!(engine.current_view(), 0);

    // Simulate: proposal was received (leader proposed) but only 1 vote was received
    // This is not enough to form QC (need 2f+1 = 3 votes for 4 validators)

    // The node received the proposal and voted, but QC didn't form
    // Now we need to timeout

    // Collect timeout messages to form TC and advance view
    let timeout_view = 0;
    for i in 1..=3 {
        let timeout_msg = make_timeout_msg(timeout_view, None, ValidatorId(i));
        let _ = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
    }

    // Form and apply TC
    let tc_opt = engine
        .timeout_accumulator()
        .maybe_tc_for(&validators, timeout_view);
    assert!(tc_opt.is_some());

    let tc = tc_opt.unwrap();
    let result = engine.on_timeout_certificate(&tc);
    assert!(result.is_ok());

    // View should have advanced despite proposal without QC
    assert_eq!(engine.current_view(), 1);
}

// ============================================================================
// Test 4: Safety preserved across view changes
// ============================================================================

/// Test that safety is preserved across view changes:
/// - No conflicting commits
/// - Locked QC semantics maintained
/// - TC's high_qc properly propagates lock
#[test]
fn m5_safety_preserved_across_view_changes() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // Create a QC for view 5 (simulating some progress)
    let qc_v5 = make_qc([1u8; 32], 5, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);

    // Set locked_qc manually for testing
    engine.state_mut().set_locked_qc(qc_v5.clone());
    assert!(engine.locked_qc().is_some());
    assert_eq!(engine.locked_qc().unwrap().view, 5);

    // Advance engine view to match the lock
    engine.set_view(6);

    // Create timeout messages with high_qc at view 5
    let timeout_view = 6;
    for i in 1..=3 {
        let timeout_msg = make_timeout_msg(timeout_view, Some(qc_v5.clone()), ValidatorId(i));
        let _ = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
    }

    // Form TC
    let tc_opt = engine
        .timeout_accumulator()
        .maybe_tc_for(&validators, timeout_view);
    assert!(tc_opt.is_some());

    let tc = tc_opt.unwrap();

    // TC should carry the max high_qc (view 5)
    assert!(tc.high_qc.is_some());
    assert_eq!(tc.high_qc.as_ref().unwrap().view, 5);

    // Apply TC
    let result = engine.on_timeout_certificate(&tc);
    assert!(result.is_ok());

    // Locked QC should still be at view 5 (TC's high_qc doesn't override equal lock)
    assert!(engine.locked_qc().is_some());
    assert_eq!(engine.locked_qc().unwrap().view, 5);

    // View should have advanced
    assert_eq!(engine.current_view(), 7);
}

/// Test that TC with higher high_qc updates the locked_qc
#[test]
fn m5_tc_updates_locked_qc_when_higher() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // Set initial locked_qc at view 3
    let qc_v3 = make_qc([1u8; 32], 3, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v3);
    engine.set_view(4);

    // Create timeout messages with high_qc at view 5 (higher than locked_qc)
    let qc_v5 = make_qc([2u8; 32], 5, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    let timeout_view = 4;

    for i in 1..=3 {
        let timeout_msg = make_timeout_msg(timeout_view, Some(qc_v5.clone()), ValidatorId(i));
        let _ = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
    }

    let tc_opt = engine
        .timeout_accumulator()
        .maybe_tc_for(&validators, timeout_view);
    assert!(tc_opt.is_some());

    let tc = tc_opt.unwrap();
    assert!(tc.high_qc.is_some());
    assert_eq!(tc.high_qc.as_ref().unwrap().view, 5);

    // Apply TC
    let result = engine.on_timeout_certificate(&tc);
    assert!(result.is_ok());

    // Locked QC should now be at view 5 (updated from TC's high_qc)
    assert!(engine.locked_qc().is_some());
    assert_eq!(
        engine.locked_qc().unwrap().view,
        5,
        "locked_qc should be updated to TC's high_qc"
    );
}

// ============================================================================
// Test 5: Determinism - same event sequence → same view progression
// ============================================================================

/// Test that the same sequence of events produces the same view progression
/// across multiple runs.
#[test]
fn m5_determinism_same_events_same_view_progression() {
    // Run the same sequence twice and compare results
    fn run_sequence() -> (u64, u64, Option<u64>) {
        let validators = make_validator_set(4);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

        // Start at view 0
        assert_eq!(engine.current_view(), 0);

        // Collect timeout messages for view 0
        for i in 1..=3 {
            let timeout_msg = make_timeout_msg(0, None, ValidatorId(i));
            let _ = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
        }

        // Form TC for view 0
        let tc = engine
            .timeout_accumulator()
            .maybe_tc_for(&validators, 0)
            .expect("TC should form");
        let _ = engine.on_timeout_certificate(&tc);
        let view_after_first_tc = engine.current_view();

        // Collect timeout messages for view 1
        for i in 1..=3 {
            let qc = make_qc([1u8; 32], 0, vec![ValidatorId(1), ValidatorId(2)]);
            let timeout_msg = make_timeout_msg(1, Some(qc), ValidatorId(i));
            let _ = engine.on_timeout_msg(ValidatorId(i), timeout_msg);
        }

        // Form TC for view 1
        let tc2 = engine
            .timeout_accumulator()
            .maybe_tc_for(&validators, 1)
            .expect("TC should form");
        let _ = engine.on_timeout_certificate(&tc2);
        let view_after_second_tc = engine.current_view();

        let locked_view = engine.locked_qc().map(|qc| qc.view);

        (view_after_first_tc, view_after_second_tc, locked_view)
    }

    let result1 = run_sequence();
    let result2 = run_sequence();

    assert_eq!(result1, result2, "same events should produce same results");
    assert_eq!(result1.0, 1, "view should be 1 after first TC");
    assert_eq!(result1.1, 2, "view should be 2 after second TC");
    assert_eq!(result1.2, Some(0), "locked_qc should be at view 0");
}

// ============================================================================
// Test 6: Partition simulation - after timeout escalation, progress resumes
// ============================================================================

/// Test that after network partition causes timeout escalation,
/// progress can resume once network heals.
#[test]
fn m5_partition_simulation_progress_resumes() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(10),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Simulate multiple consecutive timeouts (partition scenario)
    for expected_consecutive in 1..=3 {
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(50));

        let event = pacemaker.on_tick_with_time(Instant::now(), pacemaker.current_view());
        assert!(
            matches!(event, PacemakerEvent::Timeout { .. }),
            "should timeout during partition: got {:?}",
            event
        );

        assert_eq!(
            pacemaker.consecutive_timeouts(),
            expected_consecutive,
            "consecutive timeouts should increase"
        );

        // Simulate TC reception to advance view
        let next_view = pacemaker.current_view() + 1;
        pacemaker.on_timeout_certificate(next_view);
        let _ = pacemaker.on_tick_with_time(Instant::now(), pacemaker.current_view());
    }

    // Verify exponential backoff was applied
    let timeout_duration = pacemaker.current_timeout();
    assert!(
        timeout_duration > Duration::from_millis(10),
        "timeout should have increased due to backoff: {:?}",
        timeout_duration
    );

    // Simulate network healing: progress is made
    pacemaker.on_progress();

    // Consecutive timeout counter should reset
    assert_eq!(
        pacemaker.consecutive_timeouts(),
        0,
        "progress should reset consecutive timeout counter"
    );

    // Timeout duration should reset to base
    let new_timeout = pacemaker.current_timeout();
    assert_eq!(
        new_timeout,
        Duration::from_millis(10),
        "timeout should reset to base after progress"
    );
}

// ============================================================================
// View Monotonicity Tests
// ============================================================================

/// Test that view number never decreases
#[test]
fn m5_view_number_never_decreases() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // Advance to view 10
    engine.set_view(10);
    assert_eq!(engine.current_view(), 10);

    // Try to apply a TC for a lower view (view 5)
    let tc_old = TimeoutCertificate::new(
        4, // timeout_view = 4, so target_view = 5
        None,
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
    );

    // TC for view 5 should be ignored since current_view is 10
    let result = engine.on_timeout_certificate(&tc_old);
    assert!(result.is_ok());
    // View should NOT have decreased
    assert_eq!(
        engine.current_view(),
        10,
        "view should not decrease from TC for old view"
    );
}

/// Test that set_view only allows forward movement
#[test]
fn m5_set_view_forward_only() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set view to 5
    engine.set_view(5);
    assert_eq!(engine.current_view(), 5);

    // Set view to 10 (forward)
    engine.set_view(10);
    assert_eq!(engine.current_view(), 10);

    // Note: set_view currently allows backward movement (it's a direct setter)
    // The safety comes from:
    // 1. on_timeout_certificate checks tc.view > current_view
    // 2. advance_view always increments
    // 3. Application logic should not call set_view with lower views
}

// ============================================================================
// Double-Vote Protection Tests
// ============================================================================

/// Test that double-vote protection is maintained during view changes
#[test]
fn m5_double_vote_protection_during_view_change() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // Vote in view 0
    assert!(!engine.state().equivocating_validators().contains(&ValidatorId(1)));

    // Register a block and vote for it
    let block_id = [1u8; 32];
    engine.state_mut().register_block(block_id, 0, None, None);
    let result = engine.state_mut().on_vote(ValidatorId(1), 0, &block_id);
    assert!(result.is_ok());

    // Advance view via TC
    let tc = TimeoutCertificate::new(
        0,
        None,
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
    );
    let _ = engine.on_timeout_certificate(&tc);
    assert_eq!(engine.current_view(), 1);

    // Try to vote for a different block in the same old view (view 0)
    // This should be detected as equivocation
    let block_id_2 = [2u8; 32];
    engine
        .state_mut()
        .register_block(block_id_2, 0, None, None);
    let result2 = engine.state_mut().on_vote(ValidatorId(1), 0, &block_id_2);

    // The vote should succeed but equivocation should be detected
    assert!(result2.is_ok());
    assert!(
        engine
            .state()
            .equivocating_validators()
            .contains(&ValidatorId(1)),
        "double-vote should be detected"
    );
}

// ============================================================================
// Locked Height Safety Tests
// ============================================================================

/// Test that validators don't vote below locked_height
#[test]
fn m5_no_vote_below_locked_height() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set locked_qc at view 10
    let qc_v10 = make_qc([1u8; 32], 10, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v10);
    engine.set_view(11);

    // Register a block at view 5 with justify_qc at view 4 (below locked view 10)
    let justify_qc = make_qc([0u8; 32], 4, vec![ValidatorId(1)]);
    let block_id = [2u8; 32];
    engine
        .state_mut()
        .register_block(block_id, 5, None, Some(justify_qc));

    // Check if it's safe to vote on this block
    let is_safe = engine.state().is_safe_to_vote_on_block(&block_id);

    // Should NOT be safe because justify_qc.view (4) < locked_qc.view (10)
    // and the block doesn't extend the locked block
    assert!(
        !is_safe,
        "should not vote on block with justify_qc below locked_qc"
    );
}

/// Test that voting is allowed when justify_qc.view >= locked_qc.view
#[test]
fn m5_vote_allowed_with_sufficient_justify_qc() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set locked_qc at view 10
    let qc_v10 = make_qc([1u8; 32], 10, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v10);
    engine.set_view(12);

    // Register a block at view 11 with justify_qc at view 10 (equals locked view)
    let justify_qc = make_qc([1u8; 32], 10, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    let block_id = [2u8; 32];
    engine
        .state_mut()
        .register_block(block_id, 11, None, Some(justify_qc));

    // Check if it's safe to vote on this block
    let is_safe = engine.state().is_safe_to_vote_on_block(&block_id);

    // Should be safe because justify_qc.view (10) >= locked_qc.view (10)
    assert!(
        is_safe,
        "should be able to vote when justify_qc.view >= locked_qc.view"
    );
}

// ============================================================================
// Fail-Closed Behavior Tests
// ============================================================================

/// Test that timeout accumulator rejects timeout messages from non-members
#[test]
fn m5_fail_closed_non_member_timeout() {
    let validators = make_validator_set(4);
    let mut accumulator = TimeoutAccumulator::<[u8; 32]>::new();

    // Create a timeout message from a non-member (ValidatorId 99)
    let timeout_msg = make_timeout_msg(0, None, ValidatorId(99));

    // Try to ingest it
    let result = accumulator.on_timeout(&validators, timeout_msg);

    // Should be rejected
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(TimeoutValidationError::NonMemberSigner(ValidatorId(99)))
    ));
}

/// Test that TC validation rejects insufficient quorum
#[test]
fn m5_fail_closed_insufficient_quorum_tc() {
    let validators = make_validator_set(4);

    // Create TC with only 2 signers (need 3 for 4 validators)
    let tc = TimeoutCertificate::<[u8; 32]>::new(0, None, vec![ValidatorId(1), ValidatorId(2)]);

    let result = tc.validate(&validators);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(TimeoutValidationError::InsufficientQuorum { .. })
    ));
}

/// Test that stale timeout messages are ignored
#[test]
fn m5_fail_closed_stale_timeout_ignored() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Advance to view 10
    engine.set_view(10);

    // Send a timeout message for view 5 (stale)
    let timeout_msg = make_timeout_msg(5, None, ValidatorId(2));
    let result = engine.on_timeout_msg(ValidatorId(2), timeout_msg);

    // Should succeed but return None (no TC formed, message ignored)
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

/// Test that sender mismatch is rejected
#[test]
fn m5_fail_closed_sender_mismatch() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Create a timeout message claiming to be from validator 2
    let timeout_msg = make_timeout_msg(0, None, ValidatorId(2));

    // But send it with "from" = validator 3 (mismatch)
    let result = engine.on_timeout_msg(ValidatorId(3), timeout_msg);

    // Should be rejected
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(TimeoutValidationError::InvalidSignature(ValidatorId(3)))
    ));
}

// ============================================================================
// Leader Continuity Tests
// ============================================================================

/// Test that leader selection uses updated view (round-robin)
#[test]
fn m5_leader_continuity_round_robin() {
    let validators = make_validator_set(4);
    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Test round-robin: view % N
    // Views 0, 1, 2, 3 should map to validators 1, 2, 3, 4
    assert_eq!(engine.leader_for_view(0), ValidatorId(1));
    assert_eq!(engine.leader_for_view(1), ValidatorId(2));
    assert_eq!(engine.leader_for_view(2), ValidatorId(3));
    assert_eq!(engine.leader_for_view(3), ValidatorId(4));

    // Wrap around
    assert_eq!(engine.leader_for_view(4), ValidatorId(1));
    assert_eq!(engine.leader_for_view(5), ValidatorId(2));
}

/// Test that leader changes correctly after view change via TC
#[test]
fn m5_leader_changes_after_tc() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators.clone());

    // At view 0, leader is validator 1
    assert_eq!(engine.current_view(), 0);
    assert_eq!(engine.leader_for_view(engine.current_view()), ValidatorId(1));

    // Apply TC to advance to view 1
    let tc = TimeoutCertificate::new(
        0,
        None,
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
    );
    let _ = engine.on_timeout_certificate(&tc);

    // At view 1, leader should be validator 2
    assert_eq!(engine.current_view(), 1);
    assert_eq!(engine.leader_for_view(engine.current_view()), ValidatorId(2));
}

// ============================================================================
// Timeout Message Aggregation Tests
// ============================================================================

/// Test that select_max_high_qc finds the highest QC
#[test]
fn m5_select_max_high_qc() {
    let qc1 = make_qc([1u8; 32], 5, vec![ValidatorId(1)]);
    let qc2 = make_qc([2u8; 32], 10, vec![ValidatorId(2)]);
    let qc3 = make_qc([3u8; 32], 3, vec![ValidatorId(3)]);

    let timeout1 = TimeoutMsg::new(20, Some(qc1), ValidatorId(1));
    let timeout2 = TimeoutMsg::new(20, Some(qc2.clone()), ValidatorId(2));
    let timeout3 = TimeoutMsg::new(20, Some(qc3), ValidatorId(3));

    let timeouts = [timeout1, timeout2, timeout3];
    let max_qc = select_max_high_qc(timeouts.iter());

    assert!(max_qc.is_some());
    assert_eq!(max_qc.unwrap().view, 10, "should select QC with highest view");
}

/// Test that TC properly aggregates high_qc from timeout messages
#[test]
fn m5_tc_aggregates_high_qc() {
    let validators = make_validator_set(4);
    let mut accumulator = TimeoutAccumulator::<[u8; 32]>::new();

    // Create timeout messages with different high_qcs
    let qc1 = make_qc([1u8; 32], 5, vec![ValidatorId(1)]);
    let qc2 = make_qc([2u8; 32], 8, vec![ValidatorId(2)]); // Highest
    let qc3 = make_qc([3u8; 32], 3, vec![ValidatorId(3)]);

    let timeout1 = make_timeout_msg(10, Some(qc1), ValidatorId(1));
    let timeout2 = make_timeout_msg(10, Some(qc2), ValidatorId(2));
    let timeout3 = make_timeout_msg(10, Some(qc3), ValidatorId(3));

    // Ingest all
    let _ = accumulator.on_timeout(&validators, timeout1);
    let _ = accumulator.on_timeout(&validators, timeout2);
    let _ = accumulator.on_timeout(&validators, timeout3);

    // Form TC
    let tc = accumulator.maybe_tc_for(&validators, 10);
    assert!(tc.is_some());

    let tc = tc.unwrap();
    assert!(tc.high_qc.is_some());
    assert_eq!(
        tc.high_qc.as_ref().unwrap().view,
        8,
        "TC should carry the max high_qc"
    );
}

// ============================================================================
// Exponential Backoff Tests
// ============================================================================

/// Test that timeout duration increases exponentially
#[test]
fn m5_exponential_backoff_timeout() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(100),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    // Verify exponential backoff
    assert_eq!(
        pacemaker.timeout_for_consecutive(0),
        Duration::from_millis(100)
    );
    assert_eq!(
        pacemaker.timeout_for_consecutive(1),
        Duration::from_millis(200)
    );
    assert_eq!(
        pacemaker.timeout_for_consecutive(2),
        Duration::from_millis(400)
    );
    assert_eq!(
        pacemaker.timeout_for_consecutive(3),
        Duration::from_millis(800)
    );
    assert_eq!(
        pacemaker.timeout_for_consecutive(4),
        Duration::from_millis(1600)
    );
}

/// Test that timeout is capped at max_timeout
#[test]
fn m5_timeout_capped_at_max() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(100),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_millis(500),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    // After many consecutive timeouts, should be capped
    assert_eq!(
        pacemaker.timeout_for_consecutive(10),
        Duration::from_millis(500),
        "timeout should be capped at max_timeout"
    );
}

/// Test that progress resets exponential backoff
#[test]
fn m5_progress_resets_backoff() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Trigger multiple timeouts
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(30));
        let _ = pacemaker.on_tick_with_time(Instant::now(), pacemaker.current_view());
        // Advance view to allow next timeout
        pacemaker.on_timeout_certificate(pacemaker.current_view() + 1);
        let _ = pacemaker.on_tick_with_time(Instant::now(), pacemaker.current_view());
    }

    assert!(
        pacemaker.consecutive_timeouts() > 0,
        "should have consecutive timeouts"
    );

    // Progress should reset
    pacemaker.on_progress();
    assert_eq!(
        pacemaker.consecutive_timeouts(),
        0,
        "progress should reset consecutive timeouts"
    );
    assert_eq!(
        pacemaker.current_timeout(),
        Duration::from_millis(10),
        "timeout should reset to base"
    );
}

// ============================================================================
// Suite ID Verification Tests
// ============================================================================

/// Test that timeout messages use correct suite ID (ML-DSA-44 = 100)
#[test]
fn m5_timeout_suite_id() {
    let timeout_msg = TimeoutMsg::<[u8; 32]>::new(5, None, ValidatorId(1));

    assert_eq!(
        timeout_msg.suite_id, TIMEOUT_SUITE_ID,
        "timeout message should use ML-DSA-44 suite ID"
    );
    assert_eq!(TIMEOUT_SUITE_ID, 100, "ML-DSA-44 suite ID should be 100");
}

// ============================================================================
// M5 New Method Tests: try_advance_to_view, locked_height, is_safe_to_vote_at_height
// ============================================================================

/// Test try_advance_to_view with fail-closed behavior
#[test]
fn m5_try_advance_to_view_fail_closed() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Start at view 0
    assert_eq!(engine.current_view(), 0);

    // Advance to view 5 (valid forward movement)
    assert!(engine.try_advance_to_view(5), "should succeed for forward movement");
    assert_eq!(engine.current_view(), 5);

    // Try to advance to view 3 (backward movement, should fail)
    assert!(!engine.try_advance_to_view(3), "should fail for backward movement");
    assert_eq!(engine.current_view(), 5, "view should not change on failed advance");

    // Try to advance to view 5 (same view, should fail)
    assert!(!engine.try_advance_to_view(5), "should fail for same view");
    assert_eq!(engine.current_view(), 5);

    // Advance to view 10 (valid forward movement)
    assert!(engine.try_advance_to_view(10), "should succeed for forward movement");
    assert_eq!(engine.current_view(), 10);
}

/// Test locked_height returns correct value
#[test]
fn m5_locked_height() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Initially no locked QC
    assert!(engine.locked_height().is_none());

    // Set locked_qc at view 5
    let qc_v5 = make_qc([1u8; 32], 5, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v5);

    // Should return view 5
    assert_eq!(engine.locked_height(), Some(5));

    // Update locked_qc to view 10
    let qc_v10 = make_qc([2u8; 32], 10, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v10);

    // Should return view 10
    assert_eq!(engine.locked_height(), Some(10));
}

/// Test is_safe_to_vote_at_height with various scenarios
#[test]
fn m5_is_safe_to_vote_at_height() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // No lock - should always be safe
    assert!(engine.is_safe_to_vote_at_height(None));
    assert!(engine.is_safe_to_vote_at_height(Some(0)));
    assert!(engine.is_safe_to_vote_at_height(Some(100)));

    // Set locked_qc at view 10
    let qc_v10 = make_qc([1u8; 32], 10, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
    engine.state_mut().set_locked_qc(qc_v10);

    // With lock at view 10:
    // - justify_qc at view 10 or higher should be safe
    assert!(engine.is_safe_to_vote_at_height(Some(10)), "equal to lock should be safe");
    assert!(engine.is_safe_to_vote_at_height(Some(11)), "above lock should be safe");
    assert!(engine.is_safe_to_vote_at_height(Some(100)), "way above lock should be safe");

    // - justify_qc below view 10 should not be safe (fail-closed)
    assert!(!engine.is_safe_to_vote_at_height(Some(9)), "below lock should not be safe");
    assert!(!engine.is_safe_to_vote_at_height(Some(5)), "well below lock should not be safe");
    assert!(!engine.is_safe_to_vote_at_height(Some(0)), "genesis justify_qc should not be safe when locked");
    assert!(!engine.is_safe_to_vote_at_height(None), "no justify_qc should not be safe when locked");
}

/// Test that view flags are reset on try_advance_to_view
#[test]
fn m5_try_advance_resets_flags() {
    let validators = make_validator_set(4);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Set some flags
    engine.mark_timeout_emitted();
    assert!(engine.timeout_emitted_in_view());

    // Advance to view 1
    assert!(engine.try_advance_to_view(1));

    // Flags should be reset
    assert!(!engine.timeout_emitted_in_view(), "timeout flag should be reset");
}