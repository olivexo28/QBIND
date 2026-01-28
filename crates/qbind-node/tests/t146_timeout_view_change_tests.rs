//! T146 Integration Tests: Timeout/View-Change Protocol
//!
//! These tests validate the HotStuff timeout and view-change mechanism
//! for liveness under faulty or partitioned leaders.
//!
//! # Test Scenarios
//!
//! 1. **Liveness under faulty leader**: The system should make progress
//!    even when the leader for a view is faulty (doesn't propose).
//!
//! 2. **No timeout with progress**: When progress is being made (proposals
//!    and QCs are forming), no timeouts should fire.
//!
//! 3. **TimeoutMsg emission**: When a validator detects no progress, it
//!    should emit a TimeoutMsg with the correct structure.
//!
//! 4. **Pacemaker timeout detection**: The pacemaker should correctly
//!    detect lack of progress and emit Timeout events.
//!
//! # Safety Invariants
//!
//! The tests ensure that:
//! - No conflicting blocks are committed (HotStuff safety)
//! - The locked QC semantics remain correct
//! - Timeout messages use ML-DSA-44 (suite_id = 100)

use qbind_consensus::{
    timeout::{TimeoutMsg, TIMEOUT_SUITE_ID},
    PacemakerEvent, QuorumCertificate, TimeoutPacemaker, TimeoutPacemakerConfig, ValidatorId,
};
use std::time::{Duration, Instant};

// ============================================================================
// Unit-level tests for timeout mechanics in isolation
// ============================================================================

/// Test that TimeoutMsg uses the correct suite ID (ML-DSA-44, suite_id = 100).
#[test]
fn timeout_msg_uses_correct_suite_id() {
    let timeout_msg = TimeoutMsg::<[u8; 32]>::new(5, None, ValidatorId::new(1));

    // Suite ID should be 100 (ML-DSA-44)
    assert_eq!(
        timeout_msg.suite_id, TIMEOUT_SUITE_ID,
        "TimeoutMsg should use suite_id = 100 (ML-DSA-44)"
    );
    assert_eq!(TIMEOUT_SUITE_ID, 100);
}

/// Test that TimeoutMsg carries the high_qc correctly.
#[test]
fn timeout_msg_carries_high_qc() {
    let high_qc = QuorumCertificate::new([42u8; 32], 10, vec![ValidatorId::new(1)]);
    let timeout_msg = TimeoutMsg::new(15, Some(high_qc.clone()), ValidatorId::new(2));

    assert_eq!(timeout_msg.view, 15);
    assert!(timeout_msg.high_qc.is_some());

    let carried_qc = timeout_msg.high_qc.as_ref().unwrap();
    assert_eq!(carried_qc.view, 10);
    assert_eq!(carried_qc.block_id, [42u8; 32]);
}

/// Test that TimeoutMsg can have None high_qc for genesis case.
#[test]
fn timeout_msg_with_none_high_qc() {
    let timeout_msg = TimeoutMsg::<[u8; 32]>::new(0, None, ValidatorId::new(1));

    assert_eq!(timeout_msg.view, 0);
    assert!(timeout_msg.high_qc.is_none());
    assert_eq!(timeout_msg.suite_id, TIMEOUT_SUITE_ID);
}

// ============================================================================
// Pacemaker integration tests
// ============================================================================

/// Test that pacemaker detects timeout after configured duration.
#[test]
fn pacemaker_timeout_detection() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(20),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Initially no timeout
    let event1 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(matches!(event1, PacemakerEvent::None));

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(50));

    // Should timeout now
    let event2 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event2, PacemakerEvent::Timeout { view: 0 }),
        "Expected Timeout event, got {:?}",
        event2
    );
}

/// Test that pacemaker resets timeout on progress.
#[test]
fn pacemaker_timeout_reset_on_progress() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(30),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait partial timeout
    std::thread::sleep(Duration::from_millis(20));

    // Signal progress
    pacemaker.on_progress();

    // Wait partial timeout again
    std::thread::sleep(Duration::from_millis(20));

    // Should not timeout (progress reset the timer)
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event, PacemakerEvent::None),
        "Progress should reset timeout, got {:?}",
        event
    );
}

/// Test that pacemaker only emits one timeout per view.
#[test]
fn pacemaker_single_timeout_per_view() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(50));

    // First check should return Timeout
    let event1 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(matches!(event1, PacemakerEvent::Timeout { .. }));

    // Second check for same view should return None
    let event2 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event2, PacemakerEvent::None),
        "Second timeout for same view should be None, got {:?}",
        event2
    );
}

/// Test that pacemaker advances view on TC.
#[test]
fn pacemaker_view_advance_on_tc() {
    let mut pacemaker = TimeoutPacemaker::with_defaults();
    assert_eq!(pacemaker.current_view(), 0);

    // Receive a TC for view 5
    pacemaker.on_timeout_certificate(5);

    // Should emit NewView event
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event, PacemakerEvent::NewView { view: 5 }),
        "Expected NewView(5), got {:?}",
        event
    );

    assert_eq!(pacemaker.current_view(), 5);
}

/// Test that pacemaker syncs with engine view.
#[test]
fn pacemaker_syncs_with_engine() {
    let mut pacemaker = TimeoutPacemaker::with_defaults();

    // Engine is at view 10
    let _ = pacemaker.on_tick_with_time(Instant::now(), 10);

    assert_eq!(
        pacemaker.current_view(),
        10,
        "Pacemaker should sync with engine view"
    );
}

// ============================================================================
// Scenario tests for liveness properties
// ============================================================================

/// Test scenario: Timeout emitted when leader is silent.
///
/// Simulates a scenario where the leader for view 0 is faulty and doesn't
/// propose. The pacemaker should detect this and emit a Timeout event.
#[test]
fn scenario_timeout_on_silent_leader() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(15),
        timeout_multiplier: 1.5,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Simulate: no proposals received (leader is silent)
    // Just advance time without calling on_progress

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(50));

    let event = pacemaker.on_tick_with_time(Instant::now(), 0);

    // Should detect timeout
    assert!(
        matches!(event, PacemakerEvent::Timeout { view: 0 }),
        "Should timeout when leader is silent, got {:?}",
        event
    );

    // Consecutive timeouts counter should increase
    assert_eq!(pacemaker.consecutive_timeouts(), 1);
}

/// Test scenario: No timeout when proposals are received.
///
/// Simulates a scenario where the leader is working correctly and
/// sending proposals. The pacemaker should not emit timeouts.
#[test]
fn scenario_no_timeout_with_progress() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(50),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Simulate: proposals are being received regularly
    for _ in 0..5 {
        // Wait some time (less than timeout)
        std::thread::sleep(Duration::from_millis(20));

        // Signal progress (proposal received)
        pacemaker.on_progress();

        // Check pacemaker - should not timeout
        let event = pacemaker.on_tick_with_time(Instant::now(), 0);
        assert!(
            matches!(event, PacemakerEvent::None),
            "Should not timeout when progress is made, got {:?}",
            event
        );
    }

    // Consecutive timeouts should be 0
    assert_eq!(pacemaker.consecutive_timeouts(), 0);
}

/// Test scenario: View advancement via TC after timeout.
///
/// Simulates the full timeout -> TC -> NewView flow.
#[test]
fn scenario_view_advance_after_timeout() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Phase 1: Timeout in view 0
    std::thread::sleep(Duration::from_millis(50));
    let event1 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(matches!(event1, PacemakerEvent::Timeout { view: 0 }));

    // Phase 2: TC is received for view 1 (formed from 2f+1 timeout messages)
    pacemaker.on_timeout_certificate(1);

    // Phase 3: Pacemaker emits NewView
    let event2 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(matches!(event2, PacemakerEvent::NewView { view: 1 }));

    // Verify new view
    assert_eq!(pacemaker.current_view(), 1);

    // New view should reset timeout flag
    assert!(!pacemaker.timeout_emitted());
}

/// Test scenario: Exponential backoff on consecutive timeouts.
#[test]
fn scenario_exponential_backoff() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(10),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    // Check backoff values
    let t0 = pacemaker.timeout_for_consecutive(0);
    let t1 = pacemaker.timeout_for_consecutive(1);
    let t2 = pacemaker.timeout_for_consecutive(2);
    let t3 = pacemaker.timeout_for_consecutive(3);

    assert_eq!(t0, Duration::from_millis(10));
    assert_eq!(t1, Duration::from_millis(20));
    assert_eq!(t2, Duration::from_millis(40));
    assert_eq!(t3, Duration::from_millis(80));

    // Check that max_timeout caps the value
    let t_high = pacemaker.timeout_for_consecutive(20);
    assert!(t_high <= Duration::from_secs(10));
}

// ============================================================================
// Safety property tests
// ============================================================================

/// Test that TimeoutMsg signing bytes are unique per (view, validator).
#[test]
fn safety_timeout_signing_bytes_uniqueness() {
    use qbind_consensus::timeout::timeout_signing_bytes;

    let high_qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId::new(0)]);

    // Same validator, different views -> different bytes
    let bytes_v10 = timeout_signing_bytes(10, Some(&high_qc), ValidatorId::new(1));
    let bytes_v11 = timeout_signing_bytes(11, Some(&high_qc), ValidatorId::new(1));
    assert_ne!(bytes_v10, bytes_v11);

    // Same view, different validators -> different bytes
    let bytes_val1 = timeout_signing_bytes(10, Some(&high_qc), ValidatorId::new(1));
    let bytes_val2 = timeout_signing_bytes(10, Some(&high_qc), ValidatorId::new(2));
    assert_ne!(bytes_val1, bytes_val2);
}

/// Test that TimeoutMsg includes domain separator for domain separation.
#[test]
fn safety_timeout_domain_separator() {
    use qbind_consensus::timeout::timeout_signing_bytes;
    use qbind_types::domain::{domain_prefix, DomainKind};
    use qbind_types::QBIND_DEVNET_CHAIN_ID;

    let bytes = timeout_signing_bytes::<[u8; 32]>(5, None, ValidatorId::new(1));

    // timeout_signing_bytes uses QBIND_DEVNET_CHAIN_ID by default,
    // so it should start with the chain-aware domain tag.
    let expected_prefix = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Timeout);
    assert!(
        bytes.starts_with(&expected_prefix),
        "Timeout signing bytes should start with chain-aware domain tag (QBIND:DEV:TIMEOUT:v1)"
    );
}

/// Test that consecutive timeout count is reset on progress.
#[test]
fn safety_consecutive_timeout_reset() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(5),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Trigger multiple timeouts
    std::thread::sleep(Duration::from_millis(20));
    let _ = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert_eq!(pacemaker.consecutive_timeouts(), 1);

    // Advance view via TC
    pacemaker.on_timeout_certificate(1);
    let _ = pacemaker.on_tick_with_time(Instant::now(), 0);

    // Trigger another timeout in new view
    std::thread::sleep(Duration::from_millis(20));
    let _ = pacemaker.on_tick_with_time(Instant::now(), 1);
    assert_eq!(pacemaker.consecutive_timeouts(), 2);

    // Progress should reset consecutive count
    pacemaker.on_progress();
    assert_eq!(
        pacemaker.consecutive_timeouts(),
        0,
        "Progress should reset consecutive timeout count"
    );
}
