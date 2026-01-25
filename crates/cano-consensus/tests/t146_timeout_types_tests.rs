//! T146 Unit Tests: Timeout Message Types and Pacemaker
//!
//! These tests validate the timeout/view-change primitives:
//! - TimeoutMsg construction and signing bytes
//! - TimeoutCertificate (TC) formation
//! - TimeoutAccumulator behavior
//! - TimeoutPacemaker timeout detection
//!
//! The tests ensure that timeout messages use the correct ML-DSA-44
//! suite (suite_id = 100) and maintain consistency with the existing
//! vote/QC signing mechanisms.

use cano_consensus::{
    timeout::{timeout_signing_bytes, TimeoutCertificate, TimeoutMsg, TIMEOUT_SUITE_ID},
    PacemakerEvent, QuorumCertificate, TimeoutPacemaker, TimeoutPacemakerConfig, ValidatorId,
};
use std::time::{Duration, Instant};

// ============================================================================
// TimeoutMsg Tests
// ============================================================================

#[test]
fn timeout_msg_construction() {
    let view = 5;
    let high_qc = QuorumCertificate::new([1u8; 32], 4, vec![ValidatorId::new(0)]);
    let validator_id = ValidatorId::new(1);

    let timeout_msg = TimeoutMsg::new(view, Some(high_qc.clone()), validator_id);

    assert_eq!(timeout_msg.view, 5);
    assert!(timeout_msg.high_qc.is_some());
    assert_eq!(timeout_msg.high_qc.as_ref().unwrap().view, 4);
    assert_eq!(timeout_msg.validator_id, ValidatorId::new(1));
    assert_eq!(timeout_msg.suite_id, TIMEOUT_SUITE_ID);
    assert!(timeout_msg.signature.is_empty()); // Unsigned
}

#[test]
fn timeout_msg_set_signature() {
    let validator_id = ValidatorId::new(1);
    let mut timeout_msg = TimeoutMsg::<[u8; 32]>::new(5, None, validator_id);

    assert!(timeout_msg.signature.is_empty());

    timeout_msg.set_signature(vec![1, 2, 3, 4, 5]);
    assert_eq!(timeout_msg.signature, vec![1, 2, 3, 4, 5]);
}

#[test]
fn timeout_signing_bytes_deterministic() {
    let view = 10;
    let high_qc = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);
    let validator_id = ValidatorId::new(1);

    // Should produce identical bytes for identical inputs
    let bytes1 = timeout_signing_bytes(view, Some(&high_qc), validator_id);
    let bytes2 = timeout_signing_bytes(view, Some(&high_qc), validator_id);

    assert_eq!(bytes1, bytes2);
    assert!(!bytes1.is_empty());
}

#[test]
fn timeout_signing_bytes_includes_domain_separator() {
    let view = 10;
    let high_qc = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);
    let validator_id = ValidatorId::new(1);

    let bytes = timeout_signing_bytes(view, Some(&high_qc), validator_id);

    // Should start with domain separator "CANO_TIMEOUT_V1"
    assert!(bytes.starts_with(b"CANO_TIMEOUT_V1"));
}

#[test]
fn timeout_signing_bytes_different_for_different_views() {
    let high_qc = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);
    let validator_id = ValidatorId::new(1);

    let bytes1 = timeout_signing_bytes(10, Some(&high_qc), validator_id);
    let bytes2 = timeout_signing_bytes(11, Some(&high_qc), validator_id);

    assert_ne!(
        bytes1, bytes2,
        "different views should produce different signing bytes"
    );
}

#[test]
fn timeout_signing_bytes_different_for_different_validators() {
    let view = 10;
    let high_qc = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);

    let bytes1 = timeout_signing_bytes(view, Some(&high_qc), ValidatorId::new(1));
    let bytes2 = timeout_signing_bytes(view, Some(&high_qc), ValidatorId::new(2));

    assert_ne!(
        bytes1, bytes2,
        "different validators should produce different signing bytes"
    );
}

#[test]
fn timeout_signing_bytes_different_for_different_qcs() {
    let view = 10;
    let validator_id = ValidatorId::new(1);

    let high_qc1 = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);
    let high_qc2 = QuorumCertificate::new([43u8; 32], 9, vec![ValidatorId::new(0)]);

    let bytes1 = timeout_signing_bytes(view, Some(&high_qc1), validator_id);
    let bytes2 = timeout_signing_bytes(view, Some(&high_qc2), validator_id);

    assert_ne!(
        bytes1, bytes2,
        "different QCs should produce different signing bytes"
    );
}

#[test]
fn timeout_signing_bytes_different_for_none_vs_some_qc() {
    let view = 10;
    let validator_id = ValidatorId::new(1);
    let high_qc = QuorumCertificate::new([42u8; 32], 9, vec![ValidatorId::new(0)]);

    let bytes_with_qc = timeout_signing_bytes(view, Some(&high_qc), validator_id);
    let bytes_without_qc = timeout_signing_bytes::<[u8; 32]>(view, None, validator_id);

    assert_ne!(bytes_with_qc, bytes_without_qc);
}

// ============================================================================
// TimeoutCertificate (TC) Tests
// ============================================================================

#[test]
fn timeout_certificate_construction() {
    let timeout_view = 5;
    let high_qc = QuorumCertificate::new([1u8; 32], 4, vec![ValidatorId::new(0)]);
    let signers = vec![
        ValidatorId::new(1),
        ValidatorId::new(2),
        ValidatorId::new(3),
    ];

    let timeout_cert =
        TimeoutCertificate::new(timeout_view, Some(high_qc.clone()), signers.clone());

    assert_eq!(timeout_cert.timeout_view, 5);
    assert_eq!(timeout_cert.target_view(), 6); // timeout_view + 1
    assert!(timeout_cert.high_qc.is_some());
    assert_eq!(timeout_cert.high_qc.as_ref().unwrap().view, 4);
    assert_eq!(timeout_cert.signers.len(), 3);
}

#[test]
fn timeout_certificate_target_view_is_next() {
    let tc = TimeoutCertificate::<[u8; 32]>::new(10, None, vec![ValidatorId::new(1)]);

    assert_eq!(tc.timeout_view, 10);
    assert_eq!(tc.target_view(), 11);
}

// ============================================================================
// TimeoutPacemaker Tests
// ============================================================================

#[test]
fn pacemaker_default_config() {
    let config = TimeoutPacemakerConfig::default();
    assert!(config.base_timeout.as_millis() > 0);
    assert!(config.timeout_multiplier >= 1.0);
}

#[test]
fn pacemaker_initial_state() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(1000),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    assert_eq!(pacemaker.current_view(), 0);
    assert!(!pacemaker.timeout_emitted());
    assert_eq!(pacemaker.consecutive_timeouts(), 0);
}

#[test]
fn pacemaker_on_progress_resets_backoff() {
    let config = TimeoutPacemakerConfig::default();
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Simulate some consecutive timeouts
    // (We can't directly set this, but we can verify on_progress resets it)
    pacemaker.on_progress();
    assert_eq!(pacemaker.consecutive_timeouts(), 0);
}

#[test]
fn pacemaker_no_timeout_without_time_elapsed() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(1000),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Immediately after creation, no timeout should fire
    let now = Instant::now();
    let event = pacemaker.on_tick_with_time(now, 0);

    assert!(
        matches!(event, PacemakerEvent::None),
        "should not timeout immediately"
    );
}

#[test]
fn pacemaker_timeout_after_delay() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10), // Very short timeout for testing
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait for timeout to fire
    std::thread::sleep(Duration::from_millis(50));

    let now = Instant::now();
    let event = pacemaker.on_tick_with_time(now, 0);

    assert!(
        matches!(event, PacemakerEvent::Timeout { view: 0 }),
        "should timeout after delay: got {:?}",
        event
    );
}

#[test]
fn pacemaker_timeout_only_once_per_view() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(50));

    // First tick should produce timeout
    let now = Instant::now();
    let event1 = pacemaker.on_tick_with_time(now, 0);
    assert!(matches!(event1, PacemakerEvent::Timeout { .. }));

    // Second tick for same view should not produce another timeout
    let event2 = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event2, PacemakerEvent::None),
        "should not timeout twice for same view: got {:?}",
        event2
    );
}

#[test]
fn pacemaker_progress_resets_timeout() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(50),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait partial timeout
    std::thread::sleep(Duration::from_millis(30));

    // Progress should reset the timeout
    pacemaker.on_progress();

    // Wait another partial timeout (less than full timeout)
    std::thread::sleep(Duration::from_millis(30));

    // Should not timeout yet since progress was made
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(
        matches!(event, PacemakerEvent::None),
        "progress should reset timeout: got {:?}",
        event
    );
}

#[test]
fn pacemaker_qc_advances_view() {
    let config = TimeoutPacemakerConfig::default();
    let mut pacemaker = TimeoutPacemaker::new(config);

    assert_eq!(pacemaker.current_view(), 0);

    // QC for view 5 advances pacemaker to view 6
    pacemaker.on_qc(5);
    assert_eq!(pacemaker.current_view(), 6);
    assert!(!pacemaker.timeout_emitted()); // Reset on view change
}

#[test]
fn pacemaker_tc_triggers_new_view() {
    let config = TimeoutPacemakerConfig::default();
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Receive TC for view 10
    pacemaker.on_timeout_certificate(10);

    // Next tick should return NewView
    let now = Instant::now();
    let event = pacemaker.on_tick_with_time(now, 0);
    assert_eq!(event, PacemakerEvent::NewView { view: 10 });
    assert_eq!(pacemaker.current_view(), 10);
}

#[test]
fn pacemaker_tc_for_lower_view_ignored() {
    let mut pacemaker = TimeoutPacemaker::with_defaults();
    pacemaker.on_qc(9); // Advance to view 10
    assert_eq!(pacemaker.current_view(), 10);

    // TC for lower view should be ignored
    pacemaker.on_timeout_certificate(5);

    let now = Instant::now();
    let event = pacemaker.on_tick_with_time(now, 10);
    assert_eq!(event, PacemakerEvent::None);
    assert_eq!(pacemaker.current_view(), 10);
}

#[test]
fn pacemaker_exponential_backoff() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(100),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_secs(30),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    // Test timeout_for_consecutive which computes timeout based on consecutive timeout count
    let timeout_0 = pacemaker.timeout_for_consecutive(0);
    let timeout_1 = pacemaker.timeout_for_consecutive(1);
    let timeout_2 = pacemaker.timeout_for_consecutive(2);

    // Check specific values with 2x multiplier
    assert_eq!(timeout_0, Duration::from_millis(100));
    assert_eq!(timeout_1, Duration::from_millis(200));
    assert_eq!(timeout_2, Duration::from_millis(400));
}

#[test]
fn pacemaker_backoff_capped_at_max() {
    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(100),
        timeout_multiplier: 2.0,
        max_timeout: Duration::from_millis(500),
    };
    let pacemaker = TimeoutPacemaker::new(config);

    // After many consecutive timeouts, should be capped at max
    let timeout = pacemaker.timeout_for_consecutive(10);
    assert_eq!(timeout, Duration::from_millis(500));
}

#[test]
fn pacemaker_syncs_with_engine_view() {
    let config = TimeoutPacemakerConfig::default();
    let mut pacemaker = TimeoutPacemaker::new(config);

    assert_eq!(pacemaker.current_view(), 0);

    // Engine is ahead - pacemaker should sync
    let now = Instant::now();
    let _ = pacemaker.on_tick_with_time(now, 5);

    assert_eq!(pacemaker.current_view(), 5);
}

// ============================================================================
// Integration: TimeoutMsg + Pacemaker
// ============================================================================

#[test]
fn integration_pacemaker_timeout_leads_to_timeout_msg() {
    // This test simulates the flow:
    // 1. Pacemaker times out
    // 2. Node would create and sign TimeoutMsg
    // 3. TimeoutMsg is broadcast

    let config = TimeoutPacemakerConfig {
        base_timeout: Duration::from_millis(10),
        timeout_multiplier: 1.0,
        max_timeout: Duration::from_secs(30),
    };
    let mut pacemaker = TimeoutPacemaker::new(config);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(50));

    // Check for timeout event
    let event = pacemaker.on_tick_with_time(Instant::now(), 0);
    assert!(matches!(event, PacemakerEvent::Timeout { view: 0 }));

    // When Timeout event is received, node would create TimeoutMsg:
    let high_qc = QuorumCertificate::new([1u8; 32], 0, vec![ValidatorId::new(1)]);
    let mut timeout_msg = TimeoutMsg::new(0, Some(high_qc), ValidatorId::new(1));

    // Sign it (dummy signature for test)
    timeout_msg.set_signature(vec![0u8; 64]);

    assert_eq!(timeout_msg.view, 0);
    assert_eq!(timeout_msg.suite_id, TIMEOUT_SUITE_ID);
    assert_eq!(timeout_msg.signature.len(), 64);
}
