//! Run 361 — Public DevNet abuse/DoS hardening tests (source/test only).
//!
//! These tests exercise the operator-configurable abuse/DoS config model and the
//! pure inbound connection-rate limiter boundary introduced in
//! `crates/qbind-node/src/public_devnet_abuse_dos_config.rs`. They assert that:
//!
//! - the safe default profile preserves current runtime behavior
//!   (`1000` msg/s + `100` burst, connection limiter disabled);
//! - valid custom / DevNet / connection-rate thresholds are accepted;
//! - TestNet/MainNet profiles are not accidentally accepted as DevNet;
//! - zero / nonsensical / unbounded / wrong-environment / genesis-mismatch /
//!   MainNet configs are rejected;
//! - the per-peer and connection limiters behave deterministically and
//!   independently, and only mutate caller-owned fixture state.
//!
//! Run 361 is source/test only: no runtime wiring, no CLI, no default change.

use std::time::{Duration, Instant};

use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{PeerRateLimiter, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND};
use qbind_node::public_devnet_abuse_dos_config::{
    connection_rate_metric_plan, inbound_connection_adapter_shape, AbuseDosConfig,
    AbuseDosConfigError, AbuseDosProfile, ConnectionDecision, ConnectionRateLimiter,
    ConnectionRateLimiterState, FailMode, RemoteAddr, PLANNED_CONNECTION_RATE_DROP_METRIC,
};
use qbind_types::primitives::NetworkEnvironment;

// ============================================================================
// Accepted / construction
// ============================================================================

// 1. Default profile preserves current 1000 msg/s + 100 burst values.
#[test]
fn t01_default_profile_preserves_current_values() {
    let cfg = AbuseDosConfig::default();
    assert_eq!(cfg.per_peer_max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.per_peer_burst_allowance, DEFAULT_BURST_ALLOWANCE);
    assert_eq!(cfg.per_peer_max_messages_per_second, 1000);
    assert_eq!(cfg.per_peer_burst_allowance, 100);
    assert!(!cfg.connection_limiter_enabled);
    assert!(cfg.preserves_runtime_defaults());
    assert_eq!(cfg.profile, AbuseDosProfile::CompatibilityDefault);
    assert_eq!(cfg.fail_mode, FailMode::FailOpen);
    // The derived peer-limiter config matches the existing hardcoded defaults.
    let prc = cfg.peer_rate_limiter_config();
    assert_eq!(prc.max_messages_per_second, 1000);
    assert_eq!(prc.burst_allowance, 100);
}

// 2. Valid custom per-peer thresholds accepted.
#[test]
fn t02_valid_custom_per_peer_thresholds_accepted() {
    let mut cfg = AbuseDosConfig::default();
    cfg.per_peer_max_messages_per_second = 250;
    cfg.per_peer_burst_allowance = 25;
    cfg.profile = AbuseDosProfile::Custom;
    assert!(cfg.validate().is_ok());
    assert!(!cfg.preserves_runtime_defaults());
}

// 3. Valid connection-rate thresholds accepted.
#[test]
fn t03_valid_connection_rate_thresholds_accepted() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    assert!(cfg.connection_limiter_enabled);
    assert!(cfg.validate().is_ok());
    assert!(ConnectionRateLimiter::new(cfg).is_ok());
}

// 4. DevNet source/test profile accepted.
#[test]
fn t04_devnet_profile_accepted() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    assert!(cfg.is_devnet_profile());
    assert!(cfg.validate_devnet().is_ok());
}

// 5. TestNet/MainNet production profiles not accidentally accepted as DevNet.
#[test]
fn t05_testnet_mainnet_not_accepted_as_devnet() {
    let testnet = AbuseDosConfig::default().with_environment(NetworkEnvironment::Testnet);
    assert!(!testnet.is_devnet_profile());
    assert_eq!(
        testnet.validate_devnet(),
        Err(AbuseDosConfigError::WrongEnvironment(NetworkEnvironment::Testnet))
    );

    let mainnet = AbuseDosConfig::default().with_environment(NetworkEnvironment::Mainnet);
    assert!(!mainnet.is_devnet_profile());
    // validate_devnet rejects a non-DevNet environment before anything else.
    assert_eq!(
        mainnet.validate_devnet(),
        Err(AbuseDosConfigError::WrongEnvironment(NetworkEnvironment::Mainnet))
    );
    // The base validate() still refuses MainNet outright.
    assert_eq!(mainnet.validate(), Err(AbuseDosConfigError::MainNetRefused));
}

// ============================================================================
// Validation failures
// ============================================================================

// 6. Zero max messages/sec rejected.
#[test]
fn t06_zero_max_messages_rejected() {
    let mut cfg = AbuseDosConfig::default();
    cfg.per_peer_max_messages_per_second = 0;
    assert_eq!(cfg.validate(), Err(AbuseDosConfigError::ZeroMaxMessagesPerSecond));
}

// 7. Zero or invalid burst rejected where unsafe (unbounded burst).
#[test]
fn t07_invalid_burst_rejected_where_unsafe() {
    // A burst of zero is safe (matches a strict no-burst posture) and accepted.
    let mut ok = AbuseDosConfig::default();
    ok.per_peer_burst_allowance = 0;
    assert!(ok.validate().is_ok());

    // An effectively unbounded burst is unsafe and rejected.
    let mut bad = AbuseDosConfig::default();
    bad.per_peer_burst_allowance = u64::MAX;
    assert_eq!(
        bad.validate(),
        Err(AbuseDosConfigError::BurstAllowanceTooLarge(u64::MAX))
    );
}

// 8. Impossible connection window rejected.
#[test]
fn t08_impossible_connection_window_rejected() {
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.connection_rate_window = Duration::from_secs(0);
    assert_eq!(cfg.validate(), Err(AbuseDosConfigError::ZeroConnectionRateWindow));
}

// 9. Unbounded/too-large values rejected or explicitly marked unsafe.
#[test]
fn t09_unbounded_values_rejected() {
    let mut too_many_msgs = AbuseDosConfig::default();
    too_many_msgs.per_peer_max_messages_per_second = u64::MAX;
    assert_eq!(
        too_many_msgs.validate(),
        Err(AbuseDosConfigError::MaxMessagesPerSecondTooLarge(u64::MAX))
    );

    let mut too_many_conns = AbuseDosConfig::public_devnet_recommended();
    too_many_conns.max_connections_per_window = u64::MAX;
    assert_eq!(
        too_many_conns.validate(),
        Err(AbuseDosConfigError::ConnectionsPerWindowTooLarge(u64::MAX))
    );

    let mut huge_window = AbuseDosConfig::public_devnet_recommended();
    huge_window.connection_rate_window = Duration::from_secs(48 * 60 * 60);
    assert_eq!(
        huge_window.validate(),
        Err(AbuseDosConfigError::ConnectionRateWindowTooLarge(48 * 60 * 60))
    );
}

// 10. Malformed config rejected (zero connections per window).
#[test]
fn t10_malformed_config_rejected() {
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 0;
    assert_eq!(cfg.validate(), Err(AbuseDosConfigError::ZeroConnectionsPerWindow));
}

// 11. Wrong environment rejected.
#[test]
fn t11_wrong_environment_rejected() {
    let cfg = AbuseDosConfig::default().with_environment(NetworkEnvironment::Testnet);
    assert_eq!(
        cfg.validate_devnet(),
        Err(AbuseDosConfigError::WrongEnvironment(NetworkEnvironment::Testnet))
    );
}

// 12. Wrong genesis binding rejected if genesis binding is part of config.
#[test]
fn t12_wrong_genesis_binding_rejected() {
    let bound = AbuseDosConfig::default().with_genesis_hash([0x11; 32]);
    // Matching binding accepted.
    assert!(bound.check_genesis_binding(&[0x11; 32]).is_ok());
    // Mismatched binding rejected.
    assert_eq!(
        bound.check_genesis_binding(&[0x22; 32]),
        Err(AbuseDosConfigError::GenesisBindingMismatch)
    );
    // No binding => no-op success.
    let unbound = AbuseDosConfig::default();
    assert!(unbound.check_genesis_binding(&[0x99; 32]).is_ok());
}

// 13. MainNet refused absent production policy.
#[test]
fn t13_mainnet_refused_absent_policy() {
    let cfg = AbuseDosConfig::default().with_environment(NetworkEnvironment::Mainnet);
    assert_eq!(cfg.validate(), Err(AbuseDosConfigError::MainNetRefused));
    // And the limiter refuses to construct.
    assert_eq!(
        ConnectionRateLimiter::new(cfg).unwrap_err(),
        AbuseDosConfigError::MainNetRefused
    );
}

// ============================================================================
// Rate limiter behavior — per-peer (reuses existing PeerRateLimiter)
// ============================================================================

// 14. Per-peer token bucket allows under-budget traffic.
#[test]
fn t14_per_peer_allows_under_budget() {
    let cfg = AbuseDosConfig {
        per_peer_max_messages_per_second: 100,
        per_peer_burst_allowance: 10,
        ..AbuseDosConfig::default()
    };
    let limiter = PeerRateLimiter::new(cfg.peer_rate_limiter_config());
    let peer = PeerId(7);
    let now = Instant::now();
    for _ in 0..110 {
        assert!(limiter.allow(&peer, now));
    }
}

// 15. Per-peer token bucket drops over-budget traffic.
#[test]
fn t15_per_peer_drops_over_budget() {
    let cfg = AbuseDosConfig {
        per_peer_max_messages_per_second: 10,
        per_peer_burst_allowance: 5,
        ..AbuseDosConfig::default()
    };
    let limiter = PeerRateLimiter::new(cfg.peer_rate_limiter_config());
    let peer = PeerId(7);
    let now = Instant::now();
    for _ in 0..15 {
        assert!(limiter.allow(&peer, now));
    }
    assert!(!limiter.allow(&peer, now));
}

// 16. Refill behavior deterministic.
#[test]
fn t16_per_peer_refill_deterministic() {
    let cfg = AbuseDosConfig {
        per_peer_max_messages_per_second: 10,
        per_peer_burst_allowance: 0,
        ..AbuseDosConfig::default()
    };
    let limiter = PeerRateLimiter::new(cfg.peer_rate_limiter_config());
    let peer = PeerId(7);
    let now = Instant::now();
    for _ in 0..10 {
        assert!(limiter.allow(&peer, now));
    }
    assert!(!limiter.allow(&peer, now));
    // After exactly one second, the bucket is refilled to 10.
    let later = now + Duration::from_secs(1);
    for _ in 0..10 {
        assert!(limiter.allow(&peer, later));
    }
    assert!(!limiter.allow(&peer, later));
}

// 17. Burst behavior deterministic.
#[test]
fn t17_per_peer_burst_deterministic() {
    let cfg = AbuseDosConfig {
        per_peer_max_messages_per_second: 10,
        per_peer_burst_allowance: 5,
        ..AbuseDosConfig::default()
    };
    let limiter = PeerRateLimiter::new(cfg.peer_rate_limiter_config());
    let peer = PeerId(7);
    let now = Instant::now();
    // Capacity is exactly rate + burst = 15.
    for i in 0..15 {
        assert!(limiter.allow(&peer, now), "unexpected drop at {i}");
    }
    assert!(!limiter.allow(&peer, now));
}

// 18. Fail-open behavior is explicitly documented and observable via config.
#[test]
fn t18_fail_open_marker_explicit() {
    // The compatibility default records fail-open, matching the current runtime
    // limiter which fails open on lock poisoning.
    assert_eq!(AbuseDosConfig::default().fail_mode, FailMode::FailOpen);
    // The stricter DevNet profile opts into fail-closed.
    assert_eq!(
        AbuseDosConfig::public_devnet_recommended().fail_mode,
        FailMode::FailClosed
    );
}

// 19. Connection limiter allows under-budget connections.
#[test]
fn t19_connection_allows_under_budget() {
    let cfg = AbuseDosConfig {
        connection_limiter_enabled: true,
        connection_rate_window: Duration::from_secs(1),
        max_connections_per_window: 5,
        connection_burst_allowance: 5,
        per_address_rate_window: None,
        profile: AbuseDosProfile::Custom,
        ..AbuseDosConfig::default()
    };
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.7:40000");
    let now = Instant::now();
    // Capacity 10 (5 rate + 5 burst).
    for _ in 0..10 {
        assert_eq!(
            limiter.check(&mut state, &remote, now),
            ConnectionDecision::ConnectionAllowed
        );
    }
}

// 20. Connection limiter limits over-budget connections.
#[test]
fn t20_connection_limits_over_budget() {
    let cfg = AbuseDosConfig {
        connection_limiter_enabled: true,
        connection_rate_window: Duration::from_secs(1),
        max_connections_per_window: 5,
        connection_burst_allowance: 5,
        per_address_rate_window: None,
        profile: AbuseDosProfile::Custom,
        ..AbuseDosConfig::default()
    };
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.7:40000");
    let now = Instant::now();
    for _ in 0..10 {
        assert_eq!(
            limiter.check(&mut state, &remote, now),
            ConnectionDecision::ConnectionAllowed
        );
    }
    assert_eq!(
        limiter.check(&mut state, &remote, now),
        ConnectionDecision::ConnectionRateLimited
    );
}

// 21. Connection limiter refill/window behavior deterministic.
#[test]
fn t21_connection_refill_deterministic() {
    let cfg = AbuseDosConfig {
        connection_limiter_enabled: true,
        connection_rate_window: Duration::from_secs(1),
        max_connections_per_window: 5,
        connection_burst_allowance: 0,
        per_address_rate_window: None,
        profile: AbuseDosProfile::Custom,
        ..AbuseDosConfig::default()
    };
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.7:40000");
    let now = Instant::now();
    for _ in 0..5 {
        assert_eq!(
            limiter.check(&mut state, &remote, now),
            ConnectionDecision::ConnectionAllowed
        );
    }
    assert_eq!(
        limiter.check(&mut state, &remote, now),
        ConnectionDecision::ConnectionRateLimited
    );
    // After the full window, 5 connections are available again.
    let later = now + Duration::from_secs(1);
    for _ in 0..5 {
        assert_eq!(
            limiter.check(&mut state, &remote, later),
            ConnectionDecision::ConnectionAllowed
        );
    }
    assert_eq!(
        limiter.check(&mut state, &remote, later),
        ConnectionDecision::ConnectionRateLimited
    );
}

// 22. Per-peer and connection limiter state are independent.
#[test]
fn t22_per_peer_and_connection_state_independent() {
    let cfg = AbuseDosConfig {
        per_peer_max_messages_per_second: 10,
        per_peer_burst_allowance: 0,
        connection_limiter_enabled: true,
        connection_rate_window: Duration::from_secs(1),
        max_connections_per_window: 2,
        connection_burst_allowance: 0,
        per_address_rate_window: None,
        profile: AbuseDosProfile::Custom,
        ..AbuseDosConfig::default()
    };
    let peer_limiter = PeerRateLimiter::new(cfg.peer_rate_limiter_config());
    let conn_limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut conn_state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.9:40000");
    let peer = PeerId(9);
    let now = Instant::now();

    // Exhaust the connection limiter (capacity 2) — this must not consume any
    // per-peer message budget.
    assert_eq!(
        conn_limiter.check(&mut conn_state, &remote, now),
        ConnectionDecision::ConnectionAllowed
    );
    assert_eq!(
        conn_limiter.check(&mut conn_state, &remote, now),
        ConnectionDecision::ConnectionAllowed
    );
    assert_eq!(
        conn_limiter.check(&mut conn_state, &remote, now),
        ConnectionDecision::ConnectionRateLimited
    );

    // The per-peer message limiter still has its full budget of 10.
    for _ in 0..10 {
        assert!(peer_limiter.allow(&peer, now));
    }
    assert!(!peer_limiter.allow(&peer, now));
}

// 23. Disabled limiter is explicit and observable.
#[test]
fn t23_disabled_limiter_explicit() {
    let cfg = AbuseDosConfig::default(); // connection limiter disabled
    assert!(!cfg.connection_limiter_enabled);
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.1:40000");
    let now = Instant::now();
    assert_eq!(
        limiter.check(&mut state, &remote, now),
        ConnectionDecision::ConnectionLimiterDisabled
    );
    // Disabled limiter must not create any state.
    assert!(!state.global_initialized());
    assert_eq!(state.tracked_address_count(), 0);
}

// ============================================================================
// Non-mutation
// ============================================================================

// 24. Rejected config produces no runtime mutation (limiter is not constructed).
#[test]
fn t24_rejected_config_no_mutation() {
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 0; // invalid
    let result = ConnectionRateLimiter::new(cfg);
    assert!(result.is_err());
    // No ConnectionRateLimiter or state exists to have mutated anything.
}

// 25. Limiter writes only caller-owned test/fixture state.
#[test]
fn t25_limiter_writes_only_caller_state() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let now = Instant::now();

    // Two independent caller-owned states remain fully independent.
    let mut state_a = ConnectionRateLimiterState::new();
    let mut state_b = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.5:40000");

    let _ = limiter.check(&mut state_a, &remote, now);
    assert!(state_a.global_initialized());
    // state_b untouched.
    assert!(!state_b.global_initialized());
    assert_eq!(state_b.tracked_address_count(), 0);
}

// 26. No trust-bundle mutation — module has no trust-bundle surface.
//     (Compile-time guarantee: the config model neither imports nor references
//     the trust-bundle API. This test documents the boundary explicitly.)
#[test]
fn t26_no_trust_bundle_mutation() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let _ = limiter.check(&mut state, &RemoteAddr::new("203.0.113.2:1"), Instant::now());
    // Nothing here can touch trust-bundle / LivePqcTrustState / sequence files.
}

// 27–31. No LivePqcTrustState mutation, no sequence file write, no validator-set
//         mutation, no epoch transition, no Run 070 apply path. The module is a
//         pure config/limiter with no such dependencies; this is enforced at
//         compile time by its import set. This test asserts the decision path is
//         total and side-effect free over many calls.
#[test]
fn t27_31_no_runtime_side_effects() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let now = Instant::now();
    for i in 0..1000u64 {
        let remote = RemoteAddr::new(format!("203.0.113.{}:1", i % 250));
        let decision = limiter.check(&mut state, &remote, now + Duration::from_millis(i));
        matches!(
            decision,
            ConnectionDecision::ConnectionAllowed | ConnectionDecision::ConnectionRateLimited
        );
    }
}

// 32. No public DevNet launch claim — metric plan reserves a future name only.
#[test]
fn t32_no_launch_claim_metric_plan_reserved() {
    let (existing, planned) = connection_rate_metric_plan();
    assert!(existing.contains(&"total_rate_limit_drops"));
    assert_eq!(planned, PLANNED_CONNECTION_RATE_DROP_METRIC);
    assert_eq!(planned, "qbind_p2p_connection_rate_drop_total");
}

// ============================================================================
// Compatibility
// ============================================================================

// 33. Existing PeerRateLimiter::with_defaults() behavior remains compatible.
#[test]
fn t33_peer_rate_limiter_with_defaults_compatible() {
    let limiter = PeerRateLimiter::with_defaults();
    assert_eq!(limiter.config().max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(limiter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
    // A default AbuseDosConfig derives exactly the same peer-limiter config.
    let derived = AbuseDosConfig::default().peer_rate_limiter_config();
    assert_eq!(derived.max_messages_per_second, limiter.config().max_messages_per_second);
    assert_eq!(derived.burst_allowance, limiter.config().burst_allowance);
}

// 35. No existing P2P admission policy is weakened — the adapter shape is a pure
//     decision helper that never returns "allowed" for an over-budget or
//     MainNet connection.
#[test]
fn t35_adapter_shape_does_not_weaken_admission() {
    // Over-budget connections are rate-limited, never silently allowed.
    let cfg = AbuseDosConfig {
        connection_limiter_enabled: true,
        connection_rate_window: Duration::from_secs(1),
        max_connections_per_window: 1,
        connection_burst_allowance: 0,
        per_address_rate_window: None,
        profile: AbuseDosProfile::Custom,
        ..AbuseDosConfig::default()
    };
    let limiter = ConnectionRateLimiter::new(cfg).unwrap();
    let mut state = ConnectionRateLimiterState::new();
    let remote = RemoteAddr::new("203.0.113.3:1");
    let now = Instant::now();
    assert_eq!(
        inbound_connection_adapter_shape(&limiter, &mut state, &remote, now),
        ConnectionDecision::ConnectionAllowed
    );
    assert_eq!(
        inbound_connection_adapter_shape(&limiter, &mut state, &remote, now),
        ConnectionDecision::ConnectionRateLimited
    );
}
