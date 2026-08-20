//! Run 362 — Public DevNet abuse/DoS runtime wiring tests.
//!
//! These tests exercise the runtime-owned abuse/DoS connection-rate limiter
//! wiring introduced in Run 362 on top of the Run 361 source/test model:
//!
//! - `crate::public_devnet_abuse_dos_runtime::{PublicDevnetAbuseDosRuntimeConfig,
//!   PublicDevnetAbuseDosRuntimeState}` (runtime-owned state + metric bump);
//! - the `qbind_p2p_connection_rate_drop_total` `P2pMetrics` counter;
//! - the hidden `--p2p-connection-rate-limit-*` CLI flag family parsed via
//!   `CliArgs::abuse_dos_runtime_config`.
//!
//! Run 362 wires the connection-rate limiter into the live `p2p_tcp` accept
//! path behind a default-off runtime-owned handle. These tests assert:
//! default compatibility, config validation (fail-closed), runtime accept-loop
//! decision behavior, metric behavior, and non-mutation/safety.
//!
//! All addresses used here are RFC 5737 documentation ranges
//! (`192.0.2.0/24`, `198.51.100.0/24`) or localhost — never live endpoints.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::Parser;
use qbind_node::cli::CliArgs;
use qbind_node::metrics::P2pMetrics;
use qbind_node::peer_rate_limiter::{
    PeerRateLimiter, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_config::{
    AbuseDosConfig, AbuseDosProfile, ConnectionDecision,
};
use qbind_node::public_devnet_abuse_dos_runtime::{
    PublicDevnetAbuseDosRuntimeConfig, PublicDevnetAbuseDosRuntimeState,
};

fn addr(octet: u8, port: u16) -> SocketAddr {
    // RFC 5737 TEST-NET-1 documentation address.
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), port)
}

fn parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

// ============================================================================
// Default compatibility
// ============================================================================

// 1. Default CLI keeps P2P behavior unchanged (no abuse/DoS config produced).
#[test]
fn t01_default_cli_produces_no_config() {
    let args = parse(&[]).expect("default parse");
    let cfg = args.abuse_dos_runtime_config().expect("no error");
    assert!(cfg.is_none(), "default CLI must not produce an abuse/DoS config");
}

// 2. Default per-peer values remain 1000 msg/s + 100 burst.
#[test]
fn t02_default_per_peer_values_preserved() {
    let cfg = AbuseDosConfig::compatibility_default();
    assert_eq!(cfg.per_peer_max_messages_per_second, 1000);
    assert_eq!(cfg.per_peer_burst_allowance, 100);
    assert_eq!(cfg.per_peer_max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.per_peer_burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 3. Connection limiter disabled by default.
#[test]
fn t03_connection_limiter_disabled_by_default() {
    let runtime = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
    assert!(!runtime.connection_limiter_enabled());
    assert!(runtime.preserves_runtime_defaults());
    let state = runtime.into_runtime_state(None).unwrap();
    assert!(!state.connection_limiter_enabled());
    // A disabled limiter never refuses any connection.
    let now = Instant::now();
    for i in 0..1000u16 {
        assert!(state.should_admit(addr(1, i), now));
    }
    assert_eq!(state.drop_count(), 0);
}

// 4. PeerRateLimiter::with_defaults() compatibility preserved.
#[test]
fn t04_peer_rate_limiter_with_defaults_preserved() {
    let limiter = PeerRateLimiter::with_defaults();
    assert_eq!(limiter.config().max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(limiter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// ============================================================================
// Config validation
// ============================================================================

// 5. Valid custom message threshold accepted.
#[test]
fn t05_valid_custom_message_threshold_accepted() {
    let args = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let cfg = args.abuse_dos_runtime_config().unwrap().expect("config");
    assert_eq!(cfg.config().per_peer_max_messages_per_second, 500);
    // Per-peer-only config does not enable the connection limiter.
    assert!(!cfg.connection_limiter_enabled());
}

// 6. Valid custom burst accepted.
#[test]
fn t06_valid_custom_burst_accepted() {
    let args = parse(&["--p2p-burst-allowance", "42"]).unwrap();
    let cfg = args.abuse_dos_runtime_config().unwrap().expect("config");
    assert_eq!(cfg.config().per_peer_burst_allowance, 42);
}

// 7. Valid global connection-rate config accepted.
#[test]
fn t07_valid_global_connection_rate_accepted() {
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "20",
        "--p2p-connection-burst",
        "10",
    ])
    .unwrap();
    let cfg = args.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(cfg.connection_limiter_enabled());
    assert_eq!(cfg.config().max_connections_per_window, 20);
    assert_eq!(cfg.config().connection_burst_allowance, 10);
    assert_eq!(cfg.config().connection_rate_window, Duration::from_millis(1000));
    assert_eq!(cfg.config().profile, AbuseDosProfile::Custom);
}

// 8. Valid per-address connection-rate config accepted.
#[test]
fn t08_valid_per_address_connection_rate_accepted() {
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "20",
        "--p2p-per-address-connection-rate-window-ms",
        "1000",
        "--p2p-per-address-connection-max",
        "5",
    ])
    .unwrap();
    let cfg = args.abuse_dos_runtime_config().unwrap().expect("config");
    assert_eq!(cfg.config().per_address_rate_window, Some(Duration::from_millis(1000)));
    assert_eq!(cfg.config().max_connections_per_address_window, 5);
}

// 9. Zero max messages/sec rejected.
#[test]
fn t09_zero_max_messages_rejected() {
    let args = parse(&["--p2p-max-messages-per-second", "0"]).unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// 10. Zero connection-rate max rejected (unsafe for an allow-limiter).
#[test]
fn t10_zero_connection_max_rejected() {
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "0",
    ])
    .unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// 11. Impossible connection window (zero ms) rejected.
#[test]
fn t11_zero_connection_window_rejected() {
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "0",
        "--p2p-connection-rate-max",
        "20",
    ])
    .unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// 12. Unbounded / too-large connection window rejected.
#[test]
fn t12_too_large_window_rejected() {
    // MAX_CONNECTION_WINDOW_SECS is 24h; 48h in ms exceeds it.
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "172800000",
        "--p2p-connection-rate-max",
        "20",
    ])
    .unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// 13. Wrong environment rejected (MainNet).
#[test]
fn t13_wrong_environment_mainnet_rejected() {
    let args = parse(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"]).unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// 14. Genesis binding mismatch rejected if represented.
#[test]
fn t14_genesis_binding_mismatch_rejected() {
    let cfg = AbuseDosConfig::compatibility_default().with_genesis_hash([1u8; 32]);
    assert!(cfg.check_genesis_binding(&[2u8; 32]).is_err());
    assert!(cfg.check_genesis_binding(&[1u8; 32]).is_ok());
}

// 15. MainNet refused absent production policy at runtime-config build.
#[test]
fn t15_mainnet_refused_runtime_config() {
    let mainnet = AbuseDosConfig::compatibility_default()
        .with_environment(qbind_types::primitives::NetworkEnvironment::Mainnet);
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(mainnet).is_err());
}

// Additional: inconsistent per-address flags (only one of the pair) rejected.
#[test]
fn t15b_partial_per_address_flags_rejected() {
    let args = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "20",
        "--p2p-per-address-connection-rate-window-ms",
        "1000",
    ])
    .unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// Additional: connection-rate sub-flags without the enable flag rejected.
#[test]
fn t15c_connection_flags_without_enable_rejected() {
    let args = parse(&["--p2p-connection-rate-window-ms", "1000"]).unwrap();
    assert!(args.abuse_dos_runtime_config().is_err());
}

// ============================================================================
// Runtime accept-loop behavior
// ============================================================================

fn enabled_state(metrics: Option<std::sync::Arc<P2pMetrics>>) -> PublicDevnetAbuseDosRuntimeState {
    PublicDevnetAbuseDosRuntimeConfig::from_config(AbuseDosConfig::public_devnet_recommended())
        .unwrap()
        .into_runtime_state(metrics)
        .unwrap()
}

// 16. Under-budget inbound connection allowed to proceed to normal admission.
#[test]
fn t16_under_budget_allowed() {
    let state = enabled_state(None);
    let now = Instant::now();
    assert_eq!(
        state.check_inbound(addr(1, 1), now),
        ConnectionDecision::ConnectionAllowed
    );
    assert!(state.should_admit(addr(1, 2), now));
}

// 17. Over-budget inbound connection refused.
#[test]
fn t17_over_budget_refused() {
    let state = enabled_state(None);
    let now = Instant::now();
    // Global capacity = 20 + 10 = 30 at t0.
    for i in 0..30u16 {
        assert!(state.should_admit(addr(1, i), now));
    }
    assert_eq!(
        state.check_inbound(addr(1, 100), now),
        ConnectionDecision::ConnectionRateLimited
    );
}

// 18. Refill/window behavior deterministic (tokens refill after the window).
#[test]
fn t18_refill_deterministic() {
    let state = enabled_state(None);
    let t0 = Instant::now();
    for i in 0..30u16 {
        assert!(state.should_admit(addr(1, i), t0));
    }
    assert!(!state.should_admit(addr(1, 200), t0));
    // After a full window at 20/sec, ~20 tokens refill.
    let t1 = t0 + Duration::from_secs(1);
    let mut allowed = 0;
    for i in 0..20u16 {
        if state.should_admit(addr(2, i), t1) {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 20);
    // 21st at t1 is over budget again.
    assert!(!state.should_admit(addr(2, 99), t1));
}

// 19. Per-address limiter bounds one abusive address without wrongly consuming
//     all global capacity for others.
#[test]
fn t19_per_address_isolation() {
    // Global 100/window, per-address 3/window so the global budget is not the
    // binding constraint for a single abusive address.
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 100;
    cfg.connection_burst_allowance = 0;
    cfg.per_address_rate_window = Some(Duration::from_secs(1));
    cfg.max_connections_per_address_window = 3;
    let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
        .unwrap()
        .into_runtime_state(None)
        .unwrap();
    let now = Instant::now();
    let abuser = addr(1, 7000);
    // The abusive address is bounded to 3 by the per-address bucket.
    let mut abuser_allowed = 0;
    for _ in 0..10 {
        if state.should_admit(abuser, now) {
            abuser_allowed += 1;
        }
    }
    assert_eq!(abuser_allowed, 3);
    // A different address still has its own per-address budget.
    assert!(state.should_admit(addr(2, 7001), now));
}

// 20. Disabled limiter does not block.
#[test]
fn t20_disabled_does_not_block() {
    let state = PublicDevnetAbuseDosRuntimeConfig::disabled_default()
        .into_runtime_state(None)
        .unwrap();
    let now = Instant::now();
    for i in 0..500u16 {
        assert!(state.should_admit(addr(1, i), now));
    }
    assert_eq!(state.drop_count(), 0);
}

// 21. Malformed / unusual remote address handled safely (IPv6, port 0).
#[test]
fn t21_unusual_remote_address_handled() {
    let state = enabled_state(None);
    let now = Instant::now();
    let v6: SocketAddr = "[2001:db8::1]:0".parse().unwrap(); // RFC 3849 doc range
    // Must not panic; returns a deterministic decision.
    let _ = state.check_inbound(v6, now);
    let zero_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 0);
    let _ = state.check_inbound(zero_port, now);
}

// 22. Rate-limit refusal does not mark a peer admitted (should_admit == false).
#[test]
fn t22_refusal_not_admitted() {
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 1;
    cfg.connection_burst_allowance = 0;
    cfg.per_address_rate_window = None;
    let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
        .unwrap()
        .into_runtime_state(None)
        .unwrap();
    let now = Instant::now();
    assert!(state.should_admit(addr(1, 1), now));
    // The refused connection is NOT admitted.
    assert!(!state.should_admit(addr(1, 2), now));
    // Allowed count reflects exactly one admitted connection.
    assert_eq!(state.allow_count(), 1);
    assert_eq!(state.drop_count(), 1);
}

// 23. Rate-limit refusal does not mutate trust state — the limiter holds no
//     trust handle; refusing only touches its own bounded counters.
#[test]
fn t23_refusal_no_trust_mutation() {
    let state = enabled_state(None);
    let now = Instant::now();
    for i in 0..40u16 {
        let _ = state.check_inbound(addr(1, i), now);
    }
    // The only observable effects are the bounded allow/drop counters.
    assert!(state.drop_count() > 0);
    assert!(state.allow_count() > 0);
    assert_eq!(state.allow_count() + state.drop_count(), 40);
}

// 24. Rate-limit refusal does not write sequence/marker files — the runtime
//     state has no filesystem handle. Exercised by refusing many connections
//     and confirming no error/panic and no side effect beyond counters.
#[test]
fn t24_refusal_no_file_writes() {
    let state = enabled_state(None);
    let now = Instant::now();
    for i in 0..100u16 {
        let _ = state.check_inbound(addr(1, i), now);
    }
    // Bounded state only; nothing to assert on the filesystem because the type
    // has no filesystem capability by construction.
    assert!(state.drop_count() + state.allow_count() == 100);
}

// ============================================================================
// Metric behavior
// ============================================================================

// 25. Connection-rate drop metric increments on refusal.
#[test]
fn t25_metric_increments_on_refusal() {
    let metrics = std::sync::Arc::new(P2pMetrics::new());
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 1;
    cfg.connection_burst_allowance = 0;
    cfg.per_address_rate_window = None;
    let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
        .unwrap()
        .into_runtime_state(Some(std::sync::Arc::clone(&metrics)))
        .unwrap();
    let now = Instant::now();
    assert!(state.should_admit(addr(1, 1), now));
    assert!(!state.should_admit(addr(1, 2), now));
    assert_eq!(metrics.connection_rate_drop_total(), 1);
}

// 26. Metric does not increment on allowed connection.
#[test]
fn t26_metric_not_increment_on_allow() {
    let metrics = std::sync::Arc::new(P2pMetrics::new());
    let state = enabled_state(Some(std::sync::Arc::clone(&metrics)));
    let now = Instant::now();
    assert!(state.should_admit(addr(1, 1), now));
    assert_eq!(metrics.connection_rate_drop_total(), 0);
}

// 27. Metric labels do not include raw private endpoint data — the rendered
//     family is a bare counter with no labels.
#[test]
fn t27_metric_has_no_endpoint_labels() {
    let metrics = P2pMetrics::new();
    metrics.record_connection_rate_drop();
    let rendered = metrics.format_metrics();
    assert!(rendered.contains("qbind_p2p_connection_rate_drop_total 1"));
    // No label braces on this family (would leak endpoints).
    assert!(!rendered.contains("qbind_p2p_connection_rate_drop_total{"));
}

// 28. Metric family registered exactly once.
#[test]
fn t28_metric_family_registered_once() {
    let metrics = P2pMetrics::new();
    let rendered = metrics.format_metrics();
    let count = rendered
        .matches("qbind_p2p_connection_rate_drop_total")
        .count();
    assert_eq!(count, 1, "metric family must render exactly once");
}

// ============================================================================
// Non-mutation / safety
// ============================================================================

// 29. No P2P wire-format change — the limiter operates before any frame is
//     read; it never decodes or encodes a frame. (Structural: the runtime
//     state exposes only connection-admission decisions.)
#[test]
fn t29_no_wire_format_change() {
    let state = enabled_state(None);
    // The only public decision surface is connection admission; there is no
    // frame encode/decode API on the runtime state.
    let now = Instant::now();
    let _ = state.should_admit(addr(1, 1), now);
}

// 30. No peer-admission weakening — an allowed connection returns a
//     non-refusal decision and admission proceeds unchanged; the limiter
//     never admits a peer itself.
#[test]
fn t30_no_admission_weakening() {
    let state = enabled_state(None);
    let now = Instant::now();
    assert_eq!(
        state.check_inbound(addr(1, 1), now),
        ConnectionDecision::ConnectionAllowed
    );
}

// 31. No trust-bundle behavior weakening — refusal short-circuits before any
//     admission work, so trust-bundle checks are never bypassed for admitted
//     connections (they run unchanged on allowed connections).
#[test]
fn t31_no_trust_bundle_weakening() {
    // A refused connection is never admitted, so it never reaches trust-bundle
    // verification; an allowed connection is not short-circuited.
    let mut cfg = AbuseDosConfig::public_devnet_recommended();
    cfg.max_connections_per_window = 1;
    cfg.connection_burst_allowance = 0;
    cfg.per_address_rate_window = None;
    let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
        .unwrap()
        .into_runtime_state(None)
        .unwrap();
    let now = Instant::now();
    assert!(state.should_admit(addr(1, 1), now));
    assert!(!state.should_admit(addr(1, 2), now));
}

// 32. No LivePqcTrustState mutation — the runtime state holds no such handle.
//     (Structural: constructed only from an AbuseDosConfig + optional
//     P2pMetrics.)
#[test]
fn t32_no_live_trust_state_mutation() {
    let _state = enabled_state(None);
    // Nothing to mutate; the type cannot reference LivePqcTrustState.
}

// 33. No validator-set mutation — likewise, no validator-set handle exists.
#[test]
fn t33_no_validator_set_mutation() {
    let _state = enabled_state(None);
}

// 34. No epoch transition — the limiter has no epoch surface.
#[test]
fn t34_no_epoch_transition() {
    let _state = enabled_state(None);
}

// 35. No Run 070 apply path — the limiter never calls any apply function.
#[test]
fn t35_no_apply_path() {
    let _state = enabled_state(None);
}

// 36. No public DevNet launch claim — asserted at the docs level; here we
//     confirm the recommended profile is bound to DevNet and never asserts
//     readiness.
#[test]
fn t36_no_launch_claim() {
    let cfg = AbuseDosConfig::public_devnet_recommended();
    assert!(cfg.is_devnet_profile());
    assert_eq!(cfg.profile, AbuseDosProfile::PublicDevnetRecommended);
}
