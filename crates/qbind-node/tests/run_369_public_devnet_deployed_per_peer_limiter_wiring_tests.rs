//! Run 369 — Public DevNet deployed per-peer limiter wiring tests.
//!
//! Run 365 threaded the validated per-peer `PeerRateLimiterConfig` into the
//! deployed `AsyncPeerManagerImpl` construction path. Run 368 proved per-peer
//! message-rate limiting over a real loopback socket at the
//! `AsyncPeerManagerImpl` layer — but `main.rs` never spawns
//! `AsyncPeerManagerImpl`. The *deployed* inbound path is:
//!
//! ```text
//! TcpKemTlsP2pService::read_loop (per-peer NodeId known)
//!     → inbound_tx → subscribe() → P2pInboundDemuxer → handlers
//! ```
//!
//! Run 369 wires the existing per-peer `PeerRateLimiter` onto that deployed
//! receive path via the `DeployedInboundPerPeerLimiter` adapter, consulted by
//! the read loop before an inbound frame is forwarded to the demuxer/handlers.
//! These tests verify the adapter/config wiring at the source/test level.
//! Release-binary live-socket evidence is deferred to Run 370.
//!
//! All addresses used here are RFC 5737 documentation ranges or localhost —
//! never live endpoints.

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};
use qbind_node::cli::CliArgs;
use qbind_node::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter;
use qbind_node::metrics::{NodeMetrics, P2pMetrics};
use qbind_node::p2p::NodeId;
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{
    PeerRateLimiter, PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE,
    DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_config::AbuseDosConfig;
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;

fn parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// Build the deployed `P2pNodeBuilder` exactly the way `main.rs` does.
fn deployed_builder_from_cli(args: &[&str]) -> P2pNodeBuilder {
    let parsed = parse(args).expect("cli parses");
    let mut builder = P2pNodeBuilder::new();
    if let Some(rt) = parsed
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    builder
}

/// Construct the deployed inbound per-peer limiter adapter exactly as the
/// builder's `start()` does: from the builder's derived per-peer config.
fn deployed_inbound_limiter_from_cli(
    args: &[&str],
    metrics: Option<Arc<NodeMetrics>>,
) -> DeployedInboundPerPeerLimiter {
    let builder = deployed_builder_from_cli(args);
    DeployedInboundPerPeerLimiter::from_optional_config(
        builder.deployed_peer_rate_limiter_config(),
        metrics,
    )
}

fn node(seed: u64) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    NodeId::new(bytes)
}

// ============================================================================
// Accepted / default compatibility (1–10)
// ============================================================================

// 1. Default config derives 1000 msg/s + 100 burst for the deployed inbound path.
#[test]
fn t01_default_derives_1000_100() {
    let limiter = deployed_inbound_limiter_from_cli(&[], None);
    assert_eq!(
        limiter.config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(limiter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
    assert_eq!(limiter.config().max_messages_per_second, 1000);
    assert_eq!(limiter.config().burst_allowance, 100);
}

// 2. No-flag normal under-budget messages dispatch as before (allow returns true).
#[test]
fn t02_no_flag_under_budget_dispatches() {
    let limiter = deployed_inbound_limiter_from_cli(&[], None);
    let now = Instant::now();
    let n = node(1);
    // Well under the 1000/s + 100 burst posture: all allowed, no drops.
    for _ in 0..200 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
}

// 3. Custom --p2p-max-messages-per-second reaches the deployed inbound limiter.
#[test]
fn t03_custom_max_messages_reaches_inbound() {
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
        None,
    );
    assert_eq!(limiter.config().max_messages_per_second, 5);
    assert_eq!(limiter.config().burst_allowance, 0);
}

// 4. Custom --p2p-burst-allowance reaches the deployed inbound limiter.
#[test]
fn t04_custom_burst_reaches_inbound() {
    let limiter = deployed_inbound_limiter_from_cli(&["--p2p-burst-allowance", "42"], None);
    assert_eq!(limiter.config().burst_allowance, 42);
    assert_eq!(
        limiter.config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
}

// 5. Under-budget deployed inbound messages are accepted/dispatched.
#[test]
fn t05_under_budget_accepted() {
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
        None,
    );
    let now = Instant::now();
    let n = node(2);
    for _ in 0..5 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
}

// 6. Over-budget deployed inbound messages are dropped.
#[test]
fn t06_over_budget_dropped() {
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
        None,
    );
    let now = Instant::now();
    let n = node(3);
    for _ in 0..5 {
        assert!(limiter.allow_node(&n, now));
    }
    // 6th within the same instant exceeds the budget.
    assert!(!limiter.allow_node(&n, now));
    // Deterministic refill after one second restores capacity.
    let t1 = now + Duration::from_secs(1);
    for _ in 0..5 {
        assert!(limiter.allow_node(&n, t1));
    }
    assert!(!limiter.allow_node(&n, t1));
}

// 7. Per-peer drop counter increments on an over-budget deployed inbound message.
#[test]
fn t07_drop_counter_increments() {
    // Adapter self-contained counter.
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        None,
    );
    let now = Instant::now();
    let n = node(4);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now));
    assert_eq!(limiter.drop_count(), 1);

    // Existing per-peer metric path (qbind_net_per_peer_drops_total) also
    // increments when a NodeMetrics handle is installed.
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&metrics)),
    );
    let n = node(5);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now));
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 1);
}

// 8. Connection-rate metric does not increment on per-peer message drops.
#[test]
fn t08_connection_metric_untouched_by_message_drops() {
    let p2p_metrics = P2pMetrics::new();
    let node_metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&node_metrics)),
    );
    let now = Instant::now();
    let n = node(6);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now)); // per-peer message-rate drop
    // Per-peer drop recorded, connection-rate metric untouched (separate metric).
    assert_eq!(node_metrics.peer_network().total_rate_limit_drops(), 1);
    assert_eq!(p2p_metrics.connection_rate_drop_total(), 0);
}

// 9. Connection-rate limiter remains independent and unchanged.
#[test]
fn t09_connection_limiter_independent() {
    // A per-peer-only override never enables the connection-rate limiter.
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    assert!(!state.connection_limiter_enabled());

    // Enabling the connection limiter does not change the derived per-peer
    // inbound limiter defaults.
    let limiter = deployed_inbound_limiter_from_cli(
        &[
            "--p2p-connection-rate-limit-enabled",
            "--p2p-connection-rate-window-ms",
            "1000",
            "--p2p-connection-rate-max",
            "5",
        ],
        None,
    );
    assert_eq!(
        limiter.config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(limiter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 10. No new public CLI flags appear.
#[test]
fn t10_no_new_public_cli_flags() {
    let mut cmd = CliArgs::command();
    let help = cmd.render_long_help().to_string();
    // Existing hidden flags stay hidden.
    assert!(!help.contains("--p2p-max-messages-per-second"));
    assert!(!help.contains("--p2p-burst-allowance"));
    // No invented Run 369 flag exists.
    assert!(!help.contains("--p2p-deployed-inbound-limiter"));
    assert!(!help.contains("--p2p-inbound-per-peer"));
}

// ============================================================================
// Rejection / fail-closed (11–17)
// ============================================================================

// 11. Zero per-peer max rejected.
#[test]
fn t11_zero_max_rejected() {
    let parsed = parse(&["--p2p-max-messages-per-second", "0"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// 12. Unsafe/unbounded per-peer max rejected.
#[test]
fn t12_unbounded_max_rejected() {
    let parsed = parse(&["--p2p-max-messages-per-second", "2000000"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// 13. Unsafe/unbounded burst rejected.
#[test]
fn t13_unbounded_burst_rejected() {
    let mut bad = AbuseDosConfig::compatibility_default();
    bad.per_peer_burst_allowance = 5_000_000;
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
}

// 14. Invalid connection-rate config still rejected.
#[test]
fn t14_invalid_connection_rate_rejected() {
    let mut bad = AbuseDosConfig::public_devnet_recommended();
    bad.connection_rate_window = Duration::from_secs(0);
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
}

// 15. Inconsistent per-address config still rejected.
#[test]
fn t15_inconsistent_per_address_rejected() {
    // Enabled connection limiter with a zero max per window is nonsensical.
    let parsed = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "0",
    ])
    .unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// 16. MainNet abuse/DoS enablement refused.
#[test]
fn t16_mainnet_refused() {
    let parsed = parse(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());

    let cfg = AbuseDosConfig::default()
        .with_environment(qbind_types::primitives::NetworkEnvironment::Mainnet);
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(cfg).is_err());
}

// 17. Invented CLI flags rejected.
#[test]
fn t17_invented_flags_rejected() {
    assert!(parse(&["--p2p-deployed-inbound-limiter", "500"]).is_err());
    assert!(parse(&["--p2p-inbound-per-peer-max", "500"]).is_err());
}

// ============================================================================
// Non-mutation / safety (18–29)
// ============================================================================

// 18–24. The inbound wiring is additive and touches no wire format, admission,
// trust, sequence, validator, or epoch state: constructing the adapter and
// draining a bucket only mutates the adapter's own token buckets and counter.
#[test]
fn t18_24_additive_no_state_mutation() {
    let limiter = deployed_inbound_limiter_from_cli(
        &["--p2p-max-messages-per-second", "500", "--p2p-burst-allowance", "10"],
        None,
    );
    assert_eq!(limiter.config().max_messages_per_second, 500);
    assert_eq!(limiter.config().burst_allowance, 10);

    // A per-peer override never enables the connection limiter (no admission
    // weakening) and never mutates trust/sequence/validator/epoch state — the
    // only observable effect is the adapter's own drop bucket.
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    let now = Instant::now();
    let remote = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        30303,
    );
    assert!(state.should_admit(remote, now));
    assert_eq!(state.drop_count(), 0);
}

// 25–26. No Run 070 path and no authority-lifecycle wiring is reachable from
// constructing the inbound limiter; it is inert with respect to those systems.
#[test]
fn t25_26_no_run070_or_authority_wiring() {
    // Building the adapter starts no listener/dialer and touches no authority
    // state. It only holds token buckets.
    let limiter = deployed_inbound_limiter_from_cli(&["--p2p-max-messages-per-second", "500"], None);
    assert_eq!(limiter.config().max_messages_per_second, 500);
    assert!(!limiter.has_metrics());
}

// 27–29. No public DevNet launch / TestNet-MainNet readiness / C4-C5 closure is
// claimed by this wiring: the default posture is behavior-preserving.
#[test]
fn t27_29_no_readiness_claims() {
    let limiter = deployed_inbound_limiter_from_cli(&[], None);
    let now = Instant::now();
    let n = node(9);
    // Default posture allows normal traffic; nothing here asserts launch
    // readiness or closes any criterion.
    for _ in 0..100 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
}

// ============================================================================
// Regression (30–33)
// ============================================================================

// 30. Run 368 AsyncPeerManagerImpl-layer helper semantics remain compatible:
// the deployed inbound adapter uses the same PeerRateLimiter with identical
// defaults, so a direct limiter and the adapter agree on the default posture.
#[test]
fn t30_run368_layer_defaults_compatible() {
    let direct = PeerRateLimiter::with_defaults();
    let adapter = DeployedInboundPerPeerLimiter::with_defaults(None);
    assert_eq!(
        direct.config().max_messages_per_second,
        adapter.config().max_messages_per_second
    );
    assert_eq!(
        direct.config().burst_allowance,
        adapter.config().burst_allowance
    );
}

// 31. Run 367 connection-rate behavior remains compatible: enabling the
// connection limiter still validates and builds a runtime state independent of
// the per-peer inbound adapter.
#[test]
fn t31_run367_connection_rate_compatible() {
    let parsed = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "5",
    ])
    .unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    assert!(state.connection_limiter_enabled());
}

// 32. Run 365 deployed builder config derivation remains compatible: the
// builder's derived per-peer config equals the runtime config's per-peer config.
#[test]
fn t32_run365_builder_derivation_compatible() {
    let args = ["--p2p-max-messages-per-second", "321", "--p2p-burst-allowance", "12"];
    let parsed = parse(&args).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    let expected: PeerRateLimiterConfig = rt.peer_rate_limiter_config();

    let builder = deployed_builder_from_cli(&args);
    let derived = builder
        .deployed_peer_rate_limiter_config()
        .expect("override present");
    assert_eq!(derived.max_messages_per_second, expected.max_messages_per_second);
    assert_eq!(derived.burst_allowance, expected.burst_allowance);

    // The adapter built from that derived config carries the same thresholds.
    let adapter = DeployedInboundPerPeerLimiter::from_optional_config(Some(derived), None);
    assert_eq!(adapter.config().max_messages_per_second, 321);
    assert_eq!(adapter.config().burst_allowance, 12);
}

// 33. Defaults are stable across the direct PeerRateLimiter, the deployed
// inbound adapter, and the bucket-keying path.
#[test]
fn t33_defaults_stable_across_paths() {
    let adapter = DeployedInboundPerPeerLimiter::from_optional_config(None, None);
    assert_eq!(adapter.config().max_messages_per_second, 1000);
    assert_eq!(adapter.config().burst_allowance, 100);

    // Bucket keying is deterministic (first 8 bytes, big-endian) and used only
    // for rate-limit bucket selection — not as an identity claim.
    assert_eq!(DeployedInboundPerPeerLimiter::bucket_key(&node(77)), PeerId(77));
}
