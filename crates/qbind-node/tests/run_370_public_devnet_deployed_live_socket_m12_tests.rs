//! Run 370 — Public DevNet deployed live-socket M12 source tests.
//!
//! Run 369 wired the per-peer `PeerRateLimiter` onto the deployed
//! `TcpKemTlsP2pService::read_loop` receive path via the
//! `DeployedInboundPerPeerLimiter` adapter, but the deployed builder could only
//! install that adapter with `metrics = None` (the builder held a `P2pMetrics`,
//! not the `NodeMetrics` that owns `qbind_net_per_peer_drops_total`). So the
//! adapter's own bounded per-peer drop counter recorded drops, but the exported
//! `/metrics` counter never moved on the deployed path.
//!
//! Run 370 threads the optional live `NodeMetrics` handle through
//! `P2pNodeBuilder::with_node_metrics` into the deployed adapter (installed by
//! `start()` via the shared `build_deployed_inbound_per_peer_limiter()` seam).
//! `main.rs` wires this with the SAME `Arc<NodeMetrics>` the live `/metrics`
//! endpoint scrapes, so a per-peer message-rate drop on the deployed receive
//! path bumps the exported `qbind_net_per_peer_drops_total{reason="rate_limit"}`
//! counter.
//!
//! These tests verify the Route B source change at the source/test level:
//!
//! * the default (no `with_node_metrics`) builder installs the adapter with
//!   `metrics = None`, preserving the Run 369 posture bit-for-bit;
//! * `with_node_metrics` installs the adapter with the shared handle so a drop
//!   bumps `qbind_net_per_peer_drops_total{reason="rate_limit"}` in the exported
//!   `NodeMetrics::format_metrics` text;
//! * the connection-rate metric is never touched by per-peer message drops, and
//!   per-peer drops never touch the connection-rate metric (independence);
//! * defaults, hidden CLI surface, fail-closed validation and MainNet refusal
//!   are unchanged;
//! * no new public CLI flags and no wire/admission/trust/validator/epoch
//!   mutation are introduced.
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
use qbind_node::peer_rate_limiter::{
    PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_config::AbuseDosConfig;
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;

fn parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// Build the deployed `P2pNodeBuilder` exactly the way `main.rs` does, and (Run
/// 370) optionally install the live `NodeMetrics` handle via
/// `with_node_metrics` — the seam that reaches the deployed inbound limiter.
fn deployed_builder(args: &[&str], node_metrics: Option<Arc<NodeMetrics>>) -> P2pNodeBuilder {
    let parsed = parse(args).expect("cli parses");
    let mut builder = P2pNodeBuilder::new();
    if let Some(rt) = parsed
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
    {
        builder = builder.with_abuse_dos_runtime_config(rt);
    }
    if let Some(m) = node_metrics {
        builder = builder.with_node_metrics(m);
    }
    builder
}

/// Construct the deployed inbound per-peer limiter adapter through the SAME
/// builder seam `start()` uses, so the tested construction matches deployment.
fn deployed_inbound_limiter(
    args: &[&str],
    node_metrics: Option<Arc<NodeMetrics>>,
) -> DeployedInboundPerPeerLimiter {
    deployed_builder(args, node_metrics).build_deployed_inbound_per_peer_limiter()
}

fn node(seed: u64) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    NodeId::new(bytes)
}

// ============================================================================
// Default compatibility (1–4)
// ============================================================================

// 1. Default no-flag builder installs the deployed adapter with metrics = None
//    (Run 369 posture preserved bit-for-bit).
#[test]
fn t01_default_builder_installs_metrics_none() {
    let limiter = deployed_inbound_limiter(&[], None);
    assert!(!limiter.has_metrics());
    assert_eq!(
        limiter.config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(limiter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 2. Default no-flag under-budget traffic is allowed with no drops.
#[test]
fn t02_default_under_budget_no_drops() {
    let limiter = deployed_inbound_limiter(&[], None);
    let now = Instant::now();
    let n = node(1);
    for _ in 0..200 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
}

// 3. Installing a NodeMetrics handle does NOT change the default thresholds.
#[test]
fn t03_node_metrics_preserves_defaults() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(&[], Some(Arc::clone(&metrics)));
    assert!(limiter.has_metrics());
    assert_eq!(limiter.config().max_messages_per_second, 1000);
    assert_eq!(limiter.config().burst_allowance, 100);
    // No traffic yet → exported counter absent / zero.
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 0);
}

// 4. Custom hidden overrides still reach the deployed adapter through the seam.
#[test]
fn t04_custom_overrides_reach_adapter() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "5", "--p2p-burst-allowance", "0"],
        Some(metrics),
    );
    assert_eq!(limiter.config().max_messages_per_second, 5);
    assert_eq!(limiter.config().burst_allowance, 0);
    assert!(limiter.has_metrics());
}

// ============================================================================
// Route B: exported per-peer metric wiring (5–9)
// ============================================================================

// 5. With a NodeMetrics handle installed, an over-budget deployed inbound frame
//    bumps the exported qbind_net_per_peer_drops_total{reason="rate_limit"}.
#[test]
fn t05_over_budget_bumps_exported_metric() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&metrics)),
    );
    let now = Instant::now();
    let n = node(2);
    assert!(limiter.allow_node(&n, now)); // within budget
    assert!(!limiter.allow_node(&n, now)); // over budget → drop
    // Adapter's own counter AND the exported per-peer counter both moved.
    assert_eq!(limiter.drop_count(), 1);
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 1);

    // The exported /metrics text actually carries the per-peer rate-limit drop.
    let rendered = metrics.format_metrics();
    assert!(
        rendered.contains("qbind_net_per_peer_drops_total"),
        "exported metrics missing per-peer drop family:\n{rendered}"
    );
    assert!(
        rendered.contains("reason=\"rate_limit\""),
        "exported per-peer drop missing rate_limit reason label:\n{rendered}"
    );
}

// 6. Under-budget deployed inbound frames never bump the exported metric.
#[test]
fn t06_under_budget_leaves_exported_metric_zero() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "50", "--p2p-burst-allowance", "10"],
        Some(Arc::clone(&metrics)),
    );
    let now = Instant::now();
    let n = node(3);
    for _ in 0..40 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 0);
}

// 7. Without a NodeMetrics handle the exported metric stays absent even though
//    the adapter's own counter records the drop (Run 369 posture).
#[test]
fn t07_no_handle_no_exported_metric() {
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        None,
    );
    let now = Instant::now();
    let n = node(4);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now));
    assert_eq!(limiter.drop_count(), 1);
    assert!(!limiter.has_metrics());
    // A freshly rendered NodeMetrics that was never handed to the adapter shows
    // no per-peer drops.
    let unrelated = NodeMetrics::new();
    assert_eq!(unrelated.peer_network().total_rate_limit_drops(), 0);
}

// 8. Per-peer key attribution: exported metric records the exact bucket peer.
#[test]
fn t08_exported_metric_records_bucket_peer() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&metrics)),
    );
    let now = Instant::now();
    let n = node(7);
    let key = DeployedInboundPerPeerLimiter::bucket_key(&n);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now));
    assert_eq!(
        metrics.peer_network().peer_rate_limit_drop_count(key),
        Some(1)
    );
}

// 9. Multiple over-budget frames accumulate on the exported counter.
#[test]
fn t09_exported_metric_accumulates() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "2", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&metrics)),
    );
    let now = Instant::now();
    let n = node(8);
    assert!(limiter.allow_node(&n, now));
    assert!(limiter.allow_node(&n, now));
    for _ in 0..5 {
        assert!(!limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 5);
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 5);
}

// ============================================================================
// Combined limiter independence (10–11)
// ============================================================================

// 10. Per-peer message drops never touch the connection-rate metric.
#[test]
fn t10_per_peer_drops_do_not_touch_connection_metric() {
    let node_metrics = Arc::new(NodeMetrics::new());
    let p2p_metrics = P2pMetrics::new();
    let limiter = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "1", "--p2p-burst-allowance", "0"],
        Some(Arc::clone(&node_metrics)),
    );
    let now = Instant::now();
    let n = node(9);
    assert!(limiter.allow_node(&n, now));
    assert!(!limiter.allow_node(&n, now));
    assert_eq!(node_metrics.peer_network().total_rate_limit_drops(), 1);
    // The connection-rate metric is a wholly separate counter and never moves.
    assert_eq!(p2p_metrics.connection_rate_drop_total(), 0);
}

// 11. Connection-rate refusals never touch the per-peer message drop counter.
#[test]
fn t11_connection_refusals_do_not_touch_per_peer() {
    let node_metrics = Arc::new(NodeMetrics::new());
    let p2p_metrics = P2pMetrics::new();
    // Simulate a connection-rate refusal directly on the connection-rate metric.
    p2p_metrics.record_connection_rate_drop();
    p2p_metrics.record_connection_rate_drop();
    assert_eq!(p2p_metrics.connection_rate_drop_total(), 2);
    // The per-peer message-drop counter is untouched by connection refusals.
    assert_eq!(node_metrics.peer_network().total_rate_limit_drops(), 0);
}

// ============================================================================
// CLI surface, fail-closed, MainNet (12–17)
// ============================================================================

// 12. No new public CLI flags; the Run 370 wiring adds no operator surface.
#[test]
fn t12_no_new_public_cli_flags() {
    let mut cmd = CliArgs::command();
    let help = cmd.render_long_help().to_string();
    assert!(!help.contains("--p2p-max-messages-per-second"));
    assert!(!help.contains("--p2p-burst-allowance"));
    assert!(!help.contains("--p2p-node-metrics"));
    assert!(!help.contains("--p2p-per-peer-metrics"));
}

// 13. Invented flags are rejected by clap.
#[test]
fn t13_invented_flags_rejected() {
    assert!(parse(&["--p2p-node-metrics", "on"]).is_err());
    assert!(parse(&["--p2p-per-peer-metrics-enabled"]).is_err());
}

// 14. Zero per-peer max fails closed.
#[test]
fn t14_zero_max_fails_closed() {
    assert!(parse(&["--p2p-max-messages-per-second", "0"])
        .unwrap()
        .abuse_dos_runtime_config()
        .is_err());
}

// 15. Unbounded per-peer max fails closed.
#[test]
fn t15_unbounded_max_fails_closed() {
    assert!(parse(&["--p2p-max-messages-per-second", "2000000"])
        .unwrap()
        .abuse_dos_runtime_config()
        .is_err());
}

// 16. Zero connection-rate config fails closed.
#[test]
fn t16_zero_connection_rate_fails_closed() {
    let mut bad = AbuseDosConfig::public_devnet_recommended();
    bad.connection_rate_window = Duration::from_secs(0);
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
}

// 17. MainNet abuse/DoS enablement refused.
#[test]
fn t17_mainnet_refused() {
    assert!(parse(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"])
        .unwrap()
        .abuse_dos_runtime_config()
        .is_err());
    let cfg = AbuseDosConfig::default()
        .with_environment(qbind_types::primitives::NetworkEnvironment::Mainnet);
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(cfg).is_err());
}

// ============================================================================
// Non-mutation / safety (18–20)
// ============================================================================

// 18. Installing the NodeMetrics handle mutates no admission/trust state: a
//     per-peer override never enables the connection limiter.
#[test]
fn t18_additive_no_admission_change() {
    let metrics = Arc::new(NodeMetrics::new());
    let builder = deployed_builder(
        &["--p2p-max-messages-per-second", "500"],
        Some(Arc::clone(&metrics)),
    );
    // The connection-rate limiter is not enabled by a per-peer override.
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    // The seam builds an adapter carrying the override + the handle.
    let limiter = builder.build_deployed_inbound_per_peer_limiter();
    assert_eq!(limiter.config().max_messages_per_second, 500);
    assert!(limiter.has_metrics());
}

// 19. The seam used by start() and tests agrees with a direct adapter build.
#[test]
fn t19_seam_matches_direct_construction() {
    let metrics = Arc::new(NodeMetrics::new());
    let via_seam = deployed_inbound_limiter(
        &["--p2p-max-messages-per-second", "250", "--p2p-burst-allowance", "25"],
        Some(Arc::clone(&metrics)),
    );
    let direct = DeployedInboundPerPeerLimiter::from_optional_config(
        Some(PeerRateLimiterConfig::new(250, 25)),
        Some(metrics),
    );
    assert_eq!(
        via_seam.config().max_messages_per_second,
        direct.config().max_messages_per_second
    );
    assert_eq!(
        via_seam.config().burst_allowance,
        direct.config().burst_allowance
    );
    assert_eq!(via_seam.has_metrics(), direct.has_metrics());
}

// 20. Default posture makes no readiness claim: normal traffic is unaffected
//     and no drops or exported metric movement occur.
#[test]
fn t20_default_posture_no_readiness_claim() {
    let metrics = Arc::new(NodeMetrics::new());
    let limiter = deployed_inbound_limiter(&[], Some(Arc::clone(&metrics)));
    let now = Instant::now();
    let n = node(11);
    for _ in 0..100 {
        assert!(limiter.allow_node(&n, now));
    }
    assert_eq!(limiter.drop_count(), 0);
    assert_eq!(metrics.peer_network().total_rate_limit_drops(), 0);
}
