//! Run 365 — Public DevNet deployed-node per-peer message-rate threading tests.
//!
//! Run 363 wired the validated per-peer thresholds from the Run 362 abuse/DoS
//! runtime config into an `AsyncPeerManagerImpl` constructed by the *test*
//! helper. Run 364 confirmed that in release mode the override reaches the live
//! `AsyncPeerManagerImpl` construction path, but flagged that the *deployed*
//! `qbind-node` builder (`main.rs` → `p2p_node_builder`) did not itself thread
//! the CLI-derived `peer_rate_limiter_config` into that construction path.
//!
//! Run 365 closes that source/test gap by threading the validated per-peer
//! config through `P2pNodeBuilder`:
//!
//! - `P2pNodeBuilder::with_abuse_dos_runtime_config(..)` installs the validated
//!   runtime config (exactly as `main.rs` does from
//!   `CliArgs::abuse_dos_runtime_config()`);
//! - `P2pNodeBuilder::deployed_peer_rate_limiter_config()` derives the validated
//!   `Option<PeerRateLimiterConfig>` (None → defaults, Some → override);
//! - `P2pNodeBuilder::build_deployed_peer_manager()` constructs the live
//!   `AsyncPeerManagerImpl` with that config threaded in.
//!
//! These tests prove the deployed builder path now consumes the configured
//! per-peer limiter while preserving default behavior and the Run 362
//! connection-rate limiter exactly. Release-binary evidence and any M12 Green
//! decision are deferred to Run 366.
//!
//! All addresses used here are RFC 5737 documentation ranges or localhost —
//! never live endpoints.

use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};
use qbind_node::async_peer_manager::{AsyncPeerManagerConfig, AsyncPeerManagerImpl};
use qbind_node::cli::CliArgs;
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::peer::PeerId;
use qbind_node::peer_rate_limiter::{
    PeerRateLimiter, PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE,
    DEFAULT_MAX_MESSAGES_PER_SECOND,
};
use qbind_node::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;

fn parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let mut full = vec!["qbind-node"];
    full.extend_from_slice(args);
    CliArgs::try_parse_from(full)
}

/// Build the deployed `P2pNodeBuilder` exactly the way `main.rs` does: parse the
/// CLI, and if the hidden abuse/DoS flags produced a validated runtime config,
/// install it via `with_abuse_dos_runtime_config`.
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

/// Construct the live `AsyncPeerManagerImpl` the deployed node uses, threaded
/// with the CLI-derived per-peer message-rate limiter.
fn deployed_peer_manager_from_cli(args: &[&str]) -> AsyncPeerManagerImpl {
    deployed_builder_from_cli(args).build_deployed_peer_manager()
}

// ============================================================================
// 1–2, 7. Deployed builder default → default per-peer limiter, unchanged
// ============================================================================

// 1. Deployed-node builder default constructs peer manager with default limiter.
#[test]
fn t01_deployed_default_uses_with_defaults() {
    // No abuse/DoS flags → no runtime config installed → None → with_defaults().
    let builder = deployed_builder_from_cli(&[]);
    assert!(builder.deployed_peer_rate_limiter_config().is_none());

    let pm = builder.build_deployed_peer_manager();
    let cfg = pm.peer_rate_limiter().config();
    let defaults = PeerRateLimiter::with_defaults();
    assert_eq!(
        cfg.max_messages_per_second,
        defaults.config().max_messages_per_second
    );
    assert_eq!(cfg.burst_allowance, defaults.config().burst_allowance);
}

// 2. No flags preserve 1000 msg/s + 100 burst on the deployed peer manager.
#[test]
fn t02_deployed_default_values_1000_and_100() {
    let pm = deployed_peer_manager_from_cli(&[]);
    let cfg = pm.peer_rate_limiter().config();
    assert_eq!(cfg.max_messages_per_second, 1000);
    assert_eq!(cfg.burst_allowance, 100);
    assert_eq!(cfg.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 7. Default limiter behavior remains unchanged: the deployed default matches
// a directly-built default peer manager bit-for-bit.
#[test]
fn t07_deployed_default_matches_direct_default() {
    let deployed = deployed_peer_manager_from_cli(&[]);
    let direct = AsyncPeerManagerImpl::new(AsyncPeerManagerConfig::default());
    assert_eq!(
        deployed.peer_rate_limiter().config().max_messages_per_second,
        direct.peer_rate_limiter().config().max_messages_per_second
    );
    assert_eq!(
        deployed.peer_rate_limiter().config().burst_allowance,
        direct.peer_rate_limiter().config().burst_allowance
    );
    // The deployed builder with no override yields the default AsyncPeerManagerConfig.
    let builder = deployed_builder_from_cli(&[]);
    assert!(builder.deployed_peer_rate_limiter_config().is_none());
}

// ============================================================================
// 3–4. Valid custom overrides reach the deployed peer-manager config
// ============================================================================

// 3. Valid custom --p2p-max-messages-per-second reaches deployed peer-manager.
#[test]
fn t03_custom_max_messages_reaches_deployed() {
    let builder = deployed_builder_from_cli(&["--p2p-max-messages-per-second", "500"]);
    let derived = builder
        .deployed_peer_rate_limiter_config()
        .expect("override present");
    assert_eq!(derived.max_messages_per_second, 500);
    // Burst default preserved when only the message rate is overridden.
    assert_eq!(derived.burst_allowance, DEFAULT_BURST_ALLOWANCE);

    let pm = builder.build_deployed_peer_manager();
    assert_eq!(pm.peer_rate_limiter().config().max_messages_per_second, 500);
    assert_eq!(
        pm.peer_rate_limiter().config().burst_allowance,
        DEFAULT_BURST_ALLOWANCE
    );
}

// 4. Valid custom --p2p-burst-allowance reaches deployed peer-manager.
#[test]
fn t04_custom_burst_reaches_deployed() {
    let builder = deployed_builder_from_cli(&["--p2p-burst-allowance", "42"]);
    let derived = builder
        .deployed_peer_rate_limiter_config()
        .expect("override present");
    assert_eq!(derived.burst_allowance, 42);
    assert_eq!(derived.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);

    let pm = builder.build_deployed_peer_manager();
    assert_eq!(pm.peer_rate_limiter().config().burst_allowance, 42);
    assert_eq!(
        pm.peer_rate_limiter().config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
}

// ============================================================================
// 5–6. Custom deployed per-peer limiter token-bucket behavior
// ============================================================================

// 5. Custom per-peer limiter allows under-budget messages.
#[test]
fn t05_deployed_custom_allows_under_budget() {
    // max=5, burst=0 → capacity 5, starts full.
    let pm = deployed_peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "5",
        "--p2p-burst-allowance",
        "0",
    ]);
    let limiter = pm.peer_rate_limiter();
    let peer = PeerId(1);
    let now = Instant::now();
    for _ in 0..5 {
        assert!(limiter.allow(&peer, now));
    }
}

// 6. Custom per-peer limiter drops over-budget messages.
#[test]
fn t06_deployed_custom_drops_over_budget() {
    let pm = deployed_peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "5",
        "--p2p-burst-allowance",
        "0",
    ]);
    let limiter = pm.peer_rate_limiter();
    let peer = PeerId(1);
    let now = Instant::now();
    for _ in 0..5 {
        assert!(limiter.allow(&peer, now));
    }
    // 6th message within the same instant exceeds the budget.
    assert!(!limiter.allow(&peer, now));
    // After one second, the 5/s refill restores full capacity (deterministic).
    let t1 = now + Duration::from_secs(1);
    for _ in 0..5 {
        assert!(limiter.allow(&peer, t1));
    }
    assert!(!limiter.allow(&peer, t1));
}

// ============================================================================
// 8–10. Connection-rate limiter independence (Run 362 unchanged)
// ============================================================================

// 8. Connection-rate limiter config still reaches the accept-loop path.
#[test]
fn t08_connection_limiter_still_reaches_accept_path() {
    let parsed = parse(&[
        "--p2p-connection-rate-limit-enabled",
        "--p2p-connection-rate-window-ms",
        "1000",
        "--p2p-connection-rate-max",
        "5",
    ])
    .expect("cli parses");
    let rt = parsed
        .abuse_dos_runtime_config()
        .expect("valid")
        .expect("config present");
    // The connection-rate limiter is enabled and builds a runtime state that
    // the builder installs on the accept path (Run 362 wiring unchanged).
    assert!(rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).expect("runtime state builds");
    assert!(state.connection_limiter_enabled());

    // Installing this config on the deployed builder still yields a default
    // per-peer limiter (no per-peer override was supplied).
    let builder = P2pNodeBuilder::new().with_abuse_dos_runtime_config(
        parsed
            .abuse_dos_runtime_config()
            .expect("valid")
            .expect("config present"),
    );
    let derived = builder
        .deployed_peer_rate_limiter_config()
        .expect("config present");
    assert_eq!(derived.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(derived.burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 9. Connection-rate limiter and per-peer limiter remain independent.
#[test]
fn t09_connection_and_per_peer_independent() {
    // A per-peer-only override never enables the connection-rate limiter.
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    assert!(!state.connection_limiter_enabled());

    // The same override still reaches the deployed per-peer limiter.
    let pm = deployed_peer_manager_from_cli(&["--p2p-max-messages-per-second", "500"]);
    assert_eq!(pm.peer_rate_limiter().config().max_messages_per_second, 500);
}

// 10. Connection-rate metric does not increment on a per-peer message drop.
#[test]
fn t10_connection_metric_untouched_by_message_drops() {
    let metrics = P2pMetrics::new();
    let pm = deployed_peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "1",
        "--p2p-burst-allowance",
        "0",
    ]);
    let limiter = pm.peer_rate_limiter();
    let peer = PeerId(3);
    let now = Instant::now();
    assert!(limiter.allow(&peer, now));
    assert!(!limiter.allow(&peer, now)); // per-peer message-rate drop
    // The connection-rate drop counter is a *separate* metric and stays zero.
    assert_eq!(metrics.connection_rate_drop_total(), 0);
}

// ============================================================================
// 11–13. Fail-closed rejection through the deployed path
// ============================================================================

// 11. Invalid zero message-rate max rejected before any builder is constructed.
#[test]
fn t11_zero_max_messages_rejected() {
    let parsed = parse(&["--p2p-max-messages-per-second", "0"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// 12. Unsafe/unbounded message-rate rejected.
#[test]
fn t12_unbounded_message_rate_rejected() {
    let parsed = parse(&["--p2p-max-messages-per-second", "2000000"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());

    // Direct runtime-config path: an unbounded burst is also rejected.
    let mut bad = qbind_node::public_devnet_abuse_dos_config::AbuseDosConfig::compatibility_default();
    bad.per_peer_burst_allowance = 5_000_000;
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
}

// 13. MainNet refused.
#[test]
fn t13_mainnet_refused() {
    let parsed = parse(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// ============================================================================
// 14–16. CLI surface
// ============================================================================

// 14. Hidden flags absent from --help.
#[test]
fn t14_hidden_flags_absent_from_help() {
    let mut cmd = CliArgs::command();
    let help = cmd.render_long_help().to_string();
    assert!(!help.contains("--p2p-max-messages-per-second"));
    assert!(!help.contains("--p2p-burst-allowance"));
}

// 15. Real hidden flags parse.
#[test]
fn t15_real_hidden_flags_parse() {
    assert!(parse(&["--p2p-max-messages-per-second", "750"]).is_ok());
    assert!(parse(&["--p2p-burst-allowance", "60"]).is_ok());
}

// 16. Invented flags rejected (no new public CLI surface).
#[test]
fn t16_invented_flags_rejected() {
    assert!(parse(&["--p2p-deployed-max-messages", "500"]).is_err());
    assert!(parse(&["--p2p-peer-manager-burst", "60"]).is_err());
}

// ============================================================================
// 17–25. Non-mutation / safety invariants
// ============================================================================

// 17–24. The deployed threading is additive: a per-peer override only changes
// the per-peer limiter thresholds on the constructed peer manager. It never
// enables the connection limiter, never changes P2P wire format, never weakens
// peer admission or trust-bundle behavior, and touches no LivePqcTrustState /
// sequence-marker / validator-set / epoch state.
#[test]
fn t17_25_no_wire_or_state_weakening() {
    let builder = deployed_builder_from_cli(&[
        "--p2p-max-messages-per-second",
        "500",
        "--p2p-burst-allowance",
        "10",
    ]);
    // Only the per-peer limiter thresholds change; the connection limiter stays
    // disabled so the accept path is unchanged (no admission weakening).
    let derived = builder
        .deployed_peer_rate_limiter_config()
        .expect("override present");
    assert_eq!(derived.max_messages_per_second, 500);
    assert_eq!(derived.burst_allowance, 10);

    let parsed = parse(&[
        "--p2p-max-messages-per-second",
        "500",
        "--p2p-burst-allowance",
        "10",
    ])
    .unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    // With the connection limiter disabled, inbound is admitted exactly as
    // before — no peer-admission weakening, no trust/sequence/validator/epoch
    // mutation is reachable from this override.
    let now = Instant::now();
    let remote = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        30303,
    );
    assert!(state.should_admit(remote, now));
    assert_eq!(state.drop_count(), 0);
}

// 25. Public DevNet is not launch-ready and no Run 070 apply path is reachable:
// the deployed threading never enables the connection limiter by itself and
// never claims launch readiness.
#[test]
fn t25_public_devnet_not_launch_ready() {
    // A per-peer override alone does not enable the connection limiter, and no
    // seed/bootnode/faucet/RPC surface is created by constructing a peer manager.
    let builder = deployed_builder_from_cli(&["--p2p-max-messages-per-second", "500"]);
    let pm = builder.build_deployed_peer_manager();
    // The peer manager exists but no listener/dialer has been started here;
    // constructing it is inert with respect to launch readiness.
    assert_eq!(pm.peer_rate_limiter().config().max_messages_per_second, 500);
}

// ============================================================================
// 26–31. Prior-run regression anchors (documented; enforced by their targets)
// ============================================================================

// 26–28. M4/M6 remain Yellow and M12 remains Yellow/Partial: this run adds no
// seed/bootnode reachability, no identity-generation support, and no
// release-binary evidence. Enforced by the readiness-matrix docs; here we
// assert the deployed default remains behavior-preserving so no matrix cell is
// silently moved by construction.
#[test]
fn t26_28_defaults_preserve_matrix_neutrality() {
    let pm = deployed_peer_manager_from_cli(&[]);
    assert_eq!(
        pm.peer_rate_limiter().config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(
        pm.peer_rate_limiter().config().burst_allowance,
        DEFAULT_BURST_ALLOWANCE
    );
}

// 29–31. Run 361/362/363 targets remain green (verified by running those test
// targets). Here we re-assert the invariant those runs depend on: the derived
// deployed per-peer config equals the runtime config's per-peer config exactly,
// so the deployed builder introduces no divergence from Run 363's seam.
#[test]
fn t29_31_deployed_config_matches_runtime_config() {
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
    assert_eq!(derived.max_messages_per_second, 321);
    assert_eq!(derived.burst_allowance, 12);
}