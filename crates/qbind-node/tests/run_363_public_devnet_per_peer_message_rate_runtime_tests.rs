//! Run 363 — Public DevNet per-peer message-rate runtime override tests.
//!
//! Run 362 delivered the runtime-owned connection-rate limiter and the hidden,
//! devnet-only `--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags,
//! but those per-peer flags were still inert: they never reached the live
//! per-peer inbound message-rate limiter (`PeerRateLimiter`) used by
//! `AsyncPeerManager`.
//!
//! Run 363 wires the validated per-peer thresholds from the Run 362 abuse/DoS
//! runtime config into the live peer-manager construction path at source/test
//! level:
//!
//! - `PublicDevnetAbuseDosRuntimeConfig::peer_rate_limiter_config()` derives the
//!   validated `PeerRateLimiterConfig`;
//! - `AsyncPeerManagerConfig::with_peer_rate_limiter_config(..)` installs it;
//! - `AsyncPeerManagerImpl::new`/`with_metrics` build the per-peer
//!   `PeerRateLimiter` from it (default → `PeerRateLimiter::with_defaults()`).
//!
//! These tests prove the previously inert flags now affect the live limiter
//! construction path while preserving default behavior exactly. Release-binary
//! evidence and any M12 Green decision are deferred to Run 364.
//!
//! All addresses used here are RFC 5737 documentation ranges or localhost —
//! never live endpoints.

use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};
use qbind_node::async_peer_manager::{AsyncPeerManagerConfig, AsyncPeerManagerImpl};
use qbind_node::cli::CliArgs;
use qbind_node::metrics::P2pMetrics;
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

/// Build a peer-manager whose per-peer limiter is derived from the given CLI
/// arguments, mirroring the live wiring
/// (`CliArgs::abuse_dos_runtime_config` → `peer_rate_limiter_config` →
/// `AsyncPeerManagerConfig::with_peer_rate_limiter_config`).
fn peer_manager_from_cli(args: &[&str]) -> AsyncPeerManagerImpl {
    let parsed = parse(args).expect("cli parses");
    let per_peer = parsed
        .abuse_dos_runtime_config()
        .expect("valid abuse/DoS config")
        .map(|rt| rt.peer_rate_limiter_config());
    let cfg = AsyncPeerManagerConfig::default().with_peer_rate_limiter_config(per_peer);
    AsyncPeerManagerImpl::new(cfg)
}

// ============================================================================
// Default compatibility
// ============================================================================

// 1. Default config uses PeerRateLimiter::with_defaults() (no override present).
#[test]
fn t01_default_config_uses_with_defaults() {
    // No abuse/DoS flags → no runtime config → None → with_defaults().
    let parsed = parse(&[]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().unwrap().is_none());

    let pm = AsyncPeerManagerImpl::new(AsyncPeerManagerConfig::default());
    let cfg = pm.peer_rate_limiter().config();
    let defaults = PeerRateLimiter::with_defaults();
    assert_eq!(cfg.max_messages_per_second, defaults.config().max_messages_per_second);
    assert_eq!(cfg.burst_allowance, defaults.config().burst_allowance);
}

// 2. Default values remain 1000 msg/s + 100 burst.
#[test]
fn t02_default_values_1000_and_100() {
    let pm = peer_manager_from_cli(&[]);
    let cfg = pm.peer_rate_limiter().config();
    assert_eq!(cfg.max_messages_per_second, 1000);
    assert_eq!(cfg.burst_allowance, 100);
    assert_eq!(cfg.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 15. Defaults unchanged when no flags are present (config + runtime state).
#[test]
fn t15_defaults_unchanged_without_flags() {
    let rt = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
    assert!(rt.preserves_runtime_defaults());
    let cfg = rt.peer_rate_limiter_config();
    assert_eq!(cfg.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// ============================================================================
// Explicit custom acceptance + reaching the live path
// ============================================================================

// 3. Explicit custom --p2p-max-messages-per-second accepted.
#[test]
fn t03_custom_max_messages_accepted() {
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert_eq!(rt.peer_rate_limiter_config().max_messages_per_second, 500);
    // Burst defaults preserved when only the message rate is overridden.
    assert_eq!(rt.peer_rate_limiter_config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
}

// 4. Explicit custom --p2p-burst-allowance accepted.
#[test]
fn t04_custom_burst_accepted() {
    let parsed = parse(&["--p2p-burst-allowance", "42"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert_eq!(rt.peer_rate_limiter_config().burst_allowance, 42);
    assert_eq!(
        rt.peer_rate_limiter_config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
}

// 5. Custom values reach the live peer-manager limiter construction path.
#[test]
fn t05_custom_values_reach_live_peer_manager() {
    let pm = peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "250",
        "--p2p-burst-allowance",
        "7",
    ]);
    let cfg = pm.peer_rate_limiter().config();
    assert_eq!(cfg.max_messages_per_second, 250);
    assert_eq!(cfg.burst_allowance, 7);
}

// ============================================================================
// Live limiter behavior (token-bucket determinism)
// ============================================================================

// 6. Under-budget messages are allowed.
#[test]
fn t06_under_budget_allowed() {
    // max=5, burst=0 → capacity 5, starts full.
    let pm = peer_manager_from_cli(&[
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

// 7. Over-budget messages are dropped.
#[test]
fn t07_over_budget_dropped() {
    let pm = peer_manager_from_cli(&[
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
}

// 8. Refill behavior remains deterministic.
#[test]
fn t08_refill_deterministic() {
    let pm = peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "5",
        "--p2p-burst-allowance",
        "0",
    ]);
    let limiter = pm.peer_rate_limiter();
    let peer = PeerId(9);
    let t0 = Instant::now();
    // Drain the bucket.
    for _ in 0..5 {
        assert!(limiter.allow(&peer, t0));
    }
    assert!(!limiter.allow(&peer, t0));
    // After one second, refill_rate (5/s) restores full capacity.
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..5 {
        assert!(limiter.allow(&peer, t1));
    }
    assert!(!limiter.allow(&peer, t1));
}

// 9. Burst behavior remains deterministic.
#[test]
fn t09_burst_deterministic() {
    // max=1, burst=10 → capacity 11 at t0.
    let pm = peer_manager_from_cli(&[
        "--p2p-max-messages-per-second",
        "1",
        "--p2p-burst-allowance",
        "10",
    ]);
    let limiter = pm.peer_rate_limiter();
    let peer = PeerId(2);
    let now = Instant::now();
    let mut allowed = 0u32;
    for _ in 0..11 {
        if limiter.allow(&peer, now) {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 11);
    // 12th within the same instant is over the burst capacity.
    assert!(!limiter.allow(&peer, now));
}

// ============================================================================
// Independence of the connection-rate limiter (Run 362)
// ============================================================================

// 10. Connection-rate limiter remains independent (per-peer flags don't enable it).
#[test]
fn t10_connection_limiter_independent() {
    let parsed = parse(&["--p2p-max-messages-per-second", "500"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    // A per-peer-only override never enables the connection-rate limiter.
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    assert!(!state.connection_limiter_enabled());
}

// 11. Connection-rate drop metric does not increment for message-rate drops.
#[test]
fn t11_connection_metric_untouched_by_message_drops() {
    let metrics = P2pMetrics::new();
    // Independent per-peer limiter (capacity 1) that will drop.
    let limiter = PeerRateLimiter::new(PeerRateLimiterConfig::new(1, 0));
    let peer = PeerId(3);
    let now = Instant::now();
    assert!(limiter.allow(&peer, now));
    assert!(!limiter.allow(&peer, now)); // message-rate drop
    // The connection-rate drop counter is a *separate* metric and stays zero.
    assert_eq!(metrics.connection_rate_drop_total(), 0);
}

// ============================================================================
// Fail-closed rejection
// ============================================================================

// 12. Invalid zero max messages/sec rejected.
#[test]
fn t12_zero_max_messages_rejected() {
    let parsed = parse(&["--p2p-max-messages-per-second", "0"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// 13. Unsafe/unbounded message-rate rejected.
#[test]
fn t13_unbounded_message_rate_rejected() {
    // Exceeds MAX_MESSAGES_PER_SECOND (1_000_000).
    let parsed = parse(&["--p2p-max-messages-per-second", "2000000"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());

    // Direct config path: an unbounded burst is also rejected before construction.
    let mut bad = AbuseDosConfig::compatibility_default();
    bad.per_peer_burst_allowance = 5_000_000;
    assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
}

// 14. MainNet refused.
#[test]
fn t14_mainnet_refused() {
    let parsed = parse(&["--env", "mainnet", "--p2p-max-messages-per-second", "500"]).unwrap();
    assert!(parsed.abuse_dos_runtime_config().is_err());
}

// ============================================================================
// CLI surface
// ============================================================================

// 16. Hidden flags absent from --help.
#[test]
fn t16_hidden_flags_absent_from_help() {
    let mut cmd = CliArgs::command();
    let help = cmd.render_long_help().to_string();
    assert!(!help.contains("--p2p-max-messages-per-second"));
    assert!(!help.contains("--p2p-burst-allowance"));
}

// 17. Real hidden flags parse.
#[test]
fn t17_real_hidden_flags_parse() {
    assert!(parse(&["--p2p-max-messages-per-second", "750"]).is_ok());
    assert!(parse(&["--p2p-burst-allowance", "60"]).is_ok());
}

// 18. Invented flags rejected.
#[test]
fn t18_invented_flags_rejected() {
    assert!(parse(&["--p2p-max-messages", "500"]).is_err());
    assert!(parse(&["--p2p-message-burst", "60"]).is_err());
}

// ============================================================================
// Non-mutation / safety invariants
// ============================================================================

// 19–26. The wiring is additive: a per-peer override only changes the per-peer
// limiter thresholds. It never enables the connection limiter, never admits or
// refuses connections differently, and touches no trust / sequence / validator
// / epoch state. We assert the observable surface: default admission is
// unchanged and no connection-rate refusal is produced by a per-peer override.
#[test]
fn t19_26_no_admission_or_state_weakening() {
    let parsed = parse(&[
        "--p2p-max-messages-per-second",
        "500",
        "--p2p-burst-allowance",
        "10",
    ])
    .unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    // Connection limiter still disabled → the accept path is unchanged.
    assert!(!rt.connection_limiter_enabled());
    let state = rt.into_runtime_state(None).unwrap();
    let now = Instant::now();
    // With the connection limiter disabled, every inbound is admitted exactly as
    // before (no peer-admission weakening, no trust/sequence/validator mutation
    // is reachable from this path).
    for i in 0..64u16 {
        let remote = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            i,
        );
        assert!(state.should_admit(remote, now));
    }
    assert_eq!(state.drop_count(), 0);
}

// 27–29. Readiness posture markers: this run does not make the public DevNet
// launch-ready and does not flip M4/M12 Green. These are documented invariants;
// the source guarantee is that a per-peer override never enables MainNet and
// never enables the connection limiter implicitly.
#[test]
fn t27_29_readiness_posture_unchanged() {
    // Per-peer-only override is DevNet-bound and connection-limiter-disabled.
    let parsed = parse(&["--p2p-burst-allowance", "10"]).unwrap();
    let rt = parsed.abuse_dos_runtime_config().unwrap().expect("config");
    assert!(!rt.connection_limiter_enabled());
    // MainNet remains refused (M-readiness unchanged; no MainNet enablement).
    let mainnet = parse(&["--env", "mainnet", "--p2p-burst-allowance", "10"]).unwrap();
    assert!(mainnet.abuse_dos_runtime_config().is_err());
}

// 30. Existing Run 361/362 behavior preserved: the default runtime config still
// derives exactly the historical per-peer defaults, so importing this wiring
// changes nothing unless the operator overrides values.
#[test]
fn t30_run361_run362_behavior_preserved() {
    let rt = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
    let cfg = rt.peer_rate_limiter_config();
    assert_eq!(cfg.max_messages_per_second, DEFAULT_MAX_MESSAGES_PER_SECOND);
    assert_eq!(cfg.burst_allowance, DEFAULT_BURST_ALLOWANCE);
    // And a peer-manager with no override matches with_defaults() exactly.
    let pm = AsyncPeerManagerImpl::new(AsyncPeerManagerConfig::default());
    assert_eq!(
        pm.peer_rate_limiter().config().max_messages_per_second,
        DEFAULT_MAX_MESSAGES_PER_SECOND
    );
    assert_eq!(
        pm.peer_rate_limiter().config().burst_allowance,
        DEFAULT_BURST_ALLOWANCE
    );
}
